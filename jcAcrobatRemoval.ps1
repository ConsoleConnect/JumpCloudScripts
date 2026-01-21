<#
     ____.                    _________ .__                   .___
    |    |__ __  _____ ______ \_   ___ \|  |   ____  __ __  __| _/
    |    |  |  \/     \\____ \/    \  \/|  |  /  _ \|  |  \/ __ |
/\__|    |  |  /  Y Y  \  |_> >     \___|  |_(  <_> )  |  / /_/ |
\________|____/|__|_|  /   __/ \______  /____/\____/|____/\____ |
                     \/|__|           \/                       \/
                          (c) 2026 - Frederic Lhoest - PCCW Global 
                          
Uninstall Adobe Acrobat 2017 silently with strong remote evidence output.

DESCRIPTION
  - Finds installed Acrobat 2017 entries from registry uninstall keys (both 32/64-bit).
  - Collects evidence: DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, QuietUninstallString, ProductCode (if MSI).
  - Attempts uninstall in priority order:
      1) MSI ProductCode via msiexec /x /qn /norestart + verbose log
      2) UninstallString/QuietUninstallString (EXE) with best-effort silent flags
      3) Fallback: msiexec /x if a ProductCode can be derived from UninstallString
  - Waits for uninstall process to end and re-checks that product is gone.
  - Outputs detailed progress, timing, command lines used, exit codes, and post-check results.
  - Exits 0 if removed or not found; exits 1 if found but not removed.

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Configuration
# -------------------------
$TargetNameRegex = '(?i)\bAdobe\s+Acrobat\b'           # Must contain "Adobe Acrobat"
$TargetYearRegex = '(?i)\b2017\b'                     # Must contain 2017
$ExcludeNameRegex = '(?i)\bReader\b'                  # Exclude Reader
$ExcludeDcRegex   = '(?i)\bDC\b'                      # Exclude DC (keep as protection)

$MaxWaitMinutes = 20
$PollSeconds = 5

# Where to store MSI logs (local device)
$LogRoot = Join-Path -Path $env:ProgramData -ChildPath "JumpCloud\Logs\AdobeAcrobat2017-Uninstall"
$null = New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction SilentlyContinue

# -------------------------
# Helpers
# -------------------------
function Write-Log
{
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    Write-Output "[$ts][$Level] $Message"
}

function As-Array
{
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value)
    {
        return @()
    }

    return @($Value)
}

function Get-OsInfo
{
    try
    {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        return [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Caption      = $os.Caption
            Version      = $os.Version
            BuildNumber  = $os.BuildNumber
            Arch         = $os.OSArchitecture
            Domain       = $cs.Domain
            UserContext  = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            IsSystem     = ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
        }
    }
    catch
    {
        return $null
    }
}

function Get-RegValue
{
    param(
        [Parameter(Mandatory)]
        $Object,
        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $p = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $p)
    {
        return $null
    }

    return $p.Value
}

function Get-UninstallEntries
{
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $results = @()

    foreach ($p in $paths)
    {
        $items = @()
        try
        {
            $items = Get-ItemProperty -Path $p -ErrorAction Stop
        }
        catch
        {
            Write-Log "Failed to read uninstall registry path '$p' : $($_.Exception.Message)" "WARN"
            continue
        }

        foreach ($i in $items)
        {
            $displayName = [string](Get-RegValue -Object $i -PropertyName "DisplayName")
            if ([string]::IsNullOrWhiteSpace($displayName))
            {
                continue
            }

            $obj = [pscustomobject]@{
                RegistryPath         = $i.PSPath
                DisplayName          = $displayName
                DisplayVersion       = [string](Get-RegValue -Object $i -PropertyName "DisplayVersion")
                Publisher            = [string](Get-RegValue -Object $i -PropertyName "Publisher")
                InstallLocation      = [string](Get-RegValue -Object $i -PropertyName "InstallLocation")
                InstallDate          = [string](Get-RegValue -Object $i -PropertyName "InstallDate")
                UninstallString      = [string](Get-RegValue -Object $i -PropertyName "UninstallString")
                QuietUninstallString = [string](Get-RegValue -Object $i -PropertyName "QuietUninstallString")
                PSChildName          = [string]$i.PSChildName
            }

            $results += $obj
        }
    }

    return $results
}

function Select-TargetAcrobat2017
{
    param(
        [Parameter(Mandatory)]
        [array]$Entries
    )

    $candidates = $Entries | Where-Object {
        $_.DisplayName -match $TargetNameRegex -and
        $_.DisplayName -match $TargetYearRegex -and
        $_.DisplayName -notmatch $ExcludeNameRegex -and
        $_.DisplayName -notmatch $ExcludeDcRegex
    }

    return $candidates
}

function Get-MsiProductCodeFromEntry
{
    param(
        [Parameter(Mandatory)]
        $Entry
    )

    $guidRegex = '(?i)\{[0-9A-F]{8}\-[0-9A-F]{4}\-[0-9A-F]{4}\-[0-9A-F]{4}\-[0-9A-F]{12}\}'

    if ($Entry.PSChildName -match $guidRegex)
    {
        return $Matches[0].ToUpper()
    }

    if ($Entry.UninstallString -match $guidRegex)
    {
        return $Matches[0].ToUpper()
    }

    if ($Entry.QuietUninstallString -match $guidRegex)
    {
        return $Matches[0].ToUpper()
    }

    return $null
}

function Start-ProcessLogged
{
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string]$Arguments,
        [Parameter()][string]$WorkingDirectory = $env:TEMP
    )

    Write-Log "Starting process:" "INFO"
    Write-Log "  FilePath : $FilePath" "INFO"
    Write-Log "  Arguments: $Arguments" "INFO"
    Write-Log "  WorkDir  : $WorkingDirectory" "INFO"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -PassThru -Wait -WindowStyle Hidden
    $exitCode = $p.ExitCode

    $sw.Stop()
    Write-Log "Process finished. ExitCode=$exitCode Duration=$([math]::Round($sw.Elapsed.TotalSeconds,2))s" "INFO"

    return $exitCode
}

function Wait-ForRemovalEvidence
{
    param(
        [Parameter(Mandatory)][string]$DisplayNameSnapshot
    )

    $deadline = (Get-Date).AddMinutes($MaxWaitMinutes)
    while ((Get-Date) -lt $deadline)
    {
        $entries = Get-UninstallEntries
        $stillThere = $entries | Where-Object { $_.DisplayName -eq $DisplayNameSnapshot }

        if (-not $stillThere)
        {
            Write-Log "Post-check: '$DisplayNameSnapshot' is no longer present in uninstall registry." "INFO"
            return $true
        }

        Write-Log "Post-check: still present -> waiting $PollSeconds seconds..." "DEBUG"
        Start-Sleep -Seconds $PollSeconds
    }

    Write-Log "Post-check timeout after $MaxWaitMinutes minutes: '$DisplayNameSnapshot' still present." "WARN"
    return $false
}

# -------------------------
# Main
# -------------------------
Write-Log "===== Adobe Acrobat 2017 Uninstall - START =====" "INFO"

$osInfo = Get-OsInfo
if ($osInfo)
{
    Write-Log "Host: $($osInfo.ComputerName) | OS: $($osInfo.Caption) $($osInfo.Version) (Build $($osInfo.BuildNumber)) | Arch: $($osInfo.Arch)" "INFO"
    Write-Log "Context: $($osInfo.UserContext) | IsSystem=$($osInfo.IsSystem) | Domain=$($osInfo.Domain)" "INFO"
}
else
{
    Write-Log "Unable to retrieve OS info (continuing)." "WARN"
}

Write-Log "Scanning uninstall registry keys (32/64-bit)..." "INFO"
$allEntries = Get-UninstallEntries
Write-Log "Total uninstall entries discovered: $($allEntries.Count)" "INFO"

# Ensure variable exists (StrictMode)
$targets = $null

# Get candidates, then FORCE array semantics
$targets = Select-TargetAcrobat2017 -Entries $allEntries
$targets = @($targets)

$targetsCount = $targets.Count

if ($targetsCount -eq 0)
{
    Write-Log "No matching 'Adobe Acrobat 2017' installation found (nothing to do)." "INFO"
    Write-Log "===== Adobe Acrobat 2017 Uninstall - END (NoOp) =====" "INFO"
    exit 0
}

Write-Log "Matching targets found: $targetsCount" "INFO"

$idx = 0
foreach ($t in $targets)
{
    $idx++
    Write-Log "---- Target #$idx ----" "INFO"
    Write-Log "DisplayName          : $($t.DisplayName)" "INFO"
    Write-Log "DisplayVersion       : $($t.DisplayVersion)" "INFO"
    Write-Log "Publisher            : $($t.Publisher)" "INFO"
    Write-Log "InstallLocation      : $($t.InstallLocation)" "INFO"
    Write-Log "InstallDate          : $($t.InstallDate)" "INFO"
    Write-Log "RegistryPath         : $($t.RegistryPath)" "INFO"
    Write-Log "PSChildName          : $($t.PSChildName)" "INFO"
    Write-Log "UninstallString      : $($t.UninstallString)" "INFO"
    Write-Log "QuietUninstallString : $($t.QuietUninstallString)" "INFO"
}

$overallFailures = 0

foreach ($target in $targets)
{
    Write-Log "===== Uninstalling: $($target.DisplayName) =====" "INFO"

    $productCode = Get-MsiProductCodeFromEntry -Entry $target
    if ($productCode)
    {
        Write-Log "Detected MSI ProductCode: $productCode" "INFO"
    }
    else
    {
        Write-Log "No MSI ProductCode detected from registry entry (may be EXE-based uninstall)." "WARN"
    }

    $displayNameSnapshot = $target.DisplayName

    $uninstallSucceeded = $false
    $attempts = @()

    if ($productCode)
    {
        $msiLog = Join-Path -Path $LogRoot -ChildPath ("msiexec_uninstall_{0}_{1}.log" -f $env:COMPUTERNAME, ((Get-Date).ToString("yyyyMMdd_HHmmss")))
        $args = "/x $productCode /qn /norestart /l*v `"$msiLog`""
        $attempts += "MSI:/x ProductCode"

        try
        {
            Write-Log "Attempt: MSI uninstall via msiexec. Log file: $msiLog" "INFO"
            $code = Start-ProcessLogged -FilePath "msiexec.exe" -Arguments $args -WorkingDirectory $LogRoot

            if ($code -in 0,3010,1641)
            {
                Write-Log "msiexec returned success code ($code)." "INFO"
                $uninstallSucceeded = $true
            }
            else
            {
                Write-Log "msiexec returned non-success code ($code). Will try alternate method(s)." "WARN"
            }
        }
        catch
        {
            Write-Log "MSI uninstall attempt failed: $($_.Exception.Message)" "WARN"
        }
    }

    if (-not $uninstallSucceeded)
    {
        $raw = $null

        if (-not [string]::IsNullOrWhiteSpace($target.QuietUninstallString))
        {
            $raw = $target.QuietUninstallString
            Write-Log "Using QuietUninstallString." "INFO"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($target.UninstallString))
        {
            $raw = $target.UninstallString
            Write-Log "Using UninstallString (will try to enforce silent flags if possible)." "INFO"
        }

        if ($raw)
        {
            $attempts += "EXE/RawUninstallString"

            $exe = $null
            $arg = $null

            if ($raw -match '^\s*\"(?<p>[^"]+)\"\s*(?<a>.*)$')
            {
                $exe = $Matches['p']
                $arg = $Matches['a']
            }
            elseif ($raw -match '^\s*(?<p>\S+)\s*(?<a>.*)$')
            {
                $exe = $Matches['p']
                $arg = $Matches['a']
            }

            if ($exe -match '(?i)msiexec(\.exe)?$')
            {
                $attempts += "MSI:ConvertedFromUninstallString"
                $msiLog = Join-Path -Path $LogRoot -ChildPath ("msiexec_uninstall_fromString_{0}_{1}.log" -f $env:COMPUTERNAME, ((Get-Date).ToString("yyyyMMdd_HHmmss")))
                $arg2 = $arg

                $arg2 = $arg2 -replace '(?i)\s+/I\s+', ' /x '
                $arg2 = $arg2 -replace '(?i)\s+/i\s+', ' /x '

                if ($arg2 -notmatch '(?i)/qn')
                {
                    $arg2 = "$arg2 /qn"
                }
                if ($arg2 -notmatch '(?i)/norestart')
                {
                    $arg2 = "$arg2 /norestart"
                }
                if ($arg2 -notmatch '(?i)/l\*v')
                {
                    $arg2 = "$arg2 /l*v `"$msiLog`""
                }

                try
                {
                    Write-Log "Attempt: msiexec derived uninstall. Log file: $msiLog" "INFO"
                    $code = Start-ProcessLogged -FilePath "msiexec.exe" -Arguments $arg2 -WorkingDirectory $LogRoot
                    if ($code -in 0,3010,1641)
                    {
                        Write-Log "Derived msiexec uninstall returned success code ($code)." "INFO"
                        $uninstallSucceeded = $true
                    }
                    else
                    {
                        Write-Log "Derived msiexec uninstall returned non-success code ($code)." "WARN"
                    }
                }
                catch
                {
                    Write-Log "Derived msiexec uninstall attempt failed: $($_.Exception.Message)" "WARN"
                }
            }
            else
            {
                $arg2 = $arg

                $silentFlags = @("/S", "/s", "/quiet", "/qn", "/norestart")
                $needSilent = $true
                foreach ($f in $silentFlags)
                {
                    if ($arg2 -match [Regex]::Escape($f))
                    {
                        $needSilent = $false
                        break
                    }
                }

                if ($needSilent)
                {
                    $arg2 = "$arg2 /S /quiet /norestart"
                }

                try
                {
                    Write-Log "Attempt: EXE uninstall with best-effort silent flags." "INFO"
                    $code = Start-ProcessLogged -FilePath $exe -Arguments $arg2 -WorkingDirectory $env:TEMP
                    if ($code -in 0,3010,1641)
                    {
                        Write-Log "EXE uninstall returned success code ($code)." "INFO"
                        $uninstallSucceeded = $true
                    }
                    else
                    {
                        Write-Log "EXE uninstall returned non-success code ($code)." "WARN"
                    }
                }
                catch
                {
                    Write-Log "EXE uninstall attempt failed: $($_.Exception.Message)" "WARN"
                }
            }
        }
        else
        {
            Write-Log "No UninstallString/QuietUninstallString available. Cannot proceed with this target." "ERROR"
        }
    }

    Write-Log "Running post-uninstall verification checks..." "INFO"
    $removedFromRegistry = Wait-ForRemovalEvidence -DisplayNameSnapshot $displayNameSnapshot

    $postEntries = Get-UninstallEntries
    $postTargets = As-Array (Select-TargetAcrobat2017 -Entries $postEntries)
    $stillPresent = $postTargets | Where-Object { $_.DisplayName -eq $displayNameSnapshot }

    if ($removedFromRegistry -and -not $stillPresent)
    {
        Write-Log "SUCCESS: Target appears removed. (Registry check passed + no matching target remains.)" "INFO"
        $uninstallSucceeded = $true
    }
    else
    {
        Write-Log "FAILURE: Target still detected after uninstall attempt(s)." "ERROR"
        Write-Log "Attempts executed: $([string]::Join(', ', $attempts))" "ERROR"

        if ($stillPresent)
        {
            Write-Log "Remaining entry details (post-check):" "ERROR"
            Write-Log "DisplayName          : $($stillPresent.DisplayName)" "ERROR"
            Write-Log "DisplayVersion       : $($stillPresent.DisplayVersion)" "ERROR"
            Write-Log "RegistryPath         : $($stillPresent.RegistryPath)" "ERROR"
            Write-Log "UninstallString      : $($stillPresent.UninstallString)" "ERROR"
            Write-Log "QuietUninstallString : $($stillPresent.QuietUninstallString)" "ERROR"
        }

        $overallFailures++
    }

    Write-Log "===== Finished: $($target.DisplayName) =====" "INFO"
}

if ($overallFailures -gt 0)
{
    Write-Log "===== Adobe Acrobat 2017 Uninstall - END (FAILED targets: $overallFailures) =====" "ERROR"
    exit 1
}

Write-Log "===== Adobe Acrobat 2017 Uninstall - END (SUCCESS) =====" "INFO"
exit 0
