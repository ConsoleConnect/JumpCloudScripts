<#
     ____.                    _________ .__                   .___
    |    |__ __  _____ ______ \_   ___ \|  |   ____  __ __  __| _/
    |    |  |  \/     \\____ \/    \  \/|  |  /  _ \|  |  \/ __ |
/\__|    |  |  /  Y Y  \  |_> >     \___|  |_(  <_> )  |  / /_/ |
\________|____/|__|_|  /   __/ \______  /____/\____/|____/\____ |
                     \/|__|           \/                       \/
                          (c) 2026 - Frederic Lhoest - PCCW Global

Adobe Acrobat Audit (2017/2020) - JumpCloud EU
- Reads $ApiKey (+ optional $OrgId) from apiKey_EU.ps1
- Fetches ONLY Windows/macOS/Linux systems via POST /api/search/systems
- Checks System Insights:
  - Windows: v2/systeminsights/programs
  - macOS/Linux: v2/systeminsights/apps
- Outputs:
  - CLI summary + details
  - CSV: JC_AcrobatHits.csv
#>

# ----------------- Auth / Config -----------------
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
. "$ScriptDir/apiKey_EU.ps1"
if (-not $ApiKey)
{
    Write-Error "apiKey_EU.ps1 did not set `$ApiKey"
    return
}

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$BaseUri = "https://console.eu.jumpcloud.com/api"
$Headers = @{
    "x-api-key"    = $ApiKey
    "Content-Type" = "application/json"
    "Accept"       = "application/json"
}
if ($OrgId)
{
    $Headers["x-org-id"] = $OrgId
}

$HttpTimeoutSec = 300
$HttpMaxRetries = 5
$SysPageSize    = 1000
$ItemPageSize   = 100

$CsvPath = Join-Path $ScriptDir "JC_AcrobatHits.csv"

# ----------------- Signatures -----------------
$SoftwareSignatures = @(
    @{
        Package   = 'Adobe Acrobat 2017'
        Name      = '(?i)\bAdobe\s+Acrobat\b.*\b2017\b|\bAcrobat\b.*\b2017\b'
        Publisher = '(?i)\bAdobe\b'
    },
    @{
        Package   = 'Adobe Acrobat 2020'
        Name      = '(?i)\bAdobe\s+Acrobat\b.*\b2020\b|\bAcrobat\b.*\b2020\b'
        Publisher = '(?i)\bAdobe\b'
    }
)

# -------------------------------------------------
# Function Invoke-JCRequest
# -------------------------------------------------
# Resilient JumpCloud API request wrapper.
# - Uses EU base URI and headers (x-api-key, optional x-org-id).
# - Retries transient errors (429/408/5xx/timeouts) with backoff.
# - Returns the parsed JSON object from Invoke-RestMethod.
#
function Invoke-JCRequest
{
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('GET','POST')][string]$Method = 'GET',
        $Body = $null,
        [int]$TimeoutSec = $HttpTimeoutSec,
        [int]$MaxRetries = $HttpMaxRetries
    )

    $uri = "$BaseUri/$Path"
    $attempt = 0
    $delay = 1.5

    $payload = $null
    if ($Method -eq 'POST' -and $null -ne $Body)
    {
        $payload = if ($Body -is [string]) { $Body } else { ($Body | ConvertTo-Json -Depth 10) }
    }

    while ($true)
    {
        try
        {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -TimeoutSec $TimeoutSec -ContentType 'application/json' -Body $payload
        }
        catch
        {
            $attempt++

            $status = $null
            if ($_.Exception.Response)
            {
                try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
            }

            $isTimeout   = $_.Exception.GetType().FullName -eq 'System.OperationCanceledException' -or ($_.Exception.Message -match '(?i)timeout|task was canceled')
            $isTransient = ($status -in 408,500,502,503,504) -or $isTimeout
            $is429       = ($status -eq 429)

            if (($isTransient -or $is429) -and $attempt -le $MaxRetries)
            {
                $retryAfter = $null
                if ($_.Exception.Response)
                {
                    try { $retryAfter = $_.Exception.Response.Headers['Retry-After'] } catch { }
                }

                $sleepSec = if ($retryAfter) { [int]$retryAfter } else { [math]::Ceiling($delay + (Get-Random -Minimum 0 -Maximum 0.5)) }
                Write-Warning ("{0} on {1} {2} — retry {3}/{4} in {5}s" -f ($(if ($is429) { 'HTTP 429' } elseif ($isTimeout) { 'Timeout' } else { "HTTP $status" })), $Method, $Path, $attempt, $MaxRetries, $sleepSec)

                Start-Sleep -Seconds $sleepSec
                $delay = [math]::Min($delay * 2.0, 30)
                continue
            }

            throw
        }
    }
}

# -------------------------------------------------
# Function Unwrap-Results
# -------------------------------------------------
# Normalize JumpCloud responses to a plain array.
# - If API returns { results: [...] }, returns .results.
# - Otherwise returns the object as an array.
#
function Unwrap-Results
{
    param([Parameter(Mandatory)]$Response)

    if ($null -eq $Response) { return @() }
    if ($Response.PSObject.Properties.Name -contains 'results') { return @($Response.results) }
    return @($Response)
}

# -------------------------------------------------
# Function Resolve-Platform
# -------------------------------------------------
# Normalize a system object to: Windows | macOS | Linux | Other.
# - Uses multiple possible platform fields coming from search/systems results.
#
function Resolve-Platform
{
    param($s)

    $vals = foreach ($k in @('platform','platform_name','os','osFamily','reported.platform','reported.os','agent.platform'))
    {
        $v = $null

        if ($k -match '\.')
        {
            $cur = $s
            foreach ($p in $k -split '\.')
            {
                if ($null -eq $cur) { $cur = $null; break }
                if (-not ($cur.PSObject.Properties.Name -contains $p)) { $cur = $null; break }
                $cur = $cur.$p
            }
            $v = $cur
        }
        else
        {
            $v = $s.$k
        }

        if ($v) { [string]$v }
    }

    $text = ($vals -join ' ')
    if ($text -match '(?i)\bwin(dows)?\b')                                { return 'Windows' }
    if ($text -match '(?i)\bmac\s*os|macos|darwin|os\s*x\b')              { return 'macOS'  }
    if ($text -match '(?i)\blinux|ubuntu|debian|rhel|centos|fedora|suse') { return 'Linux'  }
    return 'Other'
}

# -------------------------------------------------
# Function Coerce-Date
# -------------------------------------------------
# Convert various timestamp formats into a UTC [datetime].
#
function Coerce-Date
{
    param($v)

    if ($null -eq $v -or ($v -is [string] -and [string]::IsNullOrWhiteSpace($v))) { return $null }

    if ($v -is [int] -or $v -is [long] -or ($v -is [string] -and $v -match '^\d{10,13}$'))
    {
        $n = [int64]$v
        if ($n -gt 9999999999) { return [DateTimeOffset]::FromUnixTimeMilliseconds($n).UtcDateTime }
        else                   { return [DateTimeOffset]::FromUnixTimeSeconds($n).UtcDateTime }
    }

    try { return [datetime]$v } catch { return $null }
}

# -------------------------------------------------
# Function Pick-LastContact
# -------------------------------------------------
# Extract a "last contact" timestamp from a system object.
#
function Pick-LastContact
{
    param($s)

    $keys = @(
        'last_contact','last_contact_time','last_contact_timestamp','last_checkin',
        'lastContact','lastContactTime','lastContactTimestamp','lastCheckin',
        'agent.last_contact','agent.last_contact_time','agent.last_checkin',
        'reported.last_contact','reported.last_contact_time'
    )

    $dates = foreach ($k in $keys)
    {
        $raw = $null

        if ($k -match '\.')
        {
            $cur = $s
            foreach ($p in $k -split '\.')
            {
                if ($null -eq $cur) { $cur = $null; break }
                if (-not ($cur.PSObject.Properties.Name -contains $p)) { $cur = $null; break }
                $cur = $cur.$p
            }
            $raw = $cur
        }
        else
        {
            $raw = $s.$k
        }

        $dt = Coerce-Date $raw
        if ($dt) { $dt }
    }

    if ($dates.Count -gt 0) { return ($dates | Sort-Object -Descending | Select-Object -First 1) }
    return $null
}

# -------------------------------------------------
# Function Get-FilteredSystems
# -------------------------------------------------
# Fetch only Windows/macOS/Linux systems using POST /api/search/systems.
# - search/systems does NOT accept logical operators like '$or' as filter fields.
# - Instead, we run 3 compatible queries (one per OS family) and merge unique systems.
# - Uses limit/skip pagination per query.
# - Returns a flat array of unique system objects.
#
function Get-FilteredSystems
{
    # OS regex queries (tune if needed)
    $osQueries = @(
        @{ Label = 'Windows'; Regex = '(?i)windows' }
        @{ Label = 'macOS';   Regex = '(?i)mac|os\s*x|darwin|macos' }
        @{ Label = 'Linux';   Regex = '(?i)linux|ubuntu|debian|rhel|centos|fedora|suse' }
    )

    # De-dupe by SystemID
    $byId = @{}

    foreach ($q in $osQueries)
    {
        $skip = 0

        while ($true)
        {
            $body = @{
                filter = @(
                    @{
                        os = @{ '$regex' = $q.Regex }
                    }
                )
                limit  = $SysPageSize
                skip   = $skip
                fields = @(
                    'id','_id','systemId','system_id',
                    'displayName','hostname','computerName','name',
                    'os','platform','platform_name','osFamily',
                    'last_contact','last_contact_time','last_contact_timestamp','last_checkin',
                    'lastContact','lastContactTime','lastContactTimestamp','lastCheckin',
                    'agent.last_contact','agent.last_contact_time','agent.last_checkin',
                    'reported.last_contact','reported.last_contact_time'
                )
            }

            $resp  = Invoke-JCRequest -Path "search/systems" -Method POST -Body $body
            $batch = Unwrap-Results -Response $resp
            if (-not $batch -or $batch.Count -eq 0)
            {
                break
            }

            foreach ($s in $batch)
            {
                $sid = $s.id
                if (-not $sid) { $sid = $s._id }
                if (-not $sid) { $sid = $s.systemId }
                if (-not $sid) { $sid = $s.system_id }
                if ([string]::IsNullOrWhiteSpace($sid)) { continue }

                if (-not $byId.ContainsKey($sid))
                {
                    $byId[$sid] = $s
                }
            }

            if ($batch.Count -lt $SysPageSize)
            {
                break
            }

            $skip += $batch.Count
        }
    }

    return @($byId.Values)
}


# -------------------------------------------------
# Function Get-ProgramsForSystem
# -------------------------------------------------
# Fetch System Insights "programs" inventory for one system (Windows).
#
function Get-ProgramsForSystem
{
    param([Parameter(Mandatory)][string]$SystemId)

    $all = @()
    $skip = 0

    while ($true)
    {
        $resp  = Invoke-JCRequest -Path "v2/systeminsights/programs?limit=$ItemPageSize&skip=$skip&filter[]=system_id:eq:$SystemId&sort=name" -Method GET
        $batch = Unwrap-Results -Response $resp
        if (-not $batch -or $batch.Count -eq 0) { break }

        $all += $batch
        if ($batch.Count -lt $ItemPageSize) { break }
        $skip += $batch.Count
    }

    return $all
}

# -------------------------------------------------
# Function Get-AppsForSystem
# -------------------------------------------------
# Fetch System Insights "apps" inventory for one system (macOS/Linux).
#
function Get-AppsForSystem
{
    param([Parameter(Mandatory)][string]$SystemId)

    $all = @()
    $skip = 0

    while ($true)
    {
        $resp  = Invoke-JCRequest -Path "v2/systeminsights/apps?limit=$ItemPageSize&skip=$skip&filter[]=system_id:eq:$SystemId&sort=name" -Method GET
        $batch = Unwrap-Results -Response $resp
        if (-not $batch -or $batch.Count -eq 0) { break }

        $all += $batch
        if ($batch.Count -lt $ItemPageSize) { break }
        $skip += $batch.Count
    }

    return $all
}

# -------------------------------------------------
# Function Test-SoftwareMatch
# -------------------------------------------------
# Check one inventory item against the signature list.
# - Matches primarily on "name" (with year).
# - Uses "publisher" as a secondary check when present.
# - Returns a small match object, or $null.
#
function Test-SoftwareMatch
{
    param(
        [Parameter(Mandatory)]$Item,
        [Parameter(Mandatory)]$Signatures
    )

    foreach ($sig in $Signatures)
    {
        if ($sig.Name -and $Item.name -and ($Item.name -match $sig.Name))
        {
            return @{ Package = $sig.Package; Field = 'Name' }
        }

        if ($sig.Publisher -and $Item.publisher -and ($Item.publisher -match $sig.Publisher))
        {
            return @{ Package = $sig.Package; Field = 'Publisher' }
        }
    }

    return $null
}

#====================================
# Main
#====================================

Write-Host "Fetching Windows/macOS/Linux devices (EU)…"
$systemsRaw = Get-FilteredSystems
if (-not $systemsRaw -or $systemsRaw.Count -eq 0)
{
    $Stopwatch.Stop()
    Write-Error "No eligible systems returned from search. Check API key / org headers."
    Write-Host ("Execution time: {0}" -f $Stopwatch.Elapsed.ToString())
    return
}

# Build device list (still defensive: enforce allowlist)
$devices = New-Object System.Collections.Generic.List[object]
foreach ($s in $systemsRaw)
{
    $sid = $s.id
    if (-not $sid) { $sid = $s._id }
    if (-not $sid) { $sid = $s.systemId }
    if (-not $sid) { $sid = $s.system_id }
    if ([string]::IsNullOrWhiteSpace($sid)) { continue }

    $hostname = $s.displayName
    if (-not $hostname) { $hostname = $s.hostname }
    if (-not $hostname) { $hostname = $s.computerName }
    if (-not $hostname) { $hostname = $s.name }

    $platform = Resolve-Platform $s
    if ($platform -notin @('Windows','macOS','Linux')) { continue }

    $devices.Add([pscustomobject]@{
        SystemID    = $sid
        Hostname    = $hostname
        Platform    = $platform
        LastContact = Pick-LastContact $s
    })
}

if ($devices.Count -eq 0)
{
    $Stopwatch.Stop()
    Write-Host "No Windows/macOS/Linux devices found to scan."
    Write-Host ("Execution time: {0}" -f $Stopwatch.Elapsed.ToString())
    return
}

$devices = $devices | Sort-Object Hostname, SystemID
Write-Host ("Devices to scan: {0} (Windows/macOS/Linux only)" -f $devices.Count)

# Scan
$results = New-Object System.Collections.Generic.List[object]
$winHits = 0
$appHits = 0

$i = 0
$total = $devices.Count

foreach ($d in $devices)
{
    $i++
    Write-Progress -Activity "Scanning System Insights" -Status "$($d.Hostname) ($i / $total)" -PercentComplete ([int](($i / $total) * 100))

    $items = @()

    if ($d.Platform -eq 'Windows')
    {
        $prog = Get-ProgramsForSystem -SystemId $d.SystemID
        if ($prog) { $items += $prog }
    }
    else
    {
        $apps = Get-AppsForSystem -SystemId $d.SystemID
        if ($apps) { $items += $apps }
    }

    if (-not $items) { continue }

    foreach ($it in $items)
    {
        $m = Test-SoftwareMatch -Item $it -Signatures $SoftwareSignatures
        if (-not $m) { continue }

        $version = $it.version
        if (-not $version) { $version = $it.bundle_short_version }
        if (-not $version) { $version = $it.bundle_version }

        $vendor = $it.vendor
        if (-not $vendor) { $vendor = $it.publisher }

        $endpoint = if ($d.Platform -eq 'Windows') { 'programs' } else { 'apps' }
        if ($endpoint -eq 'programs') { $winHits++ } else { $appHits++ }

        $lastLocal = $null
        if ($d.LastContact)
        {
            try { $lastLocal = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($d.LastContact, [TimeZoneInfo]::Local.Id) } catch { $lastLocal = $d.LastContact }
        }

        $results.Add([pscustomobject]@{
            MatchedPackage   = $m.Package
            Hostname         = $d.Hostname
            Platform         = $d.Platform
            Version          = $version
            SoftwareName     = $it.name
            Vendor           = $vendor
            SystemID         = $d.SystemID
            LastContactLocal = $lastLocal
            SourceEndpoint   = $endpoint
        })
    }
}

Write-Progress -Activity "Scanning System Insights" -Completed
$Stopwatch.Stop()

# Report
Write-Host ""
Write-Host "========== Adobe Acrobat Audit (2017/2020) =========="
Write-Host ("Scanned (eligible) devices : {0}" -f $devices.Count)
Write-Host ("Matches found             : {0}" -f $results.Count)
Write-Host ("By endpoint               : programs (Windows)={0} | apps (macOS/Linux)={1}" -f $winHits, $appHits)
Write-Host ("Execution time            : {0}" -f $Stopwatch.Elapsed.ToString())
Write-Host ""

if ($results.Count -eq 0)
{
    Write-Host "No Adobe Acrobat 2017/2020 detected."
    return
}

$sorted = $results | Sort-Object MatchedPackage, Platform, Hostname, SoftwareName, Version

Write-Host "Detected matches:"
$sorted |
    Select-Object MatchedPackage, Hostname, Platform, Version, SoftwareName, Vendor, LastContactLocal |
    Format-Table -AutoSize

$sorted | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host ("CSV exported: {0}" -f $CsvPath)
