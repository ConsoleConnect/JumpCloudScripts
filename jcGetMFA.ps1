<#
     ____.                    _________ .__                   .___
    |    |__ __  _____ ______ \_   ___ \|  |   ____  __ __  __| _/
    |    |  |  \/     \\____ \/    \  \/|  |  /  _ \|  |  \/ __ |
/\__|    |  |  /  Y Y  \  |_> >     \___|  |_(  <_> )  |  / /_/ |
\________|____/|__|_|  /   __/ \______  /____/\____/|____/\____ |
                     \/|__|           \/                       \/
                          (c) 2026 - Frederic Lhoest - PCCW Global

This script queries JumpCloud Directory Insights (the same endpoint used by the EU
JumpCloud Admin UI) and exports events for the last N days to a CSV file.

It focuses on authentication-related visibility and includes "best effort" MFA
information when those fields exist in the event payload.

Endpoint used (EU console):
  https://console.eu.jumpcloud.com/api/v2/directoryinsights/events

The script supports pagination using the "X-Search_after" response header.

--------------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------------
Default run (last 3 days, service=all, limit=200):
  ./jcGetMFA.ps1

Limit the amount of data (safety caps):
  ./jcGetMFA.ps1 -Limit 100 -MaxPages 10
  ./jcGetMFA.ps1 -Limit 200 -MaxPages 200 -MaxEvents 50000

Return only events where MFA content exists (best effort):
  ./jcGetMFA.ps1 -MfaOnly

Target a specific DI service to reduce noise:
  ./jcGetMFA.ps1 -Service sso
  ./jcGetMFA.ps1 -Service radius
  ./jcGetMFA.ps1 -Service ldap

Using a proxy:
  ./jcGetMFA.ps1 -ProxyUrl http://proxy.company:8080

--------------------------------------------------------------------------------
WHAT "MFA ONLY" MEANS
--------------------------------------------------------------------------------
When -MfaOnly is used, the script keeps rows where at least one of these is present:
- MFA field exists and is:
  - boolean $true, or
  - a non-null object/value
- MFAType is not empty
- MFAState is not empty
- AuthMethods is not empty (often contains MFA method results)

Because Directory Insights schemas can vary depending on the event type and service,
this is intentionally "best effort" rather than a strict schema guarantee.

--------------------------------------------------------------------------------
OUTPUT
--------------------------------------------------------------------------------
CSV columns:
  TimestampUtc, Service, EventType, Success, MFA, MFAType, MFAState, AuthMethods,
  InitiatedByType, InitiatedBy, Username, ClientIp, ErrorCode, ErrorMessage, EventId

Success calculation (best effort):
- If event.success exists => used directly
- Else if error_code exists:
    success = (error_code == 0 AND error_message is empty)
- Else => null

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKeyFile = ".\apiKey_EU.ps1",

    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 3,

    [Parameter(Mandatory = $false)]
    [ValidateSet("ASC", "DESC")]
    [string]$Sort = "DESC",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 5000)]
    [int]$Limit = 200,

    [Parameter(Mandatory = $false)]
    [string]$Service = "all",

    [Parameter(Mandatory = $false)]
    [string]$Query = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2000)]
    [int]$MaxPages = 500,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10000000)]
    [int]$MaxEvents = 50000,

    [Parameter(Mandatory = $false)]
    [switch]$MfaOnly,

    [Parameter(Mandatory = $false)]
    [string]$OutCsv = "",

    [Parameter(Mandatory = $false)]
    [string]$ProxyUrl = "",

    [Parameter(Mandatory = $false)]
    [switch]$NoProxy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseUri   = "https://console.eu.jumpcloud.com"
$EventsUri = "$BaseUri/api/v2/directoryinsights/events"

function Read-HttpErrorBody
{
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    try
    {
        $resp = $Exception.Response
        if ($null -eq $resp)
        {
            return ""
        }

        $stream = $resp.GetResponseStream()
        if ($null -eq $stream)
        {
            return ""
        }

        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    }
    catch
    {
        return ""
    }
}

function Get-HeaderValueCaseInsensitive
{
    param(
        [Parameter(Mandatory = $true)]
        $Headers,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($n in $Names)
    {
        foreach ($k in $Headers.Keys)
        {
            if ($k -ieq $n)
            {
                return $Headers[$k]
            }
        }
    }

    return $null
}

function Convert-SearchAfterHeaderToObject
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Raw
    )

    if ([string]::IsNullOrWhiteSpace($Raw))
    {
        return $null
    }

    try
    {
        return ($Raw | ConvertFrom-Json)
    }
    catch
    {
        return $Raw
    }
}

function Normalize-InitiatedBy
{
    param(
        [Parameter(Mandatory = $false)]
        $InitiatedBy
    )

    if ($null -eq $InitiatedBy)
    {
        return ""
    }

    if ($InitiatedBy -is [string])
    {
        return $InitiatedBy
    }

    $parts = @()

    if ($InitiatedBy.PSObject.Properties.Match("type").Count -gt 0 -and $InitiatedBy.type)
    {
        $parts += "type=$($InitiatedBy.type)"
    }

    if ($InitiatedBy.PSObject.Properties.Match("username").Count -gt 0 -and $InitiatedBy.username)
    {
        $parts += "username=$($InitiatedBy.username)"
    }
    elseif ($InitiatedBy.PSObject.Properties.Match("email").Count -gt 0 -and $InitiatedBy.email)
    {
        $parts += "email=$($InitiatedBy.email)"
    }

    if ($InitiatedBy.PSObject.Properties.Match("id").Count -gt 0 -and $InitiatedBy.id)
    {
        $parts += "id=$($InitiatedBy.id)"
    }

    return ($parts -join "; ")
}

function Format-AuthMethods
{
    param(
        [Parameter(Mandatory = $false)]
        $Event
    )

    if ($null -eq $Event)
    {
        return ""
    }

    if ($Event.PSObject.Properties.Match("auth_context").Count -eq 0)
    {
        return ""
    }

    $ac = $Event.auth_context
    if ($null -eq $ac)
    {
        return ""
    }

    if ($ac.PSObject.Properties.Match("auth_methods").Count -eq 0)
    {
        return ""
    }

    $authMethods = $ac.auth_methods
    if ($null -eq $authMethods)
    {
        return ""
    }

    $pairs = @()
    foreach ($p in $authMethods.PSObject.Properties)
    {
        $name = $p.Name
        $val  = $p.Value
        if ($null -eq $val)
        {
            continue
        }

        if ($val.PSObject.Properties.Match("success").Count -gt 0)
        {
            $pairs += ("{0}={1}" -f $name, $val.success)
        }
        else
        {
            $pairs += ("{0}={1}" -f $name, (($val | Out-String).Trim()))
        }
    }

    return ($pairs -join "; ")
}

function Get-MfaTypeBestEffort
{
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    if ($Event.PSObject.Properties.Match("mfa_meta").Count -gt 0)
    {
        $mm = $Event.mfa_meta
        if ($null -ne $mm -and $mm.PSObject.Properties.Match("type").Count -gt 0 -and $mm.type)
        {
            return [string]$mm.type
        }
    }

    foreach ($f in @("mfaType", "mfa_type"))
    {
        if ($Event.PSObject.Properties.Match($f).Count -gt 0 -and $Event.$f)
        {
            return [string]$Event.$f
        }
    }

    return ""
}

function Get-MfaStateBestEffort
{
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    foreach ($candidate in @("mfa_state", "mfaState", "mfa_status", "mfaStatus"))
    {
        if ($Event.PSObject.Properties.Match($candidate).Count -gt 0 -and $Event.$candidate)
        {
            return [string]$Event.$candidate
        }
    }

    return ""
}

function Get-SuccessBestEffort
{
    param(
        [Parameter(Mandatory = $true)]
        $Event
    )

    if ($Event.PSObject.Properties.Match("success").Count -gt 0)
    {
        return $Event.success
    }

    $errCode = $null
    $errMsg  = ""

    if ($Event.PSObject.Properties.Match("error_code").Count -gt 0)
    {
        $errCode = $Event.error_code
    }

    if ($Event.PSObject.Properties.Match("error_message").Count -gt 0 -and $Event.error_message)
    {
        $errMsg = [string]$Event.error_message
    }

    if ($null -ne $errCode)
    {
        try
        {
            if ([int]$errCode -eq 0 -and [string]::IsNullOrWhiteSpace($errMsg))
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        catch
        {
            return $null
        }
    }

    return $null
}

function Invoke-DIPage
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [hashtable]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ProxyUrl,

        [Parameter(Mandatory = $false)]
        [switch]$NoProxy,

        [Parameter(Mandatory = $false)]
        [ref]$RespHeadersOut
    )

    $json = $Body | ConvertTo-Json -Depth 12 -Compress

    $irmParams = @{
        Method                  = "POST"
        Uri                     = $EventsUri
        Headers                 = $Headers
        Body                    = $json
        ContentType             = "application/json"
        ResponseHeadersVariable = "respHeaders"
    }

    if (-not $NoProxy -and -not [string]::IsNullOrWhiteSpace($ProxyUrl))
    {
        $irmParams.Proxy = $ProxyUrl
    }

    try
    {
        $resp = Invoke-RestMethod @irmParams
        if ($null -ne $RespHeadersOut)
        {
            $RespHeadersOut.Value = $respHeaders
        }
        return $resp
    }
    catch
    {
        $bodyText = Read-HttpErrorBody -Exception $_.Exception
        if (-not [string]::IsNullOrWhiteSpace($bodyText))
        {
            throw $bodyText
        }
        throw
    }
}

function Test-RowHasMfaContent
{
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    if ($null -ne $Row.MFA)
    {
        if ($Row.MFA -is [bool])
        {
            if ($Row.MFA -eq $true)
            {
                return $true
            }
        }
        else
        {
            return $true
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Row.MFAType))
    {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Row.MFAState))
    {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Row.AuthMethods))
    {
        return $true
    }

    return $false
}

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $ApiKeyFile))
{
    throw "API key file not found: $ApiKeyFile"
}

. $ApiKeyFile

if ([string]::IsNullOrWhiteSpace($ApiKey))
{
    throw "Missing `$ApiKey in $ApiKeyFile"
}

if ([string]::IsNullOrWhiteSpace($OrgId))
{
    throw "Missing `$OrgId in $ApiKeyFile (required for console.eu /api/v2 endpoints)."
}

if ([string]::IsNullOrWhiteSpace($OutCsv))
{
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $OutCsv = ".\JC_DI_MFA_Report_{0}.csv" -f $stamp
}

Write-Host ("[INFO] Loaded API key from {0}" -f $ApiKeyFile)
Write-Host ("[INFO] Using API: {0}" -f $EventsUri)

$endUtc   = (Get-Date).ToUniversalTime()
$startUtc = $endUtc.AddDays(-1 * [double]$DaysBack)

Write-Host ("[INFO] Time range (UTC): {0} -> {1}" -f $startUtc.ToString("o"), $endUtc.ToString("o"))
Write-Host ("[INFO] Service filter: {0}" -f $Service)
Write-Host ("[INFO] Limit={0} MaxPages={1} MaxEvents={2} MfaOnly={3}" -f $Limit, $MaxPages, $MaxEvents, $MfaOnly.IsPresent)
Write-Host ("[INFO] Output CSV: {0}" -f $OutCsv)

$headers = @{
    "x-api-key" = $ApiKey
    "x-org-id"  = $OrgId
    "Accept"    = "application/json"
}

$all = New-Object System.Collections.Generic.List[object]

$searchAfter = $null
$page = 0

while ($true)
{
    $page++
    if ($page -gt $MaxPages)
    {
        Write-Host ("[WARN] Reached MaxPages={0}. Stopping fetch (output will be truncated)." -f $MaxPages)
        break
    }

    if ($all.Count -ge $MaxEvents)
    {
        Write-Host ("[WARN] Reached MaxEvents={0}. Stopping fetch (output will be truncated)." -f $MaxEvents)
        break
    }

    $body = @{
        sort       = $Sort
        service    = @($Service)
        start_time = $startUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        end_time   = $endUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        limit      = $Limit
        q          = $Query
    }

    if ($null -ne $searchAfter)
    {
        $body.search_after = $searchAfter
    }

    $rh = $null
    Write-Host ("[DI] Fetching page {0} (search_after={1})" -f $page, $(if ($null -ne $searchAfter) { "set" } else { "null" }))

    $resp = Invoke-DIPage -Headers $headers -Body $body -ProxyUrl $ProxyUrl -NoProxy:$NoProxy -RespHeadersOut ([ref]$rh)

    $items = @()
    if ($resp -is [System.Array])
    {
        $items = $resp
    }
    elseif ($resp.PSObject.Properties.Match("items").Count -gt 0)
    {
        $items = $resp.items
    }
    else
    {
        $items = @($resp)
    }

    foreach ($e in $items)
    {
        $all.Add($e) | Out-Null
        if ($all.Count -ge $MaxEvents)
        {
            break
        }
    }

    Write-Host ("[DI] Page {0}: +{1} events (total={2})" -f $page, $items.Count, $all.Count)

    $nextSearchAfterRaw = $null
    if ($null -ne $rh)
    {
        $nextSearchAfterRaw = Get-HeaderValueCaseInsensitive -Headers $rh -Names @("X-Search_after", "X-Search-After", "x-search_after", "x-search-after")
    }

    if ($null -eq $nextSearchAfterRaw -or [string]::IsNullOrWhiteSpace([string]$nextSearchAfterRaw))
    {
        break
    }

    $searchAfter = Convert-SearchAfterHeaderToObject -Raw ([string]$nextSearchAfterRaw)

    if ($items.Count -lt $Limit)
    {
        break
    }
}

Write-Host ("[INFO] Total events fetched: {0}" -f $all.Count)

$rows = foreach ($ev in $all)
{
    $initiatedByStr  = ""
    $initiatedByType = ""

    if ($ev.PSObject.Properties.Match("initiated_by").Count -gt 0)
    {
        $ib = $ev.initiated_by
        $initiatedByStr = Normalize-InitiatedBy -InitiatedBy $ib
        if ($null -ne $ib -and -not ($ib -is [string]) -and $ib.PSObject.Properties.Match("type").Count -gt 0)
        {
            $initiatedByType = [string]$ib.type
        }
    }

    $timestamp = $(if ($ev.PSObject.Properties.Match("timestamp").Count -gt 0 -and $ev.timestamp) { [string]$ev.timestamp } else { "" })
    $serviceV  = $(if ($ev.PSObject.Properties.Match("service").Count -gt 0 -and $ev.service) { [string]$ev.service } else { "" })
    $eventType = $(if ($ev.PSObject.Properties.Match("event_type").Count -gt 0 -and $ev.event_type) { [string]$ev.event_type } else { "" })

    $success = Get-SuccessBestEffort -Event $ev

    $mfa = $null
    if ($ev.PSObject.Properties.Match("mfa").Count -gt 0)
    {
        $mfa = $ev.mfa
    }

    $mfaType     = Get-MfaTypeBestEffort -Event $ev
    $mfaState    = Get-MfaStateBestEffort -Event $ev
    $authMethods = Format-AuthMethods -Event $ev

    $clientIp = $(if ($ev.PSObject.Properties.Match("client_ip").Count -gt 0 -and $ev.client_ip) { [string]$ev.client_ip } else { "" })
    $username = $(if ($ev.PSObject.Properties.Match("username").Count -gt 0 -and $ev.username) { [string]$ev.username } else { "" })
    $errorCode = $(if ($ev.PSObject.Properties.Match("error_code").Count -gt 0) { $ev.error_code } else { $null })
    $errorMsg  = $(if ($ev.PSObject.Properties.Match("error_message").Count -gt 0 -and $ev.error_message) { [string]$ev.error_message } else { "" })
    $id = $(if ($ev.PSObject.Properties.Match("id").Count -gt 0 -and $ev.id) { [string]$ev.id } else { "" })

    [PSCustomObject]@{
        TimestampUtc    = $timestamp
        Service         = $serviceV
        EventType       = $eventType
        Success         = $success
        MFA             = $mfa
        MFAType         = $mfaType
        MFAState        = $mfaState
        AuthMethods     = $authMethods
        InitiatedByType = $initiatedByType
        InitiatedBy     = $initiatedByStr
        Username        = $username
        ClientIp        = $clientIp
        ErrorCode       = $errorCode
        ErrorMessage    = $errorMsg
        EventId         = $id
    }
}

$finalRows = $rows
if ($MfaOnly.IsPresent)
{
    $finalRows = $rows | Where-Object { Test-RowHasMfaContent -Row $_ }
    Write-Host ("[INFO] MfaOnly enabled: {0} -> {1} rows kept" -f $rows.Count, $finalRows.Count)
}

$finalRows | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ("[DONE] CSV written: {0}" -f $OutCsv)
