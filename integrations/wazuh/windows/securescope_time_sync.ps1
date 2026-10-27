$ErrorActionPreference = "SilentlyContinue"

function Get-PrimaryIPv4 {
    $candidate = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Sort-Object -Property InterfaceMetric |
        Select-Object -First 1

    if ($candidate) {
        return [string]$candidate.IPAddress
    }

    return ""
}

function Convert-OffsetToMilliseconds([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $match = [regex]::Match($Text, '([+-]\d+(?:[\.,]\d+)?)s')
    if (-not $match.Success) {
        return $null
    }

    $normalized = $match.Groups[1].Value.Replace(',', '.')
    $seconds = 0.0
    if ([double]::TryParse(
        $normalized,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$seconds
    )) {
        return [math]::Round($seconds * 1000.0, 3)
    }

    return $null
}

$hostname = $env:COMPUTERNAME
$ip = Get-PrimaryIPv4
$service = Get-Service -Name W32Time
$statusOutput = (& w32tm.exe /query /status /verbose 2>&1 | Out-String)
$statusExit = $LASTEXITCODE

$source = ""
$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$registry = Get-ItemProperty -Path $registryPath
if ($registry.NtpServer) {
    $source = ([string]$registry.NtpServer).Split(',')[0].Trim()
}

if ([string]::IsNullOrWhiteSpace($source)) {
    $sourceMatch = [regex]::Match(
        $statusOutput,
        '(?im)^\s*(Source|Source de temps)\s*:\s*(.+)$'
    )
    if ($sourceMatch.Success) {
        $source = $sourceMatch.Groups[2].Value.Trim()
    }
}

$stratum = $null
$stratumMatch = [regex]::Match(
    $statusOutput,
    '(?im)^\s*(Stratum|Couche)\s*:\s*(\d+)'
)
if ($stratumMatch.Success) {
    $stratum = [int]$stratumMatch.Groups[2].Value
}

$offsetMs = $null
if (-not [string]::IsNullOrWhiteSpace($source)) {
    $stripOutput = (& w32tm.exe /stripchart /computer:$source /samples:1 /dataonly 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
        $offsetMs = Convert-OffsetToMilliseconds $stripOutput
    }
}

$localSources = @(
    "Local CMOS Clock",
    "Free-running System Clock",
    "Horloge CMOS locale"
)
$sourceIsLocal = $localSources -contains $source
$synchronized = (
    $service.Status -eq "Running" -and
    $statusExit -eq 0 -and
    -not [string]::IsNullOrWhiteSpace($source) -and
    -not $sourceIsLocal
)

$payload = [ordered]@{
    hostname = $hostname
    ip = $ip
    os = "Windows"
    service = "W32Time"
    synchronized = [bool]$synchronized
    source = $source
    stratum = $stratum
    offset_ms = $offsetMs
    epoch_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    collected_at = [DateTime]::UtcNow.ToString("o")
    status_exit_code = $statusExit
}

Write-Output ("SECURESCOPE_NTP: " + ($payload | ConvertTo-Json -Compress -Depth 4))
