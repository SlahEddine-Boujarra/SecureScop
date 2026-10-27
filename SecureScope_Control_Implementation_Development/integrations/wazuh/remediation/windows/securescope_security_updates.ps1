$ErrorActionPreference = "Stop"

$marker = "SECURESCOPE_REMEDIATION"
$recipeId = "windows-security-updates"
$logPath = Join-Path $env:ProgramFiles "ossec-agent\active-response\active-responses.log"
if (-not (Test-Path (Split-Path $logPath -Parent))) {
    $logPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\active-response\active-responses.log"
}

function Write-RemediationEvent {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Message,
        [bool]$RestartRequired = $false
    )

    $payload = [ordered]@{
        marker = $marker
        recipe_id = $recipeId
        status = $Status
        exit_code = $ExitCode
        restart_required = $RestartRequired
        message = $Message
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json -Compress
    Add-Content -Path $logPath -Value $payload -Encoding UTF8
}

try {
    $inputLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($inputLine)) {
        throw "Missing Wazuh Active Response input."
    }
    try {
        $activeResponse = $inputLine | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Wazuh Active Response input is not valid JSON."
    }
    if ([string]$activeResponse.command -ne "add") {
        Write-RemediationEvent -Status "ignored" -ExitCode 0 `
            -Message "Only the Wazuh add action is supported."
        exit 0
    }
    if (-not ([Security.Principal.WindowsPrincipal]
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )) {
        throw "Administrator privileges are required."
    }

    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $searcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $searcher.Search(
        "IsInstalled=0 and Type='Software' and IsHidden=0"
    )
    $updates = New-Object -ComObject Microsoft.Update.UpdateColl

    foreach ($update in $searchResult.Updates) {
        $categoryNames = @($update.Categories | ForEach-Object { $_.Name })
        if (
            $categoryNames -contains "Security Updates" -or
            $categoryNames -contains "Critical Updates"
        ) {
            if (-not $update.EulaAccepted) {
                $update.AcceptEula()
            }
            [void]$updates.Add($update)
        }
    }

    if ($updates.Count -eq 0) {
        Write-RemediationEvent -Status "no_change" -ExitCode 0 `
            -Message "No applicable security or critical update was found."
        exit 0
    }

    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $updates
    $downloadResult = $downloader.Download()
    if ([int]$downloadResult.ResultCode -notin @(2, 3)) {
        throw "Windows Update download did not complete successfully."
    }

    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $updates
    $installResult = $installer.Install()
    $restartRequired = [bool]$installResult.RebootRequired
    if ([int]$installResult.ResultCode -notin @(2, 3)) {
        throw "Windows Update installation did not complete successfully."
    }

    Write-RemediationEvent -Status "completed" -ExitCode 0 `
        -Message "Installed $($updates.Count) security or critical update(s)." `
        -RestartRequired $restartRequired
    exit 0
}
catch {
    Write-RemediationEvent -Status "failed" -ExitCode 1 `
        -Message $_.Exception.Message
    exit 1
}
