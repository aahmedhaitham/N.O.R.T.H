$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$details = @{
    pending_updates = $null
    last_update_at = $null
    last_scan_at = $null
    recent_defender_detections = $null
}
try {
    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $details.windows_build = [string]$os.CurrentBuild
    $details.windows_edition = [string]$os.EditionID
} catch {}
try {
    $status = Get-MpComputerStatus
    $scans = @($status.QuickScanEndTime, $status.FullScanEndTime) |
        Where-Object { $_ -is [datetime] -and $_.Year -ge 2000 }
    if ($scans) {
        $details.last_scan_at = ($scans | Sort-Object -Descending | Select-Object -First 1).ToUniversalTime().ToString('o')
    }
} catch {}
try {
    $filter = @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id = 1116
        StartTime = (Get-Date).AddDays(-7)
    }
    $details.recent_defender_detections = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 50).Count
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') { $details.recent_defender_detections = 0 }
}
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false
    $searcher.CanAutomaticallyUpgradeService = $false
    $historyCount = [Math]::Min(100, $searcher.GetTotalHistoryCount())
    if ($historyCount -gt 0) {
        $install = $searcher.QueryHistory(0, $historyCount) |
            Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } |
            Sort-Object Date -Descending | Select-Object -First 1
        if ($install) { $details.last_update_at = $install.Date.ToUniversalTime().ToString('o') }
    }
    $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
    if ($result.ResultCode -eq 2) { $details.pending_updates = $result.Updates.Count }
} catch {}
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject $details -Compress
