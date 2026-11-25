param(
    [Parameter(Mandatory)]
    [ValidatePattern('^collector-[a-f0-9]{20}$')]
    [string]$Source
)

$ErrorActionPreference = 'Stop'
$origin = 'https://north-cloud-staging.aaljindi465.workers.dev'
$pairing = Read-Host 'Staging collector pairing key' -AsSecureString
$credential = [Management.Automation.PSCredential]::new('north-staging', $pairing)
$token = $credential.GetNetworkCredential().Password.Trim()
if ($token -cnotmatch '^[a-f0-9]{64}$') { throw 'Expected the staging collector key from NORTH.' }

$eventId = [guid]::NewGuid().ToString('N').Substring(0, 24)
$caseId = [guid]::NewGuid().ToString('N').Substring(0, 24)
$timestamp = [datetimeoffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", [cultureinfo]::InvariantCulture)
$marker = 'north-staging-test-' + $eventId.Substring(0, 8)
$event = @{
    id = $eventId; timestamp = $timestamp; kind = 1; host = 'NORTH-SYNTHETIC'
    process = $marker + '.exe'; destination = ''; source_ip = ''; target = ''
    raw = @{ synthetic = $true; purpose = 'Staging workspace isolation check' }
}
$case = @{
    id = $caseId; title = "Synthetic staging check $marker"; host = 'NORTH-SYNTHETIC'
    asset_id = 'north-synthetic'; summary = 'Synthetic evidence for checking workspace isolation.'
    evidence = @($event); links = @()
}
$reports = @{}
$reports[$caseId] = "# Synthetic staging check" + [Environment]::NewLine + "Evidence ID $eventId"
$snapshot = @{
    source = @{ id = $Source; label = 'NORTH synthetic staging test' }
    network = @{ assets = @(); links = @() }
    events = @($event); cases = @($case); reports = $reports
}
try {
    $request = @{
        Method = 'Post'; Uri = "$origin/api/cloud/snapshot"; MaximumRedirection = 0; TimeoutSec = 30
        ContentType = 'application/json'; Headers = @{ Authorization = "Bearer $token" }
        Body = ($snapshot | ConvertTo-Json -Depth 12 -Compress)
    }
    $receipt = Invoke-RestMethod @request
} finally {
    Remove-Variable token,credential,pairing,request -ErrorAction SilentlyContinue
}
if (!$receipt.updated_at) { throw 'The staging Worker returned no upload receipt.' }

Write-Host "Staging accepted synthetic evidence. Search IRIS for $marker."
Write-Host "Event check: $origin/api/events/${eventId}?source=$Source"
Write-Host "Report check: $origin/api/cases/${caseId}/report?source=$Source"
Write-Host 'In the owner browser, the event must open. In a separate browser signed into a different staging account, the same URL must show Collector not found.'
