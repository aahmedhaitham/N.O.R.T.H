$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

try {
    $connections = @(Get-NetTCPConnection -ErrorAction Stop)
} catch {
    $denied = $_.FullyQualifiedErrorId -match 'AccessDenied|Unauthorized'
    for ($cause = $_.Exception; $cause; $cause = $cause.InnerException) {
        if ($cause -is [UnauthorizedAccessException] -or $cause.NativeErrorCode -eq 'AccessDenied') {
            $denied = $true
            break
        }
    }
    $state = if ($denied) {
        'access_denied'
    } elseif ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        'unavailable'
    } else { 'read_failed' }
    ConvertTo-Json -InputObject @{ state = $state; rows = @(); limited = $false } -Compress
    return
}

$listeners = @($connections | Where-Object State -eq 'Listen')
$active = @($connections | Where-Object { $_.State -in @('Established', 'SynSent', 'SynReceived', 'CloseWait') })
$sample = @($listeners | Select-Object -First 100) + @($active | Select-Object -First 100)
$processes = @{}
foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) { $processes[[long]$process.Id] = $process }

$rows = @(foreach ($connection in $sample) {
    $owner = $processes[[long]$connection.OwningProcess]
    $name = ''
    if ($owner) {
        try {
            if ($connection.CreationTime -and $owner.StartTime -and $owner.StartTime -le $connection.CreationTime) {
                $name = [string]$owner.ProcessName
            }
        } catch { $name = '' }
    }
    @{
        state = [string]$connection.State
        local_address = [string]$connection.LocalAddress
        local_port = [int]$connection.LocalPort
        remote_address = [string]$connection.RemoteAddress
        remote_port = [int]$connection.RemotePort
        pid = [long]$connection.OwningProcess
        process = $name
    }
})
ConvertTo-Json -InputObject @{ state = 'ready'; rows = $rows; limited = ($listeners.Count -gt 100 -or $active.Count -gt 100) } -Depth 4 -Compress
