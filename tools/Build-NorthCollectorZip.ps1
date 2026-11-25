param([Parameter(Mandatory)][string]$OutputPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$staging = Join-Path $root ('.north-launcher/collector-package-' + [guid]::NewGuid().ToString('N'))
$files = @(
    'Start NORTH Collector.cmd',
    'tools/Start-NorthCollector.ps1', 'tools/Export-NorthNeighbors.ps1',
    'tools/Read-NorthSysmon.ps1', 'tools/SysmonFormat.ps1',
    'backend/requirements.txt', 'backend/run_collector.py', 'backend/cloud_sync.py',
    'backend/neighbors.py', 'backend/sysmon.py', 'backend/north.py', 'backend/device_watch.py',
    'backend/network.py', 'backend/router_usage.py'
)

try {
    foreach ($file in $files) {
        $destination = Join-Path $staging $file
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $file) -Destination $destination
    }
    $output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $output -Force
} finally {
    if (Test-Path -LiteralPath $staging) {
        $checked = (Resolve-Path -LiteralPath $staging).Path
        $scratch = (Resolve-Path -LiteralPath (Join-Path $root '.north-launcher')).Path
        if ([IO.Path]::GetDirectoryName($checked) -eq $scratch) { Remove-Item -LiteralPath $checked -Recurse -Force }
    }
}
