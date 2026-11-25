$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'raw-logs'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$path = Join-Path $output 'windows-neighbors.json'

# Read existing neighbor entries without probing addresses.
$neighbors = @(
    Get-NetNeighbor | Where-Object { $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' } |
        ForEach-Object {
            @{
                address = $_.IPAddress
                mac = $_.LinkLayerAddress
                interface = $_.InterfaceAlias
                state = [string]$_.State
            }
        }
)
ConvertTo-Json -InputObject $neighbors | Set-Content -LiteralPath $path -Encoding UTF8
Write-Host "Saved $($neighbors.Count) cached neighbor entries to $path"
