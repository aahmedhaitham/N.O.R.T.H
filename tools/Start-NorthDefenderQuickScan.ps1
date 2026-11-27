$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
Start-MpScan -ScanType QuickScan | Out-Null
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
'{"accepted":true}'
