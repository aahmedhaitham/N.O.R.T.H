$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$records = @(Get-NetAdapterStatistics | ForEach-Object {
    @{
        name = $_.Name
        received = [string]$_.ReceivedBytes
        sent = [string]$_.SentBytes
    }
})
ConvertTo-Json -InputObject $records -Compress
