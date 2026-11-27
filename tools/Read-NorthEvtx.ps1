param([Parameter(Mandatory)][string]$LogPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Get-WinEvent -Path $LogPath -Oldest -MaxEvents 10001 | ForEach-Object {
    if (!$_.TimeCreated -or !$_.RecordId) { return }
    $fields = @{}
    $xml = [xml]$_.ToXml()
    foreach ($item in ($xml.GetElementsByTagName('Data') | Select-Object -First 128)) {
        $name = $item.GetAttribute('Name')
        if ($name -and $name.Length -le 64) {
            $value = [string]$item.InnerText
            $fields[$name] = $value.Substring(0, [Math]::Min(1024, $value.Length))
        }
    }
    $fields['Provider'] = [string]$_.ProviderName
    [ordered]@{
        channel = [string]$_.LogName
        host = [string]$_.MachineName
        event_id = [int]$_.Id
        record_id = [long]$_.RecordId
        timestamp = $_.TimeCreated.ToUniversalTime().ToString('o')
        fields = $fields
    } | ConvertTo-Json -Depth 3 -Compress
}
