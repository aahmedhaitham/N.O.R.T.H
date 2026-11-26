param(
    [Parameter(Mandatory)][ValidateSet('sysmon','security','system','powershell','defender')][string]$Source,
    [ValidateRange(0, 9223372036854775807)][long]$After = 0
)

$ErrorActionPreference = 'Stop'
$definition = switch ($Source) {
    'sysmon' { @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1,3,7,8,10,13,22) } }
    'security' { @{ Log = 'Security'; Ids = @(4624,4625,4688,4698) } }
    'system' { @{ Log = 'System'; Ids = @(7045) } }
    'powershell' { @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104) } }
    'defender' { @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116,1117,1118,1119,5001,5007) } }
}
$allowedFields = @('Image','ImageLoaded','ProcessGuid','ProcessId','CommandLine','ParentProcessGuid',
    'ParentImage','ParentCommandLine','User','TargetImage','TargetObject','QueryName','SourceImage',
    'NewProcessName','NewProcessId','TargetUserName','TargetDomainName','TargetUserSid','IpAddress','IpPort',
    'TaskName','ServiceName','ImagePath','ScriptBlockId','Path','Threat Name','Detection ID',
    'Initiated','DestinationIp','DestinationPort','Protocol')

function Read-Records([string]$Query, [int]$Limit, [switch]$Oldest) {
    try {
        Get-WinEvent -LogName $definition.Log -FilterXPath $Query -MaxEvents $Limit -Oldest:$Oldest -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
    }
}

$events = @()
$position = $After
$state = 'collecting'
try {
    $log = Get-WinEvent -ListLog $definition.Log -ErrorAction Stop
    if (!$log.IsEnabled) {
        $state = 'misconfigured'
    } else {
        $latest = Read-Records '*' 1
        $tail = if ($latest) { [long]$latest.RecordId } else { 0 }
        $lower = if ($tail -lt $After) { 0 } else { $After }
        $ids = ($definition.Ids | ForEach-Object { 'EventID=' + $_ }) -join ' or '
        $query = "*[System[($ids) and EventRecordID > $lower]]"
        $events = @(foreach ($item in (Read-Records $query 100 -Oldest)) {
            $fields = @{}
            $xml = [xml]$item.ToXml()
            foreach ($field in $xml.GetElementsByTagName('Data')) {
                $name = $field.GetAttribute('Name')
                if ($name -notin $allowedFields) { continue }
                $value = [string]$field.InnerText
                $fields[$name] = $value.Substring(0, [Math]::Min(1024, $value.Length))
            }
            @{
                host = [string]$item.MachineName
                event_id = [int]$item.Id
                record_id = [long]$item.RecordId
                timestamp = $item.TimeCreated.ToUniversalTime().ToString('o')
                fields = $fields
            }
        })
        $position = if ($events.Count) { $events[-1].record_id } else { $tail }
        if (!$events.Count) { $state = 'no_data' }
    }
} catch {
    if ($_.Exception -is [UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -like '*UnauthorizedAccess*') {
        $state = 'access_denied'
    } elseif ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound,*') {
        $state = 'not_installed'
    } else { throw }
}
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject @{ state = $state; position = $position; events = $events } -Depth 5 -Compress
