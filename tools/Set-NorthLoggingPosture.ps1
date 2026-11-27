param([string]$Id, [ValidateSet('read','apply')][string]$Action, [int]$Expected = -1, [int]$Desired = -1)
$ErrorActionPreference = 'Stop'
$settings = @{
    'autorun-policy' = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun')
    'process-command-line' = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled')
    'script-block' = @('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging')
}
if ($Id -eq 'smbv1') {
    $enabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
    if ($enabled -isnot [bool]) { throw 'Unknown SMB configuration' }
    $current = [int]$enabled
    if ($Action -eq 'apply') {
        if ($current -ne $Expected -or $Desired -notin @(0,1)) { throw 'The setting changed after preview' }
        Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$Desired) -Confirm:$false | Out-Null
    }
    return (@{ value = $current; location = 'SMB server configuration: EnableSMB1Protocol' } | ConvertTo-Json -Compress)
}
if ($Id -in @('firewall-domain','firewall-private','firewall-public')) {
    $profile = $Id.Substring(9)
    $enabled = (Get-NetFirewallProfile -Name $profile -PolicyStore PersistentStore).Enabled.ToString()
    $current = switch ($enabled) {
        'True' { 1 }; 'False' { 0 }; 'NotConfigured' { -1 }; default { throw 'Unknown firewall setting' }
    }
    if ($Action -eq 'apply') {
        if ($current -ne $Expected -or $Desired -notin @(-1,0,1)) { throw 'The setting changed after preview' }
        $setting = @('NotConfigured','False','True')[$Desired + 1]
        Set-NetFirewallProfile -Name $profile -PolicyStore PersistentStore -Enabled $setting
    }
    return (@{ value = $current; location = "Windows Firewall local policy: $profile profile Enabled" } | ConvertTo-Json -Compress)
}
if (!$settings.ContainsKey($Id)) { throw 'Unsupported setting' }
$maximum = if ($Id -eq 'autorun-policy') { 255 } else { 1 }
$keyPath, $name = $settings[$Id]
$root = [Microsoft.Win32.Registry]::LocalMachine
$key = $root.OpenSubKey($keyPath)
$current = -1
if ($key) {
    try {
        if ($key.GetValueNames() -contains $name) {
            if ($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'Unexpected setting type' }
            $current = [int]$key.GetValue($name)
            if ($current -lt 0 -or $current -gt $maximum) { throw 'Unexpected setting value' }
        }
    } finally { $key.Dispose() }
}
if ($Action -eq 'apply') {
    if ($current -ne $Expected -or $Desired -lt -1 -or $Desired -gt $maximum) { throw 'The setting changed after preview' }
    if ($Desired -eq -1) {
        $write = $root.OpenSubKey($keyPath, $true)
        if ($write) { try { $write.DeleteValue($name, $false) } finally { $write.Dispose() } }
    } else {
        $write = $root.CreateSubKey($keyPath)
        try { $write.SetValue($name, $Desired, [Microsoft.Win32.RegistryValueKind]::DWord) }
        finally { $write.Dispose() }
    }
}
@{ value = $current; location = "HKLM\$keyPath\$name" } | ConvertTo-Json -Compress
