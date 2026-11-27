$ErrorActionPreference='Stop'
$WarningPreference='SilentlyContinue'
function Observe([string]$Id, [scriptblock]$Read) {
    try {
        $items = @(& $Read | Select-Object -First 513)
        if ($items.Count -gt 512) { return @{id=$Id; items=$null} }
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $digests = @(foreach ($item in $items) {
                $value = ConvertTo-Json -InputObject $item -Compress -Depth 5
                [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))).Replace('-','').ToLowerInvariant()
            })
        } finally { $hash.Dispose() }
        @{id=$Id; items=$digests}
    } catch { @{id=$Id; items=$null} }
}
$snapshot = @(
    Observe 'autoruns' {
        foreach ($hive in @('HKLM:','HKCU:')) {
            foreach ($name in @('Run','RunOnce')) {
                $key = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\$name"
                if (Test-Path -LiteralPath $key) {
                    $props = Get-ItemProperty -LiteralPath $key
                    foreach ($entry in $props.PSObject.Properties) {
                        if ($entry.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
                            @($key, $entry.Name, $entry.Value) -join '|'
                        }
                    }
                }
            }
        }
        foreach ($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))) {
            if ($folder -and (Test-Path -LiteralPath $folder)) {
                Get-ChildItem -LiteralPath $folder -File -Force | ForEach-Object {
                    if ($_.Length -gt 16MB) { throw 'Startup file exceeds the observation limit' }
                    @($_.FullName,(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) -join '|'
                }
            }
        }
    }
    Observe 'services' { Get-CimInstance Win32_Service | Select-Object Name,StartMode,PathName,StartName }
    Observe 'tasks' {
        Get-ScheduledTask | ForEach-Object {
            [ordered]@{name=$_.TaskPath + $_.TaskName; enabled=$_.Settings.Enabled;
                actions=@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)}
        }
    }
    Observe 'listeners' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort }
    Observe 'firewall' {
        Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name,Enabled,Direction,Action,Profile
    }
    Observe 'users' { Get-LocalUser | Select-Object SID,Enabled,Name }
    Observe 'admins' { Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object SID }
    Observe 'hosts' {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if ((Get-Item -LiteralPath $hostsPath).Length -gt 16MB) { throw 'Hosts file exceeds the observation limit' }
        (Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash
    }
    Observe 'proxy' {
        $internet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $internet | Select-Object ProxyEnable,ProxyServer,AutoConfigURL
        $winHttp = & (Join-Path $env:SystemRoot 'System32\netsh.exe') winhttp show proxy
        if ($LASTEXITCODE -ne 0) { throw 'WinHTTP proxy unavailable' }
        $winHttp
    }
    Observe 'dns' { Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses }
    Observe 'exclusions' {
        $prefs = Get-MpPreference
        foreach ($kind in @('ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress')) {
            foreach ($entry in $prefs.$kind) { if ($entry) { "${kind}: $entry" } }
        }
    }
)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject @{categories=$snapshot} -Depth 5 -Compress
