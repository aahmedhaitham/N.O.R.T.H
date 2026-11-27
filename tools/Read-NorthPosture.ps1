$ErrorActionPreference = 'Stop'
$checks = @(
    function Read-Check($Id, $Title, [scriptblock]$Read) {
        $status = 'unknown'
        $reason = 'Windows did not expose this setting to NORTH.'
        try {
            $value = & $Read
            if ($value -is [bool]) {
                $status = if ($value) { 'pass' } else { 'fail' }
                $reason = if ($value) { 'Observed the recommended setting.' } else { 'Review this setting in Windows.' }
            }
        } catch [UnauthorizedAccessException] {
            $reason = 'Windows denied access to this setting.'
        } catch {
            if ($_.Exception -is [System.Security.SecurityException]) {
                $reason = 'Windows denied access to this setting.'
            }
        }
        @{id=$Id; title=$Title; status=$status; reason=$reason}
    }

    Read-Check 'uac' 'User Account Control enabled' {
        (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1
    }
    Read-Check 'process-command-line' 'Command-line process auditing enabled' {
        (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
    }
    Read-Check 'script-block' 'PowerShell script block logging enabled' {
        (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1
    }
    Read-Check 'smbv1' 'SMBv1 server protocol disabled' {
        $value = (Get-SmbServerConfiguration).EnableSMB1Protocol
        if ($value -is [bool]) { !$value }
    }
    Read-Check 'rdp' 'Remote Desktop disabled or requires Network Level Authentication' {
        $deny = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        if ($deny -eq 1) { return $true }
        if ($deny -eq 0) {
            (Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1
        }
    }
    Read-Check 'secure-boot' 'Secure Boot enabled' { Confirm-SecureBootUEFI }
    Read-Check 'tpm' 'TPM present and ready' {
        $tpm = Get-Tpm
        if ($tpm.TpmPresent -is [bool] -and $tpm.TpmReady -is [bool]) { $tpm.TpmPresent -and $tpm.TpmReady }
    }
    foreach ($profile in @('Domain','Private','Public')) {
        Read-Check ('firewall-' + $profile.ToLowerInvariant()) ("$profile firewall enabled") {
            $value = (Get-NetFirewallProfile -Name $profile -PolicyStore ActiveStore).Enabled.ToString()
            if ($value -in @('True','False')) { $value -eq 'True' }
        }
    }
    $defender = try { Get-MpComputerStatus } catch { $null }
    Read-Check 'defender-realtime' 'Defender real-time protection enabled' { $defender.RealTimeProtectionEnabled }
    Read-Check 'defender-tamper' 'Defender tamper protection enabled' { $defender.IsTamperProtected }
)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject @{checks=$checks} -Depth 4 -Compress
