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
    Read-Check 'defender-signatures' 'Defender signatures updated within seven days' {
        $age = $defender.AntivirusSignatureAge
        if ($null -ne $age -and $age -ge 0 -and $age -lt [uint32]::MaxValue) { $age -le 7 }
    }
    Read-Check 'defender-scan' 'Defender scan recorded within 30 days' {
        $ages = @($defender.QuickScanAge, $defender.FullScanAge) | Where-Object {
            $null -ne $_ -and $_ -ge 0 -and $_ -lt [uint32]::MaxValue
        }
        if ($ages.Count) { ($ages | Measure-Object -Minimum).Minimum -le 30 }
    }
    Read-Check 'os-encryption' 'Windows drive BitLocker protection enabled' {
        $status = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
        if ($null -ne $status -and $status.ToString() -in @('On','Off','0','1')) {
            $status.ToString() -in @('On','1')
        }
    }
    Read-Check 'guest-account' 'Built-in local Guest account disabled' {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        if ($guest.Enabled -is [bool]) { !$guest.Enabled }
    }
    Read-Check 'sysmon-service' 'Sysmon service running' {
        $services = @(Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue)
        if ($services.Count) { $services.Status -contains 'Running' }
    }
    Read-Check 'update-reboot' 'No Windows Update reboot marker' {
        !(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    }

    Read-Check 'lsa-protection-policy' 'LSA protection explicitly configured' {
        (Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -in @(1,2)
    }
    Read-Check 'credential-guard' 'Credential Guard running' {
        $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
        if ($null -ne $guard.SecurityServicesRunning) { $guard.SecurityServicesRunning -contains 1 }
    }
    Read-Check 'autorun-policy' 'Computer AutoRun policy blocks all drive types' {
        $flags = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
        ($flags -band 255) -eq 255
    }
    Read-Check 'wsh-policy' 'Computer Windows Script Host disabled' {
        (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled') -eq 0
    }
    Read-Check 'defender-behavior' 'Defender behavior monitoring enabled' { $defender.BehaviorMonitorEnabled }
    Read-Check 'defender-on-access' 'Defender on-access protection enabled' { $defender.OnAccessProtectionEnabled }
    Read-Check 'defender-exclusions' 'No exclusions returned by Defender preferences' {
        $preferences = Get-MpPreference
        if ($null -ne $preferences) {
            $entries = @($preferences.ExclusionPath) + @($preferences.ExclusionProcess) + @($preferences.ExclusionExtension)
            @($entries | Where-Object { $_ }).Count -eq 0
        }
    }

)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject @{checks=$checks} -Depth 4 -Compress
