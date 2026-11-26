param(
    [ValidateSet('Status', 'Enable', 'Disable', 'Restart', 'Stop')][string]$Action = 'Status',
    [string]$CollectorDirectory,
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'
$rootPath = if ($CollectorDirectory) { $CollectorDirectory } else { Split-Path -Parent $PSScriptRoot }
$root = (Resolve-Path -LiteralPath $rootPath).Path
$launcher = Join-Path $root 'tools\Start-NorthCollector.ps1'
$settings = Join-Path $root '.north-launcher\collector-connection.json'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $identity = [Text.Encoding]::UTF8.GetBytes($user.ToLowerInvariant() + '|' + $root.ToLowerInvariant())
    $fingerprint = [BitConverter]::ToString($hasher.ComputeHash($identity)).Replace('-', '').Substring(0, 12)
} finally {
    $hasher.Dispose()
}
$taskName = "NORTH Collector $fingerprint"
$task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue

function Stop-NorthTask {
    if ($task -and $task.State -in @('Running', 'Queued')) {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $lockPath = Join-Path $root '.north-launcher\collector.lock'
    do {
        try {
            $probe = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
            $probe.Dispose()
            return
        } catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'The collector did not finish stopping.' }
            Start-Sleep -Milliseconds 250
        }
    } while ($true)
}

switch ($Action) {
    'Status' {
        if (!$task) {
            if ($AsJson) { @{ state = 'Not scheduled'; last_start = $null; last_result = $null } | ConvertTo-Json -Compress }
            else { Write-Host 'Automatic startup is off for this collector folder.' }
            return
        }
        $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
        if ($AsJson) {
            $lastStart = if ($info.LastRunTime.Year -gt 2000) { $info.LastRunTime.ToUniversalTime().ToString('o') } else { $null }
            @{ state = [string]$task.State; last_start = $lastStart; last_result = $info.LastTaskResult } | ConvertTo-Json -Compress
            return
        }
        Write-Host "Task Scheduler status: $($task.State)"
        if ($info.LastRunTime.Year -gt 2000) {
            Write-Host "Last start: $($info.LastRunTime) | Task result: $($info.LastTaskResult)"
        }
    }
    'Enable' {
        if (!(Test-Path -LiteralPath $settings -PathType Leaf)) {
            throw 'Pair and start the collector manually once from this folder before enabling automatic startup.'
        }
        if (!(Test-Path -LiteralPath $launcher -PathType Leaf)) {
            throw 'This collector folder is missing the NORTH launcher.'
        }
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $launcher + '"'
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $root
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
        $behavior = @{
            MultipleInstances = 'IgnoreNew'
            StartWhenAvailable = $true
            AllowStartIfOnBatteries = $true
            DontStopIfGoingOnBatteries = $true
            ExecutionTimeLimit = [TimeSpan]::Zero
            RestartCount = 3
            RestartInterval = New-TimeSpan -Minutes 2
        }
        $registration = @{
            TaskName = $taskName
            TaskPath = '\'
            Action = $taskAction
            Trigger = $trigger
            Principal = $principal
            Settings = New-ScheduledTaskSettingsSet @behavior
            Description = 'Starts the paired NORTH collector when this user signs in.'
            Force = $true
        }
        Register-ScheduledTask @registration | Out-Null
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
        Write-Host 'Automatic startup is enabled. Windows requested a background collector start.'
    }
    'Disable' {
        if ($task) {
            if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName -TaskPath '\' }
            Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
        }
        Write-Host 'Automatic startup is off for this collector folder.'
    }
    'Restart' {
        if (!$task -or $task.State -eq 'Disabled') { throw 'Enable automatic startup before restarting this collector.' }
        Stop-NorthTask
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
        Write-Host 'Windows requested a collector restart.'
    }
    'Stop' { Stop-NorthTask }
}
