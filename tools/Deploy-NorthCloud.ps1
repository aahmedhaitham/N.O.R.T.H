param(
    [switch]$ShowAccessKey,
    [switch]$EnableCloudAI,
    [switch]$Staging,
    [switch]$ConfigureGoogle,
    [ValidatePattern('^https://north-cloud-staging\.[a-z0-9-]+\.workers\.dev/?$')]
    [string]$CheckStagingUrl
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$deploymentName = if ($Staging) { 'north-cloud-staging' } else { 'north-cloud' }
$configFile = if ($Staging) { 'wrangler.staging.local.jsonc' } else { 'wrangler.jsonc' }
$configPath = Join-Path (Join-Path $root 'cloud') $configFile
$templatePath = Join-Path $root 'cloud\wrangler.example.jsonc'
$stateDirectory = Join-Path $root '.north-launcher'
$keyFile = if ($Staging) { 'cloud-staging-keys.json' } else { 'cloud-keys.json' }
$keyPath = Join-Path $stateDirectory $keyFile
if ($ConfigureGoogle -and !$Staging) { throw 'Google sign-in can only be configured on staging by this script.' }

function Invoke-Wrangler {
    & npx.cmd --yes wrangler @args
    if ($LASTEXITCODE -ne 0) { throw "Wrangler command failed (exit $LASTEXITCODE)." }
}

function New-Secret {
    $bytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Find-NorthDatabase {
    $databases = Invoke-Wrangler d1 list --json | Out-String | ConvertFrom-Json
    return $databases | Where-Object { $_.name -eq $deploymentName } | Select-Object -First 1
}

function Test-StagingDeployment([string]$Origin) {
    $health = Invoke-WebRequest -Method Head -Uri "$Origin/api/cloud/health" -UseBasicParsing -TimeoutSec 20
    if ($health.StatusCode -ne 204) { throw 'The collector health endpoint did not return HTTP 204.' }
    $homepage = Invoke-WebRequest -Uri "$Origin/" -UseBasicParsing -TimeoutSec 20
    if ($homepage.StatusCode -ne 200 -or $homepage.Content -notmatch '<div id="root"') {
        throw 'The staging Worker did not serve the NORTH dashboard.'
    }
    $options = Invoke-RestMethod -Uri "$Origin/api/cloud/auth/options" -TimeoutSec 20
    if ($options.google -isnot [bool] -or ($ConfigureGoogle -and !$options.google)) {
        throw 'Staging did not report the expected Google sign-in configuration.'
    }
    try {
        $null = Invoke-WebRequest -Uri "$Origin/api/cloud/status" -UseBasicParsing -TimeoutSec 20
        throw 'The staging workspace status must require sign-in.'
    } catch {
        if ($null -eq $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 401) { throw }
    }
    $download = Invoke-WebRequest -Method Head -Uri "$Origin/downloads/NORTH-Collector-Windows.zip" -UseBasicParsing -TimeoutSec 20
    if ($download.StatusCode -ne 200 -or $download.Headers['Content-Type'] -notmatch '^application/(zip|x-zip-compressed|octet-stream)(;|$)') {
        throw 'The staging collector download did not respond with a ZIP file.'
    }
    Write-Host "Staging checks passed. Sign-in is required and the Windows collector is available. Google enabled: $($options.google)."
}

function Get-Secrets {
    if (Test-Path -LiteralPath $keyPath) {
        $saved = Get-Content -LiteralPath $keyPath -Raw | ConvertFrom-Json
        $result = @{}
        foreach ($field in $saved.PSObject.Properties) {
            $secure = ConvertTo-SecureString $field.Value
            $credential = [Management.Automation.PSCredential]::new('north', $secure)
            $result[$field.Name] = $credential.GetNetworkCredential().Password
        }
        return $result
    }
    $result = @{}
    $encrypted = @{}
    foreach ($name in 'NORTH_ACCESS_KEY','NORTH_INGEST_KEY','NORTH_SESSION_SECRET') {
        $result[$name] = New-Secret
        $encrypted[$name] = ConvertFrom-SecureString (ConvertTo-SecureString $result[$name] -AsPlainText -Force)
    }
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    $encrypted | ConvertTo-Json | Set-Content -LiteralPath $keyPath -Encoding UTF8
    return $result
}

Push-Location -LiteralPath $root
try {
    if ($CheckStagingUrl) {
        Test-StagingDeployment ($CheckStagingUrl.TrimEnd('/'))
        return
    }
    if ($ShowAccessKey) {
        if (!(Test-Path -LiteralPath $keyPath)) { throw 'Deploy NORTH Cloud before retrieving its key.' }
        Write-Host "NORTH sign-in key: $((Get-Secrets)['NORTH_ACCESS_KEY'])"
        return
    }
    if (!(Test-Path -LiteralPath $configPath)) {
        $database = Find-NorthDatabase
        if (!$database) {
            Invoke-Wrangler d1 create $deploymentName
            $database = Find-NorthDatabase
        }
        $identifier = [guid]::Empty
        if (!$database -or ![guid]::TryParse([string]$database.uuid, [ref]$identifier)) {
            throw "Could not find the $deploymentName database ID."
        }
        $config = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
        $config.name = $deploymentName
        $config.d1_databases[0].database_name = $deploymentName
        if ($Staging) {
            $config | Add-Member -NotePropertyName vars -NotePropertyValue @{ NORTH_HOSTED_RETENTION_DAYS = '30' } -Force
        }
        $config.d1_databases[0].database_id = $identifier.ToString()
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8))
    }

    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($config.name -ne $deploymentName -or $config.d1_databases.Count -ne 1 -or
        $config.d1_databases[0].database_name -ne $deploymentName -or $config.d1_databases[0].binding -ne 'DB') {
        throw "The Wrangler configuration must target only $deploymentName."
    }
    if ($Staging) {
        $database = Find-NorthDatabase
        if (!$database -or $database.uuid -ne $config.d1_databases[0].database_id) {
            throw 'The staging database binding does not match the staging database in Cloudflare.'
        }
    }

    Invoke-Wrangler d1 execute $deploymentName --config $configPath --remote --file cloud/schema.sql
    & npm.cmd --prefix frontend run build -- --mode cloud
    if ($LASTEXITCODE -ne 0) { throw 'Cloud frontend build failed.' }
    & (Join-Path $PSScriptRoot 'Build-NorthCollectorZip.ps1') -OutputPath 'frontend/dist/downloads/NORTH-Collector-Windows.zip'
    $deploymentConfig = $configPath
    if ($EnableCloudAI) {
        $aiConfig = if ($Staging) { 'wrangler.staging.ai.local.jsonc' } else { 'wrangler.ai.local.jsonc' }
        $deploymentConfig = Join-Path (Join-Path $root 'cloud') $aiConfig
        $config | Add-Member -NotePropertyName ai -NotePropertyValue @{ binding = 'AI' } -Force
        [IO.File]::WriteAllText($deploymentConfig, ($config | ConvertTo-Json -Depth 8))
    }
    $deployment = @(Invoke-Wrangler deploy --config $deploymentConfig)
    $deployment | Write-Output

    $secrets = Get-Secrets
    if ($ConfigureGoogle) {
        $googleId = (Read-Host 'Staging Google OAuth web client ID').Trim()
        $googleSecret = Read-Host 'Staging Google OAuth web client secret' -AsSecureString
        if (!$googleId.EndsWith('.apps.googleusercontent.com') -or !$googleSecret.Length) {
            throw 'Enter the staging Google OAuth web client ID and secret.'
        }
        $credential = [Management.Automation.PSCredential]::new('north-oauth', $googleSecret)
        $secrets.NORTH_GOOGLE_CLIENT_ID = $googleId
        $secrets.NORTH_GOOGLE_CLIENT_SECRET = $credential.GetNetworkCredential().Password
    }
    ($secrets | ConvertTo-Json -Compress) | & npx.cmd --yes wrangler secret bulk --config $deploymentConfig
    if ($LASTEXITCODE -ne 0) { throw 'Cloudflare did not accept the workspace secrets.' }

    $url = [regex]::Match(($deployment -join "`n"), 'https://[a-z0-9.-]+\.workers\.dev').Value
    if ($Staging -and !$url) { throw 'Wrangler did not print a staging URL. Check the staging Worker in Cloudflare before proceeding.' }
    if ($url) {
        Write-Host "NORTH Cloud URL: $url"
        if ($Staging) {
            Write-Host "Google OAuth callback: $url/api/cloud/auth/google/callback"
            Test-StagingDeployment $url
        }
    }
    Write-Host 'Deployment complete. Run this script with -ShowAccessKey to view your private sign-in key.'
    Write-Host 'No local telemetry was uploaded.'
} finally {
    Pop-Location
}
