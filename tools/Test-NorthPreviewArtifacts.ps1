[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ArtifactDirectory,
    [ValidatePattern('^[0-9a-fA-F]{40}$')] [string]$Commit
)
$ErrorActionPreference = 'Stop'
$root = (Get-Item -LiteralPath $ArtifactDirectory).FullName
$expected = @('NORTH-Desktop-Windows-x64.exe', 'NORTH-Setup-Windows-x64.exe')
$metadata = Get-Content -LiteralPath (Join-Path $root 'BUILD-INFO.json') -Raw | ConvertFrom-Json
if ($metadata.channel -ne 'unsigned-preview' -or $metadata.commit -notmatch '^[0-9a-f]{40}$') {
    throw 'Build metadata is missing the expected preview channel or commit.'
}
if ($Commit -and $metadata.commit -ne $Commit) { throw 'The artifact came from a different commit.' }
if (@($metadata.files).Count -ne $expected.Count) { throw 'Unexpected file list in BUILD-INFO.json.' }
$lines = @(Get-Content -LiteralPath (Join-Path $root 'SHA256SUMS.txt'))
if ($lines.Count -ne $expected.Count) { throw 'Unexpected number of checksums.' }
foreach ($file in $expected) {
    $row = @($metadata.files | Where-Object name -eq $file)
    $pattern = '^([0-9a-fA-F]{64})  ' + [regex]::Escape($file) + '$'
    $matchesForFile = @($lines | Select-String -Pattern $pattern)
    if ($row.Count -ne 1 -or $matchesForFile.Count -ne 1) { throw "Missing or duplicate metadata for $file." }
    $fromFile = $matchesForFile[0].Matches[0].Groups[1].Value
    $digest = (Get-FileHash -LiteralPath (Join-Path $root $file) -Algorithm SHA256).Hash
    if ($digest -ine $fromFile -or $digest -ine $row[0].sha256) { throw "Checksum mismatch for $file." }
    Write-Output "$file verified."
}
Write-Output "Commit $($metadata.commit). Attestation step: $($metadata.attestation)."
