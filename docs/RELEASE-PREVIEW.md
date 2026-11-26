# NORTH unsigned Windows preview

This is a preview release candidate. It includes the Windows desktop console, first-run setup, Simple and Analyst modes, local rule management, and NORTH Assistant. The desktop can open **This computer** without a cloud workspace. A configured collector and source permissions determine which live evidence appears.

## Download and verify

Use the artifact from a successful **Build NORTH for Windows** run for the intended commit. The upload follows the installer walkthrough. Keep the installer, portable app, `SHA256SUMS.txt`, and `BUILD-INFO.json` from the same run. [Windows build workflow](https://github.com/aahmedhaitham/N.O.R.T.H/actions/workflows/desktop.yml)

Run this in the extracted artifact folder before opening the installer:

```powershell
$name = 'NORTH-Setup-Windows-x64.exe'
$pattern = '^([a-fA-F0-9]{64})  ' + [regex]::Escape($name) + '$'
$line = @(Get-Content -LiteralPath SHA256SUMS.txt | Select-String -Pattern $pattern)
if ($line.Count -ne 1) { throw 'Expected one installer checksum.' }
$expected = $line[0].Matches[0].Groups[1].Value
$actual = (Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash
if ($actual -ine $expected) { throw 'Installer checksum mismatch.' }
'Installer checksum matched.'
```

Use `BUILD-INFO.json` to match the commit, workflow run, and file digests to the GitHub run page. If the workflow generated a build attestation, verify the installer with the GitHub CLI:

```powershell
gh attestation verify ./NORTH-Setup-Windows-x64.exe --repo aahmedhaitham/N.O.R.T.H
```

GitHub supports attestations in public repositories and eligible private repositories. The workflow records whether the attestation step ran. Keep the repository private if that is your intended access policy. An attestation verifies build provenance. Windows publisher signing is a separate release requirement. [GitHub attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Release checklist

- Select a commit with passing backend, desktop, cloud, and installed Windows checks.
- Use that run's artifacts and hashes. Confirm a build attestation where repository eligibility permits it.
- Add a screenshot or short GIF captured from synthetic data.
- Label the release **unsigned preview** and keep the download available only to its intended audience.
- Reserve the v1 label for a signed release. Live detection coverage remains [unverified](COVERAGE.md).
