# NORTH v0.4.0-preview · unsigned Windows release notes

This is the published unsigned Windows preview. It includes the Windows desktop console, first-run setup, Simple and Analyst modes, local rule management, and NORTH Assistant. The desktop can open **This computer** without a cloud workspace. A configured collector and source permissions determine which live evidence appears.

## Download and verify

Download the files from the [public preview release](https://github.com/aahmedhaitham/NORTH-Releases/releases/tag/v0.4.0-preview). To verify a future candidate, use the artifact from a successful **Build NORTH for Windows** run for the intended commit. The upload follows the installer walkthrough. Keep the installer, portable app, `SHA256SUMS.txt`, and `BUILD-INFO.json` from the same run. [Windows build workflow](https://github.com/aahmedhaitham/N.O.R.T.H/actions/workflows/desktop.yml)

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

## Clean Windows VM verification

Use a disposable Windows VM and a fresh standard user. Take a snapshot before
testing. Start with copies of the workflow artifacts and record the commit,
runner link, checksum results, and each outcome.

1. Run the artifact verifier from a checkout of the same commit.

   ```powershell
   powershell.exe -NoProfile -File ./tools/Test-NorthPreviewArtifacts.ps1 -ArtifactDirectory 'C:\NORTH-preview'
   gh attestation verify 'C:\NORTH-preview\NORTH-Setup-Windows-x64.exe' --repo aahmedhaitham/N.O.R.T.H
   ```

   Run the second command only if the workflow generated an attestation. Record
   a skipped attestation as skipped. Compare the commit to the completed run.

2. Disconnect the VM network before installation and keep it disconnected for
   first launch. Install, open This computer, finish or skip setup, change the
   display mode, and verify that NORTH opens without any cloud login.
3. Revert to a clean snapshot. Install the earlier preview, change the mode
   and appearance, and record a synthetic review state. Update with the new
   installer. Compare the preferences and local evidence before and after.
4. Uninstall using Windows Installed apps. Verify the program and launch
   shortcuts are removed. Inspect the app-data directory while signed in as
   the test user and record what remains. Uninstaller data retention for the
   candidate has not yet been verified. Review or back up local evidence
   before removing a test profile.
5. Revert the VM snapshot when done. Keep screenshots synthetic and keep raw
   collected evidence and profile contents out of release artifacts.

The GitHub walkthrough checks a fresh application profile and a clean install.
That check cannot establish upgrade, uninstallation, or a disconnected first-run
result by itself.
