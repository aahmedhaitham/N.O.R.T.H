# NORTH clean Windows VM verification

Use a disposable Windows VM on an isolated virtual network with no route to
production systems. Start from a clean snapshot. Keep a copy of the verified
preview artifacts in the VM before disconnecting it for first-launch testing.

## Collection and installation

1. Record the snapshot identifier, Windows build, NORTH commit, test user,
   network isolation, and UTC clock. Do not export real workstation data.
2. Install and configure Sysmon using a reviewed configuration for this VM.
   Confirm which event types the configuration actually records before
   assessing coverage. Check Process Create, Network Connect, Image Load,
   Create Remote Thread, Process Access, File Create, Registry Set Value and DNS
   Query if they are in scope. Use Microsoft’s [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
   and your approved local policy.
3. Review local audit policy for the Security event types NORTH collects.
   Process creation visibility depends on audit policy, and command-line
   auditing can record sensitive arguments. Check the policy for PowerShell
   Script Block Logging if its source is in scope. Keep the extra data in the VM.
4. Start as an ordinary user and check the source entries in Overview and
   Detections. If the log cannot be read, record the denial before an authorized
   administrator grants the test collector account the minimum log access.
   Recheck the source. Record missing logs separately from denied access.
5. Install the verified NORTH preview, open This computer, and follow the
   [offline, upgrade, and uninstall checks](RELEASE-PREVIEW.md#clean-windows-vm-verification).
   Use synthetic or previously approved passive recordings for UI evidence.

## Evidence review

- Record the start and end in UTC, source states and event types available, rule
  IDs and enabled state, relevant evidence IDs, and what the recorded activity
  was expected to produce. Preserve the exact original events for review.
- A finding with matching evidence is observed. A missing source or denial
  makes the result unverified. If the expected event was collected and the
  rule was enabled but no finding appears, investigate a possible rule gap.
  If platform protection blocked the recorded activity or the source does not
  apply, record that separately using the actual run evidence.
- Shut down NORTH before making a consistent test database copy. Export
  findings using the read-only tools in [Coverage](COVERAGE.md). Keep raw
  records and review notes inside the lab. Clean up and revert the snapshot.

Live detection results remain unverified until a separately authorized recorded
run provides evidence. A synthetic dry run verifies the report and renderer.
