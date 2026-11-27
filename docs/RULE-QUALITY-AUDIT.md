# Bundled rule noise audit

These estimates describe likely benign firing frequency on a general Windows workstation with the required telemetry. They are qualitative judgments based on the current predicates and documented benign uses. Server, developer and managed workstation baselines can differ substantially.

| Rule | Likely benign frequency | Why |
| --- | --- | --- |
| windows-service-installed | High | Legitimate installers and IT management can create services. It selects every creation event of that type. |
| scheduled-task-created | High | Software updates and authorized automation often create tasks. It selects every creation event of that type. |
| remote-thread-observed | Medium | Debuggers and legitimate security tools can create remote threads. The rule selects every Sysmon event 8. |
| lsass-process-access | Medium | Security tools and Windows components can legitimately access LSASS. It matches any recorded access to LSASS regardless of access mask. |
| registry-run-value-set | Medium | An installed app can register a legitimate sign-in startup entry. |
| powershell-script-write | Medium | Authorized administration and software installers can write scripts. |
| repeated-ssh-authentication-failures | Medium | A legitimate user can mistype a password or reuse an expired credential. |
| winlogon-shell | Low | Desktop customization can cause this observation. |
| winlogon-userinit | Low | Managed Windows configuration can cause this observation. |
| ifeo-debugger | Low | Application debugging can cause this observation. |
| appinit-dlls | Low | Legacy compatibility software can cause this observation. |
| lsa-security-packages | Low | Enterprise authentication provider installation can cause this observation. |
| lsa-auth-packages | Low | Enterprise authentication setup can cause this observation. |
| print-monitor-dll | Low | Printer driver installation can cause this observation. |
| boot-execute | Low | Disk maintenance or operating-system repair can cause this observation. |
| office-addin | Medium | Authorized Office add-in installation can cause this observation. |
| screensaver-path | Low | Personalization or desktop policy can cause this observation. |
| defender-realtime-setting | Medium | Managed Defender policy or troubleshooting can cause this observation. |
| uac-policy-change | Low | An approved Windows security policy change can cause this observation. |
| system-information | High | Support and hardware inventory can cause this observation. |
| account-enumeration | High | Troubleshooting account permissions can cause this observation. |
| network-configuration | High | Routine network troubleshooting can cause this observation. |
| network-connections | High | Troubleshooting local sockets can cause this observation. |
| network-name-lookup | Medium | Legacy network troubleshooting can cause this observation. |
| process-inventory | Medium | Support and performance investigation can cause this observation. |
| domain-controller-discovery | Medium | Domain maintenance can cause this observation. |
| terminal-shell | High | Interactive support and ordinary automation can cause this observation. |
| windows-script-host | Medium | Enterprise logon scripts and automation can cause this observation. |
| console-script-host | High | Routine Windows scripting can cause this observation. |
| mshta-observed | Low | Legacy HTML application launch can cause this observation. |
| msiexec-observed | High | Software installation and updates can cause this observation. |
| regsvr32-observed | Medium | Component installation can cause this observation. |
| rundll32-observed | High | Supported Windows and application functions can cause this observation. |
| installutil-observed | Low | Developer or enterprise deployment can cause this observation. |
| msbuild-observed | Medium | Compiling software can cause this observation. |
| remote-desktop-client | Medium | Authorized remote administration can cause this observation. |
| ssh-client | Medium | Authorized management or development can cause this observation. |
| certificate-utility | Medium | Certificate enrollment and diagnostics can cause this observation. |
| remote-interactive-logon-success | Medium | Ordinary Remote Desktop access can cause this observation. |
| remote-interactive-logon-failure | Medium | Ordinary Remote Desktop access can cause this observation. |
| periodic-dns-query | High | Update checks and ordinary health polling often use regular intervals. |

## Standalone process starts

- system-information
- account-enumeration
- network-configuration
- network-connections
- network-name-lookup
- process-inventory
- domain-controller-discovery
- terminal-shell
- windows-script-host
- console-script-host
- mshta-observed
- msiexec-observed
- regsvr32-observed
- rundll32-observed
- installutil-observed
- msbuild-observed
- remote-desktop-client
- ssh-client
- certificate-utility

## Design notes

Use distinct discovery utilities per observed parent process over an event-time window. Treat a missing parent identifier as insufficient context. Require command-line or parent evidence for elevated process findings. Keep unmatched telemetry searchable and record the effect on technique coverage before removing a rule. Prefer specific documented exclusions over broad process-name exemptions.

## Context added to process-start rules

Rule IDs and existing ATT&CK tags were retained. A bare executable name no longer fires any of these 19 rules. Their effective coverage now requires command-line data or an observed parent path. Historical findings are retained.

- system-information: requires parent context.
- account-enumeration: requires parent context.
- network-configuration: requires parent context.
- network-connections: requires parent context.
- network-name-lookup: requires parent context.
- process-inventory: requires parent context.
- domain-controller-discovery: requires parent context.
- terminal-shell: requires parent context.
- windows-script-host: requires parent context.
- console-script-host: requires parent context.
- mshta-observed: requires argument context.
- msiexec-observed: requires parent context.
- regsvr32-observed: requires argument context.
- rundll32-observed: requires argument context.
- installutil-observed: requires parent context.
- msbuild-observed: requires parent context.
- remote-desktop-client: requires parent context.
- ssh-client: requires parent context.
- certificate-utility: requires argument context.

## M1 scope and interpretation

- The Windows error-reporting exclusion is limited to the standard System32 and SysWOW64 executable paths. A path match does not authenticate a binary. Remote-thread detections require source and target paths. LSASS detections require a source path and the process memory-read bit in GrantedAccess. Unknown masks or missing source paths cannot satisfy that rule. Service installs and scheduled-task creation remain broad, with ordinary updater and management fixtures that intentionally match.
- The discovery burst uses Sysmon process starts, the same host and parent GUID, and case-insensitive distinct process names in a 60-second window. Its ATT&CK mapping is a rule-level description. A burst may contain different utilities, so inspect the evidence to determine which observations apply.
- Replay evaluates the latest 500 unique stored events at most, including disabled rules. The trace shows the selected event's source, named selections and condition. A correlation rule still needs its full event group. The daily rate extrapolates from the sampled elapsed time and is unavailable for a sample shorter than one hour or an evaluation that times out.
- Finding confidence describes evidence structure: correlated observations or a single observation. It is qualitative. Baseline rarity reports first seen, previously observed, rare outbound destination, or unknown when the store cannot make a comparison. Findings already stored keep their historical evidence and review status.

## Added detections

| Rule | Likely benign frequency | Why |
| --- | --- | --- |
| Discovery utility burst | Medium | Inventory and support scripts can launch multiple diagnostic tools under one parent. |
| Encoded PowerShell | Medium | Managed automation can encode arguments for quoting. |
| Hidden PowerShell window | Medium | Scheduled jobs can hide a console window. |
| Security and System log cleared | Low | Approved retention or maintenance can clear logs. |
| Local user created | Low | Provisioning can legitimately create local accounts. |
| Local administrator added | Low | Approved elevation and support provisioning can add group members. |
| Office shell start | Low | Office add-ins and approved automation can launch a shell. |
| Shadow copy deletion request | Low | Backup retention jobs can request deletion. |
| Certificate utility remote URL cache | Low | Certificate diagnostics can access a remote resource through the cache. |

New mappings checked against Enterprise ATT&CK: [T1082](https://attack.mitre.org/techniques/T1082/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1685.005](https://attack.mitre.org/techniques/T1685/005/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098.007](https://attack.mitre.org/techniques/T1098/007/), [T1490](https://attack.mitre.org/techniques/T1490/), and [T1105](https://attack.mitre.org/techniques/T1105/). Certificate decode keeps its existing T1140 tag. No original ATT&CK IDs were removed.
