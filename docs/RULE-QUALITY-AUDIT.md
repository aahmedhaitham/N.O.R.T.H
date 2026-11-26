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
