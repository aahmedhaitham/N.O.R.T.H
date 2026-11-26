# NORTH threat model

## Assets and boundaries

Assets include endpoint logs, packet headers, device observations, findings, local
databases, and cloud collector or session credentials. The important boundaries
are the browser to the loopback API, the Electron renderer to its main process,
the main process to Windows tools, and an explicitly paired collector to its
HTTPS workspace.

| Threat | Existing mitigation |
| --- | --- |
| A third-party site targets a local HTTP or WebSocket endpoint | Loopback Host validation, exact origin checks, Fetch Metadata rejection, no cross-origin grants, and a random session cookie on protected endpoints. |
| A renderer asks for an unexpected workspace operation | Setup IPC is limited to the expected top-level setup page and validates a bounded string and an HTTPS workspace origin. |
| Hostile telemetry tries to become active content | React renders displayed fields as text. Electron prevents remote navigation and applies a restrictive content policy. |
| Telemetry becomes a shell argument | The Windows readers invoke fixed PowerShell scripts with `-File` using argument arrays rather than shell interpolation. |
| A cloud account tries to read another account's records | Cloud data paths enforce workspace ownership. Desktop cloud sessions use the main-process bridge. |

## Limits

The local session protects the browser boundary. Local programs that can access
the loopback endpoint can establish their own session. It is not OS user
authentication or a defense against malware or an administrator. Browser
loopback cookies are scoped by host and path, not port, so other same-host
listeners remain inside that local trust boundary. The packaged application
still relies on Windows permissions, capture driver policy and trusted release
signing. Coverage of hostile event rendering is not exhaustive.
