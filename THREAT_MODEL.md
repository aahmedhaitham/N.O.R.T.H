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
| A question attempts to take an action or send evidence elsewhere | NORTH Assistant selects from a fixed intent registry and uses bounded, in-memory snapshots. Its controls can navigate to an app record. It has no command execution or request capability. |
| A preview download is replaced | The Windows workflow publishes per-file SHA-256 hashes from the tested build and generates attestations when the repository supports them. The preview executables are unsigned. |

## Limits

The local session protects the browser boundary. Local programs that can access
the loopback endpoint can establish their own session. It is not OS user
authentication or a defense against malware or an administrator. Browser
loopback cookies are scoped by host and path, not port, so other same-host
listeners remain inside that local trust boundary. The packaged application
still relies on Windows permissions, capture driver policy and trusted release
signing. Coverage of hostile event rendering is not exhaustive.

### Local evidence integrity

The SQLite evidence database is readable by programs with access to its files. Packet captures also rely on file permissions for confidentiality. The opt-in HMAC chain verifies the linked evidence recorded after migration and detects changes or missing records within that chain. It provides no confidentiality, and an attacker who controls the PC and the key can replace the evidence and recompute authentication data. The desktop key setup and external checkpoint workflow are pending.
