# NORTH security

Report a vulnerability privately to the repository maintainer. Include the affected
build, the behavior, and minimal synthetic evidence. Keep credentials, packet
payloads and private telemetry out of public issues.

The local FastAPI process issues a random credential per session, signed with an in-memory key. The same-origin
frontend starts a session using a deliberate POST and receives an HttpOnly,
SameSite=Strict cookie. Loopback Host validation and Origin and Fetch Metadata
checks apply to HTTP and WebSockets. Cross-origin access is disabled. Keep the
local listener bound to loopback. The Docker gateway publishes its port on loopback.
The separately configured public synthetic demo stays read-only.

The Electron windows use context isolation, sandboxing and disabled Node integration.
The setup IPC handler validates both the sender frame and its input. The console
restricts script and connection sources to its own origin. Inline styles are
allowed for charts and graphs. Collector credentials and desktop cloud session
cookies are managed outside the renderer. System capture and event collection
require the Windows privileges and configured drivers available to the user.
