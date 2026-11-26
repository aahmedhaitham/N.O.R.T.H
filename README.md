# NORTH

**Network Operations, Reconnaissance, Threat Hunting**

NORTH is a Windows-first investigation console. **ATLAS** shows devices and observed connections, **IRIS** searches evidence, and **ECHO** reconstructs investigations. Start in Simple mode for a plain-language overview, or switch to Analyst mode for rules, source coverage, and evidence details. NORTH Assistant answers from data already loaded in the app and works offline.

<!-- Preview media slot for a screenshot or short GIF from a synthetic workspace. -->

## Quick start

1. Download the Windows installer and SHA256SUMS.txt from the [public NORTH v0.3.0 preview](https://github.com/aahmedhaitham/NORTH-Releases/releases/tag/v0.3.0-preview).
2. Verify the SHA-256 checksum before running **NORTH-Setup-Windows-x64.exe**. This Windows preview is unsigned. [Preview release notes and verification](docs/RELEASE-PREVIEW.md)
3. Open NORTH, finish or skip setup, and use **Ctrl+J** for NORTH Assistant. In **This computer**, NORTH uses local data and can offer monitoring when the account has access to Windows sources.

To run the synthetic developer demo, see [Development](docs/DEVELOPMENT.md). Source builds and the optional hosted deployment have separate setup instructions.

## How it works

```mermaid
flowchart LR
  Windows[Windows observations] --> Collector[Local collector]
  Collector --> Store[(Local SQLite)]
  Store --> Desktop[Desktop console]
  Desktop --> Views[ATLAS · IRIS · ECHO]
  Views --> Assistant[Offline NORTH Assistant]
  Collector -. Optional pairing .-> Cloud[Private HTTPS workspace]
  Cloud --> Desktop
```

[Documentation index](docs/README.md) · [Architecture](docs/ARCHITECTURE.md) · [Assistant intent guide](docs/ASSISTANT.md) · [Cloud setup](docs/CLOUD.md) · [Lab and Wazuh](docs/LAB.md)

## Coverage and limits

| Evidence | Status |
|---|---|
| Bundled detection rules | Synthetic positive and negative fixtures |
| Live detection coverage | [Not yet measured](docs/COVERAGE.md) |
| Performance | [Reproducible synthetic benchmarks](docs/PERFORMANCE.md) |

Nearby devices come from observations available to the current collector or configured router. Source access and collector coverage affect what NORTH can show. A finding is a triage signal. Country attribution is approximate, and bytes per device require a source that measures them. The Windows preview is unsigned.

[Privacy](PRIVACY.md) · [Security](SECURITY.md) · [Threat model](THREAT_MODEL.md) · [Third-party notices](THIRD_PARTY_NOTICES.md) · [Progress](PROGRESS.md)
