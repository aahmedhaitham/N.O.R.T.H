# Third-party notices

- **IP Geolocation by DB-IP.** NORTH includes transformed November 2026 IP to
  Country Lite records under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  See [DB-IP](https://db-ip.com/db/lite.php) and the bundled GeoIP notice.
- **Natural Earth.** Country geometry is derived from the public-domain
  [Natural Earth](https://www.naturalearthdata.com/) 1:110m Admin 0 Countries
  dataset. NORTH rounds coordinates and retains country labels.
- **OUI data.** NORTH does not bundle an IEEE OUI registry. Its address inspector
  explains MAC address bits from the observed address.
- **Fonts.** The UI uses system font stacks, including Segoe UI and Consolas
  where present. No font files are redistributed.
- **Icons.** Interface icons use [Lucide](https://lucide.dev/license), distributed
  under its ISC license with applicable Feather MIT attribution. The NORTH app
  icon is stored with the project assets.
- **MITRE ATT&CK®.** Rule technique IDs reference MITRE ATT&CK. Tactic labels
  for bundled rule IDs are derived from [Enterprise ATT&CK v20.1 STIX data](https://github.com/mitre-attack/attack-stix-data/blob/master/index.md).
  See the [ATT&CK terms of use](https://attack.mitre.org/resources/terms-of-use/).
  NORTH's rule definitions and synthetic fixtures are maintained in this repository.
- **Electron.** The Windows application includes the Electron runtime under MIT
  terms. Its distribution includes Electron and Chromium license notices.
- **Test tooling.** The Windows walkthrough uses axe-core (MPL-2.0), and
  JavaScript property tests use fast-check (MIT). These test tools are
  development dependencies.

- **Offline EVTX dataset.** The development downloader supports a pinned file
  from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  and verifies the repository's GPL-3.0 license text. Dataset files are
  downloaded separately and are absent from the Windows package.
- **Windows servicing reference.** A small table of published Windows 11 Home
  and Pro servicing dates is sourced from [Microsoft Windows release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information).
  The table records its review date and leaves unlisted builds undetermined.

Dependency packages retain their respective licenses. The lockfiles record the
versions, and Electron distributions include their runtime dependency notices.
