# NORTH privacy policy

## Local desktop use

NORTH opens in local mode. It reads network addresses assigned to the computer, device addresses Windows has observed, and a limited set of recent Sysmon records when the account can read that log. Those records can include hostnames, IP addresses, hardware addresses, process names, filenames, and timestamps. NORTH uses them to show your network inventory, event history, and investigation evidence.

The local desktop stores device history, optional monitoring findings and evidence, and any saved cloud workspace address in its application data folder. The app stores setup completion and display mode on the device. Local mode does not send Windows events or network observations to a NORTH server. NORTH saves exported reports to a location you choose.

## NORTH Assistant

NORTH Assistant reads bounded snapshots that the app has already loaded. It makes no network requests and does not send questions, answers, or evidence to a service. The panel keeps its clearable history in memory for the current workspace session. Opening an evidence link switches to the relevant NORTH view, which follows that view's normal local or cloud data behavior.

## Optional workspace and collectors

When you connect the desktop to a cloud workspace, it contacts the HTTPS address you select for sign-in and data retrieval. Connecting the desktop does not start a collector. When you separately pair and start a collector with a workspace, the collector sends its events, investigation reports, device observations and configured router traffic totals to that workspace. The workspace operator controls access and retention. Stopping a collector or revoking its key stops future syncs. Existing workspace records remain until the operator removes them.

## Optional AI

The local Ollama feature sends evidence-derived observations to the Ollama service you configure. If the workspace operator enables Workers AI, the cloud service sends generic event descriptions to Cloudflare to prioritize observations. This feature keeps raw logs, device addresses, hostnames, and evidence IDs out of the model input.

## Windows posture

While posture checks are enabled in the visible local dashboard, NORTH reads selected Windows settings and saves the timestamp and outcome of each check in the desktop user data folder. The latest snapshot supports comparison on the next check. Defender exclusion paths and local account details are omitted from this posture snapshot.
