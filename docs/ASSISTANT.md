# NORTH Assistant

Open the built-in panel with **Ctrl+J** or find **NORTH Assistant** in **Ctrl+K**. It uses data already loaded in the active workspace. If evidence is unavailable, open the corresponding NORTH page to load its data, then ask again. Clear the panel history using **Clear history**. History is kept in memory for the current workspace session.

## Add an intent

1. Add a stable ID, example phrasings, and keywords in [assistantEngine.ts](../frontend/src/assistantEngine.ts).
2. Choose an existing read-only data area or use the guide path for static help. Use named evidence fields for filtering and keep client data structures bounded.
3. Write the answer template and follow-ups. If it describes an observation, return the existing row ID so users can open the exact evidence. If the data is absent, say what couldn't be established.
4. Add realistic variants and an expected answer with citation IDs to [the golden snapshot tests](../desktop/assistant-golden.json) and [matcher tests](../desktop/assistant-engine.test.cjs). Include an ambiguous or unsupported example if the new intent overlaps an existing one.
5. Run `node --test desktop/assistant-engine.test.cjs desktop/input-properties.test.cjs` from the repository root, then run `npm.cmd --prefix desktop run build:ui`.

The panel should keep observed names as escaped text. An intent must not run commands, read files, make requests, modify data, or turn telemetry into links. Citation buttons use NORTH's existing record navigation.
