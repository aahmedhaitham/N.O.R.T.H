# NORTH stabilization defect register

## Phase A scope and counts

The five user-reported categories contain six defects. There are 0 product blockers, 4 major, 1 minor, and 1 cosmetic item. The managed Electron launch was blocked separately. No screenshots were captured. No visual matrix, keyboard sweep, or clipboard/export behavior was verified in Phase A.

| ID | Screen and steps | Expected | Actual | Severity | Screenshot |
|---|---|---|---|---|---|
| N-01 | Open Detections and load or change rules | Rules or a plain-language retry | User saw a raw empty-JSON exception | Major | None |
| N-02 | Compare Overview Windows events with Detections coverage | Both views use the same source evidence, with unchecked status explicit | User saw collecting in Overview and every technique blind with no recent check | Major | None |
| N-03 | Open Assistant, type a question and inspect the answer at a narrow width | Searchable suggestions and a panel that leaves the workspace visible | User saw an empty native dropdown, repeated actions, and an overlay | Major | None |
| N-04a | Import a rule file or use the remaining native controls | Controls match the application styles and retain accessible labels | User saw native controls | Cosmetic | None |
| N-04b | Search rules, leave Detections and return | Start with an empty rule search | User saw the previous filter | Minor | None |
| N-05 | Open the TCP view when Windows refuses the read | Plain-language access explanation and a visible next step | User reported that the guidance was insufficient | Major | None |

Fix order is N-01, N-02, N-05, N-03, N-04b, then N-04a.

## Execution evidence

- The source Electron launch using the installed npm runtime exited before a window opened. Output: `Electron exit: 2147483651`.
- `npm.cmd --prefix desktop test` reported 27 passed. `npm.cmd --prefix desktop run build:ui` passed with the existing Vite bundle-size warning.
- From backend, `.venv/Scripts/python.exe -m pytest -q -o faulthandler_timeout=15 tests` reported 112 passed and 2 subtests passed.
- `node --test cloud/worker.test.mjs cloud/geoip.test.mjs` reported 3 passed.

## Visual verification pending

A fresh interactive profile running the current source build or matching Windows build is needed. Verify onboarding, Overview, Detections, ATLAS tabs and traces, IRIS, ECHO, Settings, Assistant, collector switching, refresh, export, keyboard use, and reduced motion. Cover Simple and Analyst, light and dark, 1280x720 and 1920x1080, and synthetic, empty, and denied sources. Capture synthetic-only screenshots under docs/qa.
