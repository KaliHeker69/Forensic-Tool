When the entire `C:\Windows\Prefetch\` folder is uploaded, every `.pf` file is parsed in batch and all run timestamps — up to 8 per file — are flattened into a single unified event stream. The timeline is built from that stream. Here is what it looks like and how it functions:## How the data pipeline works

When the folder is dropped in, every `.pf` file is parsed concurrently using Tokio tasks. Each file contributes up to 8 timestamps to the event stream — meaning a file with `run_count = 4` contributes 4 separate dots, not one. The timestamps are sorted globally into a unified `Vec<ExecutionEvent>` ordered by time. The span of the earliest to latest timestamp defines the visible window. If the folder covers multiple days, the UI defaults to showing the most recent 24-hour window with a date picker to navigate backwards.

## The five swim lanes

The timeline is divided into vertical swim lanes, assigned automatically by the suspicious indicator engine's category output:

`Credential access` — any binary that triggered a T1003.x rule lands here. `Execution` — LOLBins, scripting hosts (PowerShell, WScript, cmd), and staged executables. `Reconnaissance` — port scanners, AD enumeration tools, ShareFinder variants. `Network / tunnel` — proxying, tunneling, exfil tools. `System / normal` — everything else that passed clean. The lane assignment uses the highest-severity finding's category. A clean lane is intentional — it gives the analyst spatial context so they can see a credential dump surrounded by clean system activity, which makes the timing anomaly obvious.

## The execution burst detector

When 3 or more flagged events occur within a configurable window (default: 5 minutes), the timeline draws an amber band across all lanes for that time range and labels it. This is implemented in Rust before the data even reaches the frontend — the burst detection runs over the sorted event list with a sliding window, and any window exceeding the threshold is serialised into a `Burst` struct alongside the events. In the demo above, the three consecutive `MIMIKATZ.EXE` executions between 02:19 and 02:23 form a burst. Bursts are the most forensically important thing the timeline surfaces — they show coordinated attack phases that individual file analysis cannot reveal.

## Dot encoding

Every dot encodes two things simultaneously. Shape: round dots are clean or low-signal events; diamonds (squares rotated 45°) are flagged events. This means at a glance you can spot flagged events even when zoomed out and the colour is too small to read. Size: flagged dots are rendered at 10px, clean at 8px — another redundant encoding that aids pre-attentive scanning. Colour encodes severity: red = critical, amber = high, blue = medium, grey = clean.

## The zoom control

The zoom slider does not simply magnify the canvas — it changes the time resolution of the axis ticks and redistributes events proportionally. At 1x the axis shows 7 ticks spanning the full window. At 5x it shows 35 ticks, compressing the time span to roughly 1 hour per full width. This allows an analyst to start broad (where are the clusters?) then zoom into a specific incident window to see the precise second-by-second execution order during a burst.

## The filter controls

`Flagged only` hides all clean events — the lanes collapse to show only suspicious executions, which is the primary mode during active triage. The name search filter does a case-insensitive substring match on the executable name field and updates the event count stats live. The `System` and `User-space` filters split by whether the binary lives under `\Windows\` or outside it — a fast way to isolate attacker-introduced executables from OS noise.

## The detail panel

Clicking any dot populates the panel below the timeline with the full parsed data for that prefetch file: executable name, last run timestamp, run count, lane classification, and the full findings list with ATT&CK technique IDs. For a clean event it shows a single "no indicators" message. The panel also renders an "Explain findings" button that feeds the specific technique IDs and binary name into the next conversation turn.

## What the Rust backend serialises for the frontend

The backend produces a single `TimelinePayload` JSON struct after batch parsing. It contains a flat `events` array (each event has name, timestamp as Unix ms, lane, severity, findings, run\_count, and file\_refs), a `bursts` array (start\_ms, end\_ms, label), and a `summary` object with total event count, flagged count, unique binary count, and time span. The frontend is entirely data-driven off this payload — no parsing logic lives in JavaScript.