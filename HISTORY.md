# Release History

## v0.3.12 (2026-03-13)

### Skills — All Agents

- **Skill discovery for all agents** — each agent now implements `parse_skills()` mapping its native concept to riva skills:
  - **Cursor** — Project Rules (`~/.cursor/rules/*.mdc`, `.cursor/rules/*.mdc`), tagged `rule`
  - **Continue.dev** — Slash Commands from `slashCommands[]` in `~/.continue/config.json`, tagged `command`
  - **Windsurf** — Global memories (`~/.codeium/windsurf/memories/*.md`) and project `.windsurfrules`, tagged `memory`/`rule`
  - **Codex CLI** — `~/.codex/instructions.md` and project `AGENTS.md`, tagged `instruction`
  - **Gemini CLI** — `~/.gemini/GEMINI.md` and project `GEMINI.md`, tagged `instruction`
  - **Cline** — `~/.clinerules` and project `.clinerules`, tagged `rule`
- **Claude Code `skills/` directory** — now also scans `.claude/skills/*/SKILL.md` (installed skills with YAML frontmatter) in addition to `.claude/commands/*.md`; reads `name` and `description` from frontmatter
- **Forensic `Skill` tool detection** — `parse_session()` now recognises `Skill` tool_use blocks in assistant turns and sets `skill_id` from `tool_input["skill"]`, so skill invocations appear in `riva skills scan` results

### CLI

- **Renamed `--mcp-help` → `--skill-help`** — more accurate name; same output (structured Markdown for AI agent consumption)
- **Removed group-level auto-ping** — background hub ping now fires only in `riva watch`, `riva scan`, and `riva ping`; not on `stats`, `forensics`, `skills`, `audit`, and other read-only commands

### Bug Fixes

- Fixed tray binary not recompiling after `pip install riva` upgrade — version sidecar file (`~/.cache/riva/tray-mac.version`) now forces recompile on any version change
- Fixed `__init__.py` version not matching `pyproject.toml` (was stuck at old version)

## v0.3.11 (2026-03-13)

### Skills System

- **New `riva skills` command group** — define, track, and share reusable agent workflows (slash commands, tool sequences)
  - `riva skills list` — table of all skills with forensic stats (uses, success rate, backtrack rate, avg tokens)
  - `riva skills scan [--all-sessions]` — parse session JSONL logs and record skill invocations to SQLite
  - `riva skills stats SKILL_ID` — detailed per-skill breakdown
  - `riva skills add NAME` — create a skill in the global registry
  - `riva skills share SKILL_ID [--to AGENT]` — mark a skill as shared across agents
  - `riva skills export FILE / riva skills import FILE` — TOML round-trip

- **TOML-based skill definitions** — `~/.riva/skills.toml` (global) and `.riva/skills.toml` (workspace)
- **Forensic linkage** — slash-command patterns (e.g. `/commit`) in session JSONL are automatically detected and linked to skill invocations; success rate, backtrack rate, and token cost are computed per skill
- **Agent skill discovery** — `parse_skills()` on each detector: Claude Code reads `~/.claude/commands/*.md`; Kiro reads `~/.kiro/hooks/` and `~/.kiro/specs/`

### Kiro Agent Support

- **New `KiroDetector`** — detects and monitors [Kiro](https://kiro.aws), AWS's AI-powered IDE
- Matches Electron-based process via binary name, exe path, and cmdline
- Parses `~/.kiro/settings.json`, `auth.json`, `mcp.json`, hooks count, and steering file count
- Discovers skills from `~/.kiro/hooks/*.md` (tagged `hook`) and `~/.kiro/specs/*.md` (tagged `spec`)

### TUI — Skills Tab

- **Tab switching in `riva watch`** — press `1`/`m` for Main, `2`/`s` for Skills
- **Skills tab** shows full skills table with forensic stats per skill; hint bar with common skill commands
- Non-blocking keypress reader via `termios`/`tty`/`select` in a background daemon thread

### Web Dashboard — Skills Tab

- **New Skills tab** in the web sidebar (star icon)
- Skills table with columns: Skill, Agent, Invocation, Uses, Success%, Backtracks, Avg Tokens, Last Used
- Success% color-coded: green ≥80%, yellow 50–80%, red <50%; shared badge; tag chips
- New `/api/skills` endpoint (30s cache) — returns all skills with forensic stats attached

### Forensics — Non-Interactive Session Fix

- **Fixed missing turns in non-interactive sessions** — `claude -p "…"`, headless scripts, and MCP tool calls store user messages as structured content blocks (`[{"type": "text", "text": "..."}]`) rather than plain strings; the parser now handles both formats so all turns, actions, and token counts appear correctly in forensics

### CLI

- **`riva --skill-help`** — prints structured Markdown describing all riva commands, options, and usage patterns so any AI agent can understand how to use riva as a tool (suitable for MCP tool descriptions or skills.md)
- **`riva --no-ping`** — skip the automatic hub ping for a single invocation
- **Auto-ping on every command** — background hub ping now fires on all `riva` subcommands (not just `scan`/`watch`); uses a daemon thread so it never delays the command; only fires if consent was previously given

## v0.3.10 (2026-03-08)

### Web Dashboard

- **Riva logo in favicon and sidebar** — replaced placeholder gradient "R" with the Riva logo mark in the browser tab and sidebar header
- **Grafana dashboard title** updated to "RIVA — AI Agent Command Center"

### CI Fixes

- Fixed ruff F401 unused `import time` in `tests/test_boundary.py` and `src/riva/tui/dashboard.py`

## v0.3.9 (2026-03-08)

### Riva Hub — Community Telemetry

- **`riva ping`** — new CLI command that auto-detects running agents, resolves city/country/lat/lon via ip-api.com, and POSTs to the Riva Hub (`sarkar.ai/api/v1/ping`); prints confirmation with agent, city, and OS
- **Opt-in consent** — one-time prompt on `riva scan` and `riva watch`; stored in `~/.config/riva/hub.toml`
- **Auto-ping** — fires silently in a background daemon thread on every scan/watch session after consent
- **Agent slug mapping** — all 13 supported agents mapped to canonical hub slugs (claude-code, opencode, openclaw, codex-cli, gemini-cli, cursor, cline, windsurf, continue-dev, github-copilot, langgraph, crewai, autogen)
- **Geo via ip-api.com** — city, country, lat, lon resolved client-side; no PII, no raw IP stored

## v0.3.8 (2026-03-07)

### Bug Fix

- **Fixed invisible tray icon** — the v0.3.7 PNG was rendered with near-zero alpha values (7–185) on solid pixels due to cairosvg anti-aliasing, making the icon invisible in the macOS menu bar. Re-rendered at 2× resolution with alpha threshold (>30 → 255, else → 0) so the shield icon now displays correctly in both light and dark menu bars.

## v0.3.7 (2026-03-07)

### Branding & Tray Icon

- **New logo** — vector SVG logo (shield + curious kid with magnifying glass) with transparent background; exports in SVG, PNG, JPEG, and ICO formats
- **macOS tray icon** — replaced placeholder `"RI"` text with a proper monochrome template icon (shield silhouette with magnifying glass cut-out); auto-inverts for dark/light menu bar via `isTemplate = true`
- **README logo** — project logo now displayed at the top of the README

## v0.3.6 (2026-02-22)

### OTel as Core Dependency

- **Moved OpenTelemetry from optional extra to core dependency** — `pip install riva` now includes `opentelemetry-api`, `opentelemetry-sdk`, and `opentelemetry-exporter-otlp-proto-http` out of the box
- No longer need `pip install riva[otel]` — OTel support works immediately after install
- Removed the `[otel]` optional-dependencies group from `pyproject.toml`

## v0.3.5 (2026-02-22)

### OTel Metrics Fix — Cumulative Temporality for Prometheus

- **Fixed counter metrics not appearing in Prometheus/Grafana** — the OTel Python SDK defaults to delta temporality for counters via OTLP, but Prometheus requires cumulative temporality; configured `OTLPMetricExporter` with explicit `preferred_temporality` for all instrument types
- **Fixed one-shot scan metric export** — `riva scan --otel` now waits for one periodic collection cycle before shutdown, ensuring observable gauge callbacks fire and counter data is flushed
- **All 4 counter metrics now export correctly**: `riva.scan.total`, `riva.agent.detected_total`, `riva.agent.stopped_total`, `riva.audit.finding_total`
- **All 8 observable gauges confirmed working**: CPU %, memory, uptime, connections, child count, tree CPU, tree memory, running count

### Grafana Dashboard

- **Bundled Grafana dashboard** (`grafana-dashboard.json`) — 12-panel monitoring dashboard for the `grafana/otel-lgtm` stack:
  - **Stat panels**: Running Agents, Total Scans, Agents Detected, Child Processes
  - **Time series**: Agent CPU %, Memory, Uptime, Network Connections, Process Tree CPU/Memory
  - **Logs panel**: Agent lifecycle events via Loki (detected/stopped with PIDs and timestamps)
  - **Traces table**: Forensic session traces via Tempo with session names and durations
- Import via Grafana UI or `curl -X POST http://localhost:3000/api/dashboards/db -d @grafana-dashboard.json`

### OTel Documentation

- Comprehensive OTel setup guide in README covering all three signals (metrics, logs, traces)
- Quick-start with `grafana/otel-lgtm` all-in-one container
- Configuration reference for `[otel]` section in `.riva/config.toml`
- Metric name mapping table (OTel → Prometheus naming convention)
- Environment variable overrides (`OTEL_EXPORTER_OTLP_ENDPOINT`, `RIVA_OTEL_ENABLED`, etc.)

## v0.3.4 (2026-02-17)

### Left Sidebar Navigation

- **Replaced horizontal tab nav** with a retractable left sidebar — vertical navigation with SVG icons for all 6 tabs (Overview, Network, Security, Usage, Config, Forensics)
- **Collapsible sidebar** — toggle between expanded (220px) and collapsed (56px icon-only) modes; state persisted to `localStorage`
- **Logo and branding** in sidebar header with gradient icon
- **Settings / profile section** at sidebar bottom — opens a slide-in settings panel

### Theme System

- **Three theme modes**: Dark (default), Light, and System (follows OS `prefers-color-scheme`)
- **Full light theme** — complete CSS variable overrides for all backgrounds, text colors, borders, shadows, and accent colors
- Theme selection via settings panel with visual picker buttons; persisted to `localStorage`
- `data-theme` attribute on `<html>` drives all theming via CSS custom properties

### Mobile Responsive

- Sidebar becomes a fixed overlay on screens below 900px with backdrop dismiss
- Nav item clicks auto-close the mobile sidebar

### Other

- Synced `__version__` in `__init__.py` with `pyproject.toml` (was stuck at 0.1.0)
- No server-side changes — all 42 `test_web.py` tests pass

## v0.3.3 (2026-02-17)

### Continuous Boundary Monitoring

- New **boundary policy engine** (`core/boundary.py`) — define allowed/denied boundaries for file access, network connections, process trees, and privilege
- **Configurable via `[boundary]` section** in `.riva/config.toml`:
  - `allowed_paths` / `denied_paths` — glob patterns for file access boundaries
  - `allowed_domains` / `denied_domains` — network connection boundaries
  - `max_child_processes` — per-agent child process limit
  - `denied_process_names` — block specific child processes (e.g. `nc`, `curl`)
  - `deny_root` — flag agents running as UID 0
  - `deny_unsandboxed` — flag agents running without container/sandbox
- **Evaluated every poll cycle** (default 2s) — violations are detected in near-real-time
- **`BOUNDARY_VIOLATION` hook event** — fire custom scripts on policy violations
- Violations logged to audit log and SQLite storage

### Tamper-Evident Compliance Audit Log

- New **append-only JSONL audit log** (`core/audit_log.py`) at `~/.config/riva/audit.jsonl`
- **HMAC-SHA256 hash chain** — each entry includes the hash of the previous entry, making unauthorized modifications detectable
- **Automatic lifecycle recording** — agent detected/stopped events are logged with timestamps and PIDs
- **Boundary violations** automatically recorded with agent name, violation type, and severity
- **`riva audit log`** — view recent audit log entries with filtering by event type and time range
- **`riva audit verify`** — verify integrity of the HMAC chain (detects tampering or corruption)
- **`riva audit export`** — export audit log for compliance:
  - `--format jsonl` — structured JSONL (default)
  - `--format cef` — Common Event Format for SIEM integration (Splunk, QRadar, ArcSight)
  - `--hours` — time range filter
  - `--output` — custom output path
- Chain resumes correctly across process restarts

### CLI

- **`riva audit` is now a command group** with `run`, `log`, `verify`, `export` subcommands
- `riva audit` (bare) still runs the security audit (backward compatible)
- 22 new boundary tests covering file, network, process, and privilege policies
- 17 new audit log tests covering append, HMAC chain, tamper detection, persistence, JSONL/CEF export

## v0.3.2 (2026-02-16)

### System Tray Daemon

- **`riva tray` is now a command group** with `start`, `stop`, `status`, and `logs` subcommands — same pattern as `riva web`
- **Background daemon mode** — `riva tray start` (default) forks the tray into a background process with PID tracking and log file at `~/.config/riva/tray.log`
- **Foreground mode** — `riva tray start -f` runs the tray in the foreground (previous default behavior)
- **`riva tray stop`** — sends SIGTERM with 5-second graceful shutdown, falls back to SIGKILL
- **`riva tray status`** — shows running state and PID
- **`riva tray logs`** — view tray logs with `--follow` (`-f`) and `--lines` (`-n`) options
- New modules: `src/riva/tray/daemon.py` (PID file management, start/stop/status), `src/riva/tray/run.py` (daemon subprocess entry point)
- 6 new tests covering daemon start, duplicate detection, stop/SIGTERM, status reporting, and edge cases

## v0.3.1 (2026-02-15)

### OpenTelemetry Exporter

- New **`riva otel`** command group for OpenTelemetry integration — push Riva's observability data to any OTel-compatible backend (Datadog, Grafana, Jaeger, etc.)
- **Optional dependency** — `pip install riva[otel]` installs `opentelemetry-api`, `opentelemetry-sdk`, and `opentelemetry-exporter-otlp-proto-http`; Riva works fully without it
- **Three signal types**:
  - **Metrics**: Observable gauges for per-agent CPU/memory/connections/uptime/child processes, counters for lifecycle events and audit findings
  - **Logs**: Audit findings and lifecycle events (agent detected/stopped) as OTel log records with severity mapping
  - **Traces**: Forensic sessions exported as span trees — session root span with turn children and action grandchildren
- **`riva otel status`** — shows SDK availability, current config, and endpoint
- **`riva otel export-sessions`** — one-shot export of forensic sessions as OTel traces
- **`riva scan --otel`** — enables OTel export for a single scan
- **Configuration** via `[otel]` section in `.riva/config.toml`, environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `RIVA_OTEL_ENABLED`), or CLI flags
- **Graceful degradation** — all OTel code is import-guarded; no errors when SDK is not installed
- **Monitor integration** — `ResourceMonitor` pushes metrics on each poll and emits lifecycle events to the OTel exporter
- New subpackage: `src/riva/otel/` with `config.py`, `metrics.py`, `logs.py`, `traces.py`, `exporter.py`
- 29 new tests covering config loading, all three exporters, graceful degradation, and workspace integration
- Workspace `riva init` template now includes a commented-out `[otel]` section

### CI

- Fixed all ruff lint/format and mypy type-check issues across the codebase

## v0.3.0 (2026-02-08)

### Session Forensics

- New **`riva forensic`** command group for deep-dive analysis of AI agent session transcripts (JSONL)
- **Session discovery** — `riva forensic sessions` lists recent sessions across all projects with slug, project, age, and file size
- **Session summary** — `riva forensic summary <slug>` shows model, duration, turns, actions, tokens, files, dead-ends, and efficiency
- **Timeline** — `riva forensic timeline <slug>` renders a chronological event-by-event trace with tool names, durations, and failure markers
- **Pattern detection** — `riva forensic patterns <slug>` identifies dead ends, search thrashing, retry loops, and write-without-read anti-patterns
- **Decision analysis** — `riva forensic decisions <slug>` extracts key decision points from thinking blocks with reasoning previews
- **File report** — `riva forensic files <slug>` lists all files modified vs read-only during a session
- **Cross-session trends** — `riva forensic trends` computes aggregate metrics (efficiency, dead-end rate, top tools) across recent sessions
- All subcommands support `--json` output
- New core module: `riva.core.forensic` — `ForensicSession`, `Turn`, `Action`, `SessionPattern` data models with full parsing pipeline

### Web Dashboard — Forensics Tab

- New **Forensics** tab in the web dashboard (6th tab alongside Overview, Network, Security, Usage, Config)
- **Trends overview** — stat cards showing total sessions, turns, tokens, average efficiency, and dead-end rate with top tools bar chart
- **Sessions table** — sortable list of all discovered sessions with slug, project, last modified time, and file size; clickable rows for drill-in
- **Session detail view** — full drill-in with:
  - Summary card (model, duration, turns, actions, tokens, efficiency bar)
  - Patterns section grouped by type with severity coloring
  - Scrollable timeline with timestamps, tool names, durations, and color-coded failure/dead-end markers
  - Files section (modified vs read-only lists)
  - Decisions accordion with thinking previews and backtrack indicators
- Back button navigation from detail view to session list
- 3 new API endpoints:
  - `GET /api/forensic/sessions` — list sessions (cached 30s)
  - `GET /api/forensic/session/<id>` — full parsed session detail
  - `GET /api/forensic/trends` — cross-session aggregate trends (cached 30s)

### TUI Dashboard — Forensic Summary Panel

- New **Forensic Sessions** panel in the live TUI dashboard (`riva watch`)
- Shows 5 most recent sessions with slug, project, and relative time ago
- Uses lightweight session discovery (file listing only) — no JSONL parsing in the live refresh loop

## v0.2.3 (2026-02-06)

### Sandbox / Container Detection

- New **sandbox detection** module (`riva.core.sandbox`) — detect whether AI agents are running inside a container, sandbox, or directly on the host
- **4-layer detection**: Linux cgroup analysis, parent process chain walking, filesystem markers (`/.dockerenv`, `/run/.containerenv`), and environment variable checks
- Supported container runtimes: **Docker**, **Podman**, **containerd**, **LXC**, **CRI-O**, **runc**
- Supported sandbox tools: **firejail**, **bubblewrap**, **nsjail**, **sandbox-exec**, **flatpak**
- Kubernetes detection via `KUBERNETES_SERVICE_HOST` environment variable
- Container ID extraction from cgroup data (Docker and Podman)

### System Tray (macOS)

- New **`riva tray`** command — launches a native macOS menu bar app ("RI" icon)
- Native Swift binary compiled on first run and cached at `~/.cache/riva/tray-mac`
- Menu actions: **Open TUI Dashboard**, **Open Web Dashboard**, **Start/Stop Web Server**, **Quick Scan**, **Security Audit**, **Quit**
- Live web server status indicator with 5-second polling
- Parent process watchdog — tray auto-exits when the parent Python process dies (no orphaned tray icons)
- IPC via stdout between Swift and Python (same architecture as [deskmate](https://github.com/sarkar-ai-taken/sarkar-local-agent))
- Requires Xcode Command Line Tools (`xcode-select --install`)

### Dashboard

- New **Sandbox** column in the agent overview table — shows "Host" (red) for unsandboxed agents, container runtime name (green) for containerized agents, or sandbox tool name (yellow)
- Agent detail cards now display sandbox status with runtime and container ID

### Tests

- 26 new sandbox detection tests covering all detection paths, cgroup parsing, parent chain detection, environment checks, and edge cases
- 24 new system tray tests covering compilation, action handling, lifecycle, and error paths

## v0.2.2 (2026-02-04)

- Bump version to 0.2.2 and add dashboard screenshots

## v0.2.1 (2026-02-02)

- Fix repository URLs to point to correct GitHub organization (`sarkar-ai-taken/riva`)

## v0.2.0 (2026-02-02)

Major release: hardened security audits, expanded agent support, CPU monitoring fix, child process tracking, and timeline replay.

### New Agent Support

- **OpenCode** — detect and monitor the [OpenCode](https://opencode.ai/) terminal AI agent (`~/.config/opencode/`)
- **Cursor** — Cursor IDE agent monitoring
- **GitHub Copilot** — VS Code extension detection
- **Windsurf** — Codeium Windsurf IDE monitoring
- **Continue.dev** — Continue AI assistant detection
- **Cline** — Claude Dev VS Code extension detection
- Total supported agents: **13** (up from 4 in v0.1.0)

### Hardened Security Audits

- **15+ automated checks** across 6 categories (credentials, permissions, processes, supply chain, network, dashboard)
- **Expanded MCP config scanning** — 7 well-known paths plus dynamic per-agent discovery of `mcp.json`/`mcp_config.json`
- **MCP stdio command safety** — flag shell commands (`bash -c`, `sh -c`), temp-dir references in MCP server configs
- **14 token patterns** — added `sk-ant-` (Anthropic), `AIza` (Google), `AKIA` (AWS), `eyJ` (JWT), `hf_` (HuggingFace), `gsk_` (Groq), `r8_` (Replicate), `aws_secret`
- **Agent-specific config scanning** — `OAI_CONFIG_LIST` (AutoGen), `config.toml` (Codex CLI), `config.ts` (Continue.dev), `langgraph.json` (LangGraph), `opencode.json` (OpenCode)
- **VS Code extension scanning** — audit Cline, GitHub Copilot, and Continue extension directories for tokens and permissions
- **Windsurf App Support** — scan `~/Library/Application Support/Windsurf/User/settings.json`
- **New check: Running as root** — flag agents running with UID 0 (critical severity)
- **New check: Binary permissions** — flag group/world-writable agent binaries
- **New check: Suspicious launcher** — flag unknown launch types and script-interpreter parents
- **New check: Config file permissions** — per-file permission hardening beyond directory-level checks

### Bug Fixes

- **Fix CPU always showing 0.0** — persist `psutil.Process` objects across poll cycles so `cpu_percent(interval=None)` has a prior baseline; affects `ProcessScanner`, `ProcessTreeCollector`, and child process monitoring

### Child Process Tracking

- New `ProcessTreeCollector` for collecting child process trees per agent
- Orphan process detection — flag child processes whose parent agent has died
- Child process persistence to SQLite storage
- Orphan resolution tracking

### Timeline Replay

- `riva replay` command for historical timeline playback
- Snapshot persistence with CPU, memory, connection count, and child process data
- Timeline summary bucketing for the web dashboard
- New `/api/agents/history` endpoint with timeline data

### Web Dashboard

- Timeline visualization in the Security tab
- Audit results display in the web UI
- Improved resource history charts

### Other

- Updated README with full security audit documentation and external evidence links (OWASP, MITRE ATT&CK, GitHub secret scanning, Invariant Labs MCP research)

## v0.1.2 (2026-02-02)

- Fix static files missing from package build

## v0.1.1 (2026-02-02)

- Fix tool name reference

## v0.1.0 (2026-02-02)

Initial release.

- Agent discovery and monitoring for Claude Code, Codex CLI, Gemini CLI, and OpenClaw
- Live TUI dashboard with real-time resource tracking (CPU, memory, uptime)
- One-shot `riva scan` with JSON output
- Token usage and tool execution statistics via `riva stats`
- Agent configuration inspection via `riva config`
- Environment variable scanning for exposed API keys
- Flask web dashboard with REST API and background daemon mode
- Security audit command (`riva audit`) with JSON output
- Web dashboard security headers (CSP, X-Frame-Options, etc.)
- Optional bearer token authentication for web API (`--auth-token`)
- Host binding warnings for non-localhost addresses
- CI pipeline with matrix testing (Python 3.11/3.12/3.13, macOS/Linux)
