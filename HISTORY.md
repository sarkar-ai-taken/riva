# Release History

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
