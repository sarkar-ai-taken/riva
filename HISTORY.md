# Release History

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
