# Release History

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
