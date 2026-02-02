# Riva

Observe, monitor, and control local AI agents running on your machine.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge" alt="License"></a>
  <a href="https://pypi.org/project/riva-agent/"><img src="https://img.shields.io/pypi/v/riva-agent.svg?style=for-the-badge" alt="PyPI"></a>
  <a href="#requirements"><img src="https://img.shields.io/badge/python-%3E%3D3.11-green.svg?style=for-the-badge" alt="Python"></a>
  <a href="#requirements"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20WSL2-lightgrey.svg?style=for-the-badge" alt="Platform"></a>
</p>

Riva is a **local-first observability and control plane for AI agents**.
It helps you understand what agents are running on your machine, what they are doing, and how they are behaving in real time.

As agent frameworks push toward autonomy, visibility often disappears.
Riva exists to restore **clarity, safety, and trust**.

[Getting Started](#quick-start) · [How it works](#how-it-works) · [CLI Reference](#cli-reference) · [Web Dashboard](#web-dashboard) · [Security](#security) · [Contributing](#contributing)

---

## Demo

| Agent Overview | Resource Monitoring |
|:---:|:---:|
| _coming soon_ | _coming soon_ |

---

## How it works

```
Local Agents (Claude Code / Codex CLI / Gemini CLI / LangGraph / CrewAI / AutoGen / ...)
                 |
                 v
        +------------------+
        |       Riva       |    discovery, metrics, logs, lifecycle
        |  (observability) |
        +--------+---------+
                 |
        +--------+---------+
        |        |         |
      CLI      TUI    Web Dashboard
```

Riva runs entirely on your machine.
It **observes agent behavior** but does not execute agent actions.

---

## Highlights

- **Agent discovery** — detect locally running agents across 7 frameworks and growing
- **Lifecycle visibility** — see when agents start, stop, crash, or hang
- **Resource tracking** — CPU, memory, and uptime per agent in real time
- **Token usage stats** — track token consumption, model usage, and tool call frequency
- **Environment scanning** — detect exposed API keys in environment variables
- **Security audit** — `riva audit` checks for config permission issues, exposed secrets, and dashboard misconfiguration
- **Web dashboard** — Flask-based dashboard with REST API, security headers, and optional auth token
- **Framework-agnostic** — works across multiple agent frameworks and custom agents
- **Local-first** — no cloud, no telemetry, no hidden data flows

---

## Supported Frameworks

Riva ships with built-in detectors for these agent frameworks:

| Framework | Binary / Process | Config Dir | API Domain |
|-----------|-----------------|------------|------------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `claude` | `~/.claude` | api.anthropic.com |
| [Codex CLI](https://github.com/openai/codex) | `codex` | `~/.codex` | api.openai.com |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `gemini` | `~/.gemini` | generativelanguage.googleapis.com |
| [OpenClaw](https://github.com/openclaw) | `openclaw`, `clawdbot` | `~/.openclaw` | varies |
| [LangGraph](https://langchain-ai.github.io/langgraph/) | `langgraph` / Python | `~/.langgraph` | api.smith.langchain.com |
| [CrewAI](https://www.crewai.com/) | `crewai` / Python | `~/.crewai` | app.crewai.com |
| [AutoGen](https://microsoft.github.io/autogen/) | `autogen` / Python | `~/.autogen` | varies |

Python-based frameworks (LangGraph, CrewAI, AutoGen) are detected by matching `python` processes whose command line references the framework.

**Adding more frameworks** — Riva is extensible via:
1. Built-in detectors in `src/riva/agents/`
2. Third-party pip packages using `[project.entry-points."riva.agents"]`
3. Plugin scripts dropped into `~/.config/riva/plugins/`

---

## What Riva Is Not

Riva is intentionally not:
- An AI agent
- An orchestration framework
- A cloud monitoring service
- A replacement for agent runtimes

Riva does not make decisions.
It makes **agent behavior visible**.

---

## Requirements

- **macOS** (Ventura, Sonoma, Sequoia) or **Linux**
- Windows via **WSL2**
- Python 3.11+

---

## Quick Start

### Install from PyPI

```bash
pip install riva-agent
```

### Install via bash script

```bash
curl -fsSL https://raw.githubusercontent.com/sarkar-ai/riva/main/install.sh | bash
```

### Install from source

```bash
git clone https://github.com/sarkar-ai/riva.git
cd riva
pip install -e ".[test]"
```

### Verify

```bash
riva --help
```

---

## CLI Reference

### `riva scan`

One-shot scan for running AI agents.

```bash
riva scan              # Rich table output
riva scan --json       # JSON output
```

### `riva watch`

Launch the live TUI dashboard with real-time resource monitoring.

```bash
riva watch
```

### `riva stats`

Show token usage and tool execution statistics.

```bash
riva stats                        # All agents
riva stats --agent "Claude"       # Filter by name
riva stats --json                 # JSON output
```

### `riva list`

Show all known agent types and their install status.

```bash
riva list
```

### `riva config`

Show parsed configurations for detected agents.

```bash
riva config
```

### `riva audit`

Run a security audit and print a report.

```bash
riva audit             # Rich table with PASS/WARN/FAIL
riva audit --json      # JSON output
```

Checks performed:
- API key exposure in environment variables
- Config directory permissions (group/other-readable)
- Web dashboard status and bind address
- Plugin directory existence and permissions

---

## Web Dashboard

### Start / Stop

```bash
riva web start                  # Background daemon
riva web start -f               # Foreground
riva web start --auth-token MY_SECRET   # With API auth
riva web stop                   # Stop daemon
riva web status                 # Check status
riva web logs                   # View logs
riva web logs -f                # Follow logs
```

### Custom host and port

```bash
riva web --host 0.0.0.0 --port 9090 start
```

A warning is printed when binding to a non-localhost address.

### API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard |
| `GET /api/agents` | Running agents (fast poll) |
| `GET /api/agents/history` | CPU/memory history |
| `GET /api/stats` | Token usage stats (cached 30s) |
| `GET /api/env` | Environment variables |
| `GET /api/registry` | Known agent types |
| `GET /api/config` | Agent configurations |

### Authentication

When started with `--auth-token`, all `/api/*` routes require a `Authorization: Bearer <token>` header. The index page (`/`) remains accessible without authentication.

```bash
# Start with auth
riva web start --auth-token secret123

# Access API
curl -H "Authorization: Bearer secret123" http://127.0.0.1:8585/api/agents
```

### Security headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self' 'unsafe-inline'`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## Security

- Runs locally — no network exposure by default
- Web dashboard binds to `127.0.0.1` by default
- Non-localhost binding triggers a visible warning
- Optional bearer token auth for the web API
- Security headers on all HTTP responses
- `riva audit` checks for common misconfigurations
- No agent execution privileges — read-only observation

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## Architecture

```
src/riva/
├── agents/              # Agent detection and parsing
│   ├── base.py          # AgentInstance, AgentStatus, BaseDetector
│   ├── registry.py      # Agent registry
│   ├── claude_code.py   # Claude Code detector
│   ├── codex_cli.py     # Codex CLI detector
│   ├── gemini_cli.py    # Gemini CLI detector
│   ├── openclaw.py      # OpenClaw detector
│   ├── langgraph.py     # LangGraph / LangChain detector
│   ├── crewai.py        # CrewAI detector
│   └── autogen.py       # AutoGen detector
├── core/                # Core logic
│   ├── audit.py         # Security audit checks
│   ├── env_scanner.py   # Environment variable scanning
│   ├── monitor.py       # Resource monitoring (CPU, memory)
│   ├── scanner.py       # Process scanning
│   └── usage_stats.py   # Token/tool usage parsing
├── tui/                 # Terminal UI (Rich)
│   ├── components.py    # Rich table builders
│   └── dashboard.py     # Live dashboard
├── web/                 # Flask web dashboard
│   ├── server.py        # Flask app, REST API, security middleware
│   └── daemon.py        # Background daemon management
├── utils/               # Shared utilities
│   ├── formatting.py    # Display formatting helpers
│   └── jsonl.py         # JSONL file parsing
└── cli.py               # Click CLI entry points
```

Riva is modular by design.
New agent detectors can be added without changing the core.

---

## Development

### Setup

```bash
git clone https://github.com/sarkar-ai/riva.git
cd riva
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

### Running tests

```bash
pytest                                    # All tests
pytest --cov=riva --cov-report=term-missing  # With coverage
pytest tests/test_cli.py                  # Specific file
```

### Linting

```bash
pip install ruff
ruff check src/ tests/
ruff format --check src/ tests/
```

### Type checking

```bash
pip install mypy types-psutil
mypy src/riva/ --ignore-missing-imports --no-strict
```

---

## Release Process

1. Update version in `pyproject.toml`
2. Update `HISTORY.md` with changes
3. Run full test suite: `pytest --cov=riva`
4. Build the package: `python -m build`
5. Verify: `twine check dist/*`
6. Create a git tag: `git tag v0.x.x`
7. Push with tags: `git push --tags`
8. Create a GitHub Release — this triggers automatic PyPI publishing

### Manual publish (if needed)

```bash
python -m build
twine upload dist/*
```

---

## Uninstall

```bash
pip uninstall riva-agent
```

Or use the uninstall script:

```bash
curl -fsSL https://raw.githubusercontent.com/sarkar-ai/riva/main/uninstall.sh | bash
```

---

## Early Stage Project

Riva is early-stage and evolving rapidly.

Expect:
- Rapid iteration
- API changes
- Active design discussions

Feedback is highly encouraged.

---

## Philosophy

If you cannot see what an agent is doing, you cannot trust it.

Riva exists to make local AI agents **inspectable, understandable, and safe**.

---

## Contributing

We welcome contributions and design discussions.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
