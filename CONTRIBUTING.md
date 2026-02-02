# Contributing to Riva

Thank you for your interest in contributing to Riva! This document provides guidelines and information for contributors.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the work, not the person
- Help others learn and grow

## Reporting Bugs

When reporting bugs, please include:

1. **Description** of the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs **actual behavior**
4. **Environment details**: OS, Python version, Riva version
5. **Relevant logs** or error messages

## Suggesting Features

1. Describe the **problem** you're trying to solve
2. Propose your **solution**
3. Consider **alternatives** you've explored
4. Note any **breaking changes** that might be needed

## Development Workflow

### Setup

```bash
git clone https://github.com/sarkar-ai/riva.git
cd riva
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

### Making Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write your code and tests
4. Run the test suite: `pytest`
5. Run the linter: `ruff check src/ tests/`
6. Commit using conventional commit messages
7. Push your branch and create a Pull Request

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=riva --cov-report=term-missing

# Run a specific test file
pytest tests/test_cli.py

# Run a specific test
pytest tests/test_cli.py::TestAuditCommand::test_audit_json_output
```

### Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) conventions
- Use [ruff](https://docs.astral.sh/ruff/) for linting and formatting
- Use type hints for function signatures
- Keep functions focused and small
- Write docstrings for public modules, classes, and functions

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `refactor:` Code refactoring (no behavior change)
- `test:` Adding or updating tests
- `chore:` Maintenance tasks (CI, dependencies, etc.)

Examples:

```
feat: add security audit command
fix: handle missing config directory in detector
docs: update installation instructions
test: add tests for auth token middleware
```

## Pull Request Guidelines

- **One feature or fix per PR** — keep PRs focused
- **Update tests** for any behavior changes
- **Update documentation** if applicable
- **Follow existing patterns** in the codebase
- **Describe what and why** in the PR description

## Project Structure

```
src/riva/
├── agents/          # Agent detection and parsing
│   ├── base.py      # AgentInstance, AgentStatus, BaseDetector
│   ├── registry.py  # Agent registry
│   ├── claude_code.py
│   ├── codex_cli.py
│   ├── gemini_cli.py
│   └── openclaw.py
├── core/            # Core logic
│   ├── audit.py     # Security audit checks
│   ├── env_scanner.py
│   ├── monitor.py   # Resource monitoring
│   ├── scanner.py   # Process scanning
│   └── usage_stats.py
├── tui/             # Terminal UI (Rich)
│   ├── components.py
│   └── dashboard.py
├── web/             # Flask web dashboard
│   ├── server.py
│   └── daemon.py
├── utils/           # Shared utilities
│   ├── formatting.py
│   └── jsonl.py
└── cli.py           # Click CLI entry points
```

### Where to put new code

- **New agent detector** → `src/riva/agents/` and register in `registry.py`
- **New CLI command** → `src/riva/cli.py`
- **New core feature** → `src/riva/core/`
- **Web dashboard changes** → `src/riva/web/`
- **TUI changes** → `src/riva/tui/`
- **Shared helpers** → `src/riva/utils/`

## Questions?

Open a [GitHub Discussion](https://github.com/sarkar-ai/riva/discussions) or file an issue.
