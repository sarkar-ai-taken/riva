# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Riva, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@sarkar-ai.com**

Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Model

Riva is a **local-first** observability tool:

- Runs entirely on your machine — no cloud, no telemetry
- Does not execute agent actions — read-only observation
- Web dashboard binds to `127.0.0.1` by default
- Non-localhost binding triggers a visible warning
- Optional bearer token authentication for the web API
- Security headers applied to all HTTP responses
- `riva audit` command checks for common misconfigurations

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |
