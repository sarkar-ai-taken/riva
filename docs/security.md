# Security Audit Results

**Summary: 11 Passed · 3 Warnings · 8 Failed**

---

## ✅ Passed

| Check | What it means |
|---|---|
| **API Key Exposure** | No API keys or secrets found in environment variables. |
| **Config Permissions (OpenClaw)** | `~/.openclaw` has mode `0o700` — only you can read it. Correctly locked down. |
| **Plugin Directory** | `~/.config/riva/plugins/` doesn't exist — no plugin attack surface. |
| **MCP Configuration** | No `http://` MCP endpoints found — all HTTPS or local. |
| **Orphan Processes** | No agent child processes running without a live parent. |
| **Running as Root** | No AI agents running as UID 0. |
| **Binary Permissions** | Agent binaries are not group/world-writable. |
| **MCP Stdio Commands** | No MCP server is using a raw shell (`bash`, `sh`, `cmd`) as its stdio command. |
| **Unencrypted Connections** | All connections to known API domains use port 443 (TLS). |
| **Excessive Connections** | No agent exceeds the 50-connection threshold. |
| **Stale Sessions** | No connections in `CLOSE_WAIT`/`TIME_WAIT` state. |

---

## ⚠️ Warnings

### Dashboard Status · medium · network

The Riva web dashboard is actively running (PID 34278). It's probably bound to `127.0.0.1` — but verify it's not exposed to a non-localhost address without authentication. If you ran `riva web start` intentionally, this is expected.

### Suspicious Launcher (Codex CLI) · low · processes

Codex CLI (PID 38957) has an unknown launch type. Riva couldn't identify how it was started. This usually means it was launched by an unusual parent process (script, IDE plugin, or nested shell). Low severity — worth knowing.

### Unknown Destinations (Claude Code) · medium · network

Claude Code has 4 active connections to unrecognized hosts:

- `2607:6bc0::10:443` — IPv6, likely Anthropic CDN
- `160.79.104.10:443` — unknown
- `sea15s11-in-x1b.1e100.net:443` — Google infrastructure (`.1e100.net` is Google)
- `137.66.149.34.bc.googleusercontent.com:443` — Google Cloud

The Google connections are suspicious for Claude Code — it shouldn't be talking to Google for a coding task. This could be a CDN/analytics call from a VS Code extension sharing the same process label. Worth investigating.

---

## ❌ Failed

### Config Permissions — Claude Code, Codex CLI, Gemini CLI, Cursor, GitHub Copilot · high · permissions

Five config directories have mode `0o755` — any other local user can read them. These directories contain API keys, session data, and settings.

```bash
chmod 700 ~/.claude ~/.codex ~/.gemini ~/.cursor ~/.vscode
```

### Config File Permissions (Claude Code) · high · permissions

`~/.claude/settings.json` has mode `0o644` — world-readable. This file may contain MCP server configs, auth tokens, and custom permissions.

```bash
chmod 600 ~/.claude/settings.json
```

### Config File Permissions (VSCode / GitHub Copilot) · high · permissions

`~/.vscode/extensions/github.copilot-chat-0.38.2/package.json` has mode `0o644`. Less critical (package manifest, not secrets), but follows the same over-permissioned pattern.

```bash
chmod 600 ~/.vscode/extensions/github.copilot-chat-0.38.2/package.json
```

### Exposed Token (VSCode Extension / GitHub Copilot) · **critical** · credentials

Riva found a plaintext token matching the `sk-...` pattern inside:

```
~/.vscode/extensions/github.copilot-chat-0.38.2/package.json
```

**What to do:**

1. Open the file and locate the `sk-...` string
2. If it's a real key — **rotate it immediately** in your GitHub or OpenAI account settings
3. If it's a placeholder value embedded in the extension source, mark it as a false positive

---

## Priority Order

1. 🔴 **Rotate the `sk-...` token** — Exposed Token (critical)
2. 🔴 **`chmod 700`** on all 5 config directories
3. 🔴 **`chmod 600`** on `settings.json`
4. 🟡 **Investigate Google connections** from Claude Code
5. 🟡 **Check Codex CLI launch origin** if you didn't start it directly
