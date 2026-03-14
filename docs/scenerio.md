The Natural Story

  Deskmate = remote execution layer (Telegram → your machine → Claude Code/Codex/etc.)
  Riva = local observability layer (what is that agent actually doing?)

  Together they tell a story nobody else can: you can hand control of your machine to an AI from your phone — and still know exactly what it did.

  ---
  Demo Scenario Ideas

  Scenario A: "The Absent Developer"

  You're away from your desk. You task your machine. You come back and know exactly what happened.

  1. Open Riva TUI (riva watch) — nothing running, clean slate
  2. Send a Telegram message via Deskmate: "Write and test a Python script that parses my project's git log"
  3. Watch Riva light up — Claude Code detected, CPU/memory tracking live
  4. Task finishes. Switch to: riva forensic summary latest → full session breakdown, tools used, decisions made
  5. Run riva audit → security clean
  6. Punchline: "Your AI worked while you were away. Here's a receipt."

  Scenario B: "The Safety Net"

  Highlights security — Deskmate has broad machine access, Riva is the watchdog.

  - Configure Riva boundary policy: deny access to ~/.ssh/**, ~/.aws/**
  - Send a task that incidentally touches a protected path
  - Riva catches the boundary violation in real-time and logs it to the tamper-evident audit trail
  - riva audit log shows the flagged event with HMAC chain intact
  - Punchline: "Give AI broad access. Keep the guardrails."

  Scenario C: "Multi-Agent Orchestration View"

  More complex, more impressive scale.

  - Deskmate runs multiple tasks (two Telegram threads, different tasks) → spins up multiple agent processes
  - Riva TUI shows both side by side with resource comparison
  - riva forensic trends shows cross-session efficiency patterns
  - Punchline: "At scale, you need a control tower."

  ---
  My Recommendation

  Scenario A is the cleanest, most relatable, and most visually compelling for a first demo. It has a clear narrative arc and uses Riva's three best features (live TUI, forensic summary,
  audit) in sequence.

  Scenario B is the best for a security/enterprise audience — adds a "wow" moment with boundary violations.

  Which audience is this demo for — investors, developers, security folks? And is this a recorded video or a live demo? That'll shape how we structure it.
