<p align="center">
  <h1 align="center">⚡ Vibe Iterator</h1>
  <p align="center"><em>It goes deep into your app so hackers don't have to.</em></p>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/security-runtime%20testing-ff0040.svg?style=for-the-badge" alt="Runtime Security Testing"></a>
  <a href="#"><img src="https://img.shields.io/badge/made%20for-vibe%20coders-00ff41.svg?style=for-the-badge" alt="Made for Vibe Coders"></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-00d4ff.svg?style=for-the-badge" alt="MIT License"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.11+-b347d9.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="#"><img src="https://img.shields.io/badge/supabase-first-3ECF8E.svg?style=for-the-badge&logo=supabase&logoColor=white" alt="Supabase First"></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/PRs-welcome-00ff41.svg?style=flat-square" alt="PRs Welcome"></a>
  <a href="#"><img src="https://img.shields.io/badge/vibe%20coded-and%20secured-ff0040.svg?style=flat-square" alt="Vibe Coded and Secured"></a>
  <a href="#"><img src="https://img.shields.io/badge/goes-deep-ffb000.svg?style=flat-square" alt="Goes Deep"></a>
</p>

```

 ██╗   ██╗██╗██████╗ ███████╗  ██╗████████╗███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗
 ██║   ██║██║██╔══██╗██╔════╝  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
 ██║   ██║██║██████╔╝█████╗    ██║   ██║   █████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝    ██║   ██║   ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
  ╚████╔╝ ██║██████╔╝███████╗  ██║   ██║   ███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
   ╚═══╝  ╚═╝╚═════╝ ╚══════╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

                    )))  ⚡  Runtime Security Testing  ⚡  (((

                              ~ it goes deep ~

```

---

## What is Vibe Iterator?

You built your app with AI. Cool. But did the AI remember to:

- ✅ Validate your Supabase RLS policies?
- ✅ Stop users from changing their subscription tier in localStorage?
- ✅ Keep your JWT tokens out of the browser console?
- ✅ Block SQL injection in your PostgREST filters?
- ✅ Actually enforce upload limits server-side?

Probably not. That's where Vibe Iterator comes in.

**Vibe Iterator is a runtime security testing tool** that launches your app in a real browser, logs in as a test user, pokes around, tampers with things, and **proves** whether your vulnerabilities are actually exploitable — not just theoretically possible.

It then gives you a **copy-paste prompt** you can feed right back to your AI coding assistant to fix every issue it finds.

> 🔍 **Static scanners** read your code and say _"this pattern looks risky."_
>
> ⚡ **Vibe Iterator** runs your app and says _"I just bypassed your subscription tier. Here's the proof."_

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   You run:  vibe-iterator                               │
│                                                         │
│   ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│   │  Dashboard   │◄──│  Scan Engine  │──►│  Selenium  │  │
│   │ localhost:   │    │  + Listeners  │    │  + CDP     │  │
│   │   3001       │    │              │    │           │  │
│   └──────┬───────┘    └──────┬───────┘    └─────┬─────┘  │
│          │                   │                  │        │
│     Live scan            Findings           Launches    │
│     progress            + Evidence          your app    │
│     via WebSocket        + LLM Prompts      & tampers   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

1. **You configure** — Point it at your app with a `.env` file (target URL, test credentials)
2. **You choose a stage** — Dev (quick), Pre-Deploy (full), or Post-Deploy (production)
3. **It launches your app** — Selenium opens a real browser, logs in, crawls your pages
4. **It attacks your app** — Tampers with tokens, spoofs tiers, injects SQL, checks what leaks in devtools
5. **It streams results live** — Watch the hacker-themed dashboard as findings roll in
6. **It tells you how to fix it** — Every finding includes a copy-paste prompt for your AI assistant

---

## Quick Start

```bash
# Install
pip install vibe-iterator

# Create your config
cp .env.example .env
# Edit .env with your test account credentials and target URL

# Launch the dashboard
vibe-iterator
```

Your browser opens to `http://localhost:3001` — select a scan stage, hit **START SCAN**, and watch it work.

**Prefer the CLI?**

```bash
vibe-iterator scan --headless --stage pre-deploy
```

---

## The Dashboard

Vibe Iterator ships with a **hacker-themed control center** on `localhost:3001` — because security testing should look as cool as it is.

### 🏠 Home — Pick Your Stage

Select **DEV**, **PRE-DEPLOY**, or **POST-DEPLOY**. Each stage runs a different set of scanners tuned for that phase of your project.

### 📡 Live Scan — Watch It Happen

Split-panel view: a live terminal feed on the left streaming every action in real time, and findings cards appearing on the right as vulnerabilities are discovered.

### 📊 Results — Explore & Fix

Security score, severity breakdown, findings grouped by category. Every finding expands to show evidence, a plain-English explanation, and a **COPY FIX PROMPT** button that copies a ready-to-paste prompt for your AI assistant.

### 📄 Export — Share the Report

One click exports a self-contained HTML report file — same data, same aesthetic, no server needed. Share it with your team or keep it for your records.

---

## What It Catches

### 🔐 Authentication — Extensive

| Check | What It Proves |
|-------|---------------|
| JWT tampering | Modified token claims (`sub`, `role`, `exp`) accepted by server |
| `alg:none` bypass | Server accepts unsigned JWTs |
| Token storage | JWTs in localStorage instead of httpOnly cookies |
| Session fixation | Session ID doesn't change after login |
| Brute force | No rate limiting on login endpoint |
| Username enumeration | Different error messages for "user not found" vs "wrong password" |
| Logout invalidation | Old tokens still work after logout |
| Auth bypass | Protected routes accessible without authentication |
| OAuth state param | Missing CSRF protection on OAuth flows |
| Re-auth for sensitive ops | Password/email change without current password |

### 💉 SQL Injection — Extensive

| Check | What It Proves |
|-------|---------------|
| PostgREST filter injection | Malicious values in `.eq()`, `.or()`, `.like()` params accepted |
| RPC function injection | SQL payloads in Supabase `rpc()` arguments executed |
| `?select=` manipulation | Unauthorized columns/tables accessible via query string |
| Error-based injection | SQL errors leak database structure |
| Blind boolean injection | Different responses for `AND 1=1` vs `AND 1=2` conditions |
| Time-based injection | `pg_sleep()` payloads cause measurable response delays |
| ORM bypass | Prisma `$queryRawUnsafe`, Knex `.whereRaw()`, Sequelize `.literal()` exploitable |
| Input vector discovery | Every form, URL param, JSON field, header, and cookie tested |
| Schema leakage | Error responses reveal table names, columns, or DB version |

### 🛡️ Access Control

| Check | What It Proves |
|-------|---------------|
| RLS bypass | Supabase row-level security policies don't actually block unauthorized queries |
| Tier escalation | Subscription level modified client-side and server accepted it |
| Bucket limits | File uploads exceed plan limits without server rejection |
| Client tampering | Roles, permissions, or feature flags in localStorage trusted by server |
| IDOR | User A can access User B's data by swapping IDs |

### 🔍 Data Leakage

| Check | What It Proves |
|-------|---------------|
| Token exposure | JWTs visible in URL params, network responses, or console output |
| Key leakage | Supabase service keys or API secrets in client-visible responses |
| PII over-exposure | API responses returning more user data than the UI displays |
| UUID exposure | Internal IDs visible in devtools that shouldn't be client-accessible |
| Console logging | Sensitive data printed to browser console |

### 🌐 Web Security

| Check | What It Proves |
|-------|---------------|
| XSS (reflected/stored/DOM) | Script injection payloads execute in the browser |
| CORS misconfiguration | Wildcard origins or credentials with `*` allowed |
| API exposure | Protected endpoints accessible without auth |
| Mass assignment | API accepts fields it shouldn't (role escalation via extra JSON fields) |
| Missing security headers | No CSP, no `X-Frame-Options`, no `Strict-Transport-Security` |

---

## Scan Stages

| Stage | Scanners | When to Use |
|-------|----------|-------------|
| **🔧 DEV** | `data_leakage` · `auth_check` · `client_tampering` | During development — quick feedback loop |
| **🚀 PRE-DEPLOY** | `data_leakage` · `auth_check` · `client_tampering` · `rls_bypass` · `tier_escalation` · `bucket_limits` · `sql_injection` · `xss_check` · `api_exposure` | Before going live — full audit |
| **🌍 POST-DEPLOY** | `cors_check` · `data_leakage` · `auth_check` · `api_exposure` · `bucket_limits` · `sql_injection` | Against production — external attack surface |

---

## Configuration

### `.env`

```bash
# Required
VIBE_ITERATOR_TEST_EMAIL=test@example.com
VIBE_ITERATOR_TEST_PASSWORD=testpassword123
VIBE_ITERATOR_TARGET=http://localhost:3000

# Optional
VIBE_ITERATOR_PORT=3001
VIBE_ITERATOR_SUPABASE_URL=https://xxx.supabase.co
VIBE_ITERATOR_SUPABASE_ANON_KEY=eyJ...

# Optional: second account for cross-user testing (IDOR, RLS)
VIBE_ITERATOR_TEST_EMAIL_2=test2@example.com
VIBE_ITERATOR_TEST_PASSWORD_2=testpassword456
```

### `vibe-iterator.config.yaml`

```yaml
target: ${VIBE_ITERATOR_TARGET}

pages:
  - /
  - /login
  - /dashboard
  - /profile
  - /settings
  - /upload

stages:
  dev:
    scanners: [data_leakage, auth_check, client_tampering]
  pre-deploy:
    scanners: [data_leakage, auth_check, client_tampering, rls_bypass, tier_escalation, bucket_limits, sql_injection, xss_check, api_exposure]
  post-deploy:
    scanners: [cors_check, data_leakage, auth_check, api_exposure, bucket_limits, sql_injection]

stack:
  backend: supabase    # supabase | firebase | custom
  auth: supabase-auth
  storage: supabase
```

---

## The Fix Prompt

Every finding includes a ready-to-paste prompt for your AI assistant. Example:

```
I found a security vulnerability in my Supabase app.

VULNERABILITY: Subscription tier escalation — the server accepted a
client-modified subscription tier without server-side validation.

EVIDENCE:
- Original tier in localStorage: "free"
- Modified tier to: "premium"
- Attempted premium-only action: upload file > 10MB
- Server response: 200 OK (should have been 403)

MY STACK: Supabase, Next.js, PostgreSQL

FIX THIS: Ensure the subscription tier is always validated server-side
by checking the user's actual tier in the database before allowing
tier-gated actions. Never trust client-side tier values. Show me the
code changes needed.
```

Just paste it into Claude, ChatGPT, Copilot, or whatever AI you used to build the app. It has everything the AI needs to fix the issue.

---

## How It's Different

| | Static Scanners | **Vibe Iterator** |
|---|---|---|
| **Method** | Reads your source code | Runs your app in a real browser |
| **Proof** | "This pattern looks risky" | "I just exploited it — here's the HTTP proof" |
| **Supabase** | Checks RLS syntax | Actually queries through RLS and proves bypass |
| **Auth** | Flags `jwt.decode()` calls | Sends tampered JWTs and proves the server accepts them |
| **Output** | Code annotations | Live dashboard + exportable report + LLM fix prompts |
| **Audience** | Security engineers | Anyone who built an app with AI |

**Pairs perfectly with [raroque/vibe-security-skill](https://github.com/raroque/vibe-security-skill)** — Raroque's skill scans your code for risky patterns. Vibe Iterator proves which of those patterns are actually exploitable at runtime. Static + runtime = full coverage.

---

## Tech Stack

- **Python 3.11+** — scan engine and CLI
- **Selenium 4 + Chrome DevTools Protocol** — browser automation and network/console/storage inspection
- **FastAPI + WebSockets** — live dashboard server
- **Vanilla HTML/CSS/JS** — hacker-themed dashboard (no Node.js, no build step)
- **Jinja2** — exportable HTML report generation
- **Click** — CLI interface

**Install requirement:** `pip install vibe-iterator` — that's it. No npm. No Docker. No build step.

---

## 🔒 Privacy & Security

**Vibe Iterator runs 100% on your machine. Nothing leaves localhost.**

- **No cloud services** — the entire tool runs locally. No external APIs, no telemetry, no analytics, no phone-home
- **No data transmission** — your `.env` credentials, scan results, findings, and evidence never leave your computer
- **Dashboard is local-only** — the GUI on `localhost:3001` binds to `127.0.0.1`, not `0.0.0.0`. It's not accessible from your network
- **No accounts required** — you don't sign up for anything. There's no Vibe Iterator account, no API key, no license server
- **Your `.env` stays private** — the `.env` file is in `.gitignore` by default. The `.env.example` ships with placeholder values, never real credentials
- **Exported reports may contain sensitive data** — the HTML report includes raw evidence (request/response pairs, tokens, etc.). Treat it like you'd treat a security audit document — don't share it publicly

**Use dedicated test accounts.** Don't point Vibe Iterator at production with real user credentials. Create test accounts specifically for security scanning.

---

## Contributing

Contributions are very welcome! Whether it's a new scanner, a vulnerability pattern you've seen AI assistants introduce, or a dashboard improvement — open a PR.

### Adding a Scanner

1. Create `vibe_iterator/scanners/your_scanner.py`
2. Extend `BaseScanner`, implement `run()`
3. Return `Finding` objects with evidence and LLM prompts
4. Add the scanner name to the stage config

See `docs/ADDING_SCANNERS.md` for the full guide.

---

## Roadmap

- [x] Core architecture + scan engine
- [x] Supabase-focused scanners (RLS, tiers, buckets)
- [x] Extensive SQL injection scanner (PostgREST, ORM bypass, blind injection)
- [x] Extensive auth scanner (tokens, sessions, brute force, OAuth)
- [x] Live hacker-themed dashboard
- [x] Exportable HTML report with LLM prompts
- [ ] Firebase scanner module
- [ ] Automatic endpoint discovery / spidering
- [ ] CI/CD integration (GitHub Actions)
- [ ] Scanner marketplace (community-contributed scanners)
- [ ] Team reports and historical comparison

---

## Acknowledgments

- **[Chris Raroque](https://github.com/raroque)** ([@raroque](https://twitter.com/raroque)) — His [vibe-security-skill](https://github.com/raroque/vibe-security-skill) and [Supabase security video](https://youtu.be/tK4NQtzfZbM) were the direct inspiration for this project. Vibe Iterator complements his static scanning approach with runtime proof.
- **[Snyk](https://snyk.io)** — Their [article on Claude security skills](https://snyk.io/articles/top-claude-skills-cybersecurity-hacking-vulnerability-scanning/) helped shape the testing methodology.
- **[SecSkills](https://github.com/trilwu/secskills)** — The `web-app-security` and `api-security-testing` skill methodologies informed our scanner design.

---

## License

Vibe Iterator is available under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>You vibe coded it. Now make sure it's not vibrating with vulnerabilities.</strong>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/⚡-vibe--iterator-ff0040.svg?style=for-the-badge" alt="Vibe Iterator"></a>
</p>
