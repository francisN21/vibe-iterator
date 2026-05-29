# Firebase Scanner — Plan 4: Engine Wiring, Config, Dashboard & Docs

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the five scanners into the engine, add the `firebase` stage to config, add the Firebase dashboard panel, and update docs.

**Architecture:** All changes are additive — no existing logic changes. Engine: 5 lines in `_SCANNER_MODULE_MAP`. Config: one stage block. Dashboard: one new `<section>` in `index.html`, three functions in `app.js`, CSS rules in `dashboard.css`.

**Tech Stack:** Python, YAML, HTML, JavaScript, CSS

**Prerequisite:** Plans 1–3 complete (all scanner files and tests passing).

---

## Task 1: Register scanners in `runner.py`

**Files:**
- Modify: `vibe_iterator/engine/runner.py:90-101`

- [ ] **Step 1: Write a failing import test**

```python
# tests/test_engine_firebase_registration.py
"""Confirm all five Firebase scanners are registered in _SCANNER_MODULE_MAP."""
from vibe_iterator.engine.runner import _SCANNER_MODULE_MAP

def test_firebase_scanners_registered() -> None:
    for name in ["firebase_firestore", "firebase_rtdb", "firebase_storage",
                 "firebase_auth", "firebase_functions"]:
        assert name in _SCANNER_MODULE_MAP, f"{name} not in _SCANNER_MODULE_MAP"
        assert _SCANNER_MODULE_MAP[name].startswith("vibe_iterator.scanners.")
```

- [ ] **Step 2: Run to verify failure**

```
pytest tests/test_engine_firebase_registration.py -v
```
Expected: `AssertionError` — names not yet in map.

- [ ] **Step 3: Add the five entries to `_SCANNER_MODULE_MAP`**

In `vibe_iterator/engine/runner.py`, find `_SCANNER_MODULE_MAP` (around line 90) and add after the existing `"api_exposure"` entry:

```python
    # --- Firebase ---
    "firebase_firestore": "vibe_iterator.scanners.firebase_firestore",
    "firebase_rtdb":      "vibe_iterator.scanners.firebase_rtdb",
    "firebase_storage":   "vibe_iterator.scanners.firebase_storage",
    "firebase_auth":      "vibe_iterator.scanners.firebase_auth",
    "firebase_functions": "vibe_iterator.scanners.firebase_functions",
```

- [ ] **Step 4: Run to verify pass**

```
pytest tests/test_engine_firebase_registration.py -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add vibe_iterator/engine/runner.py tests/test_engine_firebase_registration.py
git commit -m "feat: register firebase scanners in engine _SCANNER_MODULE_MAP"
```

---

## Task 2: Add `firebase` stage to config

**Files:**
- Modify: `vibe-iterator.config.yaml.example`

> There is no `vibe-iterator.config.yaml` checked into the repo (it's `.gitignored` as a user file). Only the `.example` needs updating.

- [ ] **Step 1: No test needed** — config loading from YAML is already tested. This is a documentation/example file change.

- [ ] **Step 2: Add the `firebase` stage to `.example`**

Open `vibe-iterator.config.yaml.example`. After the `all:` stage block, add:

```yaml
  firebase:
    scanners: [firebase_firestore, firebase_rtdb, firebase_storage, firebase_auth, firebase_functions]
    # "Firebase-specific security audit — run on Firebase-backed projects"
```

The full `stages:` section should now look like:

```yaml
stages:
  dev:
    scanners: [data_leakage, auth_check, client_tampering]
    # "Catch basics during development — fast feedback loop"

  pre-deploy:
    scanners: [data_leakage, auth_check, client_tampering, rls_bypass, tier_escalation, bucket_limits, sql_injection, xss_check, api_exposure]
    # "Full audit before going live"

  post-deploy:
    scanners: [cors_check, data_leakage, auth_check, api_exposure, bucket_limits, sql_injection]
    # "External-facing checks on live site"

  all:
    scanners: [data_leakage, rls_bypass, tier_escalation, bucket_limits, auth_check, client_tampering, sql_injection, cors_check, xss_check, api_exposure]
    # "Run every scanner regardless of stage"

  firebase:
    scanners: [firebase_firestore, firebase_rtdb, firebase_storage, firebase_auth, firebase_functions]
    # "Firebase-specific security audit — run on Firebase-backed projects"
```

- [ ] **Step 3: Commit**

```
git add vibe-iterator.config.yaml.example
git commit -m "feat: add firebase stage to config example"
```

---

## Task 3: Dashboard — Firebase panel markup

**Files:**
- Modify: `vibe_iterator/server/static/index.html`

- [ ] **Step 1: No test for markup** — visual verification after dashboard starts.

- [ ] **Step 2: Add the Firebase panel section**

In `vibe_iterator/server/static/index.html`, after the closing `</details>` of the `config-summary` panel (around line 77) and before `<!-- Start scan -->`, insert:

```html
  <!-- Firebase panel — shown only when backend === "firebase" -->
  <section id="firebase-panel" class="panel firebase-panel" hidden>
    <header class="firebase-panel__head">
      <span class="firebase-panel__icon">&#x26A1;</span>
      <h2>FIREBASE SECURITY SCAN</h2>
      <p class="firebase-panel__detected">
        Detected: <span id="fb-project-id">&#x2014;</span> &middot; firebaseio.com
      </p>
    </header>

    <p class="firebase-panel__label">Select services to scan:</p>

    <div class="firebase-panel__grid">
      <label><input type="checkbox" class="fb-svc" value="firebase_firestore" checked> Firestore Rules</label>
      <label><input type="checkbox" class="fb-svc" value="firebase_rtdb"      checked> Realtime Database</label>
      <label><input type="checkbox" class="fb-svc" value="firebase_storage"   checked> Storage Rules</label>
      <label><input type="checkbox" class="fb-svc" value="firebase_auth"      checked> Authentication</label>
      <label><input type="checkbox" class="fb-svc" value="firebase_functions" checked> Cloud Functions</label>
    </div>

    <div class="firebase-panel__actions">
      <button id="fb-select-all" type="button" class="btn btn--ghost">SELECT ALL</button>
      <button id="fb-scan"       type="button" class="btn btn--primary">&#x25B6; SCAN FIREBASE</button>
    </div>
  </section>
```

- [ ] **Step 3: Commit**

```
git add vibe_iterator/server/static/index.html
git commit -m "feat: add Firebase panel markup to index.html"
```

---

## Task 4: Dashboard — Firebase panel JavaScript

**Files:**
- Modify: `vibe_iterator/server/static/js/app.js`

- [ ] **Step 1: Add the four Firebase functions**

In `app.js`, find the `initHomePage` function. Locate the line:

```javascript
async function initHomePage() {
```

After loading config and calling `renderHomeConfig(_homeConfig)`, `initFirebasePanel` must be called. Add the call:

```javascript
    initFirebasePanel(_homeConfig);
```

Place it immediately after `renderHomeConfig(_homeConfig);` inside `initHomePage`.

Then append the four Firebase functions **at the end of the HOME PAGE section** (before the `// ============================================================` divider for the SCAN PAGE):

```javascript
function initFirebasePanel(configMeta) {
  const panel = document.getElementById('firebase-panel');
  if (!panel) return;
  const isFirebase = configMeta && configMeta.stack && configMeta.stack.backend === 'firebase';
  panel.hidden = !isFirebase;
  if (!isFirebase) return;

  const projId = (configMeta.firebase && configMeta.firebase.projectId) || 'unknown';
  document.getElementById('fb-project-id').textContent = projId;

  document.getElementById('fb-select-all').addEventListener('click', toggleAllFirebaseServices);
  document.getElementById('fb-scan').addEventListener('click', startFirebaseScan);
  document.querySelectorAll('.fb-svc').forEach(cb => cb.addEventListener('change', updateFirebaseScanButton));

  updateFirebaseScanButton();
}

function updateFirebaseScanButton() {
  const anyChecked = !![...document.querySelectorAll('.fb-svc')].find(cb => cb.checked);
  const btn = document.getElementById('fb-scan');
  if (!btn) return;
  btn.disabled = !anyChecked;
  btn.classList.toggle('is-disabled', !anyChecked);
}

function toggleAllFirebaseServices() {
  const boxes = [...document.querySelectorAll('.fb-svc')];
  const allOn = boxes.every(cb => cb.checked);
  boxes.forEach(cb => { cb.checked = !allOn; });
  updateFirebaseScanButton();
}

async function startFirebaseScan() {
  const overrides = [...document.querySelectorAll('.fb-svc')]
    .filter(cb => cb.checked).map(cb => cb.value);
  if (overrides.length === 0) return;

  try {
    const resp = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ stage: 'firebase', scanner_overrides: overrides }),
    });
    if (resp.ok) {
      window.location.href = 'scan.html';
    } else {
      const err = await resp.json().catch(() => ({ detail: 'Scan failed to start' }));
      if (typeof showStartError === 'function') showStartError(err.detail || 'Scan failed to start');
    }
  } catch (e) {
    if (typeof showStartError === 'function') showStartError(e.message || 'Scan failed to start');
  }
}
```

- [ ] **Step 2: Commit**

```
git add vibe_iterator/server/static/js/app.js
git commit -m "feat: add Firebase panel JS (initFirebasePanel, SCAN FIREBASE handler)"
```

---

## Task 5: Dashboard — Firebase panel CSS

**Files:**
- Modify: `vibe_iterator/server/static/css/dashboard.css`

- [ ] **Step 1: Append Firebase panel styles**

At the end of `dashboard.css`, append:

```css
/* ---- Firebase Panel ---- */
.firebase-panel {
  border: 1px solid var(--border-bright);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.5rem;
  background: var(--bg-card-2);
}

.firebase-panel__head {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  margin-bottom: 0.75rem;
}

.firebase-panel__icon {
  color: var(--amber);
  font-size: 1.1rem;
}

.firebase-panel__head h2 {
  font-size: 12px;
  letter-spacing: 0.12em;
  color: var(--amber);
  margin: 0;
}

.firebase-panel__detected {
  font-size: 11px;
  color: var(--text-muted);
  margin: 0 0 0 auto;
}

.firebase-panel__label {
  font-size: 11px;
  color: var(--text-dim);
  margin-bottom: 0.5rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.firebase-panel__grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.4rem 1rem;
  margin-bottom: 1rem;
}

@media (max-width: 480px) {
  .firebase-panel__grid { grid-template-columns: 1fr; }
}

.firebase-panel__grid label {
  font-size: 12px;
  color: var(--text);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.firebase-panel__actions {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

.btn--ghost {
  background: transparent;
  border: 1px solid var(--border-bright);
  color: var(--text-dim);
  padding: 0.4rem 0.9rem;
  border-radius: var(--radius);
  font-family: var(--font-mono);
  font-size: 11px;
  cursor: pointer;
  letter-spacing: 0.06em;
  transition: border-color var(--transition), color var(--transition);
}

.btn--ghost:hover {
  border-color: var(--amber);
  color: var(--amber);
}

.btn--primary {
  background: var(--amber);
  color: #000;
  border: none;
  padding: 0.45rem 1.1rem;
  border-radius: var(--radius);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
  letter-spacing: 0.08em;
  transition: opacity var(--transition);
}

.btn--primary:hover { opacity: 0.85; }

.btn--primary.is-disabled,
.btn--primary:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
```

- [ ] **Step 2: Commit**

```
git add vibe_iterator/server/static/css/dashboard.css
git commit -m "feat: add Firebase panel CSS styles"
```

---

## Task 6: Update `docs/SCANNERS.md` and `docs/CONFIG.md`

**Files:**
- Modify: `docs/SCANNERS.md`
- Modify: `docs/CONFIG.md`

- [ ] **Step 1: Add Firebase scanners to `docs/SCANNERS.md`**

Find the scanner registry table in `docs/SCANNERS.md` and add these rows:

```markdown
| `firebase_firestore` | `Access Control`  | `pre-deploy, post-deploy` | `firebase` | Firestore Security Rules, IDOR, mass assignment |
| `firebase_rtdb`      | `Access Control`  | `pre-deploy, post-deploy` | `firebase` | RTDB open read/write, data enumeration |
| `firebase_storage`   | `Access Control`  | `pre-deploy, post-deploy` | `firebase` | Storage rules, unauthenticated download/upload/listing |
| `firebase_auth`      | `Authentication`  | `dev, pre-deploy, post-deploy` | `firebase` | Anonymous auth, email enumeration, token exposure |
| `firebase_functions` | `API Security`    | `pre-deploy, post-deploy` | `firebase` | Unauthenticated function calls, CORS, sensitive data |
```

- [ ] **Step 2: Add `firebase` stage to `docs/CONFIG.md`**

Find the stage table in `docs/CONFIG.md` and add a row:

```markdown
| `firebase` | Firebase-specific security audit — all five Firebase scanners |
```

- [ ] **Step 3: Commit**

```
git add docs/SCANNERS.md docs/CONFIG.md
git commit -m "docs: add Firebase scanners and firebase stage to SCANNERS.md and CONFIG.md"
```

---

## Task 7: Final full suite run

- [ ] **Step 1: Run all Firebase tests together**

```
pytest tests/test_utils/test_firebase_helpers.py tests/test_scanners/test_firebase_fixture_smoke.py tests/test_scanners/test_firebase_rtdb_proof.py tests/test_scanners/test_firebase_storage_proof.py tests/test_scanners/test_firebase_firestore_proof.py tests/test_scanners/test_firebase_functions_proof.py tests/test_scanners/test_firebase_auth_proof.py tests/test_engine_firebase_registration.py -v
```
Expected: all PASS.

- [ ] **Step 2: Run the full suite**

```
pytest -x -q
```
Expected: green, no regressions.

- [ ] **Step 3: Commit if any fixes were needed**

```
git add -p
git commit -m "fix: resolve final suite regressions"
```

- [ ] **Step 4: Final baton-pass commit**

```
git add .
git commit -m "feat: complete Firebase scanner module — all 5 scanners, fixture, proof tests, dashboard, docs"
```

---

**All four plans complete — Firebase scanner module fully implemented.**
