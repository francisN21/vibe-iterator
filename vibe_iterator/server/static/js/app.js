/**
 * app.js — Dashboard logic for all three pages.
 * Each page calls its init function: initHomePage(), initScanPage(), initResultsPage().
 */

// ============================================================
// Shared helpers
// ============================================================

async function apiFetch(path, opts = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw Object.assign(new Error(body.detail || `HTTP ${res.status}`), { status: res.status });
  }
  return res.json();
}

function sevClass(sev) {
  return { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' }[sev] || 'info';
}

function sevBadge(sev) {
  return `<span class="sev-badge ${sevClass(sev)}">${sev.toUpperCase()}</span>`;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function truncateUrl(url, max = 50) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const path = u.pathname + u.search;
    return path.length > max ? '...' + path.slice(-max) : path;
  } catch { return url.slice(-max); }
}

function fmtDuration(sec) {
  if (sec == null) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
}

function scoreGradeClass(grade) {
  if (!grade) return '';
  if ('AB'.includes(grade)) return 'grade-a';
  if ('CD'.includes(grade)) return 'grade-c';
  return 'grade-f';
}

// ============================================================
// HOME PAGE
// ============================================================

let _homeConfig = null;
let _selectedStage = null;
let _overrideStates = {};   // scanner_name -> checked

async function initHomePage() {
  try {
    _homeConfig = await apiFetch('/api/config');
    renderHomeConfig(_homeConfig);
  } catch (e) {
    document.getElementById('config-errors').classList.remove('hidden');
    const li = document.createElement('li');
    li.textContent = 'Could not load configuration: ' + e.message;
    document.getElementById('config-error-list').appendChild(li);
    return;
  }

  document.getElementById('start-btn').addEventListener('click', onStartScan);
  document.getElementById('cancel-existing-btn').addEventListener('click', cancelExistingAndStart);
}

function renderHomeConfig(cfg) {
  // Target + reachability
  document.getElementById('target-url').textContent = cfg.target;
  const dot = document.getElementById('status-dot');
  dot.className = 'status-dot ' + (cfg.target_reachable ? 'online' : 'offline');

  // Config summary
  document.getElementById('cfg-email').textContent = cfg.test_email_masked;
  document.getElementById('cfg-target').textContent = cfg.target;
  document.getElementById('cfg-pages').textContent = `${cfg.pages_count} pages`;
  document.getElementById('cfg-stack').textContent =
    `${cfg.stack.backend} (${cfg.stack.detection_source})`;

  const secondEl = document.getElementById('cfg-second');
  if (cfg.second_account_configured) {
    secondEl.textContent = 'configured ✓';
    secondEl.className = 'config-value good';
  } else {
    secondEl.textContent = 'not configured — cross-user checks disabled';
    secondEl.className = 'config-value warn';
  }

  // Stage cards
  renderStageCards(cfg);

  // Check if scan already running
  checkRunningState();
}

function renderStageCards(cfg) {
  const grid = document.getElementById('stage-grid');
  grid.innerHTML = '';

  const stages = [
    { key: 'dev',         label: 'DEV',        icon: '⟨/⟩', tag: 'Quick scan',  note: '~2 min' },
    { key: 'pre-deploy',  label: 'PRE-DEPLOY',  icon: '🚀',  tag: 'Recommended', note: '~8 min', recommend: true },
    { key: 'post-deploy', label: 'POST-DEPLOY', icon: '🌍',  tag: 'Production',  note: '~5 min' },
    { key: 'all',         label: 'ALL',         icon: '⊞',   tag: 'Full Audit',  note: '~15 min', warn: '⚠ Slow — best for deep audits' },
  ];

  stages.forEach(({ key, label, icon, tag, note, recommend, warn }) => {
    const stageInfo = cfg.stages[key];
    if (!stageInfo) return;

    const scanners = stageInfo.scanners || [];
    const skipped = scanners.filter(s => !s.available);
    const available = scanners.filter(s => s.available);

    const pillsHtml = scanners.map(s => {
      const cls = s.available ? 'pill available' : 'pill unavailable';
      const title = s.skip_reason ? `title="${escHtml(s.skip_reason)}"` : '';
      return `<span class="${cls}" ${title}>${escHtml(s.name)}</span>`;
    }).join('');

    const warnHtml = (skipped.length > 0 || warn)
      ? `<div class="stage-warning">${warn || `⚠ ${skipped.length} scanner${skipped.length > 1 ? 's' : ''} will be skipped`}</div>`
      : '';

    const card = document.createElement('div');
    card.className = 'stage-card';
    card.dataset.stage = key;
    card.innerHTML = `
      <div class="stage-card-header">
        <div class="stage-name">${icon} ${label}</div>
        <span class="stage-tag ${recommend ? 'recommended' : ''}">${tag}</span>
      </div>
      <div class="stage-est">Est. <em>${note}</em> · ${available.length} of ${scanners.length} scanners</div>
      <div class="scanner-pills">${pillsHtml}</div>
      ${warnHtml}
    `;

    card.addEventListener('click', () => selectStage(key, card, scanners));
    grid.appendChild(card);
  });
}

function selectStage(stage, cardEl, scanners) {
  _selectedStage = stage;
  _overrideStates = {};

  document.querySelectorAll('.stage-card').forEach(c => c.classList.remove('selected'));
  cardEl.classList.add('selected');

  // Populate override checkboxes
  const container = document.getElementById('override-checkboxes');
  container.innerHTML = '';
  scanners.forEach(s => {
    _overrideStates[s.name] = s.available; // default: include if available

    const label = document.createElement('label');
    label.style.cssText = 'display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-dim);cursor:pointer';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = s.available;
    cb.disabled = !s.available;
    cb.dataset.scanner = s.name;
    cb.style.accentColor = 'var(--green)';
    cb.addEventListener('change', () => { _overrideStates[s.name] = cb.checked; });

    label.appendChild(cb);
    label.appendChild(document.createTextNode(s.name + (s.skip_reason ? ` (${s.skip_reason})` : '')));
    container.appendChild(label);
  });

  updateStartBtn();
}

function updateStartBtn() {
  const btn = document.getElementById('start-btn');
  if (!_selectedStage) {
    btn.disabled = true;
    btn.title = 'Select a scan stage first';
    return;
  }
  if (!_homeConfig || !_homeConfig.target_reachable) {
    btn.disabled = true;
    btn.title = `Target unreachable — is your app running at ${_homeConfig ? _homeConfig.target : ''}?`;
    return;
  }
  btn.disabled = false;
  btn.title = '';
}

async function checkRunningState() {
  try {
    const result = await apiFetch('/api/scan/results');
    if (result.status === 'running') {
      // Show warning on start button
      const btn = document.getElementById('start-btn');
      btn.textContent = 'SCAN IN PROGRESS — VIEW';
      btn.disabled = false;
      btn.onclick = () => window.location.href = '/scan';
    }
  } catch { /* no running scan — that's fine */ }
}

async function onStartScan() {
  if (!_selectedStage) return;

  // Get enabled scanner overrides (only if any are unchecked)
  const allScanners = Object.keys(_overrideStates);
  const enabled = allScanners.filter(n => _overrideStates[n]);
  const originalAvailable = (_homeConfig.stages[_selectedStage]?.scanners || [])
    .filter(s => s.available).map(s => s.name);

  // Only send overrides if user actually deselected something
  const overrides = JSON.stringify(enabled.sort()) !== JSON.stringify(originalAvailable.sort())
    ? enabled
    : null;

  try {
    await apiFetch('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({ stage: _selectedStage, scanner_overrides: overrides }),
    });
    window.location.href = `/scan?stage=${encodeURIComponent(_selectedStage)}`;
  } catch (e) {
    if (e.status === 409) {
      document.getElementById('running-modal').classList.add('open');
    } else {
      showToast('Failed to start scan: ' + e.message);
    }
  }
}

async function cancelExistingAndStart() {
  document.getElementById('running-modal').classList.remove('open');
  try {
    await apiFetch('/api/scan/active', { method: 'DELETE' });
    // Wait briefly then start
    await new Promise(r => setTimeout(r, 800));
    onStartScan();
  } catch (e) {
    showToast('Could not cancel: ' + e.message);
  }
}

// ============================================================
// SCAN PAGE
// ============================================================

let _scanState = {
  stage: '',
  totalScanners: 0,
  scanners: [],
  currentIdx: 0,
  findingCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  startTime: null,
  status: 'idle',
  termLines: [],
  findings: [],
  activeFilter: 'all',
};

let _termAutoScroll = true;
let _elapsedInterval = null;
let _redirectTimeout = null;
let _logLines = [];

function initScanPage() {
  const params = new URLSearchParams(window.location.search);
  _scanState.stage = params.get('stage') || '';

  if (_scanState.stage) {
    document.getElementById('scan-title').textContent =
      `SCANNING — ${_scanState.stage.toUpperCase()}`;
  }

  // Terminal auto-scroll
  const termBody = document.getElementById('terminal-body');
  termBody.addEventListener('scroll', () => {
    const atBottom = termBody.scrollHeight - termBody.scrollTop - termBody.clientHeight < 60;
    _termAutoScroll = atBottom;
    document.getElementById('resume-scroll').style.display = atBottom ? 'none' : 'block';
  });

  // Cancel button
  document.getElementById('cancel-btn').addEventListener('click', () => {
    document.getElementById('cancel-modal').classList.add('open');
  });

  document.getElementById('confirm-cancel-btn').addEventListener('click', async () => {
    document.getElementById('cancel-modal').classList.remove('open');
    try {
      await apiFetch('/api/scan/active', { method: 'DELETE' });
    } catch { /* ignore */ }
  });

  // Severity filter pills
  document.querySelectorAll('.filter-pill[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill[data-sev]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _scanState.activeFilter = btn.dataset.sev;
      applyFindingsFilter();
    });
  });

  // Start elapsed timer
  _scanState.startTime = Date.now();
  _elapsedInterval = setInterval(updateElapsed, 1000);

  // Connect WebSocket
  const ws = new ScanWebSocket();
  ws
    .on('_connected', () => {
      setCdpStatus('connected');
    })
    .on('_disconnected', () => {
      setCdpStatus('disconnected');
    })
    .on('scan_started', onScanStarted)
    .on('scanner_started', onScannerStarted)
    .on('scanner_progress', onScannerProgress)
    .on('scanner_completed', onScannerCompleted)
    .on('scanner_skipped', onScannerSkipped)
    .on('finding', onFinding)
    .on('page_navigated', onPageNavigated)
    .on('scan_completed', onScanCompleted)
    .on('scan_cancelled', onScanCancelled)
    .on('scan_error', onScanError);

  ws.connect();

  // If there's already a completed result (page reload), redirect to results
  apiFetch('/api/scan/results').then(r => {
    if (r.status === 'completed') {
      window.location.href = '/results';
    }
  }).catch(() => {});
}

function setCdpStatus(state) {
  const dot = document.getElementById('cdp-dot');
  const label = document.getElementById('cdp-label');
  const indicator = document.getElementById('cdp-indicator');
  if (state === 'connected') {
    dot.style.cssText = 'background:var(--green);box-shadow:0 0 6px var(--green)';
    label.textContent = 'CDP connected';
    indicator.style.display = 'inline-block';
    indicator.style.color = 'var(--green)';
  } else {
    dot.style.cssText = 'background:var(--red);box-shadow:0 0 6px var(--red)';
    label.textContent = 'Reconnecting...';
  }
}

function updateElapsed() {
  const sec = Math.round((Date.now() - _scanState.startTime) / 1000);
  document.getElementById('elapsed-time').textContent = fmtDuration(sec) + ' elapsed';
}

function onScanStarted(event) {
  const { stage, scanner_count, scanner_names } = event.data;
  _scanState.totalScanners = scanner_count;
  _scanState.stage = stage;
  _scanState.scanners = scanner_names.map(n => ({ name: n, status: 'pending' }));
  document.getElementById('scan-title').textContent = `SCANNING — ${stage.toUpperCase()}`;
  addTermLine(`▶ Starting ${stage.toUpperCase()} scan — ${scanner_count} scanners`, 'success', event.timestamp);
  updateProgressBar();
}

function onScannerStarted(event) {
  const { scanner_name, index, total } = event.data;
  _scanState.currentIdx = index;
  document.getElementById('progress-label').textContent =
    `Scanner ${index} of ${total} — ${scanner_name}`;

  // Mark as running in progress bar
  updateScannerStatus(scanner_name, 'running');
  addTermLine(`[${scanner_name}] Starting scan... (${index}/${total})`, 'nav', event.timestamp);
}

function onScannerProgress(event) {
  const { scanner_name, message, level } = event.data;
  const cls = { info: 'info', warn: 'warning', error: 'error' }[level] || 'info';
  addTermLine(`[${scanner_name}] ${message}`, cls, event.timestamp);
}

function onScannerCompleted(event) {
  const { scanner_name, outcome, findings_count, duration_seconds } = event.data;
  updateScannerStatus(scanner_name, outcome);
  const countStr = findings_count > 0
    ? `${findings_count} finding${findings_count > 1 ? 's' : ''}`
    : 'passed';
  const cls = findings_count > 0 ? 'warning' : 'success';
  addTermLine(`✓ [${scanner_name}] Completed — ${countStr} (${duration_seconds}s)`, cls, event.timestamp);
  updateProgressBar();
}

function onScannerSkipped(event) {
  const { scanner_name, reason } = event.data;
  updateScannerStatus(scanner_name, 'skipped');
  addTermLine(`— [${scanner_name}] SKIPPED — ${reason}`, 'muted', event.timestamp);
  addFindingCard({ scanner: scanner_name, title: 'SKIPPED', description: reason }, 'status-skipped', '—');
  updateProgressBar();
}

function onFinding(event) {
  const f = event.data;
  const sev = f.severity || 'info';
  _scanState.findingCounts[sev] = (_scanState.findingCounts[sev] || 0) + 1;
  _scanState.findings.push(f);
  updateSevCounters();

  const cls = `finding ${sev} t-finding-${sev}`;
  addTermLine(`⚠ [${f.scanner}] FINDING [${sev.toUpperCase()}]: ${f.title}`, `finding-${sev}`, event.timestamp);
  addFindingCard(f, `sev-${sev}`, sev);
}

function onPageNavigated(event) {
  const { url, status_code } = event.data;
  addTermLine(`Navigating to ${url} [${status_code}]`, 'nav', event.timestamp);
  document.getElementById('current-page').textContent = url;
}

function onScanCompleted(event) {
  const { total_findings, by_severity, duration_seconds, score, score_grade } = event.data;
  _scanState.status = 'completed';
  clearInterval(_elapsedInterval);

  const sevSummary = Object.entries(by_severity)
    .filter(([, c]) => c > 0)
    .map(([s, c]) => `${c} ${s}`)
    .join(', ') || 'none';

  addTermLine('', 'muted', event.timestamp);
  addTermLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'muted', event.timestamp);
  addTermLine(`✓ SCAN COMPLETE`, 'success', event.timestamp);
  addTermLine(`  Total findings : ${total_findings} (${sevSummary})`, 'info', event.timestamp);
  addTermLine(`  Security score : ${score} (${score_grade})`, score >= 75 ? 'success' : score >= 45 ? 'warning' : 'error', event.timestamp);
  addTermLine(`  Duration       : ${fmtDuration(duration_seconds)}`, 'info', event.timestamp);
  addTermLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'muted', event.timestamp);

  // Save fingerprints for compare feature
  saveLastScanFingerprints();

  // Show complete banner
  const banner = document.getElementById('complete-banner');
  document.getElementById('complete-summary').textContent =
    `${total_findings} finding${total_findings !== 1 ? 's' : ''} · Score: ${score} (${score_grade}) · ${fmtDuration(duration_seconds)}`;
  banner.classList.add('visible');

  updateStatusLabel('COMPLETE ✓', 'complete');
  updateProgressBar();

  // Auto-redirect in 5 seconds
  _redirectTimeout = setTimeout(() => { window.location.href = '/results'; }, 5000);
}

function onScanCancelled(event) {
  _scanState.status = 'cancelled';
  clearInterval(_elapsedInterval);
  addTermLine('✗ SCAN CANCELLED', 'error', event.timestamp);
  updateStatusLabel('CANCELLED', 'cancelled');

  document.getElementById('cancel-btn').style.display = 'none';
  document.getElementById('complete-banner').innerHTML =
    `<h3 style="color:var(--amber)">SCAN CANCELLED</h3>
     <p>The scan was cancelled early.</p>
     <div style="display:flex;gap:0.75rem;justify-content:center">
       <a href="/" class="btn btn-ghost">← Home</a>
       <button class="btn btn-primary" onclick="window.location.href='/results'">VIEW PARTIAL RESULTS →</button>
     </div>`;
  document.getElementById('complete-banner').classList.add('visible');
}

function onScanError(event) {
  const { error, recoverable, scanner_name } = event.data;
  const prefix = scanner_name ? `[${scanner_name}] ` : '';
  addTermLine(`✗ ${prefix}ERROR: ${error}`, 'error', event.timestamp);
  if (!recoverable) {
    _scanState.status = 'error';
    clearInterval(_elapsedInterval);
    updateStatusLabel('ERROR ✗', 'error');
  }
}

function addTermLine(text, cls, timestamp) {
  const body = document.getElementById('terminal-body');
  const time = timestamp ? new Date(timestamp).toLocaleTimeString('en-US', { hour12: false }) : '--:--:--';

  _logLines.push(`[${time}] ${text}`);

  // Prune DOM if over 1000 lines
  if (body.children.length >= 1000) {
    body.removeChild(body.firstChild);
  }

  const line = document.createElement('div');
  line.className = 'terminal-line';
  line.innerHTML = `<span class="t-time">[${time}]</span><span class="t-${cls}">${escHtml(text)}</span>`;
  body.appendChild(line);

  if (_termAutoScroll) {
    body.scrollTop = body.scrollHeight;
  }

  // Update download blob
  updateLogDownload();
}

function updateLogDownload() {
  const btn = document.getElementById('download-log-btn');
  if (!btn) return;
  const blob = new Blob([_logLines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  btn.href = url;
  btn.download = `vibe-iterator-scan-${Date.now()}.txt`;
}

function addFindingCard(finding, extraClass, sev) {
  const body = document.getElementById('findings-body');

  // Remove empty state message
  if (body.querySelector('[style*="color:var(--text-muted)"]')) {
    body.innerHTML = '';
  }

  const card = document.createElement('div');
  card.className = `finding-card ${extraClass}`;
  card.dataset.sev = sev;

  if (extraClass === 'status-skipped' || extraClass === 'status-timeout') {
    card.innerHTML = `
      <div class="finding-card-top">
        <span class="sev-badge info">${escHtml(finding.title)}</span>
        <span class="finding-title" style="color:var(--text-muted)">${escHtml(finding.scanner)}</span>
      </div>
      <div class="finding-meta">${escHtml(finding.description || '')}</div>
    `;
  } else {
    card.innerHTML = `
      <div class="finding-card-top">
        ${sevBadge(sev)}
        <span class="finding-title">${escHtml(finding.title)}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-scanner">${escHtml(finding.scanner)}</span>
        <span>·</span>
        <span class="finding-page" title="${escHtml(finding.page || '')}">${escHtml(truncateUrl(finding.page || ''))}</span>
      </div>
    `;
  }

  body.appendChild(card);

  // Apply current filter
  if (_scanState.activeFilter !== 'all' && sev !== _scanState.activeFilter) {
    card.style.display = 'none';
  }

  body.scrollTop = body.scrollHeight;
}

function applyFindingsFilter() {
  const filter = _scanState.activeFilter;
  document.querySelectorAll('#findings-body .finding-card').forEach(card => {
    const sev = card.dataset.sev;
    card.style.display = (filter === 'all' || sev === filter) ? '' : 'none';
  });
}

function updateSevCounters() {
  const c = _scanState.findingCounts;
  document.getElementById('cnt-critical').textContent = `${c.critical || 0} CRIT`;
  document.getElementById('cnt-high').textContent = `${c.high || 0} HIGH`;
  document.getElementById('cnt-medium').textContent = `${c.medium || 0} MED`;
  document.getElementById('cnt-low').textContent = `${c.low || 0} LOW`;
}

function updateScannerStatus(name, status) {
  const s = _scanState.scanners.find(s => s.name === name);
  if (s) s.status = status;
}

function updateProgressBar() {
  const track = document.getElementById('progress-track');
  if (!_scanState.totalScanners) return;

  const total = _scanState.totalScanners;
  track.innerHTML = '';

  _scanState.scanners.forEach(s => {
    const pct = (100 / total).toFixed(2);
    const seg = document.createElement('div');
    seg.className = `progress-segment ${s.status === 'pending' ? '' : s.status}`;
    seg.style.width = `${pct}%`;
    seg.title = `${s.name}: ${s.status}`;
    track.appendChild(seg);
  });
}

function updateStatusLabel(text, cls) {
  const el = document.getElementById('status-label');
  el.className = `scan-status-label ${cls}`;
  el.innerHTML = text;
}

function resumeScroll() {
  _termAutoScroll = true;
  const body = document.getElementById('terminal-body');
  body.scrollTop = body.scrollHeight;
  document.getElementById('resume-scroll').style.display = 'none';
}

function dismissBanner() {
  clearTimeout(_redirectTimeout);
  document.getElementById('complete-banner').classList.remove('visible');
}

async function saveLastScanFingerprints() {
  try {
    const result = await apiFetch('/api/scan/results');
    const summary = result.findings.map(f => ({ fingerprint: f.fingerprint, severity: f.severity }));
    localStorage.setItem('vibe_iterator_last_scan', JSON.stringify({
      timestamp: result.completed_at,
      stage: result.stage,
      score: result.score,
      findings: summary,
    }));
  } catch { /* ignore */ }
}

// ============================================================
// RESULTS PAGE
// ============================================================

let _results = null;
let _activeFilter = { sev: 'all', search: '', showSkipped: false, showPassed: false };
let _allFindings = [];
let _filterChangeTimer = null;

async function initResultsPage() {
  try {
    _results = await apiFetch('/api/scan/results');
  } catch (e) {
    if (e.status === 404) {
      document.getElementById('findings-container').innerHTML =
        '<div class="empty-state">No scan results found. <a href="/">Run a scan first →</a></div>';
      return;
    }
    document.getElementById('findings-container').innerHTML =
      `<div class="empty-state">Error loading results: ${escHtml(e.message)}</div>`;
    return;
  }

  if (_results.status === 'running') {
    window.location.href = '/scan';
    return;
  }

  _allFindings = _results.findings;
  renderExecSummary(_results);
  renderFindings(_results);
  renderPassedChecks(_results);
  setupResultsFilters();
  setupMarkActions();
  setupActionBar(_results);
  checkCompareAvailability(_results);

  // Re-scan goes back home with same stage pre-selected
  document.getElementById('rescan-btn').addEventListener('click', () => {
    window.location.href = '/';
  });
}

function renderExecSummary(r) {
  const score = r.score ?? 0;
  const grade = r.score_grade ?? '—';

  const scoreEl = document.getElementById('score-number');
  scoreEl.textContent = score;
  scoreEl.className = `score-number ${scoreGradeClass(grade)}`;
  document.getElementById('score-grade').textContent = grade;
  document.getElementById('score-grade').className = `score-grade ${scoreGradeClass(grade)}`;

  // Severity distribution bar
  const total = r.findings.length;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  r.findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  document.getElementById('total-findings-label').textContent =
    `${total} finding${total !== 1 ? 's' : ''}`;

  const bar = document.getElementById('sev-bar');
  bar.innerHTML = '';
  if (total === 0) {
    bar.innerHTML = '<div class="sev-bar-seg passed" style="width:100%"></div>';
  } else {
    ['critical', 'high', 'medium', 'low'].forEach(sev => {
      if (counts[sev] > 0) {
        const seg = document.createElement('div');
        seg.className = `sev-bar-seg ${sev}`;
        seg.style.width = `${(counts[sev] / total * 100).toFixed(1)}%`;
        seg.title = `${counts[sev]} ${sev}`;
        seg.addEventListener('click', () => setSevFilter(sev));
        bar.appendChild(seg);
      }
    });
  }

  // Stats row
  const scanRun = r.scanner_results.filter(s => s.status !== 'skipped').length;
  const scanSkip = r.scanner_results.filter(s => s.status === 'skipped').length;
  document.getElementById('stats-row').innerHTML = `
    <div class="stat-item"><div class="stat-value">${total}</div><div class="stat-label">Findings</div></div>
    <div class="stat-item"><div class="stat-value">${r.pages_crawled.length}</div><div class="stat-label">Pages</div></div>
    <div class="stat-item"><div class="stat-value">${r.requests_captured?.total ?? 0}</div><div class="stat-label">Requests</div></div>
    <div class="stat-item"><div class="stat-value">${scanRun}${scanSkip > 0 ? `<span style="font-size:0.6em;color:var(--text-muted)"> (${scanSkip} skipped)</span>` : ''}</div><div class="stat-label">Scanners</div></div>
    <div class="stat-item"><div class="stat-value">${fmtDuration(r.duration_seconds)}</div><div class="stat-label">Duration</div></div>
  `;

  // Scan metadata panel
  const metaBody = document.getElementById('scan-meta-body');
  const scannerRows = r.scanner_results.map(s => {
    const statusColor = { passed: 'var(--green)', findings: 'var(--amber)', skipped: 'var(--text-muted)', timeout: 'var(--amber)', error: 'var(--red)' }[s.status] || 'var(--text)';
    return `<div class="config-row">
      <span class="config-label">${escHtml(s.scanner_name)}</span>
      <span style="color:${statusColor}">${escHtml(s.status)}${s.findings_count > 0 ? ` (${s.findings_count})` : ''}${s.skip_reason ? ` — ${escHtml(s.skip_reason)}` : ''}</span>
      <span style="color:var(--text-muted);margin-left:auto">${s.duration_seconds ? s.duration_seconds.toFixed(1) + 's' : ''}</span>
    </div>`;
  }).join('');
  metaBody.innerHTML = `
    <div class="config-row"><span class="config-label">Stage</span><span>${escHtml(r.stage)}</span></div>
    <div class="config-row"><span class="config-label">Target</span><span>${escHtml(r.target)}</span></div>
    <div class="config-row"><span class="config-label">Stack</span><span>${escHtml(r.stack_detected)} (${escHtml(r.stack_detection_source)})</span></div>
    <div class="config-row"><span class="config-label">Second account</span><span>${r.second_account_used ? 'Used ✓' : 'Not used'}</span></div>
    ${scannerRows}
  `;
}

const _CATEGORY_ORDER = [
  'Access Control', 'Authentication', 'Injection', 'Data Leakage',
  'Client-Side Tampering', 'API Security', 'Misconfiguration',
];

function renderFindings(r) {
  const container = document.getElementById('findings-container');
  container.innerHTML = '';

  // Apply marks from finding_marks
  const markMap = {};
  (r.finding_marks || []).forEach(m => { markMap[m.finding_id] = m; });
  r.findings.forEach(f => {
    const m = markMap[f.id];
    if (m) { f.mark_status = m.status; f.mark_note = m.note; }
  });

  const activeFindings = r.findings.filter(f =>
    !['resolved', 'false_positive'].includes(f.mark_status)
  );

  if (activeFindings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <span class="big-check">✓</span>
        No vulnerabilities found!<br>
        <span style="color:var(--text-muted)">Your app passed all scans in this stage.</span>
      </div>`;
    return;
  }

  // Group by category
  const grouped = {};
  activeFindings.forEach(f => {
    const cat = f.category || 'Uncategorized';
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(f);
  });

  // Sort categories by order defined above, then alphabetically
  const cats = Object.keys(grouped).sort((a, b) => {
    const ia = _CATEGORY_ORDER.indexOf(a);
    const ib = _CATEGORY_ORDER.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });

  cats.forEach(cat => {
    const findings = grouped[cat].sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    });

    const worstSev = findings[0]?.severity || 'info';
    const section = document.createElement('div');
    section.className = 'category-section';
    section.dataset.category = cat;

    section.innerHTML = `
      <div class="category-header" onclick="toggleCategory(this)">
        <span class="category-toggle">▼</span>
        <span class="category-name">${escHtml(cat)}</span>
        <span class="category-count">${findings.length}</span>
        <span class="category-worst-sev">${sevBadge(worstSev)}</span>
      </div>
      <div class="category-findings" id="cat-${escHtml(cat).replace(/\s+/g, '-')}"></div>
    `;

    container.appendChild(section);

    const findingsEl = section.querySelector('.category-findings');
    findings.forEach(f => findingsEl.appendChild(buildFindingCard(f)));
  });
}

function toggleCategory(header) {
  header.classList.toggle('collapsed');
  const body = header.nextElementSibling;
  body.classList.toggle('collapsed');
}

function buildFindingCard(f) {
  const card = document.createElement('div');
  card.className = `result-finding-card sev-${sevClass(f.severity)}`;
  card.dataset.findingId = f.id;
  card.dataset.sev = f.severity;
  card.dataset.title = (f.title || '').toLowerCase();
  if (f.mark_status && f.mark_status !== 'none') {
    card.classList.add(`marked-${f.mark_status.replace('_', '-')}`);
  }

  const evidenceStr = formatEvidence(f.evidence);

  card.innerHTML = `
    <div class="rf-header" onclick="toggleFinding(this)">
      ${sevBadge(f.severity)}
      <span class="rf-title">${escHtml(f.title)}</span>
      <span class="rf-scanner">${escHtml(f.scanner)}</span>
      <span class="rf-page" title="${escHtml(f.page || '')}">${escHtml(truncateUrl(f.page || ''))}</span>
      <div class="rf-actions" onclick="event.stopPropagation()">
        <div class="mark-dropdown" id="mark-${escHtml(f.id)}">
          <button class="mark-btn" onclick="toggleMarkMenu('${escHtml(f.id)}')" title="Mark finding">
            ${markLabel(f.mark_status)} ▾
          </button>
          <div class="mark-menu" id="mark-menu-${escHtml(f.id)}">
            <button class="mark-option resolved"  onclick="markFinding('${escHtml(f.id)}','resolved',null)">✓ Resolved</button>
            <button class="mark-option accepted"  onclick="markFinding('${escHtml(f.id)}','accepted_risk',null)">⚠ Accepted Risk</button>
            <button class="mark-option false-pos" onclick="markFinding('${escHtml(f.id)}','false_positive',null)">✗ False Positive</button>
            <button class="mark-option"           onclick="markFinding('${escHtml(f.id)}','none',null)">↺ Reset</button>
          </div>
        </div>
      </div>
    </div>
    <div class="rf-body" id="rfbody-${escHtml(f.id)}">
      <div class="rf-section">
        <div class="rf-section-label">What this means</div>
        <div class="rf-description">${escHtml(f.description)}</div>
      </div>
      <div class="rf-section">
        <div class="rf-section-label">Evidence</div>
        <div class="evidence-block">${evidenceStr}</div>
      </div>
      ${f.remediation ? `
      <div class="rf-section">
        <div class="rf-section-label">How to fix</div>
        <div class="remediation-block">${escHtml(f.remediation)}</div>
      </div>` : ''}
      <button class="copy-prompt-btn" onclick="copyToClipboard(${JSON.stringify(f.llm_prompt)}, this)">
        ⧉ COPY FIX PROMPT
      </button>
      <details style="margin-top:0.5rem">
        <summary style="font-size:10px;color:var(--text-muted);cursor:pointer">View prompt</summary>
        <div class="evidence-block" style="margin-top:0.4rem;white-space:pre-wrap">${escHtml(f.llm_prompt)}</div>
      </details>
      <div class="rf-tags">
        <span class="rf-tag">${escHtml(f.scanner)}</span>
        <span class="rf-tag">${escHtml(f.category)}</span>
        <span class="rf-tag">${escHtml(truncateUrl(f.page || '', 40))}</span>
      </div>
    </div>
  `;

  return card;
}

function toggleFinding(header) {
  const body = header.nextElementSibling;
  while (body && !body.classList.contains('rf-body')) { return; }
  body.classList.toggle('expanded');
}

function toggleMarkMenu(findingId) {
  const menu = document.getElementById(`mark-menu-${findingId}`);
  if (!menu) return;
  const isOpen = menu.classList.contains('open');
  // Close all other menus
  document.querySelectorAll('.mark-menu.open').forEach(m => m.classList.remove('open'));
  if (!isOpen) menu.classList.add('open');
}

// Close mark menus on outside click
document.addEventListener('click', e => {
  if (!e.target.closest('.mark-dropdown')) {
    document.querySelectorAll('.mark-menu.open').forEach(m => m.classList.remove('open'));
  }
});

function markLabel(status) {
  const labels = { resolved: '✓ Resolved', accepted_risk: '⚠ Accepted', false_positive: '✗ Dismissed', none: 'Mark as' };
  return labels[status] || 'Mark as';
}

async function markFinding(findingId, status, note) {
  const noteVal = note || (status === 'accepted_risk'
    ? prompt('Add a note (optional):')
    : null);

  try {
    await apiFetch('/api/scan/findings/mark', {
      method: 'POST',
      body: JSON.stringify({ findings: [{ finding_id: findingId, status, note: noteVal }] }),
    });

    const card = document.querySelector(`[data-finding-id="${findingId}"]`);
    if (card) {
      card.className = card.className.replace(/marked-\S+/g, '').trim();
      if (status !== 'none') card.classList.add(`marked-${status.replace('_', '-')}`);

      const markBtn = card.querySelector('.mark-btn');
      if (markBtn) markBtn.textContent = markLabel(status) + ' ▾';
    }

    document.getElementById(`mark-menu-${findingId}`)?.classList.remove('open');

    if (status === 'resolved' || status === 'false_positive') {
      showToast(`Finding marked as ${status.replace('_', ' ')}`);
    }

    renderSpecialSections();
  } catch (e) {
    showToast('Failed to mark finding: ' + e.message);
  }
}

function formatEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') return 'No evidence captured.';
  return Object.entries(evidence).map(([k, v]) => {
    const val = typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v);
    return `<span class="evidence-key">${escHtml(k)}</span>: <span class="evidence-value">${escHtml(val)}</span>`;
  }).join('\n');
}

function renderPassedChecks(r) {
  const passed = r.scanner_results.filter(s => s.status === 'passed');
  if (passed.length === 0) return;

  const section = document.getElementById('passed-section');
  section.style.display = '';
  document.getElementById('passed-count').textContent = `(${passed.length})`;
  document.getElementById('passed-body').innerHTML = passed.map(s =>
    `<div class="passed-check">${escHtml(s.scanner_name)} — ${fmtDuration(s.duration_seconds)}</div>`
  ).join('');
}

function renderSpecialSections() {
  if (!_results) return;
  const resolved = _results.findings.filter(f => f.mark_status === 'resolved');
  const dismissed = _results.findings.filter(f =>
    f.mark_status === 'false_positive' || f.mark_status === 'accepted_risk'
  );

  const resolvedSec = document.getElementById('resolved-section');
  if (resolved.length > 0) {
    resolvedSec.style.display = '';
    document.getElementById('resolved-count').textContent = `(${resolved.length})`;
    document.getElementById('resolved-body').innerHTML = resolved.map(f =>
      `<div class="passed-check" style="color:var(--text-dim)">
        ${sevBadge(f.severity)} ${escHtml(f.title)}
       </div>`
    ).join('');
  }

  const dismissedSec = document.getElementById('dismissed-section');
  if (dismissed.length > 0) {
    dismissedSec.style.display = '';
    document.getElementById('dismissed-count').textContent = `(${dismissed.length})`;
    document.getElementById('dismissed-body').innerHTML = dismissed.map(f =>
      `<div class="passed-check" style="text-decoration:line-through;color:var(--text-muted)">
        ${sevBadge(f.severity)} ${escHtml(f.title)} — ${escHtml(f.mark_status.replace('_', ' '))}
       </div>`
    ).join('');
  }
}

// ---- Filters ----

function setupResultsFilters() {
  // Severity filter pills
  document.querySelectorAll('#filter-bar .filter-pill[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => setSevFilter(btn.dataset.sev));
  });

  // Search
  document.getElementById('search-input').addEventListener('input', e => {
    _activeFilter.search = e.target.value.toLowerCase();
    scheduleFilterUpdate();
  });

  // Toggle skipped/passed
  document.getElementById('toggle-skipped').addEventListener('click', function() {
    _activeFilter.showSkipped = !_activeFilter.showSkipped;
    this.classList.toggle('active', _activeFilter.showSkipped);
    scheduleFilterUpdate();
  });

  document.getElementById('toggle-passed').addEventListener('click', function() {
    _activeFilter.showPassed = !_activeFilter.showPassed;
    this.classList.toggle('active', _activeFilter.showPassed);
    scheduleFilterUpdate();
  });

  // Persist to localStorage
  const saved = localStorage.getItem('vibe_iterator_filters');
  if (saved) {
    try {
      const f = JSON.parse(saved);
      if (f.sev) setSevFilter(f.sev);
    } catch { /* ignore */ }
  }
}

function setSevFilter(sev) {
  _activeFilter.sev = sev;
  document.querySelectorAll('#filter-bar .filter-pill[data-sev]').forEach(b => {
    b.classList.toggle('active', b.dataset.sev === sev);
  });
  scheduleFilterUpdate();
  updateFilterClear();
  localStorage.setItem('vibe_iterator_filters', JSON.stringify({ sev }));
}

function scheduleFilterUpdate() {
  clearTimeout(_filterChangeTimer);
  _filterChangeTimer = setTimeout(applyResultsFilter, 100);
}

function applyResultsFilter() {
  const { sev, search } = _activeFilter;
  document.querySelectorAll('.result-finding-card').forEach(card => {
    const cardSev = card.dataset.sev;
    const cardTitle = card.dataset.title || '';
    const sevOk = sev === 'all' || cardSev === sev;
    const searchOk = !search || cardTitle.includes(search);
    card.style.display = (sevOk && searchOk) ? '' : 'none';
  });
  updateFilterClear();
}

function updateFilterClear() {
  const active = _activeFilter.sev !== 'all' || _activeFilter.search;
  document.getElementById('filter-clear').classList.toggle('hidden', !active);
}

function clearFilters() {
  _activeFilter = { sev: 'all', search: '', showSkipped: false, showPassed: false };
  document.getElementById('search-input').value = '';
  document.querySelectorAll('#filter-bar .filter-pill[data-sev]').forEach(b =>
    b.classList.toggle('active', b.dataset.sev === 'all')
  );
  applyResultsFilter();
  localStorage.removeItem('vibe_iterator_filters');
}

// ---- Action bar ----

function setupMarkActions() {
  renderSpecialSections();
}

function setupActionBar(r) {
  // Copy all prompts button opens dropdown
  const copyBtn = document.getElementById('copy-all-btn');
  const copyMenu = document.getElementById('copy-menu');
  copyBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    copyMenu.style.display = copyMenu.style.display === 'none' ? 'block' : 'none';
  });

  document.addEventListener('click', () => { copyMenu.style.display = 'none'; });

  // Export report — Phase 4 stub
  document.getElementById('export-btn').addEventListener('click', () => {
    showToast('Report export coming in Phase 4');
  });
}

function copyAllPrompts(scope) {
  if (!_results) return;
  let findings = _results.findings;

  if (scope === 'critical_high') {
    findings = findings.filter(f => ['critical', 'high'].includes(f.severity));
  } else if (scope === 'filtered') {
    const { sev, search } = _activeFilter;
    findings = findings.filter(f => {
      const sevOk = sev === 'all' || f.severity === sev;
      const searchOk = !search || f.title.toLowerCase().includes(search);
      return sevOk && searchOk;
    });
  }

  if (findings.length === 0) {
    showToast('No findings to copy');
    return;
  }

  const text = findings.map((f, i) =>
    `--- FINDING ${i + 1} of ${findings.length} ---\n${f.llm_prompt}`
  ).join('\n\n');

  copyToClipboard(text, null);
  showToast(`Copied ${findings.length} prompts`);
}

// ---- Compare feature ----

function checkCompareAvailability(r) {
  const saved = localStorage.getItem('vibe_iterator_last_scan');
  if (!saved) return;

  try {
    const last = JSON.parse(saved);
    if (last.timestamp === r.started_at) return; // same scan

    const compareBtn = document.getElementById('compare-btn');
    compareBtn.style.display = 'inline-flex';
    compareBtn.addEventListener('click', () => showCompare(r, last));
  } catch { /* ignore */ }
}

function showCompare(current, last) {
  const currentFps = new Map(current.findings.map(f => [f.fingerprint, f.severity]));
  const lastFps = new Map((last.findings || []).map(f => [f.fingerprint, f.severity]));

  const newFindings = current.findings.filter(f => !lastFps.has(f.fingerprint));
  const resolved = (last.findings || []).filter(f => !currentFps.has(f.fingerprint));
  const unchanged = current.findings.filter(f => lastFps.has(f.fingerprint) && lastFps.get(f.fingerprint) === f.severity);

  const body = document.getElementById('compare-body');
  body.innerHTML = `
    <p style="color:var(--text-muted);margin-bottom:1rem">
      Comparing current scan vs ${new Date(last.timestamp).toLocaleDateString()}
    </p>
    ${newFindings.length > 0 ? `<p style="color:var(--red);margin-bottom:0.5rem">🆕 New (${newFindings.length})</p>
      ${newFindings.map(f => `<div class="passed-check" style="color:var(--text)">${sevBadge(f.severity)} ${escHtml(f.title)}</div>`).join('')}` : ''}
    ${resolved.length > 0 ? `<p style="color:var(--green);margin-top:0.75rem;margin-bottom:0.5rem">✅ Resolved (${resolved.length})</p>
      ${resolved.map(f => `<div class="passed-check">${escHtml(f.fingerprint)} — was ${escHtml(f.severity)}</div>`).join('')}` : ''}
    ${unchanged.length > 0 ? `<p style="color:var(--text-muted);margin-top:0.75rem;margin-bottom:0.5rem">↔ Unchanged (${unchanged.length})</p>` : ''}
    ${newFindings.length === 0 && resolved.length > 0 ? `<p style="color:var(--green);margin-top:1rem">All previous findings resolved! 🎉</p>` : ''}
  `;

  document.getElementById('compare-modal').classList.add('open');
}
