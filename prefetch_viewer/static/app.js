// ═══════════════════════════════════════════════════════════════
// Prefetch Viewer — Frontend
// ═══════════════════════════════════════════════════════════════

const LANES = [
  { id: 'cred',   label: 'Credential access', color: '#c084fc' },
  { id: 'exec',   label: 'Execution',          color: '#fb923c' },
  { id: 'recon',  label: 'Reconnaissance',     color: '#38bdf8' },
  { id: 'net',    label: 'Network / tunnel',   color: '#34d399' },
  { id: 'system', label: 'System / normal',    color: '#94a3b8' },
];

const SEV_COLORS = {
  critical: '#E24B4A',
  high:     '#BA7517',
  medium:   '#378ADD',
  low:      '#6b7280',
  clean:    '#4a4848',
};

// ── State ─────────────────────────────────────────────────────────────────────
const S = {
  files:       [],    // FileListItem[] from /api/files
  payload:     null,  // TimelinePayload from /api/timeline
  fileLookup:  new Map(), // id → FileListItem (for severity on dots)
  selectedExe: null,  // Filtered to one exe group name (null = all)
  selectedId:  null,  // Currently selected file id in sidebar
  activeEvt:   null,  // Currently clicked event (for highlight ring)
  zoom:        1,
  filter:      'all',
  search:      '',
};

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupUpload();
  loadAll();
});

// ── Time helpers (browser local timezone) ─────────────────────────────────────
function msToLocalTime(ms) {
  if (!ms || ms <= 0) return '–';
  return new Date(ms).toLocaleTimeString(undefined, {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

function msToLocalDateTime(ms) {
  if (!ms || ms <= 0) return '–';
  const d    = new Date(ms);
  const date = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  return `${date}  ${time}`;
}

function msToLocalShort(ms) {
  if (!ms || ms <= 0) return '–';
  return new Date(ms).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

function isoToMs(iso) {
  if (!iso) return 0;
  return new Date(iso).getTime();
}

// ── API ───────────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// ── Upload ────────────────────────────────────────────────────────────────────
function setupUpload() {
  const input = document.getElementById('file-input');
  input.addEventListener('change', () => {
    if (input.files.length) uploadFiles(input.files);
  });

  document.addEventListener('dragover', e => {
    e.preventDefault();
    document.getElementById('drop-overlay').classList.remove('hidden');
  });
  document.addEventListener('dragleave', e => {
    if (!e.relatedTarget) document.getElementById('drop-overlay').classList.add('hidden');
  });
  document.addEventListener('drop', async e => {
    e.preventDefault();
    document.getElementById('drop-overlay').classList.add('hidden');
    const files = await collectDroppedFiles(e.dataTransfer);
    if (files.length) uploadFiles(files);
  });

  document.getElementById('upload-zone').addEventListener('click', () => input.click());
}

async function collectDroppedFiles(dt) {
  const result = [];
  if (dt.items && dt.items[0]?.webkitGetAsEntry) {
    const traversal = [];
    for (let i = 0; i < dt.items.length; i++) {
      const entry = dt.items[i].webkitGetAsEntry();
      if (entry) traversal.push(entry);
    }
    const readEntry = (entry) => new Promise(resolve => {
      if (entry.isFile) {
        entry.getFile(f => resolve([f]));
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        const readAll = (acc) => {
          reader.readEntries(async entries => {
            if (!entries.length) {
              const nested = await Promise.all(acc.map(readEntry));
              resolve(nested.flat());
            } else {
              readAll([...acc, ...entries]);
            }
          });
        };
        readAll([]);
      } else {
        resolve([]);
      }
    });
    const nested = await Promise.all(traversal.map(readEntry));
    result.push(...nested.flat());
  } else {
    for (let i = 0; i < dt.files.length; i++) result.push(dt.files[i]);
  }
  return result.filter(f => f.name.toLowerCase().endsWith('.json'));
}

async function uploadFiles(fileList) {
  const jsonFile = Array.from(fileList).find(f => f.name.toLowerCase().endsWith('.json'));
  if (!jsonFile) { showToast('No JSON file found', true); return; }

  showToast('Loading…');

  const fd = new FormData();
  fd.append('file', jsonFile, jsonFile.name);
  try {
    const res  = await fetch('/api/upload', { method: 'POST', body: fd });
    const data = await res.json();
    const uploaded = data.uploaded?.length ?? 0;
    const errors   = data.errors?.length   ?? 0;
    await loadAll();
    showToast(
      errors > 0 ? `Loaded ${uploaded} · ${errors} error(s)` : `Loaded ${uploaded} prefetch entries`,
      errors > 0
    );
  } catch (e) {
    showToast('Upload failed: ' + e.message, true);
  }
  document.getElementById('file-input').value = '';
}

async function clearAll() {
  await Promise.all(S.files.map(f => fetch(`/api/files/${f.id}`, { method: 'DELETE' })));
  S.selectedExe = null;
  S.selectedId  = null;
  S.activeEvt   = null;
  await loadAll();
}

// ── Data ──────────────────────────────────────────────────────────────────────
async function loadAll() {
  try {
    [S.files, S.payload] = await Promise.all([
      apiFetch('/api/files'),
      apiFetch('/api/timeline'),
    ]);
  } catch {
    S.files = []; S.payload = null;
  }
  // Build file lookup for fast severity checking on timeline dots
  S.fileLookup = new Map();
  for (const f of S.files) S.fileLookup.set(f.id, f);
  renderAll();
}

function renderAll() {
  const has = S.files.length > 0;
  el('upload-zone').classList.toggle('hidden', has);
  el('sidebar-list').classList.toggle('hidden', !has);
  el('empty-state').classList.toggle('hidden', has);
  el('timeline-area').classList.toggle('hidden', !has);
  el('stats-strip').classList.toggle('hidden', !has);
  el('btn-report').disabled = !has;
  if (!has) return;
  renderStats();
  renderSidebar();
  renderTimeline();
}

function el(id) { return document.getElementById(id); }

// ── Severity helpers ──────────────────────────────────────────────────────────
function itemSev(item) {
  if (!item.score) return 'clean';
  const fc = item.finding_counts;
  if (fc?.critical > 0 || fc?.Critical > 0) return 'critical';
  if (fc?.high > 0     || fc?.High > 0)     return 'high';
  if (fc?.medium > 0   || fc?.Medium > 0)   return 'medium';
  return 'low';
}

function worstSev(items) {
  for (const sev of ['critical','high','medium','low']) {
    if (items.some(i => itemSev(i) === sev)) return sev;
  }
  return 'clean';
}

function isFlagged(fileId) {
  const f = S.fileLookup.get(fileId);
  if (!f) return false;
  return f.score > 0;
}

function fileSev(fileId) {
  const f = S.fileLookup.get(fileId);
  if (!f) return 'clean';
  return itemSev(f);
}

// ── Stats strip ───────────────────────────────────────────────────────────────
function renderStats() {
  if (!S.payload) return;
  const evts = visibleEvents();
  const ts   = evts.map(e => e.timestamp_ms).filter(Boolean);
  const span = ts.length > 1 ? fmtSpan(Math.max(...ts) - Math.min(...ts)) : '–';
  const exes = new Set(evts.map(e => e.name)).size;

  el('st-events').textContent = evts.length;
  el('st-exes').textContent   = exes;
  el('st-files').textContent  = S.payload.summary.total_files;
  el('st-span').textContent   = span;

  // Aggregate finding counts across all files
  let crit = 0, high = 0, med = 0, low = 0, flaggedCount = 0;
  for (const f of S.files) {
    const fc = f.finding_counts || {};
    const c = (fc.critical || fc.Critical || 0);
    const h = (fc.high || fc.High || 0);
    const m = (fc.medium || fc.Medium || 0);
    const l = (fc.low || fc.Low || 0);
    crit += c; high += h; med += m; low += l;
    if (c + h + m + l > 0) flaggedCount++;
  }
  el('st-flagged').textContent = flaggedCount;

  const chipsEl = el('st-sev-chips');
  let chips = '';
  if (crit) chips += `<span class="sev-chip critical">${crit} critical</span>`;
  if (high) chips += `<span class="sev-chip high">${high} high</span>`;
  if (med)  chips += `<span class="sev-chip medium">${med} medium</span>`;
  if (low)  chips += `<span class="sev-chip low">${low} low</span>`;
  chipsEl.innerHTML = chips;
}

function fmtSpan(ms) {
  if (ms <= 0) return '–';
  const m = ms / 60000, h = m / 60, d = h / 24;
  if (d >= 1) return `${Math.floor(d)}d ${Math.floor(h % 24)}h`;
  if (h >= 1) return `${Math.floor(h)}h ${Math.floor(m % 60)}m`;
  return `${Math.floor(m)}m`;
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function groupFiles(files) {
  const map = {};
  for (const f of files) (map[f.exe_name] = map[f.exe_name] || []).push(f);
  return map;
}

function aggregateFindings(items) {
  let c = 0, h = 0, m = 0, l = 0;
  for (const item of items) {
    const fc = item.finding_counts || {};
    c += (fc.critical || fc.Critical || 0);
    h += (fc.high || fc.High || 0);
    m += (fc.medium || fc.Medium || 0);
    l += (fc.low || fc.Low || 0);
  }
  return { critical: c, high: h, medium: m, low: l };
}

function renderSidebar() {
  const scrollTop = el('exe-groups').parentElement?.scrollTop || 0;
  const groups   = groupFiles(S.files);
  const sevOrder = ['critical','high','medium','low','clean'];
  const exeNames = Object.keys(groups).sort((a, b) => {
    const sa = sevOrder.indexOf(worstSev(groups[a]));
    const sb = sevOrder.indexOf(worstSev(groups[b]));
    return sa !== sb ? sa - sb : a.localeCompare(b);
  });

  el('sb-count').textContent = `${exeNames.length} executable${exeNames.length !== 1 ? 's' : ''}`;

  const container = el('exe-groups');
  container.innerHTML = '';

  for (const exeName of exeNames) {
    const items     = groups[exeName];
    const sev       = worstSev(items);
    const color     = SEV_COLORS[sev];
    const isActive  = S.selectedExe === exeName;
    const totalRuns = items.reduce((s, i) => s + (i.run_count || 0), 0);
    const agg       = aggregateFindings(items);
    const hasFinding = agg.critical + agg.high + agg.medium + agg.low > 0;

    const group = document.createElement('div');
    group.className = 'exe-group';

    // Build count chips HTML
    let chipsHtml = '';
    if (hasFinding) {
      chipsHtml = '<div class="eg-chips">';
      if (agg.critical) chipsHtml += `<span class="eg-chip critical">${agg.critical}</span>`;
      if (agg.high)     chipsHtml += `<span class="eg-chip high">${agg.high}</span>`;
      if (agg.medium)   chipsHtml += `<span class="eg-chip medium">${agg.medium}</span>`;
      if (agg.low)      chipsHtml += `<span class="eg-chip low">${agg.low}</span>`;
      chipsHtml += '</div>';
    }

    const hdr = document.createElement('div');
    hdr.className = `exe-group-header${isActive ? ' active open' : ''}`;
    hdr.innerHTML = `
      <div class="eg-sev-bar${hasFinding ? ' has-findings' : ''}" style="background:${color};color:${color}"></div>
      <div class="eg-info">
        <div class="eg-name">${escHtml(exeName)}</div>
        <div class="eg-meta">${items.length} variant${items.length !== 1 ? 's' : ''} · ${totalRuns} runs</div>
      </div>
      ${chipsHtml}
      ${sev !== 'clean' ? `<span class="eg-badge ${sev}">${sev}</span>` : ''}
      <span class="eg-chevron">▶</span>`;

    hdr.addEventListener('click', () => {
      if (S.selectedExe === exeName) {
        S.selectedExe = null; S.selectedId = null;
      } else {
        S.selectedExe = exeName; S.selectedId = null;
      }
      S.activeEvt = null;
      updateTopbar(); renderSidebar(); renderStats(); renderTimeline();
    });

    const fileList = document.createElement('div');
    fileList.className = `exe-group-files${isActive ? ' open' : ''}`;

    for (const item of items) {
      const lastRun = item.last_run ? msToLocalShort(isoToMs(item.last_run)) : '–';
      const isSel   = S.selectedId === item.id;

      const row = document.createElement('div');
      row.className = `pf-item${isSel ? ' selected' : ''}`;
      row.title = `${item.exe_name} · Last run: ${lastRun} · Refs: ${item.file_count}`;
      row.innerHTML = `
        <div class="pf-item-dot" style="background:${color}"></div>
        <div class="pf-item-name">${escHtml(item.prefetch_hash)}</div>
        <div class="pf-item-runs">${item.run_count}×</div>`;
      row.addEventListener('click', e => {
        e.stopPropagation();
        S.selectedId = isSel ? null : item.id;
        S.selectedExe = item.exe_name;
        S.activeEvt = null;
        updateTopbar(); renderSidebar(); renderStats(); renderTimeline();
      });
      fileList.appendChild(row);
    }

    group.appendChild(hdr);
    group.appendChild(fileList);
    container.appendChild(group);
  }

  // Preserve scroll position
  if (container.parentElement) container.parentElement.scrollTop = scrollTop;
}

function updateTopbar() {
  if (S.selectedExe) {
    el('tb-title').textContent = S.selectedExe;
    const count = (groupFiles(S.files)[S.selectedExe] || []).length;
    el('tb-sub').textContent = `${count} variant${count !== 1 ? 's' : ''}`;
  } else {
    el('tb-title').textContent = 'All Prefetch Files';
    el('tb-sub').textContent   = '';
  }
}

// ── Timeline ──────────────────────────────────────────────────────────────────
function visibleEvents() {
  if (!S.payload) return [];
  let evts = S.payload.events;
  if (S.selectedExe) evts = evts.filter(e => e.name === S.selectedExe);
  if (S.selectedId)  evts = evts.filter(e => e.id   === S.selectedId);
  if (S.filter === 'system')  evts = evts.filter(e => e.lane === 'system');
  if (S.filter === 'user')    evts = evts.filter(e => e.lane !== 'system');
  if (S.filter === 'flagged') evts = evts.filter(e => isFlagged(e.id));
  if (S.search)               evts = evts.filter(e => e.name.toLowerCase().includes(S.search.toLowerCase()));
  return evts;
}

function renderTimeline() {
  if (!S.payload) return;
  const evts = visibleEvents();

  if (!evts.length) {
    el('tl-axis').innerHTML = '<span style="position:absolute;left:50%;transform:translateX(-50%);font-size:11px;color:var(--t4);top:9px">No events match current filter</span>';
    el('tl-body').innerHTML = '';
    return;
  }

  const tsList = evts.map(e => e.timestamp_ms).filter(Boolean);
  let startMs = Math.min(...tsList);
  let endMs   = Math.max(...tsList);
  if (endMs - startMs < 10000) { startMs -= 5000; endMs += 5000; }

  if (S.zoom > 1) {
    const centre   = (startMs + endMs) / 2;
    const halfSpan = (endMs - startMs) / 2 / S.zoom;
    startMs = centre - halfSpan;
    endMs   = centre + halfSpan;
  }

  buildAxis(startMs, endMs);
  buildLanes(evts, startMs, endMs);
}

function buildAxis(startMs, endMs) {
  const axEl = el('tl-axis');
  const span = endMs - startMs;
  const ticks = Math.max(4, Math.min(10, Math.floor((axEl.offsetWidth || 700) / 85)));

  axEl.innerHTML = '';
  for (let i = 0; i <= ticks; i++) {
    const pct  = (i / ticks) * 100;
    const tsMs = startMs + (span * i / ticks);
    const tick = document.createElement('div');
    tick.className  = 'tl-tick';
    tick.style.left = `${pct}%`;
    tick.innerHTML  = `<span>${msToLocalTime(tsMs)}</span>`;
    axEl.appendChild(tick);
  }
}

// ── Burst detection (client-side) ──────────────────────────────────────────────
function computeBursts(evts, startMs, endMs) {
  // Only consider flagged events for burst detection
  const flagged = evts.filter(e => isFlagged(e.id)).sort((a, b) => a.timestamp_ms - b.timestamp_ms);
  const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
  const MIN_COUNT = 3;
  const bursts = [];

  let i = 0;
  while (i < flagged.length) {
    let j = i;
    while (j < flagged.length && (flagged[j].timestamp_ms - flagged[i].timestamp_ms) <= WINDOW_MS) j++;
    if (j - i >= MIN_COUNT) {
      bursts.push({
        startMs: flagged[i].timestamp_ms,
        endMs: flagged[j - 1].timestamp_ms,
        count: j - i,
      });
      i = j; // skip past this burst
    } else {
      i++;
    }
  }
  return bursts;
}

function buildLanes(evts, startMs, endMs) {
  const body = el('tl-body');
  body.innerHTML = '';
  const span = endMs - startMs || 1;
  const bursts = computeBursts(evts, startMs, endMs);

  // Set min-width for horizontal scrolling at high zoom
  const wrap = document.querySelector('.tl-canvas-wrap');
  if (S.zoom > 1) {
    const baseW = wrap.parentElement?.offsetWidth || 800;
    body.style.minWidth = `${baseW * S.zoom * 0.8}px`;
    el('tl-axis').parentElement.style.minWidth = body.style.minWidth;
  } else {
    body.style.minWidth = '';
    el('tl-axis').parentElement.style.minWidth = '';
  }

  for (const lane of LANES) {
    const laneEvts = evts.filter(e => e.lane === lane.id);

    const row = document.createElement('div');
    row.className = 'tl-lane-row';

    // Lane label
    const lbl = document.createElement('div');
    lbl.className = 'tl-lane-label';
    lbl.innerHTML = `<div class="tl-lane-dot" style="background:${lane.color}"></div>${lane.label}`;
    row.appendChild(lbl);

    // Track
    const track = document.createElement('div');
    track.className = 'tl-track';

    // Gridlines
    for (let g = 1; g < 7; g++) {
      const gl = document.createElement('div');
      gl.className  = 'tl-gridline';
      gl.style.left = `${(g / 7) * 100}%`;
      track.appendChild(gl);
    }

    // Burst bands for this lane
    for (const b of bursts) {
      const bStartPct = ((b.startMs - startMs) / span) * 100;
      const bEndPct   = ((b.endMs - startMs) / span) * 100;
      const widthPct  = Math.max(bEndPct - bStartPct, 0.5);
      if (bEndPct < -2 || bStartPct > 102) continue;

      const band = document.createElement('div');
      band.className = 'burst-band';
      band.style.left  = `${bStartPct}%`;
      band.style.width = `${widthPct}%`;
      track.appendChild(band);

      // Only show label on first lane
      if (lane === LANES[0]) {
        const label = document.createElement('div');
        label.className = 'burst-label';
        label.style.left = `${bStartPct + widthPct / 2}%`;
        label.textContent = `${b.count} in burst`;
        track.appendChild(label);
      }
    }

    // Event dots — flagged get diamond shape + severity color
    for (const e of laneEvts) {
      const pct = ((e.timestamp_ms - startMs) / span) * 100;
      if (pct < -2 || pct > 102) continue;

      const flagged = isFlagged(e.id);
      const sev     = fileSev(e.id);
      const dotColor = flagged ? SEV_COLORS[sev] || lane.color : lane.color;
      const size     = flagged ? 10 : 8;
      const isActive = S.activeEvt && S.activeEvt.id === e.id && S.activeEvt.timestamp_ms === e.timestamp_ms;

      const dot = document.createElement('div');
      dot.className = `evt${flagged ? ' flagged' : ''}${isActive ? ' active' : ''}`;
      dot.style.cssText = `left:${pct}%;width:${size}px;height:${size}px;background:${dotColor}`;

      // Rich tooltip on hover
      dot.addEventListener('mouseenter', (ev) => showTooltip(ev, e));
      dot.addEventListener('mousemove', (ev) => moveTooltip(ev));
      dot.addEventListener('mouseleave', () => hideTooltip());

      dot.addEventListener('click', () => {
        S.activeEvt = e;
        renderTimeline(); // re-render to update .active class
        showDetail(e);
      });
      track.appendChild(dot);
    }

    row.appendChild(track);
    body.appendChild(row);
  }
}

// ── Tooltip ───────────────────────────────────────────────────────────────────
function showTooltip(mouseEvt, event) {
  const tip = el('evt-tooltip');
  const sev = fileSev(event.id);
  const flagged = isFlagged(event.id);

  let sevHtml = '';
  if (flagged && sev !== 'clean' && sev !== 'low') {
    sevHtml = `<span class="tt-sev ${sev}">${sev}</span>`;
  }

  tip.innerHTML = `
    <div class="tt-name">${escHtml(event.name)}</div>
    <div class="tt-time">${msToLocalDateTime(event.timestamp_ms)}</div>
    <div class="tt-meta">Runs: ${event.run_count} · Refs: ${event.file_refs_count}</div>
    ${sevHtml}`;

  tip.classList.add('visible');
  moveTooltip(mouseEvt);
}

function moveTooltip(ev) {
  const tip = el('evt-tooltip');
  const x = ev.clientX + 14;
  const y = ev.clientY - 10;
  tip.style.left = `${Math.min(x, window.innerWidth - 300)}px`;
  tip.style.top  = `${Math.max(y, 4)}px`;
}

function hideTooltip() {
  el('evt-tooltip').classList.remove('visible');
}

// ── Detail panel ──────────────────────────────────────────────────────────────
async function showDetail(event) {
  el('dp-title').textContent  = event.name;
  el('dp-badges').innerHTML   = `<span class="badge badge-lane">${LANES.find(l=>l.id===event.lane)?.label || event.lane}</span>`;
  el('dp-body').innerHTML     = '<p class="dp-placeholder">Loading…</p>';

  let data;
  try {
    data = await apiFetch(`/api/files/${event.id}`);
  } catch {
    el('dp-body').innerHTML = '<p class="dp-placeholder" style="color:var(--red)">Failed to load file details.</p>';
    return;
  }

  const pf  = data.parsed;
  const hdr = pf.header;
  const analysis = data.analysis;

  // Severity badge for header
  const sev = fileSev(event.id);
  let sevBadge = '';
  if (sev !== 'clean') {
    sevBadge = `<span class="badge badge-${sev}">${sev}</span>`;
  }

  // Run timestamps
  const runTimes = (hdr.last_run_times || []).map(iso =>
    `<span style="font-family:var(--mono);font-size:11px;color:var(--t1)">${msToLocalDateTime(isoToMs(iso))}</span>`
  ).join('<br>');

  // Directories
  const allDirs = pf.volumes.flatMap(v => v.directories);
  const dirItems = allDirs.length
    ? allDirs.sort().map(d => `<div class="ref-item dir-item">${escHtml(d)}</div>`).join('')
    : '<div class="ref-item" style="color:var(--t3)">No directories recorded</div>';

  // File references
  const fileRefs = pf.file_metrics || [];
  const fileItems = fileRefs.map(f =>
    `<div class="ref-item file-item">${escHtml(f.filename)}</div>`
  ).join('');

  // Findings section
  let findingsHtml = '';
  if (analysis && analysis.findings && analysis.findings.length > 0) {
    const sevPriority = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
    const sorted = [...analysis.findings].sort((a, b) =>
      (sevPriority[a.severity] ?? 9) - (sevPriority[b.severity] ?? 9)
    );

    const findingRows = sorted.map(f => {
      const s = (f.severity || '').toLowerCase();
      const dotColor = SEV_COLORS[s] || '#6b7280';
      const techs = (f.mitre_techniques || []).map(t =>
        `<span class="badge-att">${escHtml(t)}</span>`
      ).join('');

      return `<div class="finding-row">
        <div class="finding-dot" style="background:${dotColor}"></div>
        <div class="finding-body">
          <div class="finding-desc">${escHtml(f.description)}</div>
          <div class="finding-meta">${escHtml(f.rule_name)}${f.matched_value ? ' · ' + escHtml(f.matched_value) : ''}</div>
          ${techs ? `<div class="finding-techs">${techs}</div>` : ''}
        </div>
      </div>`;
    }).join('');

    findingsHtml = `
      <div class="dp-section-lbl" style="margin-top:14px">
        Detection findings
        <span style="font-weight:400;color:var(--t4);margin-left:6px">${sorted.length}</span>
      </div>
      ${findingRows}`;
  }

  el('dp-badges').innerHTML = `
    ${sevBadge}
    <span class="badge badge-lane">${LANES.find(l=>l.id===event.lane)?.label || event.lane}</span>
    <span class="badge" style="background:var(--bg5);color:var(--t2);font-size:9px">${pf.file_metrics.length} refs</span>`;

  el('dp-body').innerHTML = `
    <div class="dp-grid">
      <div><div class="dp-field-lbl">Executable</div><div class="dp-field-val">${escHtml(hdr.exe_name)}</div></div>
      <div><div class="dp-field-lbl">Prefetch hash</div><div class="dp-field-val">${escHtml(hdr.prefetch_hash)}</div></div>
      <div><div class="dp-field-lbl">Run count</div><div class="dp-field-val">${hdr.run_count}</div></div>
      <div style="grid-column:1/-1">
        <div class="dp-field-lbl">Run times (local)</div>
        <div style="margin-top:3px;line-height:1.8">${runTimes || '–'}</div>
      </div>
    </div>

    ${findingsHtml}

    <div class="dp-section-lbl" style="margin-top:12px">
      Directories accessed
      <span style="font-weight:400;color:var(--t4);margin-left:6px">${allDirs.length}</span>
    </div>
    <div class="ref-list" style="max-height:120px;overflow-y:auto;margin-bottom:14px">
      ${dirItems}
    </div>

    <div class="dp-section-lbl" style="display:flex;align-items:center;gap:8px">
      Files referenced
      <span style="font-weight:400;color:var(--t4)">${fileRefs.length}</span>
      <input type="text" class="tl-search" placeholder="Filter files…"
             style="margin-left:auto;height:22px;font-size:11px;width:140px"
             oninput="filterRefList(this.value)">
    </div>
    <div id="ref-file-list" class="ref-list" style="max-height:160px;overflow-y:auto">
      ${fileItems}
    </div>`;
}

function filterRefList(query) {
  const q = query.trim().toLowerCase();
  const items = document.querySelectorAll('#ref-file-list .file-item');
  items.forEach(item => {
    item.style.display = (!q || item.textContent.toLowerCase().includes(q)) ? '' : 'none';
  });
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Controls ──────────────────────────────────────────────────────────────────
function setFilter(val, btn) {
  S.filter = val;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderStats();
  renderTimeline();
}

function setSearch(val) {
  S.search = val.trim();
  renderStats();
  renderTimeline();
}

function setZoom(z) {
  S.zoom = +z;
  el('zoom-val').textContent = `${z}×`;
  renderTimeline();
}

// ── Forensic report ───────────────────────────────────────────────────────────
function openReport() {
  window.open('/api/report', '_blank');
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let _toastTimer;
function showToast(msg, isError = false) {
  const t = el('toast');
  t.textContent = msg;
  t.className   = `toast${isError ? ' error' : ''}`;
  t.classList.remove('hidden');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
}
