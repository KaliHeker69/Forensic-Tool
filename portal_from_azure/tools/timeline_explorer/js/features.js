/**
 * Timeline Explorer - Features Module
 * Adds: stats ribbon, histogram, severity coloring, KAPE presets,
 * multi-mode search, row detail panel, bookmarks, tags, IOC matching,
 * find duplicates
 */

// ============================================
// Feature State
// ============================================

const featureState = {
    bookmarks: new Set(),
    tags: {},            // rowIndex → color
    iocList: [],
    iocMatches: new Set(),
    searchMode: 'plain', // plain|regex|fuzzy|exact
    showBookmarkedOnly: false,
    detailPanelOpen: false,
    selectedRowIndex: null,
    severityColumn: null,
    sourceColumn: null,
    detectedFormat: null, // 'hayabusa'|'evtxecmd'|null
    histogramGranularity: 'hour',
    histogramBuckets: [],
    brushRange: null,
};

// ============================================
// KAPE Format Detection
// ============================================

const KAPE_FORMATS = {
    hayabusa: {
        required: ['Timestamp', 'RuleTitle', 'Level'],
        optional: ['Computer', 'Channel', 'EventID', 'RecordID', 'Details', 'ExtraFieldInfo'],
        severityCol: 'Level',
        sourceCol: 'Channel',
        dateCol: 'Timestamp',
        pinCols: ['Timestamp', 'Level', 'RuleTitle', 'Computer', 'Channel', 'EventID']
    },
    evtxecmd: {
        required: ['TimeCreated', 'EventId', 'Channel'],
        optional: ['Provider', 'Computer', 'MapDescription', 'PayloadData1'],
        severityCol: null,
        sourceCol: 'Channel',
        dateCol: 'TimeCreated',
        pinCols: ['TimeCreated', 'EventId', 'Channel', 'Provider', 'MapDescription']
    }
};

function detectKAPEFormat(columns) {
    for (const [name, fmt] of Object.entries(KAPE_FORMATS)) {
        const colLower = columns.map(c => c.toLowerCase());
        const matched = fmt.required.every(r => colLower.includes(r.toLowerCase()));
        if (matched) return { name, ...fmt };
    }
    return null;
}

// Detect any severity-like column
function detectSeverityColumn(columns) {
    const patterns = ['level', 'rulelevel', 'severity', 'priority', 'risk'];
    return columns.find(c => patterns.includes(c.toLowerCase()));
}

// Detect source column
function detectSourceColumn(columns) {
    const patterns = ['channel', 'provider', 'source', 'computer', 'logsource'];
    return columns.find(c => patterns.includes(c.toLowerCase()));
}

// ============================================
// Severity Helpers
// ============================================

function normalizeSeverity(val) {
    if (!val) return null;
    const v = String(val).toLowerCase().trim();
    if (v === 'critical' || v === 'crit') return 'critical';
    if (v === 'high') return 'high';
    if (v === 'medium' || v === 'med') return 'medium';
    if (v === 'low') return 'low';
    if (v === 'informational' || v === 'info') return 'info';
    return null;
}

function getSeverityCounts(data, sevCol) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (!sevCol) return counts;
    data.forEach(row => {
        const sev = normalizeSeverity(row[sevCol]);
        if (sev && counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
}

// ============================================
// Row Formatter (called by Tabulator hook)
// ============================================

window.formatTimelineRow = function (row) {
    const data = row.getData();
    const el = row.getElement();
    const idx = row.getPosition();

    // Severity coloring
    if (featureState.severityColumn) {
        const sev = normalizeSeverity(data[featureState.severityColumn]);
        el.classList.remove('severity-critical', 'severity-high', 'severity-medium', 'severity-low');
        if (sev === 'critical') el.classList.add('severity-critical');
        else if (sev === 'high') el.classList.add('severity-high');
        else if (sev === 'medium') el.classList.add('severity-medium');
        else if (sev === 'low') el.classList.add('severity-low');
    }

    // Bookmark indicator
    if (featureState.bookmarks.has(idx)) {
        el.classList.add('bookmarked');
    } else {
        el.classList.remove('bookmarked');
    }

    // IOC match indicator
    if (featureState.iocMatches.has(idx)) {
        el.classList.add('ioc-match');
    } else {
        el.classList.remove('ioc-match');
    }

    // Tag indicator
    const tag = featureState.tags[idx];
    const existingDot = el.querySelector('.tag-indicator');
    if (existingDot) existingDot.remove();
    if (tag) {
        const dot = document.createElement('span');
        dot.className = 'tag-indicator';
        dot.style.background = getTagColor(tag);
        el.prepend(dot);
    }
};

function getTagColor(name) {
    const map = { red: '#ff4444', orange: '#ff8c00', yellow: '#ffd700', green: '#3fb950', blue: '#58a6ff', purple: '#bc8cff' };
    return map[name] || name;
}

// ============================================
// Row Click → Detail Panel
// ============================================

window.onTimelineRowClick = function (row) {
    if (!row) return;
    const data = row.getData();
    if (!data) return;

    // Use getIndex() for stable row ID (getPosition may be undefined in some versions)
    let idx;
    try { idx = row.getIndex(); } catch (e) { idx = null; }
    if (idx === null || idx === undefined) {
        try { idx = row.getPosition(true); } catch (e) { idx = 0; }
    }
    featureState.selectedRowIndex = idx;

    const panel = document.getElementById('detailPanel');
    const content = document.getElementById('detailContent');
    const titleEl = document.getElementById('detailTitle');

    if (!panel) { console.error('Detail panel element #detailPanel not found'); return; }
    if (!content) { console.error('Detail content element #detailContent not found'); return; }

    // Update header like irflow: "Row Detail → Row N (ID: N)"
    if (titleEl) {
        titleEl.innerHTML = `<i class="fa-solid fa-info-circle"></i> Row Detail → Row ${idx} (ID: ${idx})`;
    }

    // Build two-column table
    let html = '<table class="detail-table">';
    for (const [key, val] of Object.entries(data)) {
        const isEmpty = val === null || val === undefined || String(val).trim() === '';
        const strVal = String(val);
        const hexDecoded = isEmpty ? null : tryDecodeHex(strVal);

        let displayVal;
        if (isEmpty) {
            displayVal = '<span class="empty-val">(hidden)</span>';
        } else if (hexDecoded) {
            // Show both hex and decoded with a toggle
            const hexId = 'hex_' + Math.random().toString(36).substr(2, 9);
            displayVal = `<div class="hex-decode-container">
                <div class="hex-original">${escapeHtmlF(strVal.length > 80 ? strVal.substring(0, 80) + '…' : strVal)}</div>
                <div class="hex-decoded-block" id="${hexId}">
                    <span class="hex-decode-label"><i class="fa-solid fa-language"></i> Decoded</span>
                    <pre class="hex-decoded-text">${escapeHtmlF(hexDecoded)}</pre>
                </div>
            </div>`;
        } else {
            displayVal = escapeHtmlF(strVal);
        }
        const valClass = isEmpty ? 'field-value empty-val' : 'field-value';
        html += `<tr>
            <td class="field-name">${escapeHtmlF(key)}</td>
            <td class="${valClass}">${displayVal}</td>
        </tr>`;
    }
    html += '</table>';
    content.innerHTML = html;

    // Update bookmark button state
    const bmBtn = document.getElementById('detailBookmarkBtn');
    if (bmBtn) {
        bmBtn.innerHTML = featureState.bookmarks.has(idx)
            ? '<i class="fa-solid fa-bookmark"></i>'
            : '<i class="fa-regular fa-bookmark"></i>';
    }

    // Update tag selection
    const currentTag = featureState.tags[idx] || '';
    document.querySelectorAll('.tag-dot').forEach(dot => {
        dot.classList.toggle('active', dot.dataset.color === currentTag);
    });

    // Open bottom panel
    panel.classList.add('open');
    featureState.detailPanelOpen = true;
};

function escapeHtmlF(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

// ============================================
// Hex Decoding for ADS / Forensic Data
// ============================================

/**
 * Detect if a string is a hex-encoded value and attempt to decode it.
 * Returns the decoded text if the input looks like a valid hex string
 * and the result is mostly printable, or null otherwise.
 */
function tryDecodeHex(str) {
    if (!str || typeof str !== 'string') return null;
    const trimmed = str.trim();

    // Must be even length, at least 8 hex chars, and only hex characters
    if (trimmed.length < 8 || trimmed.length % 2 !== 0) return null;
    if (!/^[0-9A-Fa-f]+$/.test(trimmed)) return null;

    // Decode hex to bytes
    const bytes = [];
    for (let i = 0; i < trimmed.length; i += 2) {
        bytes.push(parseInt(trimmed.substring(i, i + 2), 16));
    }

    // Try UTF-8 decoding first
    let decoded;
    try {
        decoded = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
    } catch (e) {
        // Fall back to latin-1
        decoded = bytes.map(b => String.fromCharCode(b)).join('');
    }

    // Check if the result is mostly printable (ASCII 0x20-0x7E, plus common controls like \r\n\t)
    let printable = 0;
    let total = 0;
    for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i);
        total++;
        if ((code >= 0x20 && code <= 0x7E) || code === 0x0A || code === 0x0D || code === 0x09) {
            printable++;
        }
    }

    // At least 70% printable to be considered valid text
    if (total === 0 || (printable / total) < 0.7) return null;

    // Clean up: replace null bytes and other unprintable chars with dots
    decoded = decoded.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '·');

    return decoded;
}

// ============================================
// Stats Ribbon
// ============================================

function updateStatsRibbon() {
    const s = window.APP_STATE;
    if (!s || !s.rawData || s.rawData.length === 0) return;

    const ribbon = document.getElementById('statsRibbon');
    if (ribbon) ribbon.style.display = 'flex';

    // Total events
    const totalEl = document.getElementById('statTotalEvents');
    if (totalEl) totalEl.textContent = s.rawData.length.toLocaleString();

    // Sources
    const srcCol = featureState.sourceColumn;
    if (srcCol) {
        const uniq = new Set(s.rawData.map(r => r[srcCol]).filter(Boolean));
        const srcEl = document.getElementById('statSources');
        if (srcEl) srcEl.textContent = uniq.size.toLocaleString();
    }

    // Time span
    if (s.dateColumn) {
        let minDate = null, maxDate = null;
        s.rawData.forEach(r => {
            const d = new Date(r[s.dateColumn]);
            if (!isNaN(d.getTime())) {
                if (!minDate || d < minDate) minDate = d;
                if (!maxDate || d > maxDate) maxDate = d;
            }
        });
        if (minDate && maxDate) {
            const diffMs = maxDate - minDate;
            const days = Math.floor(diffMs / 86400000);
            const hours = Math.floor((diffMs % 86400000) / 3600000);
            const spanEl = document.getElementById('statTimeSpan');
            if (spanEl) spanEl.textContent = days > 0 ? `${days}d ${hours}h` : `${hours}h ${Math.floor((diffMs % 3600000) / 60000)}m`;
        }
    }

    // Alerts (high + critical)
    if (featureState.severityColumn) {
        const counts = getSeverityCounts(s.rawData, featureState.severityColumn);
        const alertEl = document.getElementById('statAlerts');
        if (alertEl) alertEl.textContent = (counts.critical + counts.high).toLocaleString();

        // Severity pills
        const pills = document.querySelectorAll('.severity-pill');
        const order = ['critical', 'high', 'medium', 'low', 'info'];
        pills.forEach((pill, i) => {
            if (order[i]) pill.textContent = counts[order[i]].toLocaleString();
        });
    } else {
        const alertEl = document.getElementById('statAlerts');
        if (alertEl) alertEl.textContent = '0';
        document.querySelectorAll('.severity-pill').forEach(pill => {
            pill.textContent = '0';
        });
    }

    // Detected format
    const fmtEl = document.getElementById('detectedFormat');
    const fmtName = document.getElementById('formatName');
    const activeFormat = featureState.detectedFormat
        ? featureState.detectedFormat.charAt(0).toUpperCase() + featureState.detectedFormat.slice(1)
        : (s.fileFormatLabel || null);

    if (fmtEl && fmtName) {
        if (activeFormat) {
            fmtEl.style.display = 'flex';
            fmtName.textContent = activeFormat;
        } else {
            fmtEl.style.display = 'none';
        }
    }
}

// ============================================
// Histogram
// ============================================

function buildHistogram() {
    const s = window.APP_STATE;
    if (!s || !s.dateColumn || !s.rawData || s.rawData.length === 0) return;

    const container = document.getElementById('histogramContainer');
    if (container) container.style.display = 'block';

    const canvas = document.getElementById('histogramCanvas');
    if (!canvas) return;

    // Parse all dates
    const dates = [];
    s.rawData.forEach((row, i) => {
        const d = new Date(row[s.dateColumn]);
        if (!isNaN(d.getTime())) dates.push({
            date: d, index: i,
            severity: featureState.severityColumn ? normalizeSeverity(row[featureState.severityColumn]) : null
        });
    });

    if (dates.length === 0) return;

    dates.sort((a, b) => a.date - b.date);
    const minDate = dates[0].date;
    const maxDate = dates[dates.length - 1].date;

    // Bucket by granularity
    const gran = featureState.histogramGranularity;
    let bucketMs;
    if (gran === 'minute') bucketMs = 60000;
    else if (gran === 'hour') bucketMs = 3600000;
    else bucketMs = 86400000;

    const bucketStart = new Date(Math.floor(minDate.getTime() / bucketMs) * bucketMs);
    const bucketEnd = new Date(Math.ceil(maxDate.getTime() / bucketMs) * bucketMs);
    const numBuckets = Math.max(1, Math.min(600, Math.ceil((bucketEnd - bucketStart) / bucketMs)));

    const buckets = new Array(numBuckets).fill(null).map((_, i) => ({
        count: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
        time: new Date(bucketStart.getTime() + i * bucketMs)
    }));

    dates.forEach(d => {
        const idx = Math.min(numBuckets - 1, Math.floor((d.date - bucketStart) / bucketMs));
        buckets[idx].count++;
        if (d.severity === 'critical') buckets[idx].critical++;
        else if (d.severity === 'high') buckets[idx].high++;
        else if (d.severity === 'medium') buckets[idx].medium++;
        else if (d.severity === 'low') buckets[idx].low++;
        else buckets[idx].info++;
    });

    featureState.histogramBuckets = buckets;
    featureState._histBucketStart = bucketStart;
    featureState._histBucketMs = bucketMs;

    drawHistogram(canvas, buckets);
    updateHistogramAxis(buckets);
    initHistogramInteraction(canvas, buckets, bucketStart, bucketMs);
}

function drawHistogram(canvas, buckets) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const maxCount = Math.max(1, ...buckets.map(b => b.count));
    const pad = { left: 6, right: 6, top: 8, bottom: 4 };
    const chartW = w - pad.left - pad.right;
    const chartH = h - pad.top - pad.bottom;
    const barWidth = Math.max(1, chartW / buckets.length);
    const gap = barWidth > 4 ? 1 : 0;

    ctx.clearRect(0, 0, w, h);

    // Draw subtle gridlines
    ctx.strokeStyle = 'rgba(48, 54, 61, 0.4)';
    ctx.lineWidth = 0.5;
    for (let i = 1; i <= 4; i++) {
        const y = pad.top + (chartH * i / 4);
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(w - pad.right, y);
        ctx.stroke();
    }

    // Draw bars
    buckets.forEach((b, i) => {
        if (b.count === 0) return;
        const barH = (b.count / maxCount) * chartH;
        const x = pad.left + i * barWidth;
        const y = pad.top + chartH - barH;

        // Create gradient based on severity composition
        const grad = ctx.createLinearGradient(x, y, x, y + barH);

        if (b.critical > 0 && (b.critical / b.count) > 0.3) {
            grad.addColorStop(0, 'rgba(255, 68, 68, 0.9)');
            grad.addColorStop(1, 'rgba(255, 68, 68, 0.4)');
        } else if (b.high > 0 && (b.high / b.count) > 0.3) {
            grad.addColorStop(0, 'rgba(255, 140, 0, 0.9)');
            grad.addColorStop(1, 'rgba(255, 140, 0, 0.4)');
        } else if (b.medium > 0 && (b.medium / b.count) > 0.3) {
            grad.addColorStop(0, 'rgba(255, 215, 0, 0.8)');
            grad.addColorStop(1, 'rgba(255, 215, 0, 0.3)');
        } else {
            grad.addColorStop(0, 'rgba(244, 96, 54, 0.8)');
            grad.addColorStop(1, 'rgba(244, 96, 54, 0.25)');
        }

        ctx.fillStyle = grad;

        // Rounded top corners for wider bars
        const radius = barWidth > 6 ? 2 : 0;
        if (radius > 0) {
            ctx.beginPath();
            ctx.moveTo(x + gap, y + barH);
            ctx.lineTo(x + gap, y + radius);
            ctx.quadraticCurveTo(x + gap, y, x + gap + radius, y);
            ctx.lineTo(x + barWidth - gap - radius, y);
            ctx.quadraticCurveTo(x + barWidth - gap, y, x + barWidth - gap, y + radius);
            ctx.lineTo(x + barWidth - gap, y + barH);
            ctx.closePath();
            ctx.fill();
        } else {
            ctx.fillRect(x + gap, y, barWidth - gap * 2, barH);
        }

        // Glow effect for high-count bars
        if (b.count > maxCount * 0.7) {
            ctx.save();
            ctx.shadowColor = b.critical > 0 ? 'rgba(255, 68, 68, 0.5)' : 'rgba(244, 96, 54, 0.4)';
            ctx.shadowBlur = 8;
            ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
            ctx.fillRect(x + gap, y, barWidth - gap * 2, Math.min(barH, 3));
            ctx.restore();
        }
    });

    // Draw brush selection overlay
    if (featureState.brushRange) {
        const { start, end } = featureState.brushRange;
        ctx.fillStyle = 'rgba(88, 166, 255, 0.12)';
        ctx.fillRect(start, 0, end - start, h);
        ctx.strokeStyle = 'rgba(88, 166, 255, 0.6)';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 3]);
        ctx.strokeRect(start, 0, end - start, h);
        ctx.setLineDash([]);
    }
}

function updateHistogramAxis(buckets) {
    const axisEl = document.getElementById('histAxis');
    if (!axisEl || buckets.length === 0) return;

    // Show 5 evenly-spaced time labels
    const labels = [];
    const count = Math.min(7, buckets.length);
    for (let i = 0; i < count; i++) {
        const idx = Math.floor((i / (count - 1)) * (buckets.length - 1));
        const t = buckets[idx]?.time;
        if (t) {
            const gran = featureState.histogramGranularity;
            let label;
            if (gran === 'day') {
                label = t.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
            } else {
                label = t.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
            }
            labels.push(label);
        }
    }
    axisEl.innerHTML = labels.map(l => `<span>${l}</span>`).join('');
}

function initHistogramInteraction(canvas, buckets, bucketStart, bucketMs) {
    let isDragging = false;
    let startX = 0;
    const pad = { left: 6, right: 6 };
    const tooltip = document.getElementById('histTooltip');

    // Hover tooltip
    canvas.onmousemove = (e) => {
        const rect = canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;

        if (isDragging) {
            featureState.brushRange = { start: Math.min(startX, mouseX), end: Math.max(startX, mouseX) };
            drawHistogram(canvas, buckets);
            if (tooltip) tooltip.style.display = 'none';
            return;
        }

        // Show tooltip
        const chartW = rect.width - pad.left - pad.right;
        const barWidth = chartW / buckets.length;
        const idx = Math.floor((mouseX - pad.left) / barWidth);

        if (idx >= 0 && idx < buckets.length && tooltip) {
            const b = buckets[idx];
            const gran = featureState.histogramGranularity;
            let timeStr;
            if (gran === 'day') {
                timeStr = b.time.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
            } else {
                timeStr = b.time.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
            }

            let html = `<div style="font-weight:700;color:#f46036;">${b.count} event${b.count !== 1 ? 's' : ''}</div>`;
            html += `<div style="color:#8b949e;">${timeStr}</div>`;
            if (featureState.severityColumn && (b.critical + b.high + b.medium) > 0) {
                let parts = [];
                if (b.critical > 0) parts.push(`<span style="color:#ff4444;">● ${b.critical} crit</span>`);
                if (b.high > 0) parts.push(`<span style="color:#ff8c00;">● ${b.high} high</span>`);
                if (b.medium > 0) parts.push(`<span style="color:#ffd700;">● ${b.medium} med</span>`);
                html += `<div style="margin-top:2px;">${parts.join('  ')}</div>`;
            }
            tooltip.innerHTML = html;
            tooltip.style.display = 'block';

            // Position tooltip
            const tx = Math.min(mouseX + 10, rect.width - 180);
            tooltip.style.left = tx + 'px';
            tooltip.style.top = '4px';
        }
    };

    canvas.onmouseleave = () => {
        if (tooltip) tooltip.style.display = 'none';
    };

    // Brush selection
    canvas.onmousedown = (e) => {
        const rect = canvas.getBoundingClientRect();
        startX = e.clientX - rect.left;
        isDragging = true;
    };

    canvas.onmouseup = (e) => {
        if (!isDragging) return;
        isDragging = false;

        if (!featureState.brushRange || featureState.brushRange.end - featureState.brushRange.start < 5) {
            featureState.brushRange = null;
            drawHistogram(canvas, buckets);
            return;
        }

        // Convert pixel range to bucket index range
        const rect = canvas.getBoundingClientRect();
        const chartW = rect.width - pad.left - pad.right;
        const startPct = (featureState.brushRange.start - pad.left) / chartW;
        const endPct = (featureState.brushRange.end - pad.left) / chartW;

        const startIdx = Math.max(0, Math.floor(startPct * buckets.length));
        const endIdx = Math.min(buckets.length - 1, Math.floor(endPct * buckets.length));

        const fromDate = new Date(bucketStart.getTime() + startIdx * bucketMs);
        const toDate = new Date(bucketStart.getTime() + (endIdx + 1) * bucketMs);

        // Set date filter inputs
        const els = window.APP_ELEMENTS;
        if (els) {
            els.dateFrom.value = fromDate.toISOString().slice(0, 16);
            els.dateTo.value = toDate.toISOString().slice(0, 16);
        }

        // Show clear button
        const clearBtn = document.getElementById('histClearBrush');
        if (clearBtn) clearBtn.style.display = 'inline-flex';

        if (typeof applyAllFilters === 'function') applyAllFilters();
    };
}

// ============================================
// Multi-Mode Search
// ============================================

function initSearchModes() {
    const btns = document.querySelectorAll('.search-mode-btn');
    const label = document.getElementById('searchModeLabel');

    btns.forEach(btn => {
        btn.addEventListener('click', () => {
            btns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            featureState.searchMode = btn.dataset.mode;
            if (label) label.textContent = btn.dataset.mode.charAt(0).toUpperCase() + btn.dataset.mode.slice(1);

            // Re-apply search
            const searchEl = document.getElementById('globalSearch');
            if (searchEl && searchEl.value.trim()) {
                if (typeof applyAllFilters === 'function') applyAllFilters();
            }
        });
    });

    // Override the default filter to use search modes
    patchSearchFilter();
}

function patchSearchFilter() {
    // Store original applyAllFilters reference
    const origApply = window.applyAllFilters || (typeof applyAllFilters === 'function' ? applyAllFilters : null);
    // We don't override; instead, the search mode is read inside the existing filter function.
    // The search filter in applyAllFilters already does substring matching.
    // We enhance it by checking featureState.searchMode
}

// Fuzzy match using simple Levenshtein
function fuzzyMatch(text, pattern, maxDist = 2) {
    text = text.toLowerCase();
    pattern = pattern.toLowerCase();
    if (text.includes(pattern)) return true;
    if (pattern.length > 30) return text.includes(pattern); // skip Levenshtein for long patterns

    // Sliding window Levenshtein
    for (let i = 0; i <= text.length - pattern.length + maxDist; i++) {
        const chunk = text.substring(i, i + pattern.length + maxDist);
        if (levenshtein(chunk, pattern) <= maxDist) return true;
    }
    return false;
}

function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
            dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
    return dp[m][n];
}

// ============================================
// Bookmarks & Tags
// ============================================

function toggleBookmark(idx) {
    if (featureState.bookmarks.has(idx)) {
        featureState.bookmarks.delete(idx);
    } else {
        featureState.bookmarks.add(idx);
    }
    updateBookmarkCount();
    saveBookmarks();
    const s = window.APP_STATE;
    if (s && s.table) s.table.redraw(true);
}

function updateBookmarkCount() {
    const el = document.getElementById('bookmarkCount');
    if (el) el.textContent = featureState.bookmarks.size;
}

function saveBookmarks() {
    const s = window.APP_STATE;
    if (!s || !s.fileName) return;
    const key = 'tl_bookmarks_' + s.fileName;
    const data = { bookmarks: [...featureState.bookmarks], tags: featureState.tags };
    try { localStorage.setItem(key, JSON.stringify(data)); } catch (e) { }
}

function loadBookmarks() {
    const s = window.APP_STATE;
    if (!s || !s.fileName) return;
    const key = 'tl_bookmarks_' + s.fileName;
    try {
        const saved = localStorage.getItem(key);
        if (saved) {
            const data = JSON.parse(saved);
            featureState.bookmarks = new Set(data.bookmarks || []);
            featureState.tags = data.tags || {};
        }
    } catch (e) { }
    updateBookmarkCount();
}

function initBookmarkHandlers() {
    // Detail panel bookmark button
    const bmBtn = document.getElementById('detailBookmarkBtn');
    if (bmBtn) {
        bmBtn.addEventListener('click', () => {
            if (featureState.selectedRowIndex !== null) {
                toggleBookmark(featureState.selectedRowIndex);
                // Update the button icon
                if (featureState.bookmarks.has(featureState.selectedRowIndex)) {
                    bmBtn.innerHTML = '<i class="fa-solid fa-bookmark"></i>';
                } else {
                    bmBtn.innerHTML = '<i class="fa-regular fa-bookmark"></i>';
                }
            }
        });
    }

    // Toggle bookmarked only
    const toggleBtn = document.getElementById('toggleBookmarkedBtn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            featureState.showBookmarkedOnly = !featureState.showBookmarkedOnly;
            toggleBtn.classList.toggle('active', featureState.showBookmarkedOnly);
            if (featureState.showBookmarkedOnly) {
                toggleBtn.innerHTML = '<i class="fa-solid fa-bookmark"></i> Bookmarks';
            } else {
                toggleBtn.innerHTML = '<i class="fa-regular fa-bookmark"></i> Bookmarks';
            }
            if (typeof applyAllFilters === 'function') applyAllFilters();
        });
    }

    // Tag dots
    document.querySelectorAll('.tag-dot').forEach(dot => {
        dot.addEventListener('click', () => {
            if (featureState.selectedRowIndex === null) return;
            const color = dot.dataset.color;
            if (color) {
                featureState.tags[featureState.selectedRowIndex] = color;
            } else {
                delete featureState.tags[featureState.selectedRowIndex];
            }
            document.querySelectorAll('.tag-dot').forEach(d => d.classList.toggle('active', d.dataset.color === color));
            saveBookmarks();
            const s = window.APP_STATE;
            if (s && s.table) s.table.redraw(true);
        });
    });

    // Detail panel copy button
    const copyBtn = document.getElementById('detailCopyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const s = window.APP_STATE;
            if (s && s.table && featureState.selectedRowIndex !== null) {
                const rows = s.table.getRows();
                const row = rows.find(r => r.getPosition() === featureState.selectedRowIndex);
                if (row) {
                    navigator.clipboard.writeText(JSON.stringify(row.getData(), null, 2))
                        .then(() => { if (typeof showNotification === 'function') showNotification('Copied as JSON', 'success'); });
                }
            }
        });
    }

    // Close detail panel
    const closeBtn = document.getElementById('closeDetailPanel');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            const panel = document.getElementById('detailPanel');
            if (panel) panel.classList.remove('open');
            featureState.detailPanelOpen = false;
        });
    }
}

// ============================================
// IOC Matching
// ============================================

function initIOCHandlers() {
    const iocBtn = document.getElementById('iocMatchBtn');
    const iocModal = document.getElementById('iocModal');
    const closeModal = document.getElementById('closeIocModal');
    const scanBtn = document.getElementById('iocScanBtn');
    const clearBtn = document.getElementById('iocClearBtn');
    const textarea = document.getElementById('iocTextarea');
    const countEl = document.getElementById('iocCount');

    if (iocBtn) {
        iocBtn.addEventListener('click', () => {
            if (iocModal) iocModal.style.display = 'flex';
        });
    }

    if (closeModal) {
        closeModal.addEventListener('click', () => {
            if (iocModal) iocModal.style.display = 'none';
        });
    }

    if (textarea) {
        textarea.addEventListener('input', () => {
            const lines = textarea.value.split('\n').map(l => l.trim()).filter(Boolean);
            if (countEl) countEl.textContent = `${lines.length} IOC${lines.length !== 1 ? 's' : ''}`;
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            if (textarea) textarea.value = '';
            if (countEl) countEl.textContent = '0 IOCs';
            featureState.iocList = [];
            featureState.iocMatches.clear();
            const s = window.APP_STATE;
            if (s && s.table) s.table.redraw(true);
            if (typeof showNotification === 'function') showNotification('IOC matches cleared', 'info');
        });
    }

    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            const s = window.APP_STATE;
            if (!s || !s.rawData) return;

            const lines = (textarea ? textarea.value : '').split('\n').map(l => l.trim()).filter(Boolean);
            if (lines.length === 0) return;

            featureState.iocList = lines;
            featureState.iocMatches.clear();

            // Scan all rows
            const lowerIOCs = lines.map(ioc => ioc.toLowerCase());
            s.rawData.forEach((row, i) => {
                const rowStr = Object.values(row).map(v => String(v || '').toLowerCase()).join('|');
                for (const ioc of lowerIOCs) {
                    if (rowStr.includes(ioc)) {
                        featureState.iocMatches.add(i);
                        break;
                    }
                }
            });

            if (iocModal) iocModal.style.display = 'none';
            if (s.table) s.table.redraw(true);
            if (typeof showNotification === 'function') {
                showNotification(`Found ${featureState.iocMatches.size} rows matching ${lines.length} IOCs`, featureState.iocMatches.size > 0 ? 'warning' : 'info');
            }
        });
    }
}

// ============================================
// Find Duplicates
// ============================================

function initFindDuplicates() {
    const btn = document.getElementById('findDuplicatesBtn');
    const selector = document.getElementById('duplicatesSelector');
    const list = document.getElementById('duplicatesColumnList');

    if (!btn || !selector || !list) return;

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const s = window.APP_STATE;
        if (!s || !s.columns) return;

        list.innerHTML = '';
        s.columns.forEach(col => {
            const item = document.createElement('div');
            item.className = 'column-list-item';
            item.innerHTML = `<i class="fa-solid fa-clone" style="color:var(--text-faint);width:16px;"></i> ${escapeHtmlF(col)}`;
            item.addEventListener('click', () => {
                findDuplicatesInColumn(col);
                selector.style.display = 'none';
            });
            list.appendChild(item);
        });

        // Position
        const rect = btn.getBoundingClientRect();
        selector.style.position = 'fixed';
        selector.style.top = (rect.bottom + 4) + 'px';
        selector.style.left = rect.left + 'px';
        selector.style.display = 'block';
    });

    document.addEventListener('click', () => {
        selector.style.display = 'none';
    });
}

function findDuplicatesInColumn(col) {
    const s = window.APP_STATE;
    if (!s || !s.table || !s.rawData) return;

    // Count occurrences
    const counts = {};
    s.rawData.forEach(row => {
        const val = String(row[col] || '');
        counts[val] = (counts[val] || 0) + 1;
    });

    const duplicateValues = new Set(Object.keys(counts).filter(k => counts[k] > 1));

    if (duplicateValues.size === 0) {
        if (typeof showNotification === 'function') showNotification(`No duplicates found in "${col}"`, 'info');
        return;
    }

    // Apply filter to show only duplicates
    s.table.setFilter((data) => {
        return duplicateValues.has(String(data[col] || ''));
    });

    if (typeof showNotification === 'function') {
        showNotification(`Showing ${duplicateValues.size} duplicate values in "${col}"`, 'warning');
    }
}

// ============================================
// Histogram Controls
// ============================================

function initHistogramControls() {
    // Granularity buttons
    document.querySelectorAll('.hist-granularity').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.hist-granularity').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            featureState.histogramGranularity = btn.dataset.gran;
            featureState.brushRange = null;
            buildHistogram();
        });
    });

    // Clear brush
    const clearBtn = document.getElementById('histClearBrush');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            featureState.brushRange = null;
            clearBtn.style.display = 'none';
            const els = window.APP_ELEMENTS;
            if (els) {
                els.dateFrom.value = '';
                els.dateTo.value = '';
            }
            if (typeof applyAllFilters === 'function') applyAllFilters();
            const canvas = document.getElementById('histogramCanvas');
            if (canvas) drawHistogram(canvas, featureState.histogramBuckets);
        });
    }

    // Resize handler
    window.addEventListener('resize', () => {
        const canvas = document.getElementById('histogramCanvas');
        if (canvas && featureState.histogramBuckets.length > 0) {
            drawHistogram(canvas, featureState.histogramBuckets);
        }
    });

    // Toggle graph visibility
    const toggleBtn = document.getElementById('histToggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const wrapper = document.querySelector('.histogram-canvas-wrapper');
            const axis = document.getElementById('histAxis');
            const icon = toggleBtn.querySelector('i');
            if (wrapper) {
                const hidden = wrapper.style.display === 'none';
                wrapper.style.display = hidden ? 'block' : 'none';
                if (axis) axis.style.display = hidden ? 'flex' : 'none';
                if (icon) {
                    icon.className = hidden ? 'fa-solid fa-chevron-up' : 'fa-solid fa-chevron-down';
                }
                // Redraw when showing again
                if (hidden) {
                    const canvas = document.getElementById('histogramCanvas');
                    if (canvas && featureState.histogramBuckets.length > 0) {
                        drawHistogram(canvas, featureState.histogramBuckets);
                    }
                }
            }
        });
    }
}

// ============================================
// Severity Filter (sidebar)
// ============================================

function initSeverityFilter() {
    const section = document.getElementById('severityFilterSection');
    if (!section) return;

    // Show only if severity column detected
    if (!featureState.severityColumn) {
        section.style.display = 'none';
        return;
    }

    section.querySelector('.filter-section-header')?.addEventListener('click', () => {
        section.classList.toggle('expanded');
    });

    section.querySelectorAll('.severity-check input').forEach(cb => {
        cb.addEventListener('change', () => {
            if (typeof applyAllFilters === 'function') applyAllFilters();
        });
    });
}

// Get active severity levels from filter checkboxes
function getActiveSeverities() {
    const checks = document.querySelectorAll('.severity-check input:checked');
    return [...checks].map(cb => cb.value);
}

// ============================================
// Context Menu Bookmark Extension
// ============================================

function initContextMenuBookmark() {
    // Hook into context menu
    document.querySelector('[data-action="bookmark"]')?.addEventListener('click', () => {
        const s = window.APP_STATE;
        if (s && s.contextMenuTarget) {
            const row = s.contextMenuTarget;
            const idx = row.getPosition ? row.getPosition() : null;
            if (idx !== null) toggleBookmark(idx);
        }
        const cm = document.getElementById('contextMenu');
        if (cm) cm.classList.remove('show');
    });
}

// ============================================
// Show IOC button after data load
// ============================================

function showFeatureButtons() {
    const iocBtn = document.getElementById('iocMatchBtn');
    if (iocBtn) iocBtn.style.display = 'inline-flex';
}

// ============================================
// Main Data-Loaded Hook
// ============================================

window.onTimelineDataLoaded = function () {
    const s = window.APP_STATE;
    if (!s) return;

    // Detect KAPE format
    const kape = detectKAPEFormat(s.columns);
    if (kape) {
        featureState.detectedFormat = kape.name;
        featureState.severityColumn = kape.severityCol;
        featureState.sourceColumn = kape.sourceCol;
    } else {
        featureState.detectedFormat = null;
        featureState.severityColumn = detectSeverityColumn(s.columns);
        featureState.sourceColumn = detectSourceColumn(s.columns);
    }

    // Attach row click handler directly to the Tabulator instance
    if (s.table) {
        try {
            s.table.on('rowClick', function (e, row) {
                window.onTimelineRowClick(row);
            });
        } catch (err) {
            console.warn('Could not attach rowClick via .on(), using DOM fallback');
        }

        // Also add a DOM-level fallback: listen for clicks on tabulator rows
        const holder = document.getElementById('tableHolder');
        if (holder) {
            holder.addEventListener('click', function (e) {
                // Walk up DOM to find a tabulator-row element
                let target = e.target;
                while (target && target !== holder) {
                    if (target.classList && target.classList.contains('tabulator-row')) {
                        // Get the row component from Tabulator
                        try {
                            const rows = s.table.getRows('active');
                            const rowEl = target;
                            for (const row of rows) {
                                if (row.getElement() === rowEl) {
                                    window.onTimelineRowClick(row);
                                    break;
                                }
                            }
                        } catch (err) {
                            console.warn('Row click fallback error:', err);
                        }
                        break;
                    }
                    target = target.parentElement;
                }
            });
        }
    }

    loadBookmarks();
    updateStatsRibbon();
    buildHistogram();
    initSeverityFilter();
    showFeatureButtons();
};

// ============================================
// Initialize Features on DOM Ready
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initSearchModes();
    initBookmarkHandlers();
    initIOCHandlers();
    initFindDuplicates();
    initHistogramControls();
    initContextMenuBookmark();
});
