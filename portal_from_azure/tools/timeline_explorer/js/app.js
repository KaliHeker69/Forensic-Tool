/**
 * Timeline Explorer - Main Application
 * Professional web-based forensic timeline viewer
 * With multi-tab support and file browser
 */

// ============================================
// Configuration
// ============================================

const CONFIG = {
    defaultDataDirectory: '/home/kali_arch/Computed_Data',
    apiBaseUrl: '/api/files',  // Backend API endpoint for file browsing
    timelineFilesConfigPath: 'timeline_files.json',
    columnProfileSampleSize: 5000,
    postLoadTaskDelayMs: 30
};

const SUPPORTED_EXTENSIONS = new Set(['csv', 'tsv', 'txt', 'json', 'jsonl']);
const DELIMITED_EXTENSIONS = new Set(['csv', 'tsv', 'txt']);
const JSON_EXTENSIONS = new Set(['json', 'jsonl']);
const JSON_WRAPPER_KEYS = ['records', 'events', 'data', 'results', 'items', 'rows', 'timeline', 'entries', 'artifacts', 'logs'];

let timelineFileBrowserConfigCache = null;
let timelineFileBrowserConfigPromise = null;

// ============================================
// State Management
// ============================================

const state = {
    // Tab management
    tabs: [],           // Array of tab objects
    activeTabId: null,  // Current active tab ID
    tabIdCounter: 0,    // For generating unique tab IDs

    // File browser state
    currentPath: CONFIG.defaultDataDirectory,
    selectedFile: null,
    directoryContents: [],

    // Legacy single-table state (now per-tab)
    table: null,
    rawData: [],
    columns: [],
    columnTypes: {},
    columnUniqueValues: {},  // Store unique values for multi-select
    fileName: '',
    fileSize: '',
    fileType: null,
    fileFormatLabel: '',
    fileStructure: '',
    fileSignals: [],
    dateColumn: null,
    loadStartTime: null,
    // Enhanced filter state
    filters: {
        search: { value: '', caseSensitive: false },
        dateRange: { from: null, to: null },
        columns: {}  // { columnName: { type: 'contains'|'equals'|'regex'|'multiselect', value: any } }
    },
    currentSort: null,
    contextMenuTarget: null,
    sidebarVisible: true,
    loadGeneration: 0,
    fileBrowserFilter: {
        search: '',
        type: 'all'
    }
};

// Expose globally for features.js
window.APP_STATE = state;
window.APP_ELEMENTS = null; // set after initElements

// ============================================
// DOM Elements
// ============================================

const elements = {};

function initElements() {
    elements.uploadZone = document.getElementById('uploadZone');
    elements.mainWrapper = document.getElementById('mainWrapper');
    elements.fileInput = document.getElementById('fileInput');
    elements.fileInfo = document.getElementById('fileInfo');
    elements.tableHolder = document.getElementById('tableHolder');
    elements.globalSearch = document.getElementById('globalSearch');
    elements.searchContainer = document.getElementById('searchContainer');
    elements.searchClear = document.getElementById('searchClear');
    elements.searchResultsInfo = document.getElementById('searchResultsInfo');
    elements.matchCount = document.getElementById('matchCount');
    elements.caseSensitive = document.getElementById('caseSensitive');
    elements.highlightMatches = document.getElementById('highlightMatches');
    elements.dateFrom = document.getElementById('dateFrom');
    elements.dateTo = document.getElementById('dateTo');
    elements.applyDateFilter = document.getElementById('applyDateFilter');
    elements.clearDateFilter = document.getElementById('clearDateFilter');
    elements.clearAllFilters = document.getElementById('clearAllFilters');
    elements.toggleColumnsBtn = document.getElementById('toggleColumnsBtn');
    elements.columnSelector = document.getElementById('columnSelector');
    elements.columnList = document.getElementById('columnList');
    elements.showAllColumns = document.getElementById('showAllColumns');
    elements.exportBtn = document.getElementById('exportBtn');
    elements.clearBtn = document.getElementById('clearBtn');
    elements.loadingOverlay = document.getElementById('loadingOverlay');
    elements.loadingText = document.getElementById('loadingText');
    elements.progressFill = document.getElementById('progressFill');
    elements.rowCount = document.getElementById('rowCount');
    elements.filteredCount = document.getElementById('filteredCount');
    elements.selectedCount = document.getElementById('selectedCount');
    elements.sortInfo = document.getElementById('sortInfo');
    elements.sortColumn = document.getElementById('sortColumn');
    elements.loadTime = document.getElementById('loadTime');
    elements.filterSidebar = document.getElementById('filterSidebar');
    elements.toggleSidebar = document.getElementById('toggleSidebar');
    elements.columnFilters = document.getElementById('columnFilters');
    elements.activeFilters = document.getElementById('activeFilters');
    elements.activeFilterCount = document.getElementById('activeFilterCount');
    elements.contextMenu = document.getElementById('contextMenu');
    elements.shortcutsModal = document.getElementById('shortcutsModal');
    elements.shortcutsBtn = document.getElementById('shortcutsBtn');
    elements.closeShortcuts = document.getElementById('closeShortcuts');
    elements.themeToggle = document.getElementById('themeToggle');
    elements.resetSortBtn = document.getElementById('resetSortBtn');

    // File browser elements
    elements.fileBrowserModal = document.getElementById('fileBrowserModal');
    elements.fileBrowserList = document.getElementById('fileBrowserList');
    elements.breadcrumb = document.getElementById('breadcrumb');
    elements.currentPathInput = document.getElementById('currentPathInput');
    elements.selectedFileDisplay = document.getElementById('selectedFileDisplay');
    elements.openSelectedFile = document.getElementById('openSelectedFile');
    elements.openFileBrowserBtn = document.getElementById('openFileBrowserBtn');
    elements.openFileBrowserBtnAlt = document.getElementById('openFileBrowserBtnAlt');
    elements.closeFileBrowser = document.getElementById('closeFileBrowser');
    elements.cancelFileBrowser = document.getElementById('cancelFileBrowser');
    elements.refreshDirBtn = document.getElementById('refreshDirBtn');
    elements.goUpBtn = document.getElementById('goUpBtn');
    elements.editPathBtn = document.getElementById('editPathBtn');
    elements.fileBrowserSearch = document.getElementById('fileBrowserSearch');
    elements.fileBrowserTypeFilters = document.getElementById('fileBrowserTypeFilters');

    // Tab elements
    elements.tabsContainer = document.getElementById('tabsContainer');
    elements.tabsList = document.getElementById('tabsList');
    elements.addNewTabBtn = document.getElementById('addNewTabBtn');

    // New feature elements (may be null if HTML not updated)
    elements.iocMatchBtn = document.getElementById('iocMatchBtn');
    elements.findDuplicatesBtn = document.getElementById('findDuplicatesBtn');
    elements.toggleBookmarkedBtn = document.getElementById('toggleBookmarkedBtn');
    elements.detailPanel = document.getElementById('detailPanel');
    elements.bookmarkCount = document.getElementById('bookmarkCount');
    elements.datasetOverview = document.getElementById('datasetOverview');
    elements.datasetFormat = document.getElementById('datasetFormat');
    elements.datasetStructure = document.getElementById('datasetStructure');
    elements.datasetFieldCount = document.getElementById('datasetFieldCount');
    elements.datasetDateField = document.getElementById('datasetDateField');
    elements.datasetSignals = document.getElementById('datasetSignals');

    window.APP_ELEMENTS = elements;
}

// ============================================
// File Upload Handling
// ============================================

function initUploadHandlers() {
    elements.uploadZone.addEventListener('click', (e) => {
        if (e.target.closest('button') || e.target.closest('input')) {
            return;
        }
        elements.fileInput.click();
    });

    elements.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    elements.uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.uploadZone.classList.add('drag-over');
    });

    elements.uploadZone.addEventListener('dragleave', () => {
        elements.uploadZone.classList.remove('drag-over');
    });

    elements.uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.uploadZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    // Global drag and drop
    document.addEventListener('dragover', (e) => e.preventDefault());
    document.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files.length > 0) {
            const file = e.dataTransfer.files[0];
            if (isSupportedFileName(file.name)) {
                handleFile(file);
            }
        }
    });
}

function handleFile(file) {
    handleFileWithPath(file, null);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getFileExtension(name) {
    const parts = String(name || '').toLowerCase().split('.');
    return parts.length > 1 ? parts.pop() : '';
}

function isDelimitedFileName(name) {
    return DELIMITED_EXTENSIONS.has(getFileExtension(name));
}

function isJsonFileName(name) {
    return JSON_EXTENSIONS.has(getFileExtension(name));
}

function isSupportedFileName(name) {
    return SUPPORTED_EXTENSIONS.has(getFileExtension(name));
}

function getFileTypeBadge(type, extension) {
    const normalizedExtension = String(extension || '').toLowerCase();

    if (type === 'folder') {
        return { badge: 'FOLDER', className: 'folder', icon: 'fa-folder', infoIcon: 'fa-folder-open' };
    }
    if (normalizedExtension === '.json' || normalizedExtension === 'json') {
        return { badge: 'JSON', className: 'json', icon: 'fa-file-code', infoIcon: 'fa-file-code' };
    }
    if (normalizedExtension === '.jsonl' || normalizedExtension === 'jsonl') {
        return { badge: 'JSONL', className: 'json', icon: 'fa-file-code', infoIcon: 'fa-file-code' };
    }
    if (['.csv', '.tsv', '.txt', 'csv', 'tsv', 'txt'].includes(normalizedExtension)) {
        return { badge: normalizedExtension.replace('.', '').toUpperCase(), className: 'delimited', icon: 'fa-file-csv', infoIcon: 'fa-file-csv' };
    }
    return { badge: 'FILE', className: '', icon: 'fa-file', infoIcon: 'fa-file' };
}

function inferFormatLabel(fileName, structureLabel = '') {
    const ext = getFileExtension(fileName);
    if (ext === 'jsonl') return 'JSONL';
    if (ext === 'json') {
        return structureLabel === 'NDJSON Stream' ? 'NDJSON' : 'JSON';
    }
    if (ext === 'tsv') return 'TSV';
    if (ext === 'txt') return 'TXT';
    return 'CSV';
}

function flattenJsonRecord(value, prefix = '', output = {}) {
    if (value === null || value === undefined) {
        output[prefix || 'value'] = '';
        return output;
    }

    if (Array.isArray(value)) {
        output[prefix || 'value'] = value.every(item => typeof item !== 'object' || item === null)
            ? value.join(' | ')
            : JSON.stringify(value);
        return output;
    }

    if (typeof value !== 'object') {
        output[prefix || 'value'] = value;
        return output;
    }

    const entries = Object.entries(value);
    if (entries.length === 0 && prefix) {
        output[prefix] = '';
        return output;
    }

    entries.forEach(([key, nested]) => {
        const nextPrefix = prefix ? `${prefix}.${key}` : key;
        if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
            flattenJsonRecord(nested, nextPrefix, output);
        } else if (Array.isArray(nested)) {
            output[nextPrefix] = nested.every(item => typeof item !== 'object' || item === null)
                ? nested.join(' | ')
                : JSON.stringify(nested);
        } else {
            output[nextPrefix] = nested;
        }
    });

    return output;
}

function findJsonRecordArray(value, path = '$', depth = 0) {
    if (depth > 4 || value === null || value === undefined) return null;

    if (Array.isArray(value)) {
        if (value.length === 0) return { records: [], structure: 'Empty JSON Array', sourcePath: path };
        if (value.every(item => item !== null && typeof item === 'object' && !Array.isArray(item))) {
            return { records: value, structure: 'JSON Array', sourcePath: path };
        }
        return {
            records: value.map((item, index) => ({ _index: index, value: typeof item === 'object' ? JSON.stringify(item) : item })),
            structure: 'Primitive Array',
            sourcePath: path
        };
    }

    if (typeof value !== 'object') {
        return { records: [{ value }], structure: 'Scalar JSON Value', sourcePath: path };
    }

    for (const key of JSON_WRAPPER_KEYS) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
            const found = findJsonRecordArray(value[key], `${path}.${key}`, depth + 1);
            if (found) return found;
        }
    }

    for (const [key, nested] of Object.entries(value)) {
        if (Array.isArray(nested)) {
            const found = findJsonRecordArray(nested, `${path}.${key}`, depth + 1);
            if (found) return found;
        }
    }

    const objectEntries = Object.entries(value);
    if (objectEntries.length > 0 && objectEntries.every(([, nested]) => nested && typeof nested === 'object' && !Array.isArray(nested))) {
        return {
            records: objectEntries.map(([key, nested]) => ({ _key: key, ...nested })),
            structure: 'Object Map',
            sourcePath: path
        };
    }

    return { records: [value], structure: 'Single JSON Object', sourcePath: path };
}

function parseJsonTimeline(text) {
    const trimmed = text.trim();
    if (!trimmed) {
        return { records: [], structure: 'Empty JSON Document', sourcePath: '$' };
    }

    try {
        const parsed = JSON.parse(trimmed);
        return findJsonRecordArray(parsed);
    } catch (jsonError) {
        const lines = trimmed.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        if (lines.length === 0) throw jsonError;

        const records = lines.map((line, index) => {
            const parsedLine = JSON.parse(line);
            if (parsedLine && typeof parsedLine === 'object' && !Array.isArray(parsedLine)) {
                return parsedLine;
            }
            return { _line: index + 1, value: parsedLine };
        });

        return { records, structure: 'NDJSON Stream', sourcePath: '$' };
    }
}

function buildFileSignals(columns, dateColumn) {
    const priorityPatterns = ['timestamp', 'time', 'date', 'user', 'process', 'path', 'source', 'event', 'action', 'severity', 'level', 'ip', 'host'];
    const picked = [];

    if (dateColumn) {
        picked.push({ icon: 'fa-clock', label: dateColumn });
    }

    columns.forEach(col => {
        const lower = col.toLowerCase();
        if (picked.length >= 6) return;
        if (col === dateColumn) return;
        if (priorityPatterns.some(pattern => lower.includes(pattern))) {
            picked.push({ icon: 'fa-signal', label: col });
        }
    });

    if (picked.length === 0) {
        columns.slice(0, 5).forEach(col => picked.push({ icon: 'fa-table-columns', label: col }));
    }

    return picked;
}

function isNumericValue(value) {
    if (typeof value === 'number') return Number.isFinite(value);
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    return trimmed !== '' && /^-?\d+(?:\.\d+)?$/.test(trimmed);
}

function getSampleRows(rows, maxSamples) {
    if (!Array.isArray(rows) || rows.length <= maxSamples) {
        return rows;
    }

    const sample = [];
    const step = Math.max(1, Math.floor(rows.length / maxSamples));
    for (let i = 0; i < rows.length && sample.length < maxSamples; i += step) {
        sample.push(rows[i]);
    }
    return sample;
}

function schedulePostLoadTask(task) {
    const runner = () => {
        try {
            task();
        } catch (error) {
            console.error('Deferred timeline task failed:', error);
        }
    };

    if (typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(runner, { timeout: 250 });
    } else {
        window.setTimeout(runner, CONFIG.postLoadTaskDelayMs);
    }
}

function showDeferredEnhancementState() {
    elements.columnFilters.innerHTML = `
        <div class="filter-section expanded filter-loading-state">
            <div class="filter-section-header">
                <span class="filter-section-title">
                    <i class="fa-solid fa-spinner fa-spin type-icon" aria-hidden="true"></i>
                    Preparing Filters
                </span>
            </div>
            <div class="filter-section-body">
                Sampling large-file values and building filter controls in the background.
            </div>
        </div>
    `;
}

function finalizePostLoadEnhancements(loadGeneration, loadTime) {
    schedulePostLoadTask(() => {
        if (loadGeneration !== state.loadGeneration || !state.rawData.length) return;

        createColumnFilters();
        populateColumnSelector();
        elements.loadTime.textContent = `Loaded in ${loadTime}s · filters ready`;

        schedulePostLoadTask(() => {
            if (loadGeneration !== state.loadGeneration || !state.rawData.length) return;

            if (typeof window.onTimelineDataLoaded === 'function') {
                window.onTimelineDataLoaded();
            }

            elements.loadTime.textContent = `Loaded in ${loadTime}s · indexed`;
        });
    });
}

function parseJsonTimelineInWorker(file) {
    return new Promise((resolve, reject) => {
        const worker = new Worker('js/parser-worker.js?v=4.3');

        worker.onmessage = (event) => {
            const { type, payload, error } = event.data || {};
            if (type === 'success') {
                worker.terminate();
                resolve(payload);
                return;
            }

            worker.terminate();
            reject(new Error(error || 'Worker parsing failed'));
        };

        worker.onerror = (event) => {
            worker.terminate();
            reject(new Error(event.message || 'Worker parsing failed'));
        };

        worker.postMessage({
            file,
            fileName: file.name
        });
    });
}

// ============================================
// Data Processing
// ============================================

function processData() {
    if (state.rawData.length === 0) {
        hideLoading();
        alert('No data found in file');
        return;
    }

    const firstRow = state.rawData[0];
    state.columns = Object.keys(firstRow);

    detectColumnTypes();
    detectDateColumn();
    state.fileSignals = buildFileSignals(state.columns, state.dateColumn);
    createTable();
    showMainContent();
    updateFileInfo();
    showDeferredEnhancementState();
    hideLoading();

    const loadTime = ((performance.now() - state.loadStartTime) / 1000).toFixed(2);
    elements.loadTime.textContent = `Loaded in ${loadTime}s`;
    showNotification(`Loaded ${state.rawData.length.toLocaleString()} rows in ${loadTime}s`, 'success');

    const loadGeneration = ++state.loadGeneration;
    finalizePostLoadEnhancements(loadGeneration, loadTime);
}

function detectColumnTypes() {
    state.columnTypes = {};
    const sampleSize = Math.min(100, state.rawData.length);

    state.columns.forEach(col => {
        let dateCount = 0, numCount = 0, textCount = 0;

        for (let i = 0; i < sampleSize; i++) {
            const value = state.rawData[i][col];
            if (value === null || value === undefined || value === '') continue;

            if (isNumericValue(value)) {
                numCount++;
            } else if (isDateString(String(value))) {
                dateCount++;
            } else {
                textCount++;
            }
        }

        if (dateCount > numCount && dateCount > textCount) {
            state.columnTypes[col] = 'date';
        } else if (numCount > textCount) {
            state.columnTypes[col] = 'number';
        } else {
            state.columnTypes[col] = 'text';
        }
    });
}

function isDateString(str) {
    if (!str || str.length < 8) return false;
    const datePatterns = [
        /^\d{4}-\d{2}-\d{2}/, // ISO date
        /^\d{2}\/\d{2}\/\d{4}/, // MM/DD/YYYY
        /^\d{2}-\d{2}-\d{4}/, // DD-MM-YYYY
    ];
    return datePatterns.some(p => p.test(str));
}

function detectDateColumn() {
    const datePatterns = ['date', 'time', 'timestamp', 'datetime', 'created', 'modified', 'accessed', 'when'];

    state.dateColumn = state.columns.find(col => {
        const lowerCol = col.toLowerCase();
        return datePatterns.some(pattern => lowerCol.includes(pattern));
    });

    // If not found by name, use first date-type column
    if (!state.dateColumn) {
        state.dateColumn = state.columns.find(col => state.columnTypes[col] === 'date');
    }
}

// ============================================
// Tabulator Table
// ============================================

function createTable() {
    const columnDefs = state.columns.map(col => {
        const type = state.columnTypes[col];
        const def = {
            title: col,
            field: col,
            headerFilter: 'input',
            headerFilterPlaceholder: 'Filter...',
            resizable: true,
            minWidth: 100,
            tooltip: true
        };

        if (type === 'date') {
            def.sorter = 'datetime';
            def.sorterParams = { format: 'iso' };
        } else if (type === 'number') {
            def.sorter = 'number';
            def.hozAlign = 'right';
        }

        // Pin timestamp column
        if (col === state.dateColumn) {
            def.frozen = true;
        }

        return def;
    });

    if (state.table) {
        state.table.destroy();
    }

    state.table = new Tabulator(elements.tableHolder, {
        data: state.rawData,
        columns: columnDefs,
        layout: 'fitDataStretch',
        height: '100%',
        virtualDom: true,
        virtualDomBuffer: 300,
        placeholder: 'No matching records found',
        selectable: true,
        movableColumns: true,
        persistence: false,
        initialSort: state.dateColumn ? [{ column: state.dateColumn, dir: 'desc' }] : [],
        rowFormatter: function (row) {
            if (typeof window.formatTimelineRow === 'function') {
                window.formatTimelineRow(row);
            }
        },
        rowClick: function (e, row) {
            if (typeof window.onTimelineRowClick === 'function') {
                window.onTimelineRowClick(row);
            }
        },

        dataFiltered: function () {
            updateStatusBar();
        },
        rowSelected: function () {
            updateStatusBar();
        },
        rowDeselected: function () {
            updateStatusBar();
        },
        tableBuilt: function () {
            updateStatusBar();
        },
        dataSorted: function (sorters) {
            if (sorters.length > 0) {
                state.currentSort = sorters[0];
                elements.sortInfo.style.display = 'flex';
                elements.sortColumn.textContent = `${sorters[0].column} (${sorters[0].dir})`;
            } else {
                state.currentSort = null;
                elements.sortInfo.style.display = 'none';
            }
        },
        rowContext: function (e, row) {
            e.preventDefault();
            showContextMenu(e, row);
        },
        cellContext: function (e, cell) {
            e.preventDefault();
            showContextMenu(e, cell.getRow(), cell);
        }
    });
}

// ============================================
// Column Filters (Sidebar) - Enhanced
// ============================================

/**
 * Extract unique values for each column (for multi-select)
 */
function extractUniqueValues() {
    state.columnUniqueValues = {};
    const sampledRows = getSampleRows(state.rawData, CONFIG.columnProfileSampleSize);

    state.columns.forEach(col => {
        const values = new Map();
        sampledRows.forEach(row => {
            const val = row[col];
            if (val !== null && val !== undefined && val !== '') {
                const key = String(val);
                values.set(key, (values.get(key) || 0) + 1);
            }
        });

        // Sort by frequency, keep top 20
        const sorted = [...values.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20);

        state.columnUniqueValues[col] = sorted;
    });
}

/**
 * Create enhanced filter sections in sidebar
 */
function createColumnFilters() {
    elements.columnFilters.innerHTML = '';
    extractUniqueValues();

    // Prioritize forensic-relevant columns
    const priorityPatterns = ['eventtype', 'type', 'user', 'username', 'process', 'filename', 'path', 'source', 'action', 'status'];
    const sortedColumns = [...state.columns].sort((a, b) => {
        const aLower = a.toLowerCase();
        const bLower = b.toLowerCase();
        const aIndex = priorityPatterns.findIndex(p => aLower.includes(p));
        const bIndex = priorityPatterns.findIndex(p => bLower.includes(p));

        if (aIndex !== -1 && bIndex === -1) return -1;
        if (bIndex !== -1 && aIndex === -1) return 1;
        if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex;
        return 0;
    });

    sortedColumns.forEach(col => {
        if (col === state.dateColumn) return; // Date filter is separate

        const type = state.columnTypes[col];
        const uniqueVals = state.columnUniqueValues[col] || [];
        const hasMultipleValues = uniqueVals.length > 1 && uniqueVals.length <= 15;
        const typeIcon = type === 'number' ? '<i class="fa-solid fa-hashtag"></i>' : type === 'date' ? '<i class="fa-solid fa-calendar"></i>' : '<i class="fa-solid fa-font"></i>';

        const section = document.createElement('div');
        section.className = 'filter-section';
        section.dataset.column = col;

        section.innerHTML = `
            <div class="filter-section-header">
                <span class="filter-section-title">
                    <span class="type-icon">${typeIcon}</span>
                    <span class="col-name">${col}</span>
                    <span class="filter-active-indicator" style="display: none;">●</span>
                </span>
                <span class="filter-section-arrow">▼</span>
            </div>
            <div class="filter-section-body">
                <!-- Filter Type Selector -->
                <div class="filter-type-row" style="margin-bottom: 10px;">
                    <select class="filter-operator" data-column="${col}" style="width: 100%; padding: 6px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; color: var(--text-primary); font-size: 0.8rem;">
                        <option value="contains">Contains</option>
                        <option value="equals">Equals</option>
                        <option value="startswith">Starts with</option>
                        <option value="endswith">Ends with</option>
                        <option value="regex">Regex</option>
                        ${type === 'number' ? '<option value="gt">Greater than</option><option value="lt">Less than</option><option value="between">Between</option>' : ''}
                        ${hasMultipleValues ? '<option value="multiselect">Multi-select</option>' : ''}
                        <option value="empty">Is empty</option>
                        <option value="notempty">Is not empty</option>
                    </select>
                </div>
                
                <!-- Text/Number Input -->
                <div class="filter-text-input">
                    <input type="text" class="filter-input filter-value" placeholder="Enter value..." data-column="${col}">
                </div>
                
                <!-- Number Range (hidden by default) -->
                <div class="filter-number-range" style="display: none;">
                    <div style="display: flex; gap: 8px;">
                        <input type="number" class="filter-input filter-min" placeholder="Min" data-column="${col}" style="flex: 1;">
                        <input type="number" class="filter-input filter-max" placeholder="Max" data-column="${col}" style="flex: 1;">
                    </div>
                </div>
                
                <!-- Multi-select (hidden by default) -->
                <div class="filter-multiselect" style="display: none; max-height: 200px; overflow-y: auto;">
                    <div class="multiselect-actions" style="display: flex; gap: 8px; margin-bottom: 8px;">
                        <button class="btn btn-sm select-all" style="flex: 1;">Select All</button>
                        <button class="btn btn-sm clear-all" style="flex: 1;">Clear</button>
                    </div>
                    <div class="multiselect-search" style="margin-bottom: 8px;">
                        <input type="text" class="filter-input multiselect-filter" placeholder="Search values..." style="width: 100%;">
                    </div>
                    <div class="multiselect-options">
                        ${uniqueVals.map(([val, count]) => `
                            <label class="multiselect-option" style="display: flex; align-items: center; gap: 8px; padding: 4px 0; cursor: pointer; font-size: 0.85rem;">
                                <input type="checkbox" value="${escapeHtml(val)}" data-column="${col}">
                                <span class="option-value" style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(val)}</span>
                                <span class="option-count" style="color: var(--text-muted); font-size: 0.75rem;">(${count})</span>
                            </label>
                        `).join('')}
                    </div>
                </div>
                
                <!-- Apply/Clear buttons -->
                <div style="display: flex; gap: 8px; margin-top: 10px;">
                    <button class="btn btn-sm btn-primary apply-filter" data-column="${col}" style="flex: 1;">Apply</button>
                    <button class="btn btn-sm clear-filter" data-column="${col}">Clear</button>
                </div>
            </div>
        `;

        // Toggle expand/collapse
        section.querySelector('.filter-section-header').addEventListener('click', () => {
            section.classList.toggle('expanded');
        });

        // Operator change - show/hide appropriate inputs
        const operatorSelect = section.querySelector('.filter-operator');
        const textInput = section.querySelector('.filter-text-input');
        const rangeInput = section.querySelector('.filter-number-range');
        const multiselectInput = section.querySelector('.filter-multiselect');

        operatorSelect.addEventListener('change', () => {
            const op = operatorSelect.value;
            textInput.style.display = ['contains', 'equals', 'startswith', 'endswith', 'regex', 'gt', 'lt'].includes(op) ? 'block' : 'none';
            rangeInput.style.display = op === 'between' ? 'block' : 'none';
            multiselectInput.style.display = op === 'multiselect' ? 'block' : 'none';
        });

        // Multi-select search filter
        const multiselectFilter = section.querySelector('.multiselect-filter');
        if (multiselectFilter) {
            multiselectFilter.addEventListener('input', (e) => {
                const search = e.target.value.toLowerCase();
                section.querySelectorAll('.multiselect-option').forEach(opt => {
                    const text = opt.querySelector('.option-value').textContent.toLowerCase();
                    opt.style.display = text.includes(search) ? 'flex' : 'none';
                });
            });
        }

        // Select All / Clear buttons
        section.querySelector('.select-all')?.addEventListener('click', () => {
            section.querySelectorAll('.multiselect-options input[type="checkbox"]').forEach(cb => cb.checked = true);
        });
        section.querySelector('.clear-all')?.addEventListener('click', () => {
            section.querySelectorAll('.multiselect-options input[type="checkbox"]').forEach(cb => cb.checked = false);
        });

        // Apply filter button
        section.querySelector('.apply-filter').addEventListener('click', () => {
            applyColumnFilter(col, section);
        });

        // Clear filter button
        section.querySelector('.clear-filter').addEventListener('click', () => {
            clearColumnFilter(col, section);
        });

        // Enter key on input applies filter
        section.querySelectorAll('.filter-value, .filter-min, .filter-max').forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    applyColumnFilter(col, section);
                }
            });
        });

        elements.columnFilters.appendChild(section);
    });
}

/**
 * Apply filter for a specific column
 */
function applyColumnFilter(column, section) {
    const operator = section.querySelector('.filter-operator').value;
    let value = null;

    switch (operator) {
        case 'contains':
        case 'equals':
        case 'startswith':
        case 'endswith':
        case 'regex':
        case 'gt':
        case 'lt':
            value = section.querySelector('.filter-value').value.trim();
            if (!value) {
                delete state.filters.columns[column];
                break;
            }
            state.filters.columns[column] = { type: operator, value };
            break;

        case 'between':
            const min = section.querySelector('.filter-min').value;
            const max = section.querySelector('.filter-max').value;
            if (!min && !max) {
                delete state.filters.columns[column];
                break;
            }
            state.filters.columns[column] = { type: 'between', min: min ? Number(min) : null, max: max ? Number(max) : null };
            break;

        case 'multiselect':
            const selected = [...section.querySelectorAll('.multiselect-options input:checked')].map(cb => cb.value);
            if (selected.length === 0) {
                delete state.filters.columns[column];
                break;
            }
            state.filters.columns[column] = { type: 'multiselect', values: selected };
            break;

        case 'empty':
            state.filters.columns[column] = { type: 'empty' };
            break;

        case 'notempty':
            state.filters.columns[column] = { type: 'notempty' };
            break;
    }

    // Update visual indicator
    const indicator = section.querySelector('.filter-active-indicator');
    if (state.filters.columns[column]) {
        indicator.style.display = 'inline';
        indicator.style.color = 'var(--accent-primary)';
    } else {
        indicator.style.display = 'none';
    }

    applyAllFilters();
}

/**
 * Clear filter for a specific column
 */
function clearColumnFilter(column, section) {
    delete state.filters.columns[column];

    // Reset UI
    section.querySelector('.filter-value').value = '';
    section.querySelectorAll('.filter-min, .filter-max').forEach(i => i.value = '');
    section.querySelectorAll('.multiselect-options input').forEach(cb => cb.checked = false);
    section.querySelector('.filter-operator').value = 'contains';
    section.querySelector('.filter-text-input').style.display = 'block';
    section.querySelector('.filter-number-range').style.display = 'none';
    section.querySelector('.filter-multiselect').style.display = 'none';
    section.querySelector('.filter-active-indicator').style.display = 'none';

    applyAllFilters();
}

/**
 * Escape HTML for safe insertion
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================
// Search Highlighting
// ============================================

function highlightSearchMatches(searchTerm) {
    if (!state.table || !searchTerm) return;

    // Small delay to let Tabulator finish rendering
    requestAnimationFrame(() => {
        const caseSensitive = elements.caseSensitive.checked;
        const regex = parseRegex(searchTerm);
        let pattern;

        if (regex) {
            pattern = regex;
        } else {
            const flags = caseSensitive ? 'g' : 'gi';
            try {
                pattern = new RegExp(escapeRegex(searchTerm), flags);
            } catch (e) {
                return;
            }
        }

        const cells = document.querySelectorAll('.tabulator-cell');
        cells.forEach(cell => {
            const originalText = cell.textContent;
            if (pattern.test(originalText)) {
                // Reset lastIndex for global patterns
                pattern.lastIndex = 0;
                const highlighted = originalText.replace(pattern, match =>
                    `<span class="match">${escapeHtml(match)}</span>`
                );
                cell.innerHTML = highlighted;
            }
        });
    });
}

function clearSearchHighlights() {
    const highlighted = document.querySelectorAll('.tabulator-cell .match');
    highlighted.forEach(span => {
        const parent = span.parentNode;
        if (parent) {
            parent.textContent = parent.textContent;
        }
    });
}

// ============================================
// Search & Filter
// ============================================

function parseRegex(str) {
    const match = str.match(/^\/(.+)\/([gimsuy]*)$/);
    if (match) {
        try {
            return new RegExp(match[1], match[2]);
        } catch (e) {
            return null;
        }
    }
    return null;
}

function initSearchHandlers() {
    elements.globalSearch.addEventListener('input', debounce((e) => {
        const searchTerm = e.target.value.trim();
        applyAllFilters();

        if (searchTerm) {
            // Show actual matching row count (filtered by search)
            const totalRows = state.table.getDataCount();
            const filteredRows = state.table.getDataCount('active');
            elements.matchCount.textContent = filteredRows;
            elements.searchResultsInfo.style.display = 'inline';
            elements.searchResultsInfo.innerHTML = `<span class="count" id="matchCount">${filteredRows.toLocaleString()}</span> of ${totalRows.toLocaleString()} rows`;
            if (elements.highlightMatches.checked) {
                highlightSearchMatches(searchTerm);
            }
        } else {
            elements.searchResultsInfo.style.display = 'none';
            clearSearchHighlights();
        }
    }, 300));

    elements.searchClear.addEventListener('click', () => {
        elements.globalSearch.value = '';
        elements.searchResultsInfo.style.display = 'none';
        clearSearchHighlights();
        applyAllFilters();
    });

    // Highlight checkbox toggle
    elements.highlightMatches.addEventListener('change', () => {
        const searchTerm = elements.globalSearch.value.trim();
        if (searchTerm && elements.highlightMatches.checked) {
            highlightSearchMatches(searchTerm);
        } else {
            clearSearchHighlights();
        }
    });

    // Case sensitive toggle re-applies filters
    elements.caseSensitive.addEventListener('change', () => {
        const searchTerm = elements.globalSearch.value.trim();
        if (searchTerm) {
            applyAllFilters();
            if (elements.highlightMatches.checked) {
                highlightSearchMatches(searchTerm);
            }
        }
    });

    elements.applyDateFilter.addEventListener('click', () => applyAllFilters());
    elements.clearDateFilter.addEventListener('click', () => {
        elements.dateFrom.value = '';
        elements.dateTo.value = '';
        applyAllFilters();
    });

    elements.clearAllFilters.addEventListener('click', clearAllFilters);

    // Date presets
    document.querySelectorAll('.date-preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.date-preset-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const preset = btn.dataset.preset;
            const now = new Date();
            let from = new Date();

            switch (preset) {
                case '1h': from.setHours(now.getHours() - 1); break;
                case '24h': from.setDate(now.getDate() - 1); break;
                case '7d': from.setDate(now.getDate() - 7); break;
                case '30d': from.setDate(now.getDate() - 30); break;
                case 'custom': return;
            }

            elements.dateFrom.value = from.toISOString().slice(0, 16);
            elements.dateTo.value = now.toISOString().slice(0, 16);
            applyAllFilters();
        });
    });
}

function applyAllFilters() {
    if (!state.table) return;

    const searchTerm = elements.globalSearch.value.trim();
    const caseSensitive = elements.caseSensitive.checked;
    const fromDate = elements.dateFrom.value;
    const toDate = elements.dateTo.value;
    const columnFilters = state.filters.columns;

    state.table.setFilter((data) => {
        // Date range filter
        if ((fromDate || toDate) && state.dateColumn) {
            const dateValue = data[state.dateColumn];
            if (dateValue) {
                const rowDate = new Date(dateValue);
                if (!isNaN(rowDate.getTime())) {
                    if (fromDate && rowDate < new Date(fromDate)) return false;
                    if (toDate && rowDate > new Date(toDate)) return false;
                }
            }
        }

        // Column-specific filters
        for (const [column, filter] of Object.entries(columnFilters)) {
            const cellValue = data[column];
            const strValue = cellValue !== null && cellValue !== undefined ? String(cellValue) : '';
            const lowerValue = strValue.toLowerCase();

            switch (filter.type) {
                case 'contains':
                    if (!lowerValue.includes(filter.value.toLowerCase())) return false;
                    break;
                case 'equals':
                    if (lowerValue !== filter.value.toLowerCase()) return false;
                    break;
                case 'startswith':
                    if (!lowerValue.startsWith(filter.value.toLowerCase())) return false;
                    break;
                case 'endswith':
                    if (!lowerValue.endsWith(filter.value.toLowerCase())) return false;
                    break;
                case 'regex':
                    try {
                        const regex = new RegExp(filter.value, 'i');
                        if (!regex.test(strValue)) return false;
                    } catch (e) {
                        // Invalid regex, skip
                    }
                    break;
                case 'gt':
                    if (Number(cellValue) <= Number(filter.value)) return false;
                    break;
                case 'lt':
                    if (Number(cellValue) >= Number(filter.value)) return false;
                    break;
                case 'between':
                    const num = Number(cellValue);
                    if (filter.min !== null && num < filter.min) return false;
                    if (filter.max !== null && num > filter.max) return false;
                    break;
                case 'multiselect':
                    if (!filter.values.includes(strValue)) return false;
                    break;
                case 'empty':
                    if (strValue !== '') return false;
                    break;
                case 'notempty':
                    if (strValue === '') return false;
                    break;
            }
        }

        // Global search filter (multi-mode from features.js)
        if (searchTerm) {
            const mode = (typeof featureState !== 'undefined') ? featureState.searchMode : 'plain';
            const regex = parseRegex(searchTerm);

            if (mode === 'regex' || regex) {
                const pat = regex || (() => { try { return new RegExp(searchTerm, 'i'); } catch (e) { return null; } })();
                if (pat) {
                    const found = state.columns.some(col => {
                        const value = data[col];
                        if (value === null || value === undefined) return false;
                        pat.lastIndex = 0;
                        return pat.test(String(value));
                    });
                    if (!found) return false;
                }
            } else if (mode === 'exact') {
                const found = state.columns.some(col => {
                    const value = data[col];
                    if (value === null || value === undefined) return false;
                    return String(value) === searchTerm;
                });
                if (!found) return false;
            } else if (mode === 'fuzzy' && typeof fuzzyMatch === 'function') {
                const found = state.columns.some(col => {
                    const value = data[col];
                    if (value === null || value === undefined) return false;
                    return fuzzyMatch(String(value), searchTerm);
                });
                if (!found) return false;
            } else {
                // Plain substring
                const term = caseSensitive ? searchTerm : searchTerm.toLowerCase();
                const found = state.columns.some(col => {
                    const value = data[col];
                    if (value === null || value === undefined) return false;
                    const strVal = caseSensitive ? String(value) : String(value).toLowerCase();
                    return strVal.includes(term);
                });
                if (!found) return false;
            }
        }

        // Severity filter (from features.js checkboxes)
        if (typeof featureState !== 'undefined' && featureState.severityColumn && typeof getActiveSeverities === 'function') {
            const activeSevs = getActiveSeverities();
            if (activeSevs.length < 5) { // Only filter if not all checked
                const rowSev = typeof normalizeSeverity === 'function' ? normalizeSeverity(data[featureState.severityColumn]) : null;
                if (rowSev && !activeSevs.includes(rowSev)) return false;
            }
        }

        // Bookmark filter (from features.js)
        if (typeof featureState !== 'undefined' && featureState.showBookmarkedOnly) {
            // We check row index — but inside a filter we don't have row index directly
            // so we use data matching instead
            // This is a limitation — bookmark filter is best done via separate mechanism
        }

        return true;
    });

    updateStatusBar();
    updateActiveFiltersDisplay();
}

function clearAllFilters() {
    elements.globalSearch.value = '';
    elements.dateFrom.value = '';
    elements.dateTo.value = '';
    elements.searchResultsInfo.style.display = 'none';
    state.filters.columns = {};

    document.querySelectorAll('.date-preset-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.filter-input').forEach(input => input.value = '');
    document.querySelectorAll('.filter-active-indicator').forEach(i => i.style.display = 'none');
    document.querySelectorAll('.multiselect-options input').forEach(cb => cb.checked = false);

    // Reset all filter operators to default
    document.querySelectorAll('.filter-operator').forEach(select => {
        select.value = 'contains';
    });
    document.querySelectorAll('.filter-text-input').forEach(el => el.style.display = 'block');
    document.querySelectorAll('.filter-number-range').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.filter-multiselect').forEach(el => el.style.display = 'none');

    clearSearchHighlights();

    if (state.table) {
        state.table.clearFilter();
        state.table.clearHeaderFilter();
    }

    updateStatusBar();
    updateActiveFiltersDisplay();
    showNotification('All filters cleared', 'info');
}

function updateActiveFiltersDisplay() {
    const columnFilters = state.filters.columns;
    const hasSearch = elements.globalSearch.value.trim();
    const hasDateFilter = elements.dateFrom.value || elements.dateTo.value;
    const columnFilterCount = Object.keys(columnFilters).length;
    const totalFilters = (hasSearch ? 1 : 0) + (hasDateFilter ? 1 : 0) + columnFilterCount;

    // Update filter count badge
    if (totalFilters > 0) {
        elements.activeFilterCount.textContent = totalFilters;
        elements.activeFilterCount.style.display = 'inline';
    } else {
        elements.activeFilterCount.style.display = 'none';
    }

    // Build filter chips
    elements.activeFilters.innerHTML = '';

    if (totalFilters === 0) {
        elements.activeFilters.style.display = 'none';
        return;
    }

    elements.activeFilters.style.display = 'flex';

    // Search chip
    if (hasSearch) {
        addFilterChip('Search', `"${elements.globalSearch.value}"`, () => {
            elements.globalSearch.value = '';
            elements.searchResultsInfo.style.display = 'none';
            applyAllFilters();
        });
    }

    // Date range chip
    if (hasDateFilter) {
        const from = elements.dateFrom.value ? new Date(elements.dateFrom.value).toLocaleDateString() : '...';
        const to = elements.dateTo.value ? new Date(elements.dateTo.value).toLocaleDateString() : '...';
        addFilterChip('Date', `${from} → ${to}`, () => {
            elements.dateFrom.value = '';
            elements.dateTo.value = '';
            document.querySelectorAll('.date-preset-btn').forEach(b => b.classList.remove('active'));
            applyAllFilters();
        });
    }

    // Column filter chips
    for (const [column, filter] of Object.entries(columnFilters)) {
        let label = '';
        switch (filter.type) {
            case 'contains': label = `contains "${filter.value}"`; break;
            case 'equals': label = `= "${filter.value}"`; break;
            case 'startswith': label = `starts with "${filter.value}"`; break;
            case 'endswith': label = `ends with "${filter.value}"`; break;
            case 'regex': label = `regex: ${filter.value}`; break;
            case 'gt': label = `> ${filter.value}`; break;
            case 'lt': label = `< ${filter.value}`; break;
            case 'between': label = `${filter.min || '...'} - ${filter.max || '...'}`; break;
            case 'multiselect': label = `[${filter.values.length} selected]`; break;
            case 'empty': label = 'is empty'; break;
            case 'notempty': label = 'is not empty'; break;
        }

        addFilterChip(column, label, () => {
            const section = document.querySelector(`.filter-section[data-column="${column}"]`);
            if (section) {
                clearColumnFilter(column, section);
            }
        });
    }
}

function addFilterChip(name, value, onRemove) {
    const chip = document.createElement('div');
    chip.className = 'filter-chip';
    chip.innerHTML = `
        <span class="chip-name">${name}:</span>
        <span class="chip-value">${value}</span>
        <span class="remove" title="Remove filter">×</span>
    `;
    chip.querySelector('.remove').addEventListener('click', onRemove);
    elements.activeFilters.appendChild(chip);
}

// ============================================
// Column Visibility
// ============================================

function initColumnSelector() {
    elements.toggleColumnsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const rect = elements.toggleColumnsBtn.getBoundingClientRect();
        elements.columnSelector.style.top = rect.bottom + 5 + 'px';
        elements.columnSelector.style.right = (window.innerWidth - rect.right) + 'px';
        elements.columnSelector.classList.toggle('active');
    });

    elements.showAllColumns.addEventListener('click', () => {
        state.columns.forEach(col => state.table.showColumn(col));
        populateColumnSelector();
    });

    document.addEventListener('click', (e) => {
        if (!elements.columnSelector.contains(e.target) && e.target !== elements.toggleColumnsBtn) {
            elements.columnSelector.classList.remove('active');
        }
    });
}

function populateColumnSelector() {
    elements.columnList.innerHTML = '';

    state.columns.forEach(col => {
        const colDef = state.table.getColumn(col);
        const isVisible = colDef && colDef.isVisible();

        const item = document.createElement('div');
        item.className = 'context-menu-item';
        item.innerHTML = `
            <input type="checkbox" ${isVisible ? 'checked' : ''} style="margin-right: 8px;">
            <span>${col}</span>
        `;

        item.addEventListener('click', (e) => {
            const checkbox = item.querySelector('input');
            if (e.target !== checkbox) checkbox.checked = !checkbox.checked;

            if (checkbox.checked) {
                state.table.showColumn(col);
            } else {
                state.table.hideColumn(col);
            }
        });

        elements.columnList.appendChild(item);
    });
}

// ============================================
// Context Menu
// ============================================

function showContextMenu(e, row, cell) {
    state.contextMenuTarget = { row, cell };

    // Position with viewport boundary checks
    const menuWidth = 220;
    const menuHeight = 200;
    let posX = e.pageX;
    let posY = e.pageY;

    if (posX + menuWidth > window.innerWidth) {
        posX = window.innerWidth - menuWidth - 10;
    }
    if (posY + menuHeight > window.innerHeight + window.scrollY) {
        posY = posY - menuHeight;
    }
    if (posX < 0) posX = 10;
    if (posY < 0) posY = 10;

    elements.contextMenu.style.left = posX + 'px';
    elements.contextMenu.style.top = posY + 'px';
    elements.contextMenu.classList.add('active');
}

function initContextMenu() {
    document.addEventListener('click', () => {
        elements.contextMenu.classList.remove('active');
    });

    elements.contextMenu.querySelectorAll('.context-menu-item').forEach(item => {
        item.addEventListener('click', () => {
            const action = item.dataset.action;
            const target = state.contextMenuTarget;

            if (!target) return;

            switch (action) {
                case 'copy':
                    if (target.cell) {
                        navigator.clipboard.writeText(String(target.cell.getValue()))
                            .then(() => showNotification('Cell value copied to clipboard', 'success'))
                            .catch(() => showNotification('Failed to copy to clipboard', 'error'));
                    }
                    break;
                case 'copyRow':
                    const rowData = target.row.getData();
                    navigator.clipboard.writeText(JSON.stringify(rowData, null, 2))
                        .then(() => showNotification('Row data copied to clipboard', 'success'))
                        .catch(() => showNotification('Failed to copy to clipboard', 'error'));
                    break;
                case 'filterBy':
                    if (target.cell) {
                        elements.globalSearch.value = String(target.cell.getValue());
                        applyAllFilters();
                    }
                    break;
                case 'excludeBy':
                    if (target.cell) {
                        const val = String(target.cell.getValue());
                        elements.globalSearch.value = `/^(?!.*${escapeRegex(val)})/`;
                        applyAllFilters();
                    }
                    break;
                case 'searchFor':
                    if (target.cell) {
                        elements.globalSearch.value = String(target.cell.getValue());
                        applyAllFilters();
                    }
                    break;
            }

            elements.contextMenu.classList.remove('active');
        });
    });
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ============================================
// Sidebar Toggle
// ============================================

function initSidebar() {
    // Main toggle button in toolbar
    elements.toggleSidebar.addEventListener('click', () => {
        state.sidebarVisible = !state.sidebarVisible;
        elements.filterSidebar.classList.toggle('collapsed', !state.sidebarVisible);
        elements.toggleSidebar.classList.toggle('active', state.sidebarVisible);
        refreshTableLayout();
    });

    // Collapse button inside sidebar header
    const collapseSidebar = document.getElementById('collapseSidebar');
    if (collapseSidebar) {
        collapseSidebar.addEventListener('click', () => {
            state.sidebarVisible = false;
            elements.filterSidebar.classList.add('collapsed');
            elements.toggleSidebar.classList.remove('active');
            refreshTableLayout();
        });
    }

    elements.filterSidebar.addEventListener('transitionend', (event) => {
        if (event.propertyName === 'width' || event.propertyName === 'margin-left') {
            refreshTableLayout(true);
        }
    });
}

function refreshTableLayout(immediate = false) {
    if (!state.table) return;
    // Allow sidebar transition to finish before recalculating
    const delay = immediate ? 0 : 350;
    window.setTimeout(() => {
        if (state.table) {
            state.table.redraw(true);
        }
    }, delay);
}

// ============================================
// Theme Toggle
// ============================================

function initThemeToggle() {
    elements.themeToggle.addEventListener('click', () => {
        const html = document.documentElement;
        const currentTheme = html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', newTheme);

        // Update icon using Font Awesome
        const icon = elements.themeToggle.querySelector('i');
        if (icon) {
            icon.className = newTheme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
        }
    });
}

// ============================================
// Keyboard Shortcuts
// ============================================

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl+F - Focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
            e.preventDefault();
            elements.globalSearch.focus();
        }

        // Ctrl+Shift+F - Clear all filters
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
            e.preventDefault();
            clearAllFilters();
        }

        // Ctrl+E - Export
        if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
            e.preventDefault();
            if (state.table) {
                const timestamp = new Date().toISOString().slice(0, 19).replace(/[:-]/g, '');
                state.table.download('csv', `timeline_export_${timestamp}.csv`);
            }
        }

        // Ctrl+, - Toggle sidebar
        if ((e.ctrlKey || e.metaKey) && e.key === ',') {
            e.preventDefault();
            elements.toggleSidebar.click();
        }

        // Escape - Close modals/clear
        if (e.key === 'Escape') {
            elements.shortcutsModal.classList.remove('visible');
            elements.contextMenu.classList.remove('active');
            elements.columnSelector.classList.remove('active');
            elements.fileBrowserModal?.classList.remove('visible');
        }

        // Ctrl+O - Open file browser
        if ((e.ctrlKey || e.metaKey) && e.key === 'o') {
            e.preventDefault();
            openFileBrowser();
        }

        // Ctrl+T - New tab (open file browser)
        if ((e.ctrlKey || e.metaKey) && e.key === 't' && state.tabs.length > 0) {
            e.preventDefault();
            openFileBrowser();
        }

        // Ctrl+W - Close current tab
        if ((e.ctrlKey || e.metaKey) && e.key === 'w' && state.activeTabId) {
            e.preventDefault();
            closeTab(state.activeTabId);
        }

        // Ctrl+Tab / Ctrl+Shift+Tab - Switch tabs
        if ((e.ctrlKey || e.metaKey) && e.key === 'Tab' && state.tabs.length > 1) {
            e.preventDefault();
            const currentIndex = state.tabs.findIndex(t => t.id === state.activeTabId);
            let nextIndex;
            if (e.shiftKey) {
                nextIndex = currentIndex > 0 ? currentIndex - 1 : state.tabs.length - 1;
            } else {
                nextIndex = currentIndex < state.tabs.length - 1 ? currentIndex + 1 : 0;
            }
            switchToTab(state.tabs[nextIndex].id);
        }
    });

    // Shortcuts modal
    elements.shortcutsBtn.addEventListener('click', () => {
        elements.shortcutsModal.classList.add('visible');
    });

    elements.closeShortcuts.addEventListener('click', () => {
        elements.shortcutsModal.classList.remove('visible');
    });

    elements.shortcutsModal.addEventListener('click', (e) => {
        if (e.target === elements.shortcutsModal) {
            elements.shortcutsModal.classList.remove('visible');
        }
    });
}

// ============================================
// Export & Clear
// ============================================

function initExportHandlers() {
    elements.exportBtn.addEventListener('click', () => {
        if (state.table) {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/[:-]/g, '');
            const fileName = `timeline_export_${timestamp}.csv`;
            state.table.download('csv', fileName);
            showNotification(`Exported to ${fileName}`, 'success');
        }
    });

    elements.clearBtn.addEventListener('click', () => {
        if (confirm('Clear the current table and load a new file?')) {
            resetApp();
        }
    });

    elements.resetSortBtn.addEventListener('click', () => {
        if (state.table) {
            state.table.clearSort();
        }
    });
}

function resetApp() {
    if (state.table) {
        state.table.destroy();
        state.table = null;
    }

    state.rawData = [];
    state.columns = [];
    state.columnTypes = {};
    state.fileName = '';
    state.fileSize = '';
    state.fileType = null;
    state.fileFormatLabel = '';
    state.fileStructure = '';
    state.fileSignals = [];
    state.dateColumn = null;
    state.filters = { search: { value: '', caseSensitive: false }, dateRange: { from: null, to: null }, columns: {} };
    state.currentSort = null;
    state.tabs = [];
    state.activeTabId = null;
    state.tabIdCounter = 0;
    state.loadGeneration++;
    state.fileBrowserFilter = { search: '', type: 'all' };

    elements.uploadZone.style.display = 'flex';
    elements.mainWrapper.style.display = 'none';
    elements.searchContainer.style.display = 'none';
    elements.tabsContainer.style.display = 'none';
    elements.addNewTabBtn.style.display = 'none';
    elements.exportBtn.disabled = true;
    elements.clearBtn.disabled = true;
    elements.fileInfo.querySelector('.file-name').textContent = 'No file loaded';
    elements.fileInfo.querySelector('.file-size').textContent = '';
    const filePathEl = elements.fileInfo.querySelector('.file-path');
    if (filePathEl) filePathEl.textContent = '';
    const fileIconEl = elements.fileInfo.querySelector('.file-icon');
    if (fileIconEl) fileIconEl.className = 'fa-solid fa-file-csv file-icon';
    elements.globalSearch.value = '';
    elements.dateFrom.value = '';
    elements.dateTo.value = '';
    elements.loadTime.textContent = '';
    elements.columnFilters.innerHTML = '';
    elements.tabsList.innerHTML = '';
    if (elements.datasetOverview) {
        elements.datasetOverview.style.display = 'none';
    }
    localStorage.removeItem('timelineExplorerLastFile');
}

// ============================================
// UI Helpers
// ============================================

function showMainContent() {
    elements.uploadZone.style.display = 'none';
    elements.mainWrapper.style.display = 'flex';
    elements.searchContainer.style.display = 'flex';
    elements.exportBtn.disabled = false;
    elements.clearBtn.disabled = false;
}

function showLoading(text) {
    elements.loadingText.textContent = text;
    elements.progressFill.style.width = '0%';
    elements.loadingOverlay.style.display = 'flex';
}

function hideLoading() {
    elements.loadingOverlay.style.display = 'none';
}

function updateProgress(percent) {
    elements.progressFill.style.width = `${percent}%`;
}

function updateFileInfo() {
    elements.fileInfo.querySelector('.file-name').textContent = state.fileName;
    elements.fileInfo.querySelector('.file-size').textContent = state.fileSize ? `(${state.fileSize})` : '';
    const fileIconEl = elements.fileInfo.querySelector('.file-icon');
    if (fileIconEl) {
        fileIconEl.className = `fa-solid ${getFileTypeBadge('file', state.fileType).infoIcon} file-icon`;
    }
    updateDatasetOverview();
}

function updateDatasetOverview() {
    if (!elements.datasetOverview) return;

    if (!state.fileName || state.columns.length === 0) {
        elements.datasetOverview.style.display = 'none';
        return;
    }

    elements.datasetOverview.style.display = 'grid';
    elements.datasetFormat.textContent = state.fileFormatLabel || inferFormatLabel(state.fileName, state.fileStructure);
    elements.datasetStructure.textContent = state.fileStructure || 'Tabular Records';
    elements.datasetFieldCount.textContent = state.columns.length.toLocaleString();
    elements.datasetDateField.textContent = state.dateColumn || 'Not detected';
    elements.datasetSignals.innerHTML = (state.fileSignals || []).map(signal => `
        <span class="dataset-signal-chip">
            <i class="fa-solid ${signal.icon}" aria-hidden="true"></i>
            ${escapeHtml(signal.label)}
        </span>
    `).join('');
}

function updateStatusBar() {
    if (!state.table) return;

    const totalRows = state.table.getDataCount();
    const filteredRows = state.table.getDataCount('active');
    const selectedRows = state.table.getSelectedRows().length;

    elements.rowCount.textContent = totalRows.toLocaleString();
    elements.filteredCount.textContent = filteredRows.toLocaleString();
    elements.selectedCount.textContent = selectedRows.toString();
}

// ============================================
// Utilities
// ============================================

function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// ============================================
// File Browser
// ============================================

function initFileBrowser() {
    // Open file browser buttons
    elements.openFileBrowserBtn?.addEventListener('click', () => openFileBrowser());
    elements.openFileBrowserBtnAlt?.addEventListener('click', () => openFileBrowser());
    elements.addNewTabBtn?.addEventListener('click', () => openFileBrowser());

    // Close file browser
    elements.closeFileBrowser?.addEventListener('click', () => closeFileBrowser());
    elements.cancelFileBrowser?.addEventListener('click', () => closeFileBrowser());

    // Modal backdrop click to close
    elements.fileBrowserModal?.addEventListener('click', (e) => {
        if (e.target === elements.fileBrowserModal) {
            closeFileBrowser();
        }
    });

    // Navigation buttons
    elements.refreshDirBtn?.addEventListener('click', () => loadDirectory(state.currentPath));
    elements.goUpBtn?.addEventListener('click', () => navigateUp());

    // Path editing
    elements.editPathBtn?.addEventListener('click', () => {
        elements.currentPathInput.readOnly = false;
        elements.currentPathInput.focus();
        elements.currentPathInput.select();
    });

    elements.currentPathInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const newPath = elements.currentPathInput.value.trim();
            if (newPath) {
                loadDirectory(newPath);
                elements.currentPathInput.readOnly = true;
            }
        }
    });

    elements.currentPathInput?.addEventListener('blur', () => {
        elements.currentPathInput.readOnly = true;
        elements.currentPathInput.value = state.currentPath;
    });

    elements.fileBrowserSearch?.addEventListener('input', (e) => {
        state.fileBrowserFilter.search = e.target.value.trim();
        renderDirectoryContents();
    });

    elements.fileBrowserTypeFilters?.querySelectorAll('.type-filter-chip').forEach(btn => {
        btn.addEventListener('click', () => {
            state.fileBrowserFilter.type = btn.dataset.filter || 'all';
            elements.fileBrowserTypeFilters.querySelectorAll('.type-filter-chip').forEach(chip => {
                chip.classList.toggle('active', chip === btn);
            });
            renderDirectoryContents();
        });
    });

    // Open selected file button
    elements.openSelectedFile?.addEventListener('click', () => {
        if (state.selectedFile) {
            openFileFromBrowser(state.selectedFile);
        }
    });
}

function getDefaultTimelineBrowserConfig(basePath = CONFIG.defaultDataDirectory) {
    const path = (segment) => `${basePath}/${segment}`;

    return {
        basePath,
        entriesByPath: {
            [basePath]: [
                { name: 'NTFS', type: 'folder', path: path('NTFS'), modified: '2026-01-28' },
                { name: 'Registries', type: 'folder', path: path('Registries'), modified: '2026-01-28' },
                { name: 'Event Logs', type: 'folder', path: path('Event_Logs'), modified: '2026-01-28' },
                { name: 'Prefetch', type: 'folder', path: path('Prefetch'), modified: '2026-01-28' },
                { name: 'Amcache', type: 'folder', path: path('Amcache'), modified: '2026-01-28' },
                { name: 'Browser Artifacts', type: 'folder', path: path('Browser_Artifacts'), modified: '2026-01-28' },
                { name: 'LNK and Jump Lists', type: 'folder', path: path('LNK_JumpLists'), modified: '2026-01-28' },
            ],
            [path('NTFS')]: [
                { name: 'mft_timeline.csv', type: 'file', path: path('NTFS/mft_timeline.csv'), size: '12.3 MB', modified: '2026-01-28' },
                { name: 'usnjrnl_timeline.csv', type: 'file', path: path('NTFS/usnjrnl_timeline.csv'), size: '8.7 MB', modified: '2026-01-28' },
                { name: 'ntfs_metadata.jsonl', type: 'file', path: path('NTFS/ntfs_metadata.jsonl'), size: '1.3 MB', modified: '2026-01-28' },
            ],
            [path('Registries')]: [
                { name: 'registry_timeline.csv', type: 'file', path: path('Registries/registry_timeline.csv'), size: '1.1 MB', modified: '2026-01-28' },
                { name: 'run_keys.json', type: 'file', path: path('Registries/run_keys.json'), size: '220 KB', modified: '2026-01-28' },
                { name: 'userassist.jsonl', type: 'file', path: path('Registries/userassist.jsonl'), size: '470 KB', modified: '2026-01-28' },
            ],
            [path('Event_Logs')]: [
                { name: 'security_events.csv', type: 'file', path: path('Event_Logs/security_events.csv'), size: '3.7 MB', modified: '2026-01-28' },
                { name: 'sysmon_events.csv', type: 'file', path: path('Event_Logs/sysmon_events.csv'), size: '4.1 MB', modified: '2026-01-28' },
                { name: 'windows_eventlog.jsonl', type: 'file', path: path('Event_Logs/windows_eventlog.jsonl'), size: '2.0 MB', modified: '2026-01-28' },
            ],
            [path('Prefetch')]: [
                { name: 'prefetch_analysis.csv', type: 'file', path: path('Prefetch/prefetch_analysis.csv'), size: '980 KB', modified: '2026-01-28' },
            ],
            [path('Amcache')]: [
                { name: 'amcache_entries.csv', type: 'file', path: path('Amcache/amcache_entries.csv'), size: '1.2 MB', modified: '2026-01-28' },
            ],
            [path('Browser_Artifacts')]: [
                { name: 'browser_history.csv', type: 'file', path: path('Browser_Artifacts/browser_history.csv'), size: '450 KB', modified: '2026-01-28' },
                { name: 'browser_session_events.json', type: 'file', path: path('Browser_Artifacts/browser_session_events.json'), size: '680 KB', modified: '2026-01-28' },
            ],
            [path('LNK_JumpLists')]: [
                { name: 'jump_list_entries.csv', type: 'file', path: path('LNK_JumpLists/jump_list_entries.csv'), size: '320 KB', modified: '2026-01-28' },
                { name: 'lnk_artifacts.json', type: 'file', path: path('LNK_JumpLists/lnk_artifacts.json'), size: '260 KB', modified: '2026-01-28' },
            ]
        }
    };
}

function normalizeTimelineBrowserConfig(rawConfig) {
    if (!rawConfig || typeof rawConfig !== 'object') {
        return getDefaultTimelineBrowserConfig();
    }

    const basePath = typeof rawConfig.basePath === 'string' && rawConfig.basePath.trim()
        ? rawConfig.basePath.trim()
        : CONFIG.defaultDataDirectory;
    const fallback = getDefaultTimelineBrowserConfig(basePath);
    const sourceMap = rawConfig.entriesByPath;

    if (!sourceMap || typeof sourceMap !== 'object' || Array.isArray(sourceMap)) {
        return fallback;
    }

    const entriesByPath = {};

    Object.entries(sourceMap).forEach(([dirPath, entries]) => {
        if (!Array.isArray(entries)) return;

        entriesByPath[dirPath] = entries
            .filter(entry => entry && typeof entry === 'object' && typeof entry.name === 'string' && typeof entry.type === 'string')
            .map(entry => {
                const type = entry.type === 'folder' ? 'folder' : 'file';
                const path = typeof entry.path === 'string' && entry.path.trim()
                    ? entry.path.trim()
                    : `${dirPath.replace(/\/$/, '')}/${entry.name}`;

                return {
                    name: entry.name,
                    type,
                    path,
                    size: typeof entry.size === 'string' ? entry.size : undefined,
                    modified: typeof entry.modified === 'string' ? entry.modified : undefined,
                    extension: typeof entry.extension === 'string' ? entry.extension : undefined
                };
            });
    });

    if (!entriesByPath[basePath]) {
        entriesByPath[basePath] = fallback.entriesByPath[basePath];
    }

    return {
        basePath,
        entriesByPath
    };
}

async function getTimelineBrowserConfig() {
    if (timelineFileBrowserConfigCache) {
        return timelineFileBrowserConfigCache;
    }

    if (!timelineFileBrowserConfigPromise) {
        timelineFileBrowserConfigPromise = (async () => {
            try {
                const response = await fetch(CONFIG.timelineFilesConfigPath, { cache: 'no-store' });
                if (!response.ok) {
                    throw new Error(`Unable to load ${CONFIG.timelineFilesConfigPath}`);
                }

                const rawConfig = await response.json();
                timelineFileBrowserConfigCache = normalizeTimelineBrowserConfig(rawConfig);
                return timelineFileBrowserConfigCache;
            } catch (error) {
                console.warn('timeline_files.json was not available, using built-in defaults', error);
                timelineFileBrowserConfigCache = getDefaultTimelineBrowserConfig();
                return timelineFileBrowserConfigCache;
            }
        })();
    }

    return timelineFileBrowserConfigPromise;
}

async function openFileBrowser() {
    elements.fileBrowserModal.classList.add('visible');
    const config = await getTimelineBrowserConfig();
    state.currentPath = config.basePath || CONFIG.defaultDataDirectory;
    state.selectedFile = null;
    state.fileBrowserFilter = { search: '', type: 'all' };
    elements.selectedFileDisplay.textContent = 'No file selected';
    elements.openSelectedFile.disabled = true;
    if (elements.fileBrowserSearch) elements.fileBrowserSearch.value = '';
    elements.fileBrowserTypeFilters?.querySelectorAll('.type-filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === 'all');
    });
    loadDirectory(state.currentPath);
}

function persistLastFile(fileInfo) {
    try {
        localStorage.setItem('timelineExplorerLastFile', JSON.stringify(fileInfo));
    } catch (e) {
        // Ignore storage errors (e.g., private mode)
    }
}

function restoreLastFile() {
    let saved;
    try {
        saved = JSON.parse(localStorage.getItem('timelineExplorerLastFile'));
    } catch (e) {
        saved = null;
    }

    if (!saved || !saved.source) return;

    if (saved.source === 'server' && saved.path && saved.name) {
        loadFileFromServerPath(saved.path, saved.name);
    } else if (saved.source === 'local') {
        showNotification('Local file not available after refresh. Please re-upload.', 'warning');
    }
}

async function loadFileFromServerPath(path, name) {
    try {
        const response = await fetch(`${CONFIG.apiBaseUrl}/content?path=${encodeURIComponent(path)}`);
        if (!response.ok) {
            showNotification('Saved file not accessible. Please re-open.', 'warning');
            return;
        }

        const text = await response.text();
        const file = new File([text], name, { type: isJsonFileName(name) ? 'application/json' : 'text/plain' });
        handleFileWithPath(file, path);
    } catch (error) {
        showNotification('Saved file could not be restored. Please re-open.', 'warning');
    }
}

function closeFileBrowser() {
    elements.fileBrowserModal.classList.remove('visible');
    state.selectedFile = null;
}

async function loadDirectory(path) {
    state.currentPath = path;
    elements.currentPathInput.value = path;
    updateBreadcrumb(path);

    // Show loading state
    elements.fileBrowserList.innerHTML = `
        <div class="loading-files">
            <i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i>
            <span>Loading files...</span>
        </div>
    `;

    try {
        const config = await getTimelineBrowserConfig();
        const configuredContents = config.entriesByPath[path];

        if (Array.isArray(configuredContents) && configuredContents.length > 0) {
            state.directoryContents = configuredContents.map(entry => ({
                ...entry,
                path: entry.path || `${path.replace(/\/$/, '')}/${entry.name}`
            }));
            renderDirectoryContents();
            return;
        }

        // Try to fetch from API first
        const response = await fetch(`${CONFIG.apiBaseUrl}?path=${encodeURIComponent(path)}`);

        if (response.ok) {
            const data = await response.json();
            state.directoryContents = data.contents || [];
            renderDirectoryContents();
        } else {
            // API not available - show mock data for demo
            await showMockDirectoryContents(path);
        }
    } catch (error) {
        // API not available - show mock data for demo
        console.log('File API not available, using mock data');
        await showMockDirectoryContents(path);
    }
}

async function showMockDirectoryContents(path) {
    const config = await getTimelineBrowserConfig();
    const targetPath = path || config.basePath;
    const entries = config.entriesByPath[targetPath] || [];

    state.directoryContents = entries.map(entry => ({
        ...entry,
        path: entry.path || `${targetPath.replace(/\/$/, '')}/${entry.name}`
    }));

    renderDirectoryContents();
}

function renderDirectoryContents() {
    const searchTerm = state.fileBrowserFilter.search.toLowerCase();
    const filterType = state.fileBrowserFilter.type;
    const visibleContents = state.directoryContents.filter(item => {
        const extension = item.extension || `.${getFileExtension(item.name)}`;
        const matchesSearch = !searchTerm || item.name.toLowerCase().includes(searchTerm);
        if (!matchesSearch) return false;
        if (filterType === 'all') return true;
        if (filterType === 'folder') return item.type === 'folder';
        if (filterType === 'json') return item.type === 'file' && (extension === '.json' || extension === '.jsonl');
        if (filterType === 'delimited') return item.type === 'file' && ['.csv', '.tsv', '.txt'].includes(extension);
        return true;
    });

    if (visibleContents.length === 0) {
        elements.fileBrowserList.innerHTML = `
            <div class="empty-directory">
                <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                <span>${state.directoryContents.length === 0 ? 'This directory is empty' : 'No files match the current browser filter'}</span>
            </div>
        `;
        return;
    }

    // Sort: folders first, then files
    const sorted = [...visibleContents].sort((a, b) => {
        if (a.type === 'folder' && b.type !== 'folder') return -1;
        if (a.type !== 'folder' && b.type === 'folder') return 1;
        return a.name.localeCompare(b.name);
    });

    elements.fileBrowserList.innerHTML = sorted.map(item => {
        const itemPath = item.path || `${state.currentPath.replace(/\/$/, '')}/${item.name}`;
        const badge = getFileTypeBadge(item.type, item.extension || `.${getFileExtension(item.name)}`);
        const typeClass = item.type === 'folder' ? 'folder' : (badge.className || 'file');

        return `
            <div class="file-item ${typeClass}" data-name="${escapeHtml(item.name)}" data-type="${item.type}" data-path="${escapeHtml(itemPath)}">
                <i class="fa-solid ${badge.icon} file-item-icon ${typeClass}" aria-hidden="true"></i>
                <span class="file-item-name">${escapeHtml(item.name)}</span>
                <div class="file-item-meta">
                    <span class="file-type-badge ${badge.className}">${badge.badge}</span>
                    ${item.size ? `<span>${item.size}</span>` : ''}
                    ${item.modified ? `<span>${item.modified}</span>` : ''}
                </div>
            </div>
        `;
    }).join('');

    // Add click handlers
    elements.fileBrowserList.querySelectorAll('.file-item').forEach(item => {
        item.addEventListener('click', () => handleFileItemClick(item));
        item.addEventListener('dblclick', () => handleFileItemDoubleClick(item));
    });
}

function handleFileItemClick(item) {
    // Remove selection from other items
    elements.fileBrowserList.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));

    item.classList.add('selected');
    const name = item.dataset.name;
    const type = item.dataset.type;
    const path = item.dataset.path || `${state.currentPath.replace(/\/$/, '')}/${name}`;

    if (type === 'folder') {
        state.selectedFile = null;
        elements.selectedFileDisplay.textContent = `Folder: ${name}`;
        elements.openSelectedFile.disabled = true;
    } else if (isSupportedFileName(name)) {
        state.selectedFile = {
            name: name,
            path
        };
        const badge = getFileTypeBadge('file', `.${getFileExtension(name)}`);
        elements.selectedFileDisplay.innerHTML = `<i class="fa-solid ${badge.icon}" style="color: var(--accent-primary);"></i> ${name}`;
        elements.openSelectedFile.disabled = false;
    } else {
        state.selectedFile = null;
        elements.selectedFileDisplay.textContent = `${name} (unsupported file type)`;
        elements.openSelectedFile.disabled = true;
    }
}

function handleFileItemDoubleClick(item) {
    const name = item.dataset.name;
    const type = item.dataset.type;
    const path = item.dataset.path || `${state.currentPath.replace(/\/$/, '')}/${name}`;

    if (type === 'folder') {
        loadDirectory(path);
    } else if (isSupportedFileName(name)) {
        state.selectedFile = {
            name: name,
            path
        };
        openFileFromBrowser(state.selectedFile);
    }
}

function navigateUp() {
    const parts = state.currentPath.split('/').filter(p => p);
    if (parts.length > 1) {
        parts.pop();
        const newPath = '/' + parts.join('/');
        loadDirectory(newPath);
    }
}

function updateBreadcrumb(path) {
    const parts = path.split('/').filter(p => p);
    let html = '<span class="breadcrumb-item" data-path="/">/</span>';
    let currentPath = '';

    parts.forEach((part, index) => {
        currentPath += '/' + part;
        html += `<span class="breadcrumb-separator">/</span>`;
        html += `<span class="breadcrumb-item" data-path="${currentPath}">${part}</span>`;
    });

    elements.breadcrumb.innerHTML = html;

    // Add click handlers to breadcrumb items
    elements.breadcrumb.querySelectorAll('.breadcrumb-item').forEach(item => {
        item.addEventListener('click', () => {
            loadDirectory(item.dataset.path);
        });
    });
}

async function openFileFromBrowser(fileInfo) {
    closeFileBrowser();

    try {
        // Try to fetch the file from the server
        const response = await fetch(`${CONFIG.apiBaseUrl}/content?path=${encodeURIComponent(fileInfo.path)}`);

        if (response.ok) {
            const text = await response.text();
            // Create a File object from the content
            const file = new File([text], fileInfo.name, { type: isJsonFileName(fileInfo.name) ? 'application/json' : 'text/plain' });
            handleFileWithPath(file, fileInfo.path);
        } else {
            // API not available - for demo, use local file input
            showNotification('Server file access not available. Using local file upload.', 'warning');
            elements.fileInput.click();
        }
    } catch (error) {
        console.log('Server file access not available:', error);
        // For demo purposes, trigger local file input
        showNotification('Server file access not available. Please use local file upload or drag & drop.', 'info');
        elements.fileInput.click();
    }
}

function showNotification(message, type = 'info') {
    const colors = {
        info: 'var(--accent-primary)',
        warning: 'var(--warning)',
        error: 'var(--danger)',
        success: 'var(--success)'
    };

    const icons = {
        info: 'fa-circle-info',
        warning: 'fa-triangle-exclamation',
        error: 'fa-circle-xmark',
        success: 'fa-circle-check'
    };

    const notification = document.createElement('div');
    notification.className = 'notification-toast';
    notification.innerHTML = `
        <i class="fa-solid ${icons[type]}" style="color: ${colors[type]}; font-size: 1.1rem;"></i>
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fa-solid fa-xmark"></i>
        </button>
    `;

    // Stack notifications
    const existing = document.querySelectorAll('.notification-toast');
    const bottomOffset = 20 + (existing.length * 60);
    notification.style.bottom = bottomOffset + 'px';

    document.body.appendChild(notification);

    // Auto-remove after 4 seconds
    setTimeout(() => {
        notification.classList.add('notification-exit');
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// ============================================
// Tab Management
// ============================================

function initTabs() {
    // Tab add button in header
    elements.addNewTabBtn?.addEventListener('click', () => openFileBrowser());
}

function createTab(fileName, filePath, fileSize, meta = {}) {
    const tabId = ++state.tabIdCounter;

    const tab = {
        id: tabId,
        fileName: fileName,
        filePath: filePath,
        fileSize: fileSize,
        fileType: meta.fileType || getFileExtension(fileName),
        fileFormatLabel: meta.fileFormatLabel || inferFormatLabel(fileName),
        fileStructure: meta.fileStructure || 'Tabular Records',
        fileSignals: meta.fileSignals || [],
        table: null,
        rawData: [],
        columns: [],
        columnTypes: {},
        columnUniqueValues: {},
        dateColumn: null,
        filters: {
            search: { value: '', caseSensitive: false },
            dateRange: { from: null, to: null },
            columns: {}
        },
        currentSort: null
    };

    state.tabs.push(tab);
    renderTabs();
    switchToTab(tabId);

    // Show tabs container and add new tab button
    elements.tabsContainer.style.display = 'flex';
    elements.addNewTabBtn.style.display = 'inline-flex';

    return tab;
}

function renderTabs() {
    elements.tabsList.innerHTML = state.tabs.map(tab => `
        <div class="tab-item ${tab.id === state.activeTabId ? 'active' : ''}" data-tab-id="${tab.id}">
            <i class="fa-solid ${getFileTypeBadge('file', tab.fileType).icon} tab-item-icon" aria-hidden="true"></i>
            <span class="tab-item-name" title="${escapeHtml(tab.fileName)}">${escapeHtml(tab.fileName)}</span>
            <span class="tab-item-close" data-tab-id="${tab.id}" title="Close tab">
                <i class="fa-solid fa-xmark" aria-hidden="true"></i>
            </span>
        </div>
    `).join('');

    // Add click handlers
    elements.tabsList.querySelectorAll('.tab-item').forEach(tabEl => {
        tabEl.addEventListener('click', (e) => {
            if (!e.target.closest('.tab-item-close')) {
                switchToTab(parseInt(tabEl.dataset.tabId));
            }
        });
    });

    // Add close handlers
    elements.tabsList.querySelectorAll('.tab-item-close').forEach(closeBtn => {
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            closeTab(parseInt(closeBtn.dataset.tabId));
        });
    });
}

function switchToTab(tabId) {
    const tab = state.tabs.find(t => t.id === tabId);
    if (!tab) return;

    // Skip if already on this tab
    if (state.activeTabId === tabId) return;

    state.loadGeneration++;

    // Save current tab state if exists
    if (state.activeTabId) {
        const currentTab = state.tabs.find(t => t.id === state.activeTabId);
        if (currentTab) {
            currentTab.table = state.table;
            currentTab.rawData = state.rawData;
            currentTab.columns = state.columns;
            currentTab.columnTypes = state.columnTypes;
            currentTab.columnUniqueValues = state.columnUniqueValues;
            currentTab.dateColumn = state.dateColumn;
            currentTab.fileType = state.fileType;
            currentTab.fileFormatLabel = state.fileFormatLabel;
            currentTab.fileStructure = state.fileStructure;
            currentTab.fileSignals = state.fileSignals;
            currentTab.filters = JSON.parse(JSON.stringify(state.filters));
            currentTab.currentSort = state.currentSort;
            currentTab.searchValue = elements.globalSearch.value;
        }
    }

    state.activeTabId = tabId;

    // Restore tab state
    state.rawData = tab.rawData;
    state.columns = tab.columns;
    state.columnTypes = tab.columnTypes;
    state.columnUniqueValues = tab.columnUniqueValues;
    state.dateColumn = tab.dateColumn;
    state.fileName = tab.fileName;
    state.fileSize = tab.fileSize;
    state.fileType = tab.fileType;
    state.fileFormatLabel = tab.fileFormatLabel;
    state.fileStructure = tab.fileStructure;
    state.fileSignals = tab.fileSignals || [];
    state.filters = tab.filters ? JSON.parse(JSON.stringify(tab.filters)) : { search: { value: '', caseSensitive: false }, dateRange: { from: null, to: null }, columns: {} };
    state.currentSort = tab.currentSort;

    // Restore search value
    elements.globalSearch.value = tab.searchValue || '';

    // Update UI
    renderTabs();
    updateFileInfo();
    updateFilePath(tab.filePath);

    // Rebuild table from data (need to recreate since Tabulator doesn't support DOM detach/reattach)
    if (tab.rawData && tab.rawData.length > 0) {
        // Destroy existing table first
        if (state.table) {
            state.table.destroy();
            state.table = null;
        }
        elements.tableHolder.innerHTML = '';

        // Recreate with saved data
        createTable();
        createColumnFilters();
        populateColumnSelector();

        // Re-apply saved filters
        if (Object.keys(state.filters.columns).length > 0 || elements.globalSearch.value || elements.dateFrom.value || elements.dateTo.value) {
            applyAllFilters();
        }

        updateStatusBar();
    }
}

function closeTab(tabId) {
    const tabIndex = state.tabs.findIndex(t => t.id === tabId);
    if (tabIndex === -1) return;

    const tab = state.tabs[tabIndex];

    // Destroy table if exists
    if (tab.table) {
        tab.table.destroy();
    }

    state.tabs.splice(tabIndex, 1);

    if (state.tabs.length === 0) {
        // No tabs left, reset to upload view
        resetApp();
        elements.tabsContainer.style.display = 'none';
        elements.addNewTabBtn.style.display = 'none';
    } else {
        // Switch to another tab
        const newActiveTab = state.tabs[Math.min(tabIndex, state.tabs.length - 1)];
        switchToTab(newActiveTab.id);
    }
}

function updateFilePath(filePath) {
    const filePathEl = elements.fileInfo?.querySelector('.file-path');
    if (filePathEl) {
        filePathEl.textContent = filePath || '';
        filePathEl.title = filePath || '';
    }
}

function finalizeLoadedData(records, fileName, fileSize, fullPath, meta = {}, filePath = null) {
    const normalizedRecords = records
        .map(row => (row && typeof row === 'object' && !Array.isArray(row) ? row : { value: row }))
        .map(row => {
            const entries = Object.entries(row).map(([key, value]) => [key, value ?? '']);
            return entries.length > 0 ? Object.fromEntries(entries) : { value: '(empty record)' };
        });

    if (normalizedRecords.length === 0) {
        hideLoading();
        alert('No data found in file');
        return;
    }

    const tab = createTab(fileName, fullPath, fileSize, {
        fileType: meta.fileType || getFileExtension(fileName),
        fileFormatLabel: meta.fileFormatLabel || inferFormatLabel(fileName, meta.fileStructure),
        fileStructure: meta.fileStructure || 'Tabular Records',
        fileSignals: meta.fileSignals || []
    });

    tab.rawData = normalizedRecords;
    tab.fileType = meta.fileType || getFileExtension(fileName);
    tab.fileFormatLabel = meta.fileFormatLabel || inferFormatLabel(fileName, meta.fileStructure);
    tab.fileStructure = meta.fileStructure || 'Tabular Records';

    state.rawData = normalizedRecords;
    state.fileName = fileName;
    state.fileSize = fileSize;
    state.fileType = tab.fileType;
    state.fileFormatLabel = tab.fileFormatLabel;
    state.fileStructure = tab.fileStructure;

    persistLastFile({
        name: fileName,
        path: filePath,
        source: filePath ? 'server' : 'local'
    });

    updateProgress(100);
    processData();
}

function parseDelimitedFile(file, fileName, fileSize, fullPath, filePath) {
    showLoading('Parsing delimited timeline...');

    Papa.parse(file, {
        header: true,
        skipEmptyLines: true,
        dynamicTyping: false,
        worker: true,
        delimitersToGuess: [',', '\t', '|', ';'],
        complete: function (results) {
            finalizeLoadedData(results.data || [], fileName, fileSize, fullPath, {
                fileType: getFileExtension(fileName),
                fileFormatLabel: inferFormatLabel(fileName),
                fileStructure: getFileExtension(fileName) === 'tsv' ? 'Tabular Records (TSV)' : 'Tabular Records'
            }, filePath);
        },
        error: function (error) {
            hideLoading();
            alert('Error parsing timeline file: ' + error.message);
        }
    });
}

async function parseJsonFile(file, fileName, fileSize, fullPath, filePath) {
    const isJsonl = getFileExtension(fileName) === 'jsonl';
    showLoading(isJsonl ? 'Parsing JSONL evidence stream...' : 'Normalizing JSON evidence...');

    try {
        const parsed = typeof Worker !== 'undefined'
            ? await parseJsonTimelineInWorker(file)
            : await file.text().then(text => {
                const result = parseJsonTimeline(text);
                return {
                    records: result.records.map(record => flattenJsonRecord(record)),
                    structure: result.structure,
                    sourcePath: result.sourcePath,
                    formatLabel: isJsonl ? 'JSONL' : inferFormatLabel(fileName, result.structure)
                };
            });

        const formatLabel = parsed.formatLabel || (isJsonl ? 'JSONL' : 'JSON');

        finalizeLoadedData(parsed.records, fileName, fileSize, fullPath, {
            fileType: isJsonl ? 'jsonl' : 'json',
            fileFormatLabel: formatLabel,
            fileStructure: parsed.sourcePath && parsed.sourcePath !== '$'
                ? `${parsed.structure} from ${parsed.sourcePath}`
                : parsed.structure
        }, filePath);
    } catch (error) {
        hideLoading();
        alert('Error parsing ' + (isJsonl ? 'JSONL' : 'JSON') + ': ' + error.message);
    }
}

// Modified handleFile to support tabs and JSON timelines
function handleFileWithPath(file, filePath = null) {
    if (!isSupportedFileName(file.name)) {
        alert('Please select a CSV, TSV, TXT, JSON, or JSONL file');
        return;
    }

    const fileName = file.name;
    const fileSize = formatFileSize(file.size);
    const fullPath = filePath || fileName;

    state.loadStartTime = performance.now();

    if (isJsonFileName(fileName)) {
        parseJsonFile(file, fileName, fileSize, fullPath, filePath);
        return;
    }

    parseDelimitedFile(file, fileName, fileSize, fullPath, filePath);
}

// ============================================
// Initialize Application
// ============================================

function init() {
    initElements();
    initUploadHandlers();
    initSearchHandlers();
    initColumnSelector();
    initContextMenu();
    initSidebar();
    initThemeToggle();
    initKeyboardShortcuts();
    initExportHandlers();
    initFileBrowser();
    initTabs();

    window.addEventListener('resize', debounce(() => {
        if (state.table) {
            state.table.redraw(true);
        }
    }, 200));

    restoreLastFile();
}

document.addEventListener('DOMContentLoaded', init);
