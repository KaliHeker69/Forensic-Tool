const JSON_WRAPPER_KEYS = ['records', 'events', 'data', 'results', 'items', 'rows', 'timeline', 'entries', 'artifacts', 'logs'];

function getFileExtension(name) {
    const parts = String(name || '').toLowerCase().split('.');
    return parts.length > 1 ? parts.pop() : '';
}

function inferFormatLabel(fileName, structureLabel = '') {
    const ext = getFileExtension(fileName);
    if (ext === 'jsonl') return 'JSONL';
    if (ext === 'json') {
        return structureLabel === 'NDJSON Stream' ? 'NDJSON' : 'JSON';
    }
    return 'JSON';
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

self.onmessage = async (event) => {
    const { file, fileName } = event.data || {};

    try {
        const text = await file.text();
        const parsed = parseJsonTimeline(text);
        const records = parsed.records.map(record => flattenJsonRecord(record));

        self.postMessage({
            type: 'success',
            payload: {
                records,
                structure: parsed.structure,
                sourcePath: parsed.sourcePath,
                formatLabel: inferFormatLabel(fileName, parsed.structure)
            }
        });
    } catch (error) {
        self.postMessage({
            type: 'error',
            error: error && error.message ? error.message : 'Failed to parse JSON payload'
        });
    }
};
