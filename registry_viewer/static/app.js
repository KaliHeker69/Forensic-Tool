// ═══════════════════════════════════════════════════════════════
// Registry Viewer — Client-side JavaScript
// ═══════════════════════════════════════════════════════════════

// ── State ──────────────────────────────────────────────────────
let selectedNode = null;
let currentHiveId = null;
let isResizing = false;

function setBusy(target, busy) {
    if (!target) return;
    target.classList.toggle('is-loading', !!busy);
}

function autoSelectFirstHive() {
    var firstHiveInfo = document.querySelector('.hive-item .hive-info');
    if (firstHiveInfo && !currentHiveId) {
        firstHiveInfo.click();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    autoSelectFirstHive();
});

document.body.addEventListener('htmx:beforeRequest', function(evt) {
    var target = evt.detail && evt.detail.target;
    if (!target) return;
    setBusy(target, true);
});

document.body.addEventListener('htmx:afterSwap', function(evt) {
    var target = evt.detail && evt.detail.target;
    if (!target) return;
    setBusy(target, false);

    if (target.id === 'hive-sidebar') {
        // If a sidebar refresh removed the selected hive, pick the next available one.
        if (currentHiveId && !document.querySelector('[data-hive-id="' + currentHiveId + '"]')) {
            currentHiveId = null;
        }
        autoSelectFirstHive();
    }

    if (target.classList && target.classList.contains('tree-children')) {
        animateOpenChildren(target);
    }
});

document.body.addEventListener('htmx:responseError', function(evt) {
    var target = evt.detail && evt.detail.target;
    setBusy(target, false);
});

// ── Split-pane Resize ──────────────────────────────────────────
(function initResize() {
    const handle = document.getElementById('resize-handle');
    const treePanel = document.getElementById('tree-panel');
    const splitPane = document.getElementById('split-pane');

    if (!handle || !treePanel || !splitPane) return;

    handle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        isResizing = true;
        handle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', function(e) {
        if (!isResizing) return;
        const rect = splitPane.getBoundingClientRect();
        const newWidth = e.clientX - rect.left;
        const pct = (newWidth / rect.width) * 100;
        if (pct > 15 && pct < 70) {
            treePanel.style.width = pct + '%';
        }
    });

    document.addEventListener('mouseup', function() {
        if (!isResizing) return;
        isResizing = false;
        const handle = document.getElementById('resize-handle');
        if (handle) handle.classList.remove('active');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    });
})();

// ── Tree Node Selection ────────────────────────────────────────
function selectNode(element, hiveId, path) {
    // Don't re-select same node
    if (selectedNode === element) return;

    if (selectedNode) {
        selectedNode.classList.remove('selected');
    }
    element.classList.add('selected');
    selectedNode = element;

    // Update address bar
    var decodedPath = decodeURIComponent(path);
    var addressText = document.getElementById('address-text');
    if (addressText) {
        addressText.textContent = decodedPath;
        addressText.title = decodedPath;
    }
}

function toggleNode(event, arrow) {
    event.stopPropagation();
    event.preventDefault();

    if (arrow.classList.contains('leaf')) return;

    var isExpanded = arrow.classList.contains('expanded');
    var treeNode = arrow.closest('.tree-node');
    if (!treeNode) return;
    var children = treeNode.querySelector(':scope > .tree-children');
    if (!children) return;

    if (isExpanded) {
        // Collapse: animate children closed and rotate arrow back.
        arrow.classList.remove('expanded');
        arrow.classList.add('collapsed');
        animateCloseChildren(children);
    } else {
        // Expand: show existing children or lazy-load once.
        arrow.classList.remove('collapsed');
        arrow.classList.add('expanded');

        if (children.innerHTML.trim().length > 0) {
            animateOpenChildren(children);
            return;
        }

        var hiveId = arrow.getAttribute('data-hive-id');
        var encodedPath = arrow.getAttribute('data-path');
        if (!hiveId || !encodedPath) return;

        htmx.ajax('GET', '/api/keys/' + hiveId + '?path=' + encodedPath, {
            target: children,
            swap: 'innerHTML'
        });
    }
}

function animateOpenChildren(children) {
    children.style.display = 'block';
    children.classList.remove('is-collapsed');
    children.classList.add('is-open');
    children.style.maxHeight = '0px';
    children.style.opacity = '0';

    requestAnimationFrame(function() {
        children.style.maxHeight = children.scrollHeight + 'px';
        children.style.opacity = '1';
    });

    setTimeout(function() {
        if (children.classList.contains('is-open')) {
            children.style.maxHeight = 'none';
        }
    }, 210);
}

function animateCloseChildren(children) {
    children.classList.remove('is-open');
    children.classList.add('is-collapsed');
    children.style.maxHeight = children.scrollHeight + 'px';
    children.style.opacity = '1';

    requestAnimationFrame(function() {
        children.style.maxHeight = '0px';
        children.style.opacity = '0';
    });

    setTimeout(function() {
        if (children.classList.contains('is-collapsed')) {
            children.style.display = 'none';
        }
    }, 210);
}

function selectHive(hiveId, hiveName) {
    currentHiveId = hiveId;

    // Highlight active hive in sidebar
    document.querySelectorAll('.hive-item').forEach(function(el) {
        el.classList.remove('active');
    });
    var item = document.querySelector('[data-hive-id="' + hiveId + '"]');
    if (item) item.classList.add('active');

    // Enable search
    var searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.disabled = false;
        searchInput.placeholder = 'Search in ' + hiveName + '...';
    }

    // Update address bar
    var addressText = document.getElementById('address-text');
    if (addressText) {
        addressText.textContent = hiveName + ' (root)';
    }

    // Clear previous selection
    selectedNode = null;

    // Load root key values immediately so browsing starts at the hive root.
    htmx.ajax('GET', '/api/values/' + hiveId, {
        target: '#detail-content',
        swap: 'innerHTML'
    });
}

// ── Search ─────────────────────────────────────────────────────
(function initSearch() {
    var searchInput = document.getElementById('search-input');
    if (!searchInput) return;

    var debounceTimer;
    searchInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        var query = searchInput.value.trim();
        if (!currentHiveId) return;

        if (query.length === 0) {
            htmx.ajax('GET', '/api/values/' + currentHiveId, {
                target: '#detail-content',
                swap: 'innerHTML'
            });
            return;
        }

        if (query.length < 2) return;

        debounceTimer = setTimeout(function() {
            htmx.ajax('GET', '/api/search/' + currentHiveId + '?q=' + encodeURIComponent(query), {
                target: '#detail-content',
                swap: 'innerHTML'
            });
        }, 400);
    });

    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            searchInput.value = '';
            if (currentHiveId) {
                htmx.ajax('GET', '/api/values/' + currentHiveId, {
                    target: '#detail-content',
                    swap: 'innerHTML'
                });
            }
        }
    });
})();

function highlightSearchResult(element) {
    document.querySelectorAll('.search-result.active').forEach(function(el) {
        el.classList.remove('active');
    });
    element.classList.add('active');
}

// ── Drag & Drop File Upload ────────────────────────────────────
(function initDragDrop() {
    var dropOverlay = document.getElementById('drop-overlay');
    if (!dropOverlay) return;

    var dragCounter = 0;

    document.addEventListener('dragenter', function(e) {
        e.preventDefault();
        dragCounter++;
        dropOverlay.classList.add('visible');
    });

    document.addEventListener('dragleave', function(e) {
        dragCounter--;
        if (dragCounter <= 0) {
            dragCounter = 0;
            dropOverlay.classList.remove('visible');
        }
    });

    document.addEventListener('dragover', function(e) {
        e.preventDefault();
    });

    document.addEventListener('drop', function(e) {
        e.preventDefault();
        dragCounter = 0;
        dropOverlay.classList.remove('visible');

        if (e.dataTransfer.files.length > 0) {
            var formData = new FormData();
            formData.append('hive_file', e.dataTransfer.files[0]);

            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(function(r) {
                if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
                return r.text();
            })
            .then(function(html) {
                var sidebar = document.getElementById('hive-sidebar');
                if (sidebar) {
                    sidebar.innerHTML = html;
                    htmx.process(sidebar);
                }
            })
            .catch(function(err) {
                alert('Failed to load hive: ' + err.message);
            });
        }
    });
})();

// ── Keyboard Navigation ────────────────────────────────────────
document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    if (!selectedNode) return;

    var li = selectedNode.closest('.tree-node');
    if (!li) return;

    if (e.key === 'ArrowDown') {
        e.preventDefault();
        var next = getNextVisibleNode(li);
        if (next) {
            var header = next.querySelector(':scope > .tree-node-header');
            if (header) header.click();
        }
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        var prev = getPrevVisibleNode(li);
        if (prev) {
            var header = prev.querySelector(':scope > .tree-node-header');
            if (header) header.click();
        }
    } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        var arrow = li.querySelector(':scope > .tree-node-header .expand-arrow.collapsed');
        if (arrow && !arrow.classList.contains('leaf')) arrow.click();
    } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        var arrow = li.querySelector(':scope > .tree-node-header .expand-arrow.expanded');
        if (arrow) {
            arrow.click();
        } else {
            // Navigate to parent
            var parentLi = li.parentElement?.closest('.tree-node');
            if (parentLi) {
                var header = parentLi.querySelector(':scope > .tree-node-header');
                if (header) header.click();
            }
        }
    }
});

function getNextVisibleNode(currentLi) {
    // First try: first child (if expanded)
    var children = currentLi.querySelector(':scope > .tree-children > .tree-list');
    if (children) {
        var firstChild = children.querySelector(':scope > .tree-node');
        if (firstChild) return firstChild;
    }

    // Then try: next sibling
    var next = currentLi.nextElementSibling;
    while (!next || !next.classList?.contains('tree-node')) {
        if (next && next.classList?.contains('tree-node')) return next;
        if (next) { next = next.nextElementSibling; continue; }
        // Go up to parent's next sibling
        var parentLi = currentLi.parentElement?.closest('.tree-node');
        if (!parentLi) return null;
        currentLi = parentLi;
        next = currentLi.nextElementSibling;
    }
    return next;
}

function getPrevVisibleNode(currentLi) {
    var prev = currentLi.previousElementSibling;
    while (prev && !prev.classList?.contains('tree-node')) {
        prev = prev.previousElementSibling;
    }

    if (prev) {
        // Go to deepest last child of prev
        return getDeepestLastChild(prev);
    }

    // Go to parent
    return currentLi.parentElement?.closest('.tree-node') || null;
}

function getDeepestLastChild(li) {
    var children = li.querySelector(':scope > .tree-children > .tree-list');
    if (!children) return li;
    var items = children.querySelectorAll(':scope > .tree-node');
    if (items.length === 0) return li;
    return getDeepestLastChild(items[items.length - 1]);
}
