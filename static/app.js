/* ============================================================================
   Tiny URL Dashboard

   No framework, no build step. The app is a single-screen table of every
   short URL whose admin token lives in this browser's localStorage. Each row
   loads its analytics on first render and lazily loads click events when
   expanded. All state is in this file's module-level variables; persistence
   is in localStorage only.

   SECURITY: every admin token returned by /api/shorten is stored under
   `tinyurl:token:<code>`. localStorage is readable by ANY same-origin script,
   so XSS or a hostile browser extension would compromise these tokens. This
   is the documented trust model — see README → Security Model.
   ========================================================================= */

(() => {
    'use strict';

    const TOKEN_PREFIX = 'tinyurl:token:';
    const LABEL_PREFIX = 'tinyurl:label:';
    const THEME_KEY    = 'tinyurl:theme';
    const REFRESH_MS   = 30_000;
    const TOAST_MS     = 3500;
    const FLASH_MS     = 2500;
    const LABEL_MAX    = 64;

    /**
     * Sparkline time-range presets. bucketCount × bucketMs = total window.
     * 1h:   12 buckets × 5 minutes  →  60 minutes
     * 24h:  24 buckets × 1 hour     →  24 hours
     * 7d:   28 buckets × 6 hours    →   7 days
     * 7d's coarseness (28 buckets) is intentional — the clicks endpoint
     * returns at most 200 most-recent events, so 28 wide buckets visually
     * smooth out gaps when only a partial week is covered.
     */
    const RANGES = {
        '1h':  { label: '1 h',  bucketCount: 12, bucketMs: 5 * 60 * 1000 },
        '24h': { label: '24 h', bucketCount: 24, bucketMs: 60 * 60 * 1000 },
        '7d':  { label: '7 d',  bucketCount: 28, bucketMs: 6 * 60 * 60 * 1000 },
    };

    // ---------- DOM refs ---------------------------------------------------

    const $ = (id) => document.getElementById(id);
    const els = {
        searchInput:    $('searchInput'),
        importBtn:      $('importBtn'),
        newBtn:         $('newBtn'),
        themeToggle:    $('themeToggle'),
        themeIcon:      $('themeIcon'),

        createPanel:    $('createPanel'),
        createForm:     $('createForm'),
        urlInput:       $('urlInput'),
        customCodeInput:$('customCodeInput'),
        expirationInput:$('expirationInput'),
        cancelCreateBtn:$('cancelCreateBtn'),
        createBtn:      $('createBtn'),

        importPanel:      $('importPanel'),
        importForm:       $('importForm'),
        importCodeInput:  $('importCodeInput'),
        importTokenInput: $('importTokenInput'),
        cancelImportBtn:  $('cancelImportBtn'),
        importSubmitBtn:  $('importSubmitBtn'),

        emptyState:     $('emptyState'),
        emptyCreateBtn: $('emptyCreateBtn'),
        emptyImportBtn: $('emptyImportBtn'),
        loadingState:   $('loadingState'),
        tableCard:      $('tableCard'),
        tableSummary:   $('tableSummary'),
        urlTableBody:   $('urlTableBody'),
        refreshBtn:     $('refreshBtn'),
        exportBtn:      $('exportBtn'),

        bulkBar:        $('bulkBar'),
        bulkCount:      $('bulkCount'),
        bulkDeleteBtn:  $('bulkDeleteBtn'),
        bulkClearBtn:   $('bulkClearBtn'),
        selectAllCheckbox: $('selectAllCheckbox'),

        toastContainer: $('toastContainer'),
    };

    // ---------- state ------------------------------------------------------

    /** @type {Map<string, {code, token, status: 'loading'|'active'|'expired'|'gone'|'error', data?, events?, eventsLoading?}>} */
    const rows = new Map();
    let searchQuery = '';
    let sortKey = 'last_accessed';
    let sortDir = 'desc';
    let currentRange = '24h';
    const expanded = new Set();
    /** Codes currently checked for bulk operations. */
    const selected = new Set();
    /**
     * Snapshot of click_count per code at the time of the last successful
     * analytics fetch. detectActivity() compares the next fetch against
     * this map to decide whether to flash a "live click" pulse on the row.
     */
    const refreshSnapshot = new Map();
    /** AbortController per code for the live SSE stream. Open on row
     *  expand; aborted on collapse so we don't leak goroutines on the
     *  server (each open stream is one server-side subscription). */
    const liveStreams = new Map();

    // ---------- theme ------------------------------------------------------

    function initTheme() {
        const stored = localStorage.getItem(THEME_KEY);
        if (stored === 'light' || stored === 'dark') {
            document.documentElement.setAttribute('data-theme', stored);
        }
        updateThemeIcon();
    }
    function effectiveTheme() {
        const explicit = document.documentElement.getAttribute('data-theme');
        if (explicit) return explicit;
        return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    function updateThemeIcon() {
        els.themeIcon.textContent = effectiveTheme() === 'dark' ? '☀️' : '🌙';
    }
    function toggleTheme() {
        const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem(THEME_KEY, next); } catch (_) {}
        updateThemeIcon();
    }

    // ---------- toasts -----------------------------------------------------

    /**
     * Show a transient notification.
     *   opts.actionLabel + opts.action → render an inline action button
     *      (e.g. "Undo"). Clicking it fires opts.action and dismisses early.
     *   opts.durationMs → override the default lifetime (used by the
     *      soft-delete flow to give users a longer undo window).
     */
    function toast(msg, kind = 'info', opts = {}) {
        const node = document.createElement('div');
        node.className = `toast toast-${kind}`;

        const text = document.createElement('span');
        text.textContent = msg;
        text.style.flex = '1';
        node.appendChild(text);

        if (opts.actionLabel && typeof opts.action === 'function') {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'toast-action';
            btn.textContent = opts.actionLabel;
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                opts.action();
                dismissToast(node);
            });
            node.appendChild(btn);
        } else {
            // Plain toast — click the body to dismiss early.
            node.addEventListener('click', () => dismissToast(node));
            node.style.cursor = 'pointer';
        }

        els.toastContainer.appendChild(node);
        const lifetime = typeof opts.durationMs === 'number' ? opts.durationMs : TOAST_MS;
        setTimeout(() => dismissToast(node), lifetime);
        return node;
    }
    function dismissToast(node) {
        if (!node || !node.parentNode) return;
        node.classList.add('fading');
        setTimeout(() => node.parentNode && node.parentNode.removeChild(node), 250);
    }

    // ---------- API helpers ------------------------------------------------

    function tokensFromStorage() {
        const out = [];
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k && k.startsWith(TOKEN_PREFIX)) {
                    out.push({ code: k.slice(TOKEN_PREFIX.length), token: localStorage.getItem(k) });
                }
            }
        } catch (_) { /* localStorage may be disabled */ }
        return out;
    }
    function dropToken(code) {
        try { localStorage.removeItem(TOKEN_PREFIX + code); } catch (_) {}
    }
    function saveToken(code, token) {
        try { localStorage.setItem(TOKEN_PREFIX + code, token); } catch (_) {}
    }

    function getLabel(code) {
        try { return localStorage.getItem(LABEL_PREFIX + code) || ''; }
        catch (_) { return ''; }
    }
    function setLabel(code, val) {
        try {
            if (val) localStorage.setItem(LABEL_PREFIX + code, val);
            else localStorage.removeItem(LABEL_PREFIX + code);
        } catch (_) {}
    }
    /** Remove every local artefact tied to a code — token AND label. Call
     *  this everywhere a row is being permanently removed (delete, stale
     *  404 cleanup) so labels don't leak past the lifetime of the URL. */
    function dropLocalEntries(code) {
        dropToken(code);
        setLabel(code, '');
        refreshSnapshot.delete(code);
    }

    /**
     * Compare new click count to the previous snapshot and flag the row
     * for a brief visual pulse if it grew. First observation never flashes
     * — the snapshot starts empty, so prev is undefined on initial load.
     */
    function detectActivity(code, newData) {
        if (!newData) return;
        const prev = refreshSnapshot.get(code);
        refreshSnapshot.set(code, newData.click_count);
        if (prev !== undefined && newData.click_count > prev) {
            const row = rows.get(code);
            if (row) {
                row.flashUntil = Date.now() + FLASH_MS;
                // Schedule a follow-up render so the dot disappears even if
                // the user never triggers anything else (no input, no click).
                setTimeout(() => render(), FLASH_MS + 100);
            }
        }
    }

    async function apiCreate({ url, custom_code, expiration_mins }) {
        const body = { url };
        if (custom_code) body.custom_code = custom_code;
        if (expiration_mins) body.expiration_mins = expiration_mins;
        const r = await fetch('/api/shorten', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.message || `Create failed (${r.status})`);
        return data;
    }
    async function apiAnalytics(code, token) {
        const r = await fetch(`/api/analytics/${encodeURIComponent(code)}`, {
            headers: { 'Authorization': `Bearer ${token}` },
        });
        return { status: r.status, data: r.status === 200 ? await r.json() : null };
    }
    async function apiClicks(code, token, limit = 50) {
        const r = await fetch(`/api/analytics/${encodeURIComponent(code)}/clicks?limit=${limit}`, {
            headers: { 'Authorization': `Bearer ${token}` },
        });
        if (!r.ok) throw new Error(`Clicks fetch failed (${r.status})`);
        return r.json();
    }
    async function apiPatch(code, token, body) {
        const r = await fetch(`/api/url/${encodeURIComponent(code)}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.message || `Update failed (${r.status})`);
        return data;
    }
    async function apiDelete(code, token) {
        const r = await fetch(`/api/url/${encodeURIComponent(code)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` },
        });
        return r.status;
    }
    async function apiRotate(code, token) {
        const r = await fetch(`/api/url/${encodeURIComponent(code)}/rotate`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.message || `Rotate failed (${r.status})`);
        return data;
    }

    // Bounded-concurrency promise pool. Avoids opening 100+ concurrent
    // requests to the same origin when the user has many saved tokens.
    async function pool(items, limit, fn) {
        const results = new Array(items.length);
        let next = 0;
        async function worker() {
            while (next < items.length) {
                const i = next++;
                results[i] = await fn(items[i], i);
            }
        }
        await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
        return results;
    }

    // ---------- data loading ----------------------------------------------

    async function loadAll() {
        const tokens = tokensFromStorage();
        if (tokens.length === 0) {
            rows.clear();
            render();
            return;
        }
        // Initialise loading states immediately so the first paint shows progress.
        for (const { code, token } of tokens) {
            if (!rows.has(code)) rows.set(code, { code, token, status: 'loading' });
        }
        render();

        let droppedStale = 0;
        await pool(tokens, 6, async ({ code, token }) => {
            try {
                const { status, data } = await apiAnalytics(code, token);
                if (status === 200 && data) {
                    rows.set(code, { code, token, status: 'active', data });
                    detectActivity(code, data);
                } else if (status === 404) {
                    dropLocalEntries(code);
                    rows.delete(code);
                    droppedStale++;
                } else if (status === 410) {
                    rows.set(code, { code, token, status: 'expired' });
                } else if (status === 401 || status === 403) {
                    rows.set(code, { code, token, status: 'gone' }); // bad token
                } else {
                    rows.set(code, { code, token, status: 'error' });
                }
            } catch (e) {
                rows.set(code, { code, token, status: 'error' });
            }
        });

        if (droppedStale > 0) {
            toast(`Removed ${droppedStale} stale token${droppedStale === 1 ? '' : 's'} (URL no longer exists).`, 'info');
        }
        render();
    }

    async function refreshOne(code) {
        const row = rows.get(code);
        if (!row) return;
        try {
            const { status, data } = await apiAnalytics(code, row.token);
            if (status === 200 && data) {
                rows.set(code, { ...row, status: 'active', data });
                detectActivity(code, data);
            } else if (status === 410) {
                rows.set(code, { ...row, status: 'expired' });
            } else if (status === 404) {
                dropLocalEntries(code); rows.delete(code);
            }
        } catch (_) { /* keep prior row on error */ }
        render();
    }

    // ---------- rendering --------------------------------------------------

    function render() {
        const all = Array.from(rows.values());
        const filtered = all.filter(matchSearch);
        const sorted = filtered.slice().sort(rowComparator);

        // Initial-load skeleton: hide table, show loading
        if (rows.size === 0) {
            els.loadingState.classList.add('hidden');
            els.tableCard.classList.add('hidden');
            els.emptyState.classList.remove('hidden');
            return;
        }
        els.emptyState.classList.add('hidden');
        els.loadingState.classList.add('hidden');
        els.tableCard.classList.remove('hidden');

        els.tableSummary.textContent = summaryLine(all, filtered);
        renderSortHeaders();
        renderTableBody(sorted);
        updateBulkBar();
    }

    function summaryLine(all, filtered) {
        const total = all.length;
        const visible = filtered.length;
        const totalClicks = all.reduce((s, r) => s + (r.data?.click_count || 0), 0);
        const expired = all.filter(r => r.status === 'expired').length;
        const parts = [
            `${total} URL${total === 1 ? '' : 's'}`,
            `${totalClicks} click${totalClicks === 1 ? '' : 's'}`,
        ];
        if (expired) parts.push(`${expired} expired`);
        if (visible !== total) parts.push(`${visible} matching`);
        return parts.join(' · ');
    }

    function renderSortHeaders() {
        document.querySelectorAll('.url-table th.sortable').forEach((th) => {
            th.classList.remove('sorted-asc', 'sorted-desc');
            if (th.dataset.sort === sortKey) {
                th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
            }
        });
    }

    function rowComparator(a, b) {
        const av = sortableField(a);
        const bv = sortableField(b);
        if (av < bv) return sortDir === 'asc' ? -1 : 1;
        if (av > bv) return sortDir === 'asc' ?  1 : -1;
        return 0;
    }
    function sortableField(r) {
        switch (sortKey) {
            case 'code':           return r.code;
            case 'destination':    return (r.data?.original_url || '').toLowerCase();
            case 'clicks':         return r.data?.click_count ?? -1;
            case 'last_accessed':  return r.data?.last_accessed ? Date.parse(r.data.last_accessed) : 0;
            case 'expires':        return r.data?.expires_at ? Date.parse(r.data.expires_at) : Number.MAX_SAFE_INTEGER;
            default: return r.code;
        }
    }

    function matchSearch(row) {
        if (!searchQuery) return true;
        const q = searchQuery.toLowerCase();
        if (row.code.toLowerCase().includes(q)) return true;
        if (row.data?.original_url?.toLowerCase().includes(q)) return true;
        if (getLabel(row.code).toLowerCase().includes(q)) return true;
        return false;
    }

    function renderTableBody(sorted) {
        // Full re-render of tbody. The data set is bounded by tokens-per-browser;
        // even with 200 entries this is cheap and avoids tracking diffs by hand.
        const frag = document.createDocumentFragment();
        for (const row of sorted) {
            frag.appendChild(buildRowSummary(row));
            if (expanded.has(row.code)) {
                frag.appendChild(buildRowDetail(row));
            }
        }
        els.urlTableBody.replaceChildren(frag);
    }

    function buildRowSummary(row) {
        const tr = document.createElement('tr');
        tr.className = 'row-summary';
        tr.dataset.code = row.code;
        if (expanded.has(row.code)) tr.classList.add('expanded');
        if (selected.has(row.code)) tr.classList.add('selected');

        const tdCheck = document.createElement('td');
        tdCheck.className = 'checkbox-col';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = selected.has(row.code);
        cb.setAttribute('aria-label', `Select ${row.code}`);
        cb.addEventListener('click', (e) => e.stopPropagation()); // don't expand the row
        cb.addEventListener('change', () => {
            if (cb.checked) selected.add(row.code);
            else selected.delete(row.code);
            updateBulkBar();
            tr.classList.toggle('selected', cb.checked);
        });
        tdCheck.appendChild(cb);
        tr.appendChild(tdCheck);

        const tdCode = document.createElement('td');
        const exp = document.createElement('span');
        exp.className = 'expander';
        exp.textContent = '▶';
        tdCode.appendChild(exp);
        const codeSpan = document.createElement('span');
        codeSpan.className = 'cell-code';
        codeSpan.textContent = row.code;
        tdCode.appendChild(codeSpan);
        const label = getLabel(row.code);
        if (label) {
            const labelSpan = document.createElement('span');
            labelSpan.className = 'cell-label';
            labelSpan.textContent = label;
            labelSpan.title = label;
            tdCode.appendChild(labelSpan);
        }
        tr.appendChild(tdCode);

        const tdDest = document.createElement('td');
        tdDest.className = 'cell-dest';
        tdDest.textContent = row.data?.original_url || '—';
        tdDest.title = row.data?.original_url || '';
        tr.appendChild(tdDest);

        const tdClicks = document.createElement('td');
        tdClicks.className = 'cell-clicks';
        tdClicks.textContent = row.data?.click_count ?? '—';
        // Show a brief pulsing dot when click_count just incremented since
        // the previous refresh — gives the dashboard a "this thing is alive"
        // feeling without needing real-time SSE.
        if (row.flashUntil && row.flashUntil > Date.now()) {
            const pulse = document.createElement('span');
            pulse.className = 'click-pulse';
            pulse.title = 'Just clicked';
            pulse.setAttribute('aria-label', 'Click count increased');
            tdClicks.appendChild(pulse);
        }
        tr.appendChild(tdClicks);

        const tdLast = document.createElement('td');
        tdLast.className = 'cell-time';
        tdLast.textContent = row.data?.last_accessed ? relativeTime(row.data.last_accessed) : '—';
        tr.appendChild(tdLast);

        const tdExp = document.createElement('td');
        tdExp.className = 'cell-time';
        tdExp.textContent = row.data?.expires_at ? relativeTime(row.data.expires_at) : 'never';
        tr.appendChild(tdExp);

        const tdStatus = document.createElement('td');
        tdStatus.appendChild(buildStatusPill(row));
        tr.appendChild(tdStatus);

        const tdActions = document.createElement('td');
        tdActions.className = 'actions-col';
        const actions = document.createElement('div');
        actions.className = 'row-actions';
        actions.appendChild(makeBtn('Copy', 'btn btn-ghost btn-sm', (e) => {
            e.stopPropagation();
            copyShortURL(row.code);
        }));
        tdActions.appendChild(actions);
        tr.appendChild(tdActions);

        tr.addEventListener('click', () => toggleExpand(row.code));
        return tr;
    }

    function buildStatusPill(row) {
        const pill = document.createElement('span');
        pill.className = 'status-pill';
        if (row.status === 'expired') {
            pill.classList.add('status-expired');
            pill.textContent = 'Expired';
        } else if (row.status === 'gone' || row.status === 'error') {
            pill.classList.add('status-expired');
            pill.textContent = row.status === 'gone' ? 'Token rejected' : 'Error';
        } else if (row.status === 'loading') {
            pill.classList.add('status-expiring');
            pill.textContent = 'Loading…';
        } else {
            const expiringSoon = row.data?.expires_at &&
                (Date.parse(row.data.expires_at) - Date.now() < 24 * 3600 * 1000);
            if (expiringSoon) {
                pill.classList.add('status-expiring');
                pill.textContent = 'Expiring';
            } else {
                pill.classList.add('status-active');
                pill.textContent = 'Active';
            }
        }
        return pill;
    }

    function buildRowDetail(row) {
        const tr = document.createElement('tr');
        tr.className = 'row-detail';
        const td = document.createElement('td');
        // colSpan covers every column the summary row has — checkbox + 7 data cols.
        td.colSpan = 8;

        const grid = document.createElement('div');
        grid.className = 'detail-grid';

        // Left column: clicks chart + breakdown
        const left = document.createElement('div');
        left.className = 'detail-block';
        const leftHeader = document.createElement('h3');
        leftHeader.textContent = `Activity (last ${RANGES[currentRange].label})`;
        left.appendChild(leftHeader);

        if (row.eventsLoading) {
            const p = document.createElement('p');
            p.className = 'muted';
            p.textContent = 'Loading click events…';
            left.appendChild(p);
        } else if (!row.events) {
            const p = document.createElement('p');
            p.className = 'muted';
            p.textContent = 'No data yet.';
            left.appendChild(p);
        } else {
            left.appendChild(buildSparkBlock(row.events));
            left.appendChild(buildBreakdown(row.events));
        }
        grid.appendChild(left);

        // Right column: QR (share) + edit + token + delete (manage)
        const right = document.createElement('div');
        right.className = 'detail-block';
        right.appendChild(buildQRBlock(row));
        const rh = document.createElement('h3');
        rh.textContent = 'Manage';
        rh.style.marginTop = '1rem';
        right.appendChild(rh);
        right.appendChild(buildLabelField(row));
        right.appendChild(buildEditForm(row));
        right.appendChild(buildTokenRow(row));
        right.appendChild(buildDangerZone(row));
        grid.appendChild(right);

        td.appendChild(grid);
        tr.appendChild(td);

        // Lazy-load events on first expand
        if (!row.events && !row.eventsLoading && row.status === 'active') {
            loadEvents(row.code);
        }
        return tr;
    }

    function buildSparkBlock(eventsResp) {
        const events = eventsResp.events || [];
        const cfg = RANGES[currentRange] || RANGES['24h'];
        const buckets = bucketize(events, currentRange);
        const total = buckets.reduce((s, n) => s + n, 0);

        const wrap = document.createElement('div');

        const toggle = buildRangeToggle();
        wrap.appendChild(toggle);

        const sparkRow = document.createElement('div');
        sparkRow.className = 'spark-wrap';

        const stats = document.createElement('div');
        stats.className = 'spark-stats';
        const big = document.createElement('strong');
        big.textContent = total;
        stats.appendChild(big);
        stats.appendChild(document.createTextNode(`click${total === 1 ? '' : 's'} / ${cfg.label}`));
        sparkRow.appendChild(stats);

        sparkRow.appendChild(sparklineSVG(buckets, cfg));
        wrap.appendChild(sparkRow);
        return wrap;
    }

    /**
     * Build the 1h / 24h / 7d pill toggle. The `currentRange` global is the
     * single source of truth — all expanded rows render with the same
     * range, which is the simpler model. (Per-row range would need state
     * on the row object and a tiny win for a single-user dashboard.)
     */
    function buildRangeToggle() {
        const wrap = document.createElement('div');
        wrap.className = 'range-toggle';
        wrap.setAttribute('role', 'tablist');
        for (const key of Object.keys(RANGES)) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'range-btn' + (key === currentRange ? ' active' : '');
            b.textContent = RANGES[key].label;
            b.setAttribute('role', 'tab');
            b.setAttribute('aria-selected', key === currentRange ? 'true' : 'false');
            b.addEventListener('click', (e) => {
                e.stopPropagation();
                if (currentRange === key) return;
                currentRange = key;
                render();
            });
            wrap.appendChild(b);
        }
        return wrap;
    }

    /**
     * bucketize: return click counts per bucket for the chosen range,
     * oldest-first, fixed length per the range config. Events outside the
     * window are silently dropped — the chart shows only what's in scope.
     */
    function bucketize(events, range) {
        const cfg = RANGES[range] || RANGES['24h'];
        const buckets = new Array(cfg.bucketCount).fill(0);
        const now = Date.now();
        const totalMs = cfg.bucketCount * cfg.bucketMs;
        for (const ev of events) {
            const t = Date.parse(ev.at);
            if (!Number.isFinite(t)) continue;
            const ago = now - t;
            if (ago < 0 || ago >= totalMs) continue;
            const idx = cfg.bucketCount - 1 - Math.floor(ago / cfg.bucketMs);
            buckets[idx] += 1;
        }
        return buckets;
    }

    function sparklineSVG(buckets, cfg) {
        // Hand-rolled SVG: cheap, themeable, no external dep.
        const W = 200, H = 36, pad = 2;
        const max = Math.max(1, ...buckets);
        const stepX = (W - pad * 2) / Math.max(1, buckets.length - 1);
        const points = buckets.map((v, i) => {
            const x = pad + i * stepX;
            const y = H - pad - (v / max) * (H - pad * 2);
            return [x, y];
        });

        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('class', 'sparkline');
        svg.setAttribute('width', W);
        svg.setAttribute('height', H);
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        const rangeLabel = cfg ? cfg.label : `${buckets.length} buckets`;
        svg.setAttribute('aria-label', `Click activity over the last ${rangeLabel}, peak ${max} per bucket`);

        // Filled area under line
        const area = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        const areaPts = [
            `${pad},${H - pad}`,
            ...points.map(([x, y]) => `${x},${y}`),
            `${W - pad},${H - pad}`,
        ].join(' ');
        area.setAttribute('points', areaPts);
        area.setAttribute('fill', 'var(--primary)');
        area.setAttribute('opacity', '0.15');
        svg.appendChild(area);

        // Line on top
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        line.setAttribute('points', points.map(([x, y]) => `${x},${y}`).join(' '));
        line.setAttribute('fill', 'none');
        line.setAttribute('stroke', 'var(--primary)');
        line.setAttribute('stroke-width', '1.5');
        line.setAttribute('stroke-linejoin', 'round');
        svg.appendChild(line);

        return svg;
    }

    function buildBreakdown(eventsResp) {
        const events = eventsResp.events || [];
        const wrap = document.createDocumentFragment();

        // Top referers
        const refs = countBy(events, (e) => normalizeReferer(e.referer));
        const topRefs = topN(refs, 3);
        if (topRefs.length) {
            const h = document.createElement('h3');
            h.textContent = 'Top referers';
            h.style.marginTop = '0.75rem';
            wrap.appendChild(h);
            const ul = document.createElement('ul');
            ul.className = 'referer-list';
            for (const [host, n] of topRefs) {
                const li = document.createElement('li');
                const left = document.createElement('span');
                left.className = 'ref-host';
                left.textContent = host;
                left.title = host;
                const right = document.createElement('span');
                right.className = 'ref-count';
                right.textContent = String(n);
                li.appendChild(left); li.appendChild(right);
                ul.appendChild(li);
            }
            wrap.appendChild(ul);
        }

        // Device class breakdown
        const dev = countBy(events, (e) => e.ua_class || 'unknown');
        const devList = topN(dev, 5);
        if (devList.length) {
            const h = document.createElement('h3');
            h.textContent = 'Devices';
            h.style.marginTop = '0.75rem';
            wrap.appendChild(h);
            const ul = document.createElement('ul');
            ul.className = 'device-list';
            for (const [name, n] of devList) {
                const li = document.createElement('li');
                const left = document.createElement('span');
                left.textContent = name;
                const right = document.createElement('span');
                right.className = 'dev-count';
                right.textContent = String(n);
                li.appendChild(left); li.appendChild(right);
                ul.appendChild(li);
            }
            wrap.appendChild(ul);
        }
        return wrap;
    }

    function normalizeReferer(ref) {
        if (!ref) return 'direct';
        try { return new URL(ref).host || 'direct'; } catch (_) { return ref.slice(0, 32); }
    }
    function countBy(arr, keyFn) {
        const m = new Map();
        for (const x of arr) {
            const k = keyFn(x);
            m.set(k, (m.get(k) || 0) + 1);
        }
        return m;
    }
    function topN(map, n) {
        return Array.from(map.entries()).sort((a, b) => b[1] - a[1]).slice(0, n);
    }

    function buildEditForm(row) {
        const wrap = document.createElement('div');
        wrap.className = 'detail-edit-form';

        const urlField = makeField('New destination', 'url', row.data?.original_url || '');
        const expField = makeField('Expiration (mins, 0 = remove)', 'number', '');
        wrap.appendChild(urlField.field);
        wrap.appendChild(expField.field);

        const actions = document.createElement('div');
        actions.className = 'form-actions';
        actions.appendChild(makeBtn('Save', 'btn btn-primary btn-sm', async (e) => {
            e.preventDefault();
            const newUrl = urlField.input.value.trim();
            const newExpRaw = expField.input.value.trim();
            const body = {};
            if (newUrl && newUrl !== row.data?.original_url) body.url = newUrl;
            if (newExpRaw !== '') body.expiration_mins = parseInt(newExpRaw, 10);
            if (Object.keys(body).length === 0) {
                toast('Nothing to save.', 'info');
                return;
            }
            try {
                await apiPatch(row.code, row.token, body);
                toast(`/${row.code} updated.`, 'success');
                expField.input.value = '';
                refreshOne(row.code);
            } catch (err) {
                toast(err.message, 'error');
            }
        }));
        wrap.appendChild(actions);
        return wrap;
    }

    function makeField(label, type, value) {
        const field = document.createElement('label');
        field.className = 'field';
        const sp = document.createElement('span');
        sp.className = 'field-label';
        sp.textContent = label;
        const input = document.createElement('input');
        input.type = type;
        input.value = value;
        field.appendChild(sp); field.appendChild(input);
        return { field, input };
    }
    function makeBtn(text, klass, onClick) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = klass;
        b.textContent = text;
        b.addEventListener('click', onClick);
        return b;
    }

    /**
     * Local-only label/note for a short code. Stored under
     * `tinyurl:label:<code>` in localStorage; the server has no idea this
     * exists. Auto-saves on blur or Enter — no explicit "save" button keeps
     * the right panel less busy.
     */
    function buildLabelField(row) {
        const wrap = document.createElement('div');
        wrap.style.marginBottom = '0.75rem';
        const field = makeField('Label (this browser only)', 'text', getLabel(row.code));
        field.input.placeholder = 'e.g. team standup link';
        field.input.maxLength = LABEL_MAX;
        const persist = () => {
            const next = field.input.value.trim().slice(0, LABEL_MAX);
            if (next !== getLabel(row.code)) {
                setLabel(row.code, next);
                render();
            }
        };
        field.input.addEventListener('blur', persist);
        field.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); field.input.blur(); }
        });
        wrap.appendChild(field.field);
        return wrap;
    }

    function buildQRBlock(row) {
        const wrap = document.createElement('div');
        wrap.className = 'qr-block';
        const h = document.createElement('h3');
        h.textContent = 'Share';
        wrap.appendChild(h);

        const qrURL = `/api/qr/${encodeURIComponent(row.code)}`;
        const img = document.createElement('img');
        img.src = qrURL;
        img.alt = `QR code for /${row.code}`;
        img.className = 'qr-preview';
        img.loading = 'lazy';
        // Hide the broken-image icon if QR generation ever fails — better to
        // show nothing than a broken visual.
        img.addEventListener('error', () => { img.style.display = 'none'; });
        wrap.appendChild(img);

        const dl = document.createElement('a');
        dl.className = 'btn btn-ghost btn-sm';
        dl.href = qrURL;
        dl.download = `qr-${row.code}.png`;
        dl.textContent = '⬇ Download PNG';
        wrap.appendChild(dl);
        return wrap;
    }

    function buildTokenRow(row) {
        const wrap = document.createElement('div');
        const h = document.createElement('h3');
        h.textContent = 'Admin token';
        h.style.marginTop = '0.75rem';
        wrap.appendChild(h);

        const note = document.createElement('p');
        note.className = 'muted';
        note.style.fontSize = '0.75rem';
        note.style.marginBottom = '0.4rem';
        note.textContent = 'Anyone with this token can edit or delete this short URL. Saved in this browser only.';
        wrap.appendChild(note);

        const tr = document.createElement('div');
        tr.className = 'token-row';
        const code = document.createElement('code');
        code.textContent = row.token;
        tr.appendChild(code);
        tr.appendChild(makeBtn('Copy', 'btn btn-ghost btn-sm', async () => {
            try {
                await navigator.clipboard.writeText(row.token);
                toast('Token copied.', 'success');
            } catch (_) {
                toast('Copy failed.', 'error');
            }
        }));
        wrap.appendChild(tr);

        wrap.appendChild(makeBtn('Rotate token', 'btn btn-ghost btn-sm', async () => {
            if (!confirm(`Issue a new admin token for /${row.code}? The current token will be invalidated immediately.`)) return;
            try {
                const data = await apiRotate(row.code, row.token);
                saveToken(row.code, data.admin_token);
                // Update the in-memory row so subsequent calls use the new token.
                row.token = data.admin_token;
                rows.set(row.code, row);
                render();
                toast('Token rotated. New token saved in this browser.', 'success');
            } catch (err) {
                toast(err.message, 'error');
            }
        }));

        return wrap;
    }

    function buildDangerZone(row) {
        const wrap = document.createElement('div');
        wrap.style.marginTop = '1rem';
        wrap.appendChild(makeBtn('Delete this short URL', 'btn btn-danger btn-sm', () => {
            // Optimistic delete with a 6-second Undo window. The actual
            // server DELETE is delayed; if the user clicks Undo, we cancel
            // the timer and restore the row from the captured snapshot.
            // No confirm dialog — undo IS the confirmation.
            softDelete([row.code]);
        }));
        return wrap;
    }

    async function loadEvents(code) {
        const row = rows.get(code);
        if (!row || row.status !== 'active') return;
        rows.set(code, { ...row, eventsLoading: true });
        render();
        try {
            const events = await apiClicks(code, row.token, 200);
            rows.set(code, { ...row, eventsLoading: false, events });
        } catch (e) {
            rows.set(code, { ...row, eventsLoading: false, events: { count: 0, events: [] } });
        }
        render();
    }

    function toggleExpand(code) {
        if (expanded.has(code)) {
            expanded.delete(code);
            stopLiveStream(code);
        } else {
            expanded.add(code);
            startLiveStream(code);
        }
        render();
    }

    /**
     * Open a Server-Sent Events stream to /api/analytics/{code}/stream.
     * Browser EventSource doesn't support Authorization headers, so we
     * use fetch() with a streaming body reader and parse the SSE wire
     * format ourselves. AbortController on the request lets us close the
     * stream when the row collapses.
     *
     * Each click event from the server triggers a refresh of that row's
     * analytics — the displayed click_count goes up, the pulse fires,
     * and the events list (if visible) gets re-fetched naturally on the
     * next render via lazy loadEvents.
     */
    function startLiveStream(code) {
        if (liveStreams.has(code)) return;
        const row = rows.get(code);
        if (!row || row.status !== 'active') return;

        const controller = new AbortController();
        liveStreams.set(code, controller);

        (async () => {
            try {
                const resp = await fetch(`/api/analytics/${encodeURIComponent(code)}/stream`, {
                    headers: { 'Authorization': `Bearer ${row.token}` },
                    signal: controller.signal,
                });
                if (!resp.ok || !resp.body) return; // 401/404/410 etc.
                const reader = resp.body.getReader();
                const decoder = new TextDecoder();
                let buf = '';
                while (true) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    buf += decoder.decode(value, { stream: true });
                    // SSE events are separated by a blank line.
                    let idx;
                    while ((idx = buf.indexOf('\n\n')) !== -1) {
                        const raw = buf.slice(0, idx);
                        buf = buf.slice(idx + 2);
                        handleSSEEvent(code, raw);
                    }
                }
            } catch (e) {
                // AbortError is expected when stopLiveStream fires; anything
                // else (network blip, server restart) just ends the stream
                // and the periodic loadAll() will bring the row up to date.
            } finally {
                if (liveStreams.get(code) === controller) {
                    liveStreams.delete(code);
                }
            }
        })();
    }

    function stopLiveStream(code) {
        const ctrl = liveStreams.get(code);
        if (ctrl) {
            ctrl.abort();
            liveStreams.delete(code);
        }
    }

    function handleSSEEvent(code, raw) {
        // Parse a single SSE event: lines like "event: foo", "data: ...",
        // ":heartbeat" (comment, ignored).
        let event = 'message';
        let data = '';
        for (const line of raw.split('\n')) {
            if (line.startsWith(':')) continue; // comment / heartbeat
            if (line.startsWith('event: ')) event = line.slice(7).trim();
            else if (line.startsWith('data: ')) data += line.slice(6);
        }
        if (event !== 'click' || !data) return;
        // We don't parse the JSON payload here — the only signal we need
        // is "a click happened, refresh this row." refreshOne will
        // increment the displayed count and trigger detectActivity which
        // flashes the dot.
        refreshOne(code);
    }

    async function copyShortURL(code) {
        const url = `${location.origin}/${code}`;
        try {
            await navigator.clipboard.writeText(url);
            toast('Short URL copied.', 'success');
        } catch (_) {
            toast('Copy failed.', 'error');
        }
    }

    // ---------- relative time ---------------------------------------------

    const RTF = (typeof Intl !== 'undefined' && Intl.RelativeTimeFormat)
        ? new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
        : null;

    function relativeTime(iso) {
        const t = Date.parse(iso);
        if (!Number.isFinite(t)) return '—';
        const diffSec = Math.round((t - Date.now()) / 1000);
        const abs = Math.abs(diffSec);
        const units = [
            ['second', 60],
            ['minute', 60],
            ['hour',   24],
            ['day',     7],
            ['week',  4.345],
            ['month',  12],
            ['year',  Number.POSITIVE_INFINITY],
        ];
        let unit = 'second';
        let value = diffSec;
        let acc = 1;
        for (const [name, factor] of units) {
            if (Math.abs(value) < factor) { unit = name; break; }
            value = value / factor;
            unit = name;
            acc *= factor;
        }
        if (!RTF) {
            return `${Math.round(Math.abs(value))} ${unit}${Math.abs(Math.round(value)) === 1 ? '' : 's'}` +
                (diffSec >= 0 ? ' from now' : ' ago');
        }
        return RTF.format(Math.round(value), unit);
    }

    // ---------- create flow -----------------------------------------------

    function openCreate() {
        els.importPanel.classList.add('hidden');
        els.createPanel.classList.remove('hidden');
        els.urlInput.focus();
    }
    function closeCreate() {
        els.createPanel.classList.add('hidden');
        els.createForm.reset();
    }

    async function submitCreate(e) {
        e.preventDefault();
        const url = els.urlInput.value.trim();
        if (!url) { toast('Enter a URL.', 'error'); return; }
        if (!/^https?:\/\//i.test(url)) { toast('URL must start with http:// or https://', 'error'); return; }
        const custom_code = els.customCodeInput.value.trim();
        const expRaw = els.expirationInput.value.trim();
        const expiration_mins = expRaw ? parseInt(expRaw, 10) : undefined;

        els.createBtn.disabled = true;
        const original = els.createBtn.textContent;
        els.createBtn.textContent = 'Creating…';
        try {
            const data = await apiCreate({ url, custom_code, expiration_mins });
            saveToken(data.short_code, data.admin_token);
            const seed = {
                short_code: data.short_code,
                original_url: data.original_url,
                click_count: 0,
                created_at: new Date().toISOString(),
                expires_at: data.expires_at,
                last_accessed: null,
            };
            rows.set(data.short_code, { code: data.short_code, token: data.admin_token, status: 'active', data: seed });
            // Seed the snapshot so the FIRST real click after creation is
            // flagged as activity (otherwise prev would be undefined and the
            // first observed positive count wouldn't pulse).
            refreshSnapshot.set(data.short_code, 0);
            closeCreate();
            toast(`Created /${data.short_code}.`, 'success');
            render();
        } catch (err) {
            toast(err.message, 'error');
        } finally {
            els.createBtn.disabled = false;
            els.createBtn.textContent = original;
        }
    }

    // ---------- import flow -----------------------------------------------

    function openImport() {
        // Mutually exclusive with the create panel — opening one closes the other.
        closeCreate();
        els.importPanel.classList.remove('hidden');
        els.importCodeInput.focus();
    }
    function closeImport() {
        els.importPanel.classList.add('hidden');
        els.importForm.reset();
    }

    async function submitImport(e) {
        e.preventDefault();
        const code = els.importCodeInput.value.trim();
        const token = els.importTokenInput.value.trim();
        if (!code || !token) { toast('Both code and token are required.', 'error'); return; }
        if (!/^[A-Za-z0-9_-]{3,32}$/.test(code)) { toast('Invalid code format.', 'error'); return; }
        if (rows.has(code)) { toast(`/${code} is already in your dashboard.`, 'info'); closeImport(); return; }

        els.importSubmitBtn.disabled = true;
        const orig = els.importSubmitBtn.textContent;
        els.importSubmitBtn.textContent = 'Verifying…';
        try {
            // Verify the token is valid by attempting an authenticated read.
            // 200 → token good, save it. 401 → wrong token. 404 → no such code.
            // 410 → expired (auth check happens after expiry check, so we
            // can't actually validate the token in that case; reject the import).
            const { status, data } = await apiAnalytics(code, token);
            if (status === 200 && data) {
                saveToken(code, token);
                rows.set(code, { code, token, status: 'active', data });
                refreshSnapshot.set(code, data.click_count);
                closeImport();
                toast(`Imported /${code}.`, 'success');
                render();
            } else if (status === 401 || status === 403) {
                toast('That token does not match this short code.', 'error');
            } else if (status === 404) {
                toast('Short code not found on this server.', 'error');
            } else if (status === 410) {
                toast('Short code has expired and cannot be imported.', 'error');
            } else {
                toast(`Import failed (status ${status}).`, 'error');
            }
        } catch (_) {
            toast('Network error while verifying token.', 'error');
        } finally {
            els.importSubmitBtn.disabled = false;
            els.importSubmitBtn.textContent = orig;
        }
    }

    // ---------- bulk operations -------------------------------------------

    function updateBulkBar() {
        const n = selected.size;
        if (n === 0) {
            els.bulkBar.classList.add('hidden');
        } else {
            els.bulkBar.classList.remove('hidden');
            els.bulkCount.textContent = String(n);
        }
        // Also reflect the select-all checkbox state — checked when every
        // currently-visible row is selected, indeterminate when partial.
        const visibleCodes = visibleSorted().map(r => r.code);
        if (visibleCodes.length === 0) {
            els.selectAllCheckbox.checked = false;
            els.selectAllCheckbox.indeterminate = false;
        } else {
            const allSelected = visibleCodes.every(c => selected.has(c));
            const noneSelected = visibleCodes.every(c => !selected.has(c));
            els.selectAllCheckbox.checked = allSelected;
            els.selectAllCheckbox.indeterminate = !allSelected && !noneSelected;
        }
    }

    function visibleSorted() {
        return Array.from(rows.values()).filter(matchSearch).sort(rowComparator);
    }

    function toggleSelectAll() {
        const visible = visibleSorted();
        const allSelected = visible.length > 0 && visible.every(r => selected.has(r.code));
        if (allSelected) {
            for (const r of visible) selected.delete(r.code);
        } else {
            for (const r of visible) selected.add(r.code);
        }
        render();
    }

    function bulkDelete() {
        if (selected.size === 0) return;
        const codes = Array.from(selected);
        // Snapshot of the selection — softDelete will clear it optimistically.
        softDelete(codes);
    }

    /**
     * Optimistic delete + undo. The row(s) disappear immediately; an "Undo"
     * toast holds them in a parking-lot for UNDO_MS. After the window:
     *   - if undone → restore everything, no server call.
     *   - if not   → fan out the actual DELETE requests, then drop the
     *                local-storage tokens/labels for codes the server
     *                accepted as deleted.
     *
     * Closing the tab during the window cancels the pending delete (the
     * setTimeout never fires). That's a feature: an accidental delete
     * followed by a panic-close leaves the URL alive.
     */
    const UNDO_MS = 6000;
    function softDelete(codes) {
        if (codes.length === 0) return;
        // Capture full state so we can restore on undo: row object, label,
        // selection, expansion, snapshot. Capture before any mutation.
        const captured = codes.map((code) => ({
            code,
            row: rows.get(code),
            label: getLabel(code),
            wasSelected: selected.has(code),
            wasExpanded: expanded.has(code),
            snapshot: refreshSnapshot.get(code),
        })).filter(c => c.row);
        if (captured.length === 0) return;

        // Optimistic remove from the dashboard. Close any live stream
        // before the row disappears so we don't leak server-side
        // subscriptions for tokens that may be about to be invalidated.
        for (const c of captured) {
            stopLiveStream(c.code);
            rows.delete(c.code);
            expanded.delete(c.code);
            selected.delete(c.code);
        }
        render();

        let undone = false;
        const timer = setTimeout(async () => {
            if (undone) return;
            const failed = [];
            await pool(captured, 6, async (c) => {
                try {
                    const status = await apiDelete(c.code, c.row.token);
                    if (status === 204 || status === 404 || status === 410) {
                        dropLocalEntries(c.code);
                    } else {
                        failed.push({ ...c, reason: `${status}` });
                    }
                } catch (e) {
                    failed.push({ ...c, reason: 'network' });
                }
            });
            if (failed.length > 0) {
                // Restore the rows we couldn't delete — UI state needs to
                // match server reality.
                for (const c of failed) {
                    rows.set(c.code, c.row);
                    if (c.snapshot !== undefined) refreshSnapshot.set(c.code, c.snapshot);
                }
                render();
                toast(`Failed to delete ${failed.length} URL${failed.length === 1 ? '' : 's'}.`, 'error');
            }
        }, UNDO_MS);

        const label = captured.length === 1
            ? `/${captured[0].code} deleted.`
            : `Deleted ${captured.length} short URLs.`;

        toast(label, 'success', {
            actionLabel: 'Undo',
            durationMs: UNDO_MS,
            action: () => {
                undone = true;
                clearTimeout(timer);
                for (const c of captured) {
                    rows.set(c.code, c.row);
                    if (c.wasSelected) selected.add(c.code);
                    if (c.wasExpanded) expanded.add(c.code);
                    if (c.snapshot !== undefined) refreshSnapshot.set(c.code, c.snapshot);
                }
                render();
            },
        });
    }

    function clearSelection() {
        selected.clear();
        render();
    }

    // ---------- CSV export ------------------------------------------------

    /**
     * Export the currently-visible (filtered + sorted) rows as a CSV blob.
     * Admin tokens are deliberately omitted — a CSV is the kind of file
     * people share by accident, and the tokens would be the most sensitive
     * fields in it. Users who want a token backup should copy them
     * one-at-a-time from the row detail panel.
     */
    function exportCSV() {
        const visible = visibleSorted();
        if (visible.length === 0) {
            toast('Nothing to export — the table is empty (or filtered to nothing).', 'info');
            return;
        }

        const header = ['code', 'destination', 'clicks', 'created_at', 'expires_at', 'last_accessed', 'label', 'status'];
        const lines = [header.join(',')];
        for (const row of visible) {
            const fields = [
                row.code,
                row.data?.original_url ?? '',
                row.data?.click_count ?? '',
                row.data?.created_at ?? '',
                row.data?.expires_at ?? '',
                row.data?.last_accessed ?? '',
                getLabel(row.code),
                row.status,
            ];
            lines.push(fields.map(csvField).join(','));
        }
        // RFC 4180 prescribes CRLF line endings; most spreadsheets accept LF
        // but Excel on Windows is happier with CRLF.
        const blob = new Blob([lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
        const stamp = new Date().toISOString().slice(0, 10);
        triggerDownload(blob, `tiny-url-export-${stamp}.csv`);
        toast(`Exported ${visible.length} URL${visible.length === 1 ? '' : 's'}.`, 'success');
    }

    /** RFC 4180 CSV field escaping: wrap in quotes only when the value
     *  contains a comma, quote, or newline; double-up embedded quotes. */
    function csvField(v) {
        const s = String(v ?? '');
        if (/[",\r\n]/.test(s)) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }

    function triggerDownload(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        // Revoke after a tick so the browser has time to dispatch the download.
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // ---------- search & sort ---------------------------------------------

    function bindSortHeaders() {
        document.querySelectorAll('.url-table th.sortable').forEach((th) => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                else { sortKey = key; sortDir = 'asc'; }
                render();
            });
        });
    }

    // ---------- keyboard ---------------------------------------------------

    function bindKeyboard() {
        document.addEventListener('keydown', (e) => {
            // Skip when typing in inputs
            const t = e.target;
            const inField = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);

            if (e.key === 'Escape') {
                if (!els.createPanel.classList.contains('hidden')) {
                    closeCreate();
                    e.preventDefault();
                } else if (!els.importPanel.classList.contains('hidden')) {
                    closeImport();
                    e.preventDefault();
                } else if (selected.size) {
                    clearSelection();
                    e.preventDefault();
                } else if (expanded.size) {
                    // Close every live stream we opened with the row.
                    for (const code of expanded) stopLiveStream(code);
                    expanded.clear();
                    render();
                    e.preventDefault();
                }
                return;
            }
            if (inField) return;
            if (e.key === '/') { els.searchInput.focus(); e.preventDefault(); return; }
            if (e.key === 'n') { openCreate(); e.preventDefault(); return; }
            if (e.key === 'i') { openImport(); e.preventDefault(); return; }
            if (e.key === 'r') { loadAll(); e.preventDefault(); return; }
        });
    }

    // ---------- bootstrap --------------------------------------------------

    function bind() {
        els.themeToggle.addEventListener('click', toggleTheme);
        els.newBtn.addEventListener('click', openCreate);
        els.emptyCreateBtn.addEventListener('click', openCreate);
        els.cancelCreateBtn.addEventListener('click', closeCreate);
        els.createForm.addEventListener('submit', submitCreate);

        els.importBtn.addEventListener('click', openImport);
        els.emptyImportBtn.addEventListener('click', openImport);
        els.cancelImportBtn.addEventListener('click', closeImport);
        els.importForm.addEventListener('submit', submitImport);

        els.refreshBtn.addEventListener('click', () => { loadAll(); });
        els.exportBtn.addEventListener('click', exportCSV);
        els.searchInput.addEventListener('input', () => {
            searchQuery = els.searchInput.value.trim();
            render();
        });

        els.bulkDeleteBtn.addEventListener('click', bulkDelete);
        els.bulkClearBtn.addEventListener('click', clearSelection);
        els.selectAllCheckbox.addEventListener('change', toggleSelectAll);

        bindSortHeaders();
        bindKeyboard();

        // Auto-refresh every 30s — only if document is visible to avoid wasting
        // requests on backgrounded tabs.
        setInterval(() => {
            if (document.hidden) return;
            loadAll();
        }, REFRESH_MS);
    }

    document.addEventListener('DOMContentLoaded', () => {
        initTheme();
        bind();
        // Initial load
        if (tokensFromStorage().length === 0) {
            els.loadingState.classList.add('hidden');
            els.emptyState.classList.remove('hidden');
        }
        loadAll();
    });
})();
