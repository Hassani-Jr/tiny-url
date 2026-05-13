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
    const APIKEY_KEY   = 'tinyurl:apikey'; // raw key value, persisted across sessions
    const REFRESH_MS   = 30_000;
    const TOAST_MS     = 3500;
    const FLASH_MS     = 2500;
    const LABEL_MAX    = 64;

    /**
     * Sparkline time-range presets. Each entry maps to the server-side
     * /api/analytics/{code}/series endpoint via `bucket` and `range`. The
     * server caps `range` per resolution so we don't ever send out-of-
     * spec values — see rangeCaps in handlers/series.go.
     *
     * Moving away from client-side bucketize() of the raw events log
     * (capped at 200 events) means the chart stays accurate for high-
     * volume URLs and unlocks longer windows like 30d.
     */
    const RANGES = {
        '1h':  { label: '1 h',  bucket: 'minute', range: 60  },
        '24h': { label: '24 h', bucket: 'hour',   range: 24  },
        '7d':  { label: '7 d',  bucket: 'hour',   range: 168 },
        '30d': { label: '30 d', bucket: 'day',    range: 30  },
    };

    // ---------- DOM refs ---------------------------------------------------

    const $ = (id) => document.getElementById(id);
    const els = {
        searchInput:    $('searchInput'),
        tagFilter:      $('tagFilter'),
        importBtn:      $('importBtn'),
        newBtn:         $('newBtn'),
        themeToggle:    $('themeToggle'),
        themeIcon:      $('themeIcon'),

        createPanel:    $('createPanel'),
        createForm:     $('createForm'),
        urlInput:       $('urlInput'),
        customCodeInput:$('customCodeInput'),
        expirationInput:$('expirationInput'),
        tagsInput:      $('tagsInput'),
        maxClicksInput: $('maxClicksInput'),
        passwordInput:  $('passwordInput'),
        webhookInput:   $('webhookInput'),
        cancelCreateBtn:$('cancelCreateBtn'),
        createBtn:      $('createBtn'),

        keyBtn:            $('keyBtn'),
        keyPanel:          $('keyPanel'),
        keyActiveBlock:    $('keyActiveBlock'),
        keyValue:          $('keyValue'),
        keyLabel:          $('keyLabel'),
        keyCopyBtn:        $('keyCopyBtn'),
        keyRevokeBtn:      $('keyRevokeBtn'),
        keyClearBtn:       $('keyClearBtn'),
        keyCreateForm:     $('keyCreateForm'),
        keyLabelInput:     $('keyLabelInput'),
        keyPasteInput:     $('keyPasteInput'),
        keyCancelBtn:      $('keyCancelBtn'),
        keyPasteBtn:       $('keyPasteBtn'),
        keyCreateBtn:      $('keyCreateBtn'),

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
    let tagFilter = '';
    let sortKey = 'last_accessed';
    let sortDir = 'desc';
    let currentRange = '24h';
    /**
     * apiKey: when non-empty, the dashboard is in "API key mode" — every
     * fetch uses this key as the bearer, and loadAll() pulls from
     * GET /api/urls instead of iterating per-URL admin tokens. Stored
     * in localStorage so it survives reloads.
     */
    let apiKey = '';
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
    /**
     * Show the freshly-issued webhook secret with a copy button. The
     * server returns each secret ONCE (mirrors the admin_token flow);
     * after this toast disappears the user must rotate to see a new
     * value. Stays open for a long time so it's hard to miss.
     */
    function showWebhookSecret(code, secret) {
        const node = document.createElement('div');
        node.className = 'toast toast-info';
        node.style.alignItems = 'flex-start';
        node.style.flexDirection = 'column';
        node.style.gap = '0.4rem';

        const title = document.createElement('strong');
        title.textContent = `/${code} — webhook secret (shown once)`;
        node.appendChild(title);

        const codeEl = document.createElement('code');
        codeEl.textContent = secret;
        codeEl.style.userSelect = 'all';
        codeEl.style.wordBreak = 'break-all';
        codeEl.style.fontSize = '0.78rem';
        node.appendChild(codeEl);

        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.gap = '0.4rem';
        row.style.width = '100%';

        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'toast-action';
        copy.textContent = 'Copy';
        copy.addEventListener('click', async (e) => {
            e.stopPropagation();
            try {
                await navigator.clipboard.writeText(secret);
                copy.textContent = 'Copied';
            } catch (_) {
                copy.textContent = 'Copy failed';
            }
        });
        row.appendChild(copy);

        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'toast-action';
        close.textContent = 'Dismiss';
        close.addEventListener('click', (e) => { e.stopPropagation(); dismissToast(node); });
        row.appendChild(close);

        node.appendChild(row);
        els.toastContainer.appendChild(node);
        // 60s so the user has enough time to copy into their downstream
        // env file without dismissing prematurely.
        setTimeout(() => dismissToast(node), 60_000);
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

    async function apiCreate({ url, custom_code, expiration_mins, tags, max_clicks, password, webhook_url }) {
        const body = { url };
        if (custom_code) body.custom_code = custom_code;
        if (expiration_mins) body.expiration_mins = expiration_mins;
        if (tags && tags.length) body.tags = tags;
        if (max_clicks) body.max_clicks = max_clicks;
        if (password) body.password = password;
        if (webhook_url) body.webhook_url = webhook_url;
        const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
        // Authenticate the create request when an API key is active so
        // the server claims ownership for that key (api_key_id is set
        // on the new row).
        if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
        const r = await fetch('/api/shorten', {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.message || `Create failed (${r.status})`);
        return data;
    }
    /**
     * Bearer resolver. Prefers the global API key when set; falls back
     * to the per-URL admin token. Returning the key everywhere means
     * the per-URL token still works for URLs not owned by this key
     * (the server resolves both credentials).
     */
    function bearerFor(perURLToken) {
        return apiKey || perURLToken || '';
    }

    async function apiCreateKey(label) {
        const r = await fetch('/api/keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            body: JSON.stringify({ label }),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.message || `Create key failed (${r.status})`);
        return data;
    }
    async function apiGetKey(key) {
        const r = await fetch('/api/keys', { headers: { 'Authorization': `Bearer ${key}` } });
        if (r.status === 401) return null;
        if (!r.ok) throw new Error(`Get key failed (${r.status})`);
        return r.json();
    }
    async function apiRevokeKey(key) {
        const r = await fetch('/api/keys', {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${key}` },
        });
        if (!r.ok && r.status !== 204) throw new Error(`Revoke failed (${r.status})`);
    }
    async function apiListMyURLs(key) {
        const r = await fetch('/api/urls', { headers: { 'Authorization': `Bearer ${key}` } });
        if (!r.ok) throw new Error(`List failed (${r.status})`);
        return r.json();
    }

    async function apiSeries(code, token, bucket = 'hour', range = 24) {
        const r = await fetch(`/api/analytics/${encodeURIComponent(code)}/series?bucket=${bucket}&range=${range}`, {
            headers: { 'Authorization': `Bearer ${bearerFor(token)}` },
        });
        if (!r.ok) throw new Error(`Series fetch failed (${r.status})`);
        return r.json();
    }
    async function apiAnalytics(code, token) {
        const r = await fetch(`/api/analytics/${encodeURIComponent(code)}`, {
            headers: { 'Authorization': `Bearer ${bearerFor(token)}` },
        });
        return { status: r.status, data: r.status === 200 ? await r.json() : null };
    }
    async function apiClicks(code, token, limit = 50) {
        const r = await fetch(`/api/analytics/${encodeURIComponent(code)}/clicks?limit=${limit}`, {
            headers: { 'Authorization': `Bearer ${bearerFor(token)}` },
        });
        if (!r.ok) throw new Error(`Clicks fetch failed (${r.status})`);
        return r.json();
    }
    async function apiPatch(code, token, body) {
        const r = await fetch(`/api/url/${encodeURIComponent(code)}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${bearerFor(token)}`,
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
            headers: { 'Authorization': `Bearer ${bearerFor(token)}` },
        });
        return r.status;
    }
    async function apiRotate(code, token) {
        const r = await fetch(`/api/url/${encodeURIComponent(code)}/rotate`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${bearerFor(token)}` },
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
        // API-key mode: a single /api/urls call gives us every URL the
        // key owns, no need to iterate localStorage tokens. The legacy
        // path below still runs alongside so URLs not owned by the key
        // (e.g. imports created before account mode) keep working.
        if (apiKey) {
            try {
                const data = await apiListMyURLs(apiKey);
                for (const u of (data.urls || [])) {
                    rows.set(u.short_code, {
                        code: u.short_code,
                        token: '', // API key auths everything
                        status: 'active',
                        data: u,
                    });
                    detectActivity(u.short_code, u);
                }
            } catch (e) {
                toast(`API key list failed: ${e.message}`, 'error');
            }
        }

        const tokens = tokensFromStorage();
        if (tokens.length === 0 && rows.size === 0) {
            rows.clear();
            render();
            return;
        }
        if (tokens.length === 0) {
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
                // Drop cached series for the currently-displayed range so
                // the next render fetches fresh data — otherwise a live
                // click wouldn't show up in the spark until manual refresh.
                if (row.series) delete row.series[currentRange];
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
        refreshTagFilter();
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
        // Tag filter is AND'd with the text search so a user can narrow by tag
        // and still type a freetext substring (e.g. tag=work + "stand up").
        if (tagFilter) {
            const tags = row.data?.tags || [];
            if (!tags.includes(tagFilter)) return false;
        }
        if (!searchQuery) return true;
        const q = searchQuery.toLowerCase();
        if (row.code.toLowerCase().includes(q)) return true;
        if (row.data?.original_url?.toLowerCase().includes(q)) return true;
        if (getLabel(row.code).toLowerCase().includes(q)) return true;
        if ((row.data?.tags || []).some(t => t.toLowerCase().includes(q))) return true;
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
        // 🔒 indicator for password-gated URLs. Title is hover-discoverable;
        // ARIA label is read out loud for screen readers.
        if (row.data?.has_password) {
            const lock = document.createElement('span');
            lock.className = 'cell-lock';
            lock.textContent = '🔒';
            lock.title = 'Password-protected';
            lock.setAttribute('aria-label', 'Password-protected');
            tdCode.appendChild(lock);
        }
        const label = getLabel(row.code);
        if (label) {
            const labelSpan = document.createElement('span');
            labelSpan.className = 'cell-label';
            labelSpan.textContent = label;
            labelSpan.title = label;
            tdCode.appendChild(labelSpan);
        }
        const tags = row.data?.tags || [];
        for (const t of tags) {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'tag-chip';
            chip.textContent = t;
            chip.title = `Filter by ${t}`;
            chip.addEventListener('click', (e) => {
                e.stopPropagation();
                tagFilter = (tagFilter === t) ? '' : t;
                if (els.tagFilter) els.tagFilter.value = tagFilter;
                render();
            });
            tdCode.appendChild(chip);
        }
        tr.appendChild(tdCode);

        const tdDest = document.createElement('td');
        tdDest.className = 'cell-dest';
        tdDest.textContent = row.data?.original_url || '—';
        tdDest.title = row.data?.original_url || '';
        tr.appendChild(tdDest);

        const tdClicks = document.createElement('td');
        tdClicks.className = 'cell-clicks';
        if (row.data?.max_clicks > 0) {
            // Show "used / cap" so the owner sees how close they are to
            // burning a single-use link. Stays compact when count is 0 by
            // skipping the slash form.
            tdClicks.textContent = `${row.data.click_count ?? 0} / ${row.data.max_clicks}`;
        } else {
            tdClicks.textContent = row.data?.click_count ?? '—';
        }
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

        // The sparkline pulls from the server time-series endpoint (cached
        // per range on `row.series`). The breakdown still uses the raw
        // events list for top-referers / device counts since the series
        // endpoint only aggregates time, not category.
        left.appendChild(buildSparkBlock(row));
        if (row.eventsLoading) {
            const p = document.createElement('p');
            p.className = 'muted';
            p.textContent = 'Loading click events…';
            left.appendChild(p);
        } else if (row.events) {
            left.appendChild(buildBreakdown(row.events));
        }
        grid.appendChild(left);

        // Right column: preview card (if available) + QR (share) +
        // edit + token + delete (manage)
        const right = document.createElement('div');
        right.className = 'detail-block';
        const preview = buildPreviewBlock(row);
        if (preview) right.appendChild(preview);
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

    function buildSparkBlock(row) {
        const cfg = RANGES[currentRange] || RANGES['24h'];
        const series = row.series?.[currentRange];
        const buckets = series?.counts || [];
        const total = buckets.reduce((s, n) => s + n, 0);

        const wrap = document.createElement('div');

        const toggle = buildRangeToggle(row);
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

        if (series) {
            sparkRow.appendChild(sparklineSVG(buckets, cfg));
        } else {
            const ph = document.createElement('span');
            ph.className = 'muted';
            ph.textContent = 'Loading…';
            sparkRow.appendChild(ph);
            // Fire-and-forget: result is stashed on the row and a re-render
            // picks it up. No await here so the rest of the detail block
            // still renders immediately.
            loadSeries(row.code, currentRange);
        }
        wrap.appendChild(sparkRow);
        return wrap;
    }

    /**
     * Fetch /api/analytics/{code}/series for the given range and cache it
     * on the row. The result lives at row.series[rangeKey] so switching
     * ranges back-and-forth doesn't re-request the server. Cleared on
     * refreshOne() so periodic refreshes see fresh data.
     */
    async function loadSeries(code, rangeKey) {
        const row = rows.get(code);
        if (!row || row.status !== 'active') return;
        const cfg = RANGES[rangeKey];
        if (!cfg) return;
        row.series = row.series || {};
        if (row.series[rangeKey] === 'loading') return; // already in flight
        row.series[rangeKey] = 'loading';
        try {
            const data = await apiSeries(code, row.token, cfg.bucket, cfg.range);
            row.series[rangeKey] = data;
        } catch (_) {
            row.series[rangeKey] = { counts: [] };
        }
        render();
    }

    /**
     * Build the 1h / 24h / 7d / 30d pill toggle. The `currentRange` global
     * is the single source of truth — all expanded rows render with the
     * same range, which is the simpler model.
     */
    function buildRangeToggle(row) {
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
                // Trigger a fetch for the newly-selected range if we
                // haven't seen it before — avoids a flicker through the
                // empty state on the very first switch.
                if (row && (!row.series || !row.series[key])) loadSeries(row.code, key);
                render();
            });
            wrap.appendChild(b);
        }
        return wrap;
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

        // Country breakdown. Empty country values (geoip disabled or no
        // match) are folded into "Unknown" so the section only renders
        // when there's something useful to show; if every event is
        // unknown we suppress the heading entirely.
        const countries = countBy(events, (e) => e.country || '');
        const nonEmpty = Array.from(countries.entries()).filter(([k]) => k !== '');
        if (nonEmpty.length) {
            const h = document.createElement('h3');
            h.textContent = 'Top countries';
            h.style.marginTop = '0.75rem';
            wrap.appendChild(h);
            const ul = document.createElement('ul');
            ul.className = 'device-list';
            const top = nonEmpty.sort((a, b) => b[1] - a[1]).slice(0, 5);
            for (const [cc, n] of top) {
                const li = document.createElement('li');
                const left = document.createElement('span');
                left.textContent = `${flagEmoji(cc)} ${cc}`;
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

    /**
     * Convert a 2-letter ISO country code into the corresponding regional-
     * indicator flag emoji. Browsers without flag-emoji fonts (notably
     * Windows Chrome) just render the letters, which is still readable.
     */
    function flagEmoji(cc) {
        if (!cc || cc.length !== 2) return '';
        const base = 0x1F1E6 - 'A'.charCodeAt(0);
        const c1 = cc.charCodeAt(0);
        const c2 = cc.charCodeAt(1);
        if (c1 < 65 || c1 > 90 || c2 < 65 || c2 > 90) return '';
        return String.fromCodePoint(base + c1, base + c2);
    }

    /**
     * Split a comma-separated tags input into a trimmed, deduped list.
     * Empty strings are dropped; the server applies the canonical
     * normalization (case, length cap, max-16) and returns the canonical
     * list back in the response.
     */
    function parseTagsInput(raw) {
        if (!raw) return [];
        const seen = new Set();
        const out = [];
        for (const piece of raw.split(',')) {
            const t = piece.trim();
            if (!t || seen.has(t)) continue;
            seen.add(t);
            out.push(t);
        }
        return out;
    }

    /**
     * Rebuild the tag-filter dropdown from the union of tags across all
     * rows. Preserves the user's current selection if that tag is still
     * present after the rebuild; otherwise resets to "All".
     */
    function refreshTagFilter() {
        if (!els.tagFilter) return;
        const all = new Set();
        for (const r of rows.values()) {
            for (const t of (r.data?.tags || [])) all.add(t);
        }
        const previous = tagFilter;
        const sorted = Array.from(all).sort();
        const optAll = document.createElement('option');
        optAll.value = '';
        optAll.textContent = 'All tags';
        const opts = [optAll];
        for (const t of sorted) {
            const o = document.createElement('option');
            o.value = t;
            o.textContent = t;
            opts.push(o);
        }
        els.tagFilter.replaceChildren(...opts);
        if (previous && sorted.includes(previous)) {
            els.tagFilter.value = previous;
        } else if (previous) {
            tagFilter = '';
        }
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
        const tagsField = makeField('Tags (comma-separated)', 'text', (row.data?.tags || []).join(', '));
        const maxField = makeField('Click cap (0 = unlimited)', 'number', row.data?.max_clicks || '');
        const pwField = makeField(
            row.data?.has_password ? 'Replace password (leave blank to keep, "off" to clear)' : 'Set password',
            'text', '');
        pwField.input.placeholder = row.data?.has_password ? 'leave blank to keep' : '';
        const hookField = makeField(
            row.data?.webhook_url ? 'Webhook URL ("off" to clear, blank to keep)' : 'Webhook URL',
            'url', row.data?.webhook_url || '');
        wrap.appendChild(urlField.field);
        wrap.appendChild(expField.field);
        wrap.appendChild(tagsField.field);
        wrap.appendChild(maxField.field);
        wrap.appendChild(pwField.field);
        wrap.appendChild(hookField.field);
        if (row.data?.webhook_url) {
            // Surface a "rotate secret" affordance only when there's an
            // existing webhook to rotate against. Clicking issues a PATCH
            // with webhook_rotate_secret=true and shows the new key once.
            const rot = makeBtn('Rotate webhook secret', 'btn btn-ghost btn-sm', async (e) => {
                e.preventDefault();
                if (!confirm('Issue a new webhook secret? The current secret will stop verifying immediately.')) return;
                try {
                    const data = await apiPatch(row.code, row.token, { webhook_rotate_secret: true });
                    if (data.webhook_secret) {
                        showWebhookSecret(row.code, data.webhook_secret);
                    } else {
                        toast('Rotation succeeded but server did not return a secret.', 'error');
                    }
                } catch (err) {
                    toast(err.message, 'error');
                }
            });
            rot.style.marginTop = '0.4rem';
            wrap.appendChild(rot);
        }

        const actions = document.createElement('div');
        actions.className = 'form-actions';
        actions.appendChild(makeBtn('Save', 'btn btn-primary btn-sm', async (e) => {
            e.preventDefault();
            const newUrl = urlField.input.value.trim();
            const newExpRaw = expField.input.value.trim();
            const body = {};
            if (newUrl && newUrl !== row.data?.original_url) body.url = newUrl;
            if (newExpRaw !== '') body.expiration_mins = parseInt(newExpRaw, 10);

            // Only send `tags` if the canonicalized list differs from the
            // current one — avoids gratuitous PATCH writes from a no-op save.
            const newTags = parseTagsInput(tagsField.input.value);
            const curTags = row.data?.tags || [];
            if (!sameTags(newTags, curTags)) body.tags = newTags;

            const newMaxRaw = maxField.input.value.trim();
            if (newMaxRaw !== '') {
                const parsed = parseInt(newMaxRaw, 10);
                if (Number.isFinite(parsed) && parsed !== (row.data?.max_clicks || 0)) {
                    body.max_clicks = parsed;
                }
            }

            // Password edit semantics:
            //   blank input          → leave alone
            //   the literal "off"    → clear password (uses PATCH password="")
            //   anything else        → set/replace password
            const pwVal = pwField.input.value;
            if (pwVal === 'off') body.password = '';
            else if (pwVal !== '') body.password = pwVal;

            // Webhook URL semantics mirror the password field.
            const hookVal = hookField.input.value.trim();
            const curHook = row.data?.webhook_url || '';
            if (hookVal === 'off') body.webhook_url = '';
            else if (hookVal !== '' && hookVal !== curHook) body.webhook_url = hookVal;

            if (Object.keys(body).length === 0) {
                toast('Nothing to save.', 'info');
                return;
            }
            try {
                const data = await apiPatch(row.code, row.token, body);
                toast(`/${row.code} updated.`, 'success');
                expField.input.value = '';
                pwField.input.value = '';
                // PATCH returns a fresh secret only when the webhook was
                // added or rotated server-side. Show it inline when it
                // does — same one-shot contract as creation.
                if (data && data.webhook_secret) {
                    showWebhookSecret(row.code, data.webhook_secret);
                }
                refreshOne(row.code);
            } catch (err) {
                toast(err.message, 'error');
            }
        }));
        wrap.appendChild(actions);
        return wrap;
    }

    function sameTags(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
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

    /**
     * Preview card built from the server-side unfurl. Hidden entirely
     * when no fields are populated, even after a fetch attempt — empty
     * preview metadata is normal for many sites and a "no preview"
     * placeholder would clutter the panel.
     */
    function buildPreviewBlock(row) {
        const d = row.data;
        if (!d) return null;
        const hasAny = d.preview_title || d.preview_image || d.preview_description;
        if (!hasAny) return null;

        const wrap = document.createElement('div');
        wrap.className = 'preview-block';
        const h = document.createElement('h3');
        h.textContent = 'Preview';
        wrap.appendChild(h);

        const card = document.createElement('div');
        card.className = 'preview-card';

        if (d.preview_image) {
            const img = document.createElement('img');
            img.src = d.preview_image;
            img.alt = '';
            img.loading = 'lazy';
            img.className = 'preview-img';
            // Hide a broken image rather than showing the alt text in
            // a box that's obviously placeholder-shaped.
            img.addEventListener('error', () => { img.style.display = 'none'; });
            card.appendChild(img);
        }

        const text = document.createElement('div');
        text.className = 'preview-text';
        if (d.preview_title) {
            const t = document.createElement('div');
            t.className = 'preview-title';
            t.textContent = d.preview_title;
            text.appendChild(t);
        }
        if (d.preview_description) {
            const desc = document.createElement('div');
            desc.className = 'preview-desc';
            desc.textContent = d.preview_description;
            text.appendChild(desc);
        }
        card.appendChild(text);
        wrap.appendChild(card);
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
                    headers: { 'Authorization': `Bearer ${bearerFor(row.token)}` },
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

    // ---------- API key flow ----------------------------------------------

    /**
     * Read the API key from localStorage on startup. Validates against
     * the server with GET /api/keys — a stale/revoked key is cleared so
     * the dashboard doesn't keep sending an invalid bearer.
     */
    async function initAPIKey() {
        let stored = '';
        try { stored = localStorage.getItem(APIKEY_KEY) || ''; } catch (_) {}
        if (!stored) return;
        try {
            const meta = await apiGetKey(stored);
            if (!meta) {
                try { localStorage.removeItem(APIKEY_KEY); } catch (_) {}
                toast('Saved API key was rejected by the server and has been removed.', 'info');
                return;
            }
            apiKey = stored;
        } catch (_) {
            // Network or 5xx: keep the key, retry on next user action.
            apiKey = stored;
        }
        renderKeyPanel();
    }

    function openKeyPanel() {
        closeCreate(); closeImport();
        els.keyPanel.classList.remove('hidden');
        renderKeyPanel();
    }
    function closeKeyPanel() {
        els.keyPanel.classList.add('hidden');
    }

    function renderKeyPanel() {
        if (!els.keyPanel) return;
        const active = !!apiKey;
        els.keyActiveBlock.classList.toggle('hidden', !active);
        if (active) {
            els.keyValue.textContent = apiKey;
            // Best-effort metadata fetch — failure is fine, the user
            // still sees the raw key value.
            apiGetKey(apiKey).then((m) => {
                if (m && els.keyLabel) els.keyLabel.textContent = m.label || '(no label)';
            }).catch(() => {});
        }
    }

    async function submitCreateKey(e) {
        e.preventDefault();
        const label = els.keyLabelInput.value.trim();
        try {
            const data = await apiCreateKey(label);
            useAPIKey(data.token);
            els.keyLabelInput.value = '';
            toast(`API key created (id ${data.id}). Saved in this browser.`, 'success');
            renderKeyPanel();
            // Pull the URL list with the new key right away so the table
            // populates without waiting for the next periodic refresh.
            loadAll();
        } catch (err) {
            toast(err.message, 'error');
        }
    }

    async function pasteAPIKey() {
        const v = els.keyPasteInput.value.trim();
        if (!v) { toast('Paste a key first.', 'error'); return; }
        try {
            const meta = await apiGetKey(v);
            if (!meta) {
                toast('That key was rejected by the server.', 'error');
                return;
            }
            useAPIKey(v);
            els.keyPasteInput.value = '';
            toast(`API key accepted (id ${meta.id}).`, 'success');
            renderKeyPanel();
            loadAll();
        } catch (err) {
            toast(err.message, 'error');
        }
    }

    function useAPIKey(v) {
        apiKey = v;
        try { localStorage.setItem(APIKEY_KEY, v); } catch (_) {}
    }

    function clearAPIKey() {
        apiKey = '';
        try { localStorage.removeItem(APIKEY_KEY); } catch (_) {}
        renderKeyPanel();
        // Drop server-listed rows; localStorage admin tokens remain.
        rows.clear();
        loadAll();
        toast('API key forgotten on this device. URLs not in localStorage are gone from this view.', 'info');
    }

    async function revokeAPIKey() {
        if (!apiKey) return;
        if (!confirm('Revoke this key on the server? URLs survive but lose their account binding.')) return;
        try {
            await apiRevokeKey(apiKey);
            clearAPIKey();
            toast('API key revoked.', 'success');
        } catch (err) {
            toast(err.message, 'error');
        }
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
        const tags = parseTagsInput(els.tagsInput.value);
        const maxClicksRaw = els.maxClicksInput.value.trim();
        const max_clicks = maxClicksRaw ? parseInt(maxClicksRaw, 10) : undefined;
        const password = els.passwordInput.value;
        const webhook_url = els.webhookInput.value.trim();

        els.createBtn.disabled = true;
        const original = els.createBtn.textContent;
        els.createBtn.textContent = 'Creating…';
        try {
            const data = await apiCreate({ url, custom_code, expiration_mins, tags, max_clicks, password, webhook_url });
            saveToken(data.short_code, data.admin_token);
            const seed = {
                short_code: data.short_code,
                original_url: data.original_url,
                click_count: 0,
                created_at: new Date().toISOString(),
                expires_at: data.expires_at,
                last_accessed: null,
                tags: data.tags || [],
                max_clicks: data.max_clicks || 0,
                has_password: !!data.has_password,
                webhook_url: data.webhook_url || '',
            };
            // The webhook secret is returned ONCE — surface it in a toast
            // with a copy button so the user can stash it. (We can't
            // persist it; the server has only the raw bytes for HMAC and
            // doesn't echo them again.)
            if (data.webhook_secret) {
                showWebhookSecret(data.short_code, data.webhook_secret);
            }
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

        els.keyBtn.addEventListener('click', openKeyPanel);
        els.keyCancelBtn.addEventListener('click', closeKeyPanel);
        els.keyCreateForm.addEventListener('submit', submitCreateKey);
        els.keyPasteBtn.addEventListener('click', pasteAPIKey);
        els.keyClearBtn.addEventListener('click', clearAPIKey);
        els.keyRevokeBtn.addEventListener('click', revokeAPIKey);
        els.keyCopyBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(apiKey);
                toast('API key copied.', 'success');
            } catch (_) { toast('Copy failed.', 'error'); }
        });

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
        if (els.tagFilter) {
            els.tagFilter.addEventListener('change', () => {
                tagFilter = els.tagFilter.value;
                render();
            });
        }

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

    document.addEventListener('DOMContentLoaded', async () => {
        initTheme();
        bind();
        // Init the API key before the first list call so /api/urls is
        // used right away if the key is valid.
        await initAPIKey();
        if (tokensFromStorage().length === 0 && !apiKey) {
            els.loadingState.classList.add('hidden');
            els.emptyState.classList.remove('hidden');
        }
        loadAll();
    });
})();
