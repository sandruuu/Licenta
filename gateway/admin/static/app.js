/* ═══════════════════════════════════════════════════════════════
   SecureAlert Gateway — Admin UI (Vanilla JS)
   ═══════════════════════════════════════════════════════════════ */

// ── Token management ─────────────────────────────────────────
// The admin session token is stored in an HttpOnly cookie (set by server).
// Only the CSRF token is kept in JS memory for double-submit protection.

let csrfToken = '';

function getToken() {
    // Auth token is now in HttpOnly cookie — not accessible from JS.
    // Return a truthy sentinel so existing checks like `if (getToken())` still work.
    // Actual auth is validated server-side via the cookie.
    return csrfToken ? 'cookie-auth' : '';
}

function setToken(t) {
    // Auth token is set by the server as an HttpOnly cookie.
    // Nothing to store client-side for the auth token.
}

function setCsrfToken(t) {
    csrfToken = t;
    sessionStorage.setItem('csrfToken', t);
}

function clearToken() {
    csrfToken = '';
    sessionStorage.removeItem('csrfToken');
    sessionStorage.removeItem('adminEmail');
    // Server-side cookie is cleared by calling /api/logout or on expiry.
}

// Restore CSRF token from sessionStorage on page load
(function() {
    csrfToken = sessionStorage.getItem('csrfToken') || '';
})();

// ── API helpers ──────────────────────────────────────────────

async function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.credentials = 'same-origin'; // send HttpOnly cookies
    if (csrfToken) opts.headers['X-CSRF-Token'] = csrfToken;
    var r = await fetch(path, opts);
    if (r.status === 401) {
        clearToken();
        window.location.href = '/login';
        throw new Error('Unauthorized');
    }
    return r;
}

async function apiJSON(path) {
    var r = await api(path);
    return r.json();
}

function postJSON(path, body) {
    return api(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

// ── Auth check ───────────────────────────────────────────────

function checkAuth() {
    if (!csrfToken) {
        window.location.href = '/login';
        return;
    }
    var el = document.getElementById('admin-email');
    if (el) el.textContent = sessionStorage.getItem('adminEmail') || 'admin';
}

function logout() {
    // Call server to clear the HttpOnly cookie
    fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).finally(function() {
        clearToken();
        window.location.href = '/login';
    });
}

// ── Helpers ──────────────────────────────────────────────────

function badge(color, text) {
    return '<span class="badge badge-' + color + '">' + esc(text) + '</span>';
}

function esc(s) {
    if (s == null) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function showMsg(id, type, text) {
    var el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = '<div class="' + (type === 'success' ? 'success-msg' : 'error-msg') + '">' + esc(text) + '</div>';
}

function clearMsg(id) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = '';
}

function formatUptime(s) {
    var d = Math.floor(s / 86400);
    var h = Math.floor((s % 86400) / 3600);
    var m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
}

function formatTime(t) {
    if (!t) return '—';
    return new Date(t).toLocaleString();
}

// ═══════════════════════════════════════════════════════════════
//  Login Page
// ═══════════════════════════════════════════════════════════════

function initLogin() {
    if (getToken()) {
        window.location.href = '/';
        return;
    }
    var form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var email = document.getElementById('login-email').value;
        var password = document.getElementById('login-password').value;
        var btn = document.getElementById('login-btn');
        var errEl = document.getElementById('login-error');

        btn.disabled = true;
        btn.textContent = 'Signing in...';
        errEl.style.display = 'none';

        try {
            var r = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ email: email, password: password })
            });
            var data = await r.json();
            if (data.status === 'authorized') {
                setToken(data.token); // no-op; server sets HttpOnly cookie
                setCsrfToken(data.csrf_token);
                sessionStorage.setItem('adminEmail', email);
                window.location.href = '/';
            } else {
                errEl.textContent = data.error || 'Invalid credentials';
                errEl.style.display = 'block';
            }
        } catch (ex) {
            errEl.textContent = 'Connection error';
            errEl.style.display = 'block';
        }

        btn.disabled = false;
        btn.textContent = 'Sign In';
    });
}

// ═══════════════════════════════════════════════════════════════
//  Dashboard
// ═══════════════════════════════════════════════════════════════

var dashboardSSE = null;

function initDashboard() {
    checkAuth();
    loadDashboard();
    connectDashboardSSE();
}

function connectDashboardSSE() {
    if (dashboardSSE) dashboardSSE.close();
    dashboardSSE = new EventSource('/api/events');
    dashboardSSE.onmessage = function (e) {
        try {
            var data = JSON.parse(e.data);
            updateLiveBar(data);
        } catch (ex) { /* ignore parse errors */ }
    };
    dashboardSSE.onerror = function () {
        // Update indicator to disconnected
        var tag = document.getElementById('sse-tag');
        if (tag) { tag.textContent = '● OFFLINE'; tag.style.color = '#ef4444'; }
    };
    dashboardSSE.onopen = function () {
        var tag = document.getElementById('sse-tag');
        if (tag) { tag.textContent = '● LIVE'; tag.style.color = '#16a34a'; }
    };
}

function updateLiveBar(d) {
    // Update pulse indicators
    setLivePulse('pulse-cloud', d.enrolled);
    setLivePulse('pulse-mtls', d.mtls_configured);
    setLivePulse('pulse-store', d.store_ok);

    // Update session count
    var sessEl = document.getElementById('live-sessions');
    if (sessEl) sessEl.textContent = d.active_sessions || '0';
}

function setLivePulse(id, ok) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'pulse ' + (ok ? 'green' : 'muted');
}

async function loadDashboard() {
    try {
        var stats = await apiJSON('/api/stats');
        renderDashboard(stats);
    } catch (e) {
        console.error('Failed to load dashboard', e);
    }
}

function renderDashboard(s) {
    // Stat grid
    var grid = document.getElementById('stat-grid');
    if (grid) {
        grid.innerHTML =
            '<div class="stat-card" style="animation-delay:0ms"><div class="stat-label">Active Sessions</div><div class="stat-value">' + esc(s.active_sessions) + '</div></div>' +
            '<div class="stat-card" style="animation-delay:50ms"><div class="stat-label">Applications</div><div class="stat-value">' + esc(s.total_resources) + '</div></div>' +
            '<div class="stat-card" style="animation-delay:100ms"><div class="stat-label">Uptime</div><div class="stat-value">' + formatUptime(s.uptime_seconds) + '</div></div>' +
            '<div class="stat-card" style="animation-delay:150ms"><div class="stat-label">Setup</div><div class="stat-value">' + badge(s.setup_complete ? 'green' : 'red', s.setup_complete ? 'Complete' : 'Pending') + '</div></div>';
    }

    // Status list
    var items = [
        { label: 'Session Store', ok: s.store_status === 'connected' },
        { label: 'Syslog', ok: s.syslog_status === 'connected' },
        { label: 'mTLS', ok: s.mtls_configured },
        { label: 'IdP / OIDC', ok: s.idp_configured },
        { label: 'CGNAT', ok: s.cgnat_enabled },
        { label: 'Enrolled', ok: s.enrolled }
    ];
    var statusEl = document.getElementById('status-list');
    if (statusEl) {
        statusEl.innerHTML = items.map(function (it) {
            return '<div class="detail-row"><span>' + esc(it.label) + '</span><span>' + badge(it.ok ? 'green' : 'muted', it.ok ? 'Active' : 'Inactive') + '</span></div>';
        }).join('');
    }

    // Resources table
    var resSec = document.getElementById('resources-section');
    var resTable = document.getElementById('dashboard-resources-table');
    if (resSec && resTable && s.resources && s.resources.length > 0) {
        resSec.style.display = '';
        resTable.innerHTML = s.resources.map(function (r) {
            return '<tr><td>' + esc(r.name) + '</td><td>' + esc(r.internal_ip) + '</td><td>' + esc(r.tunnel_ip || '—') + '</td><td>' + esc(r.port) + '</td><td>' + badge('blue', r.protocol) + '</td></tr>';
        }).join('');
    }
}

// ═══════════════════════════════════════════════════════════════
//  Applications (formerly Resources)
// ═══════════════════════════════════════════════════════════════

var _appFilter = 'all';
var _appList = [];
var _cloudVerified = null; // holds cloud app metadata after verification

function initApplications() {
    checkAuth();
    loadApplications();

    var form = document.getElementById('app-form');
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('resource-msg');
            var editing = document.getElementById('app-editing').value;
            var appType = document.getElementById('app-type').value;
            var payload = buildAppPayload(appType);

            if (!payload.name) { showMsg('resource-msg', 'error', 'Name is required'); return; }

            // Read cert files if provided
            if (payload.cert_source === 'upload') {
                var certFile = document.getElementById('app-cert-file').files[0];
                var keyFile = document.getElementById('app-key-file').files[0];
                if (certFile && keyFile) {
                    payload.cert_pem = await readFileText(certFile);
                    payload.key_pem = await readFileText(keyFile);
                }
            }

            var url = editing ? '/api/resources/update' : '/api/resources/add';
            try {
                var r = await postJSON(url, payload);
                if (r.ok) {
                    showMsg('resource-msg', 'success', editing ? 'Application updated' : 'Application added');
                    hideAppForm();
                    loadApplications();
                } else {
                    var d = await r.json();
                    showMsg('resource-msg', 'error', d.error || 'Failed');
                }
            } catch (ex) {
                showMsg('resource-msg', 'error', 'Connection error');
            }
        });
    }

    // Close dropdown on outside click
    document.addEventListener('click', function (e) {
        var menu = document.getElementById('add-app-menu');
        var btn = document.getElementById('add-app-btn');
        if (menu && !menu.contains(e.target) && !btn.contains(e.target)) {
            menu.classList.remove('show');
        }
    });
}

function buildAppPayload(appType) {
    var payload = {
        name: document.getElementById('app-name').value.trim(),
        type: appType,
        external_url: document.getElementById('app-external-url').value.trim(),
        session_duration: parseInt(document.getElementById('app-session').value) || 480,
        mfa_required: document.getElementById('app-mfa').checked,
        cert_source: document.querySelector('input[name="app-cert"]:checked').value
    };

    // Cloud link fields
    var cid = document.getElementById('app-cloud-cid-final');
    var csec = document.getElementById('app-cloud-secret-final');
    var caid = document.getElementById('app-cloud-app-id');
    var cdesc = document.getElementById('app-cloud-desc');
    if (cid && cid.value) payload.cloud_client_id = cid.value;
    if (csec && csec.value) payload.cloud_secret = csec.value;
    if (caid && caid.value) payload.cloud_app_id = caid.value;
    if (cdesc && cdesc.value) payload.description = cdesc.value;

    if (appType === 'web') {
        payload.internal_url = document.getElementById('app-internal-url').value.trim();
        payload.protocol = 'https';
    } else {
        payload.protocol = appType;
        payload.internal_hosts = collectHosts();
    }

    // Legacy fields
    var ip = document.getElementById('app-ip');
    var port = document.getElementById('app-port');
    var tunnel = document.getElementById('app-tunnel');
    if (ip && ip.value) payload.internal_ip = ip.value;
    if (port && port.value) payload.port = parseInt(port.value) || 0;
    if (tunnel && tunnel.value) payload.tunnel_ip = tunnel.value;

    return payload;
}

function collectHosts() {
    var list = document.getElementById('app-hosts-list');
    if (!list) return [];
    var rows = list.querySelectorAll('.host-row');
    var hosts = [];
    rows.forEach(function (row) {
        var h = row.querySelector('.host-input').value.trim();
        var p = row.querySelector('.ports-input').value.trim();
        if (h) hosts.push({ host: h, ports: p || '22' });
    });
    return hosts;
}

function readFileText(file) {
    return new Promise(function (resolve) {
        var reader = new FileReader();
        reader.onload = function () { resolve(reader.result); };
        reader.readAsText(file);
    });
}

function toggleAddMenu() {
    var menu = document.getElementById('add-app-menu');
    if (menu) menu.classList.toggle('show');
}

function showAppForm(type, editData) {
    var menu = document.getElementById('add-app-menu');
    if (menu) menu.classList.remove('show');

    _cloudVerified = null;
    document.getElementById('app-type').value = type;
    document.getElementById('app-form-card').style.display = '';

    var labels = { web: 'Web Application', ssh: 'SSH Server', rdp: 'RDP Server' };
    var isEdit = !!editData;
    document.getElementById('app-form-title').textContent = (isEdit ? 'Edit ' : 'Add ') + (labels[type] || 'Application');
    document.getElementById('app-submit-btn').textContent = isEdit ? 'Save Changes' : 'Add Application';
    document.getElementById('app-editing').value = isEdit ? editData.name : '';

    // Toggle type-specific fields
    document.getElementById('app-internal-url-group').style.display = type === 'web' ? '' : 'none';
    document.getElementById('app-hosts-group').style.display = (type === 'ssh' || type === 'rdp') ? '' : 'none';

    // Reset wizard
    var wizardSteps = document.getElementById('wizard-steps');
    var panel1 = document.getElementById('wizard-panel-1');
    var panel2 = document.getElementById('wizard-panel-2');
    var backBtn = document.getElementById('back-to-step1-btn');

    // Clear step 1 fields
    var cidInput = document.getElementById('app-cloud-client-id');
    var secInput = document.getElementById('app-cloud-secret');
    var apiInput = document.getElementById('app-cloud-api');
    if (cidInput) cidInput.value = '';
    if (secInput) secInput.value = '';
    if (apiInput) apiInput.value = '';
    var verifyResult = document.getElementById('cloud-verify-result');
    if (verifyResult) { verifyResult.style.display = 'none'; verifyResult.innerHTML = ''; }

    // Clear hidden cloud data fields
    document.getElementById('app-cloud-app-id').value = '';
    document.getElementById('app-cloud-cid-final').value = '';
    document.getElementById('app-cloud-secret-final').value = '';
    document.getElementById('app-cloud-desc').value = '';

    var summary = document.getElementById('cloud-app-summary');
    if (summary) summary.style.display = 'none';

    if (isEdit) {
        // Edit mode: skip wizard step 1, go straight to step 2
        if (wizardSteps) wizardSteps.style.display = 'none';
        if (panel1) panel1.style.display = 'none';
        if (panel2) panel2.style.display = '';
        if (backBtn) backBtn.style.display = 'none';

        // If cloud-linked, show summary
        if (editData.cloud_client_id) {
            document.getElementById('app-cloud-cid-final').value = editData.cloud_client_id;
            document.getElementById('app-cloud-secret-final').value = editData.cloud_secret || '';
            document.getElementById('app-cloud-app-id').value = editData.cloud_app_id || '';
            document.getElementById('app-cloud-desc').value = editData.description || '';
            if (summary) {
                summary.style.display = 'flex';
                document.getElementById('cloud-app-name-display').textContent = editData.name;
                document.getElementById('cloud-app-meta-display').textContent =
                    (editData.type || 'web').toUpperCase() + ' • Client ID: ' + editData.cloud_client_id.substring(0, 10) + '…';
            }
        }
    } else {
        // New app: show wizard from step 1
        if (wizardSteps) wizardSteps.style.display = 'flex';
        if (panel1) panel1.style.display = '';
        if (panel2) panel2.style.display = 'none';
        if (backBtn) backBtn.style.display = '';
        goToWizardStep(1);
    }

    // Reset form fields
    if (!isEdit) {
        document.getElementById('app-form').reset();
        document.getElementById('app-session').value = '480';
        document.getElementById('app-cert-name').textContent = 'No file chosen';
        document.getElementById('app-key-name').textContent = 'No file chosen';
        document.querySelector('input[name="app-cert"][value="upload"]').checked = true;
        toggleAppCert();
    }

    // Internal hosts default row
    var hostsList = document.getElementById('app-hosts-list');
    hostsList.innerHTML = '';
    if (type === 'ssh' || type === 'rdp') {
        if (isEdit && editData.internal_hosts && editData.internal_hosts.length) {
            editData.internal_hosts.forEach(function (h) { addHostRow(h.host, h.ports); });
        } else {
            addHostRow('', type === 'ssh' ? '22' : '3389');
        }
    }

    // Pre-fill edit data
    if (isEdit) {
        document.getElementById('app-name').value = editData.name || '';
        document.getElementById('app-name').readOnly = true;
        document.getElementById('app-external-url').value = editData.external_url || '';
        document.getElementById('app-internal-url').value = editData.internal_url || '';
        document.getElementById('app-session').value = editData.session_duration || 480;
        document.getElementById('app-mfa').checked = !!editData.mfa_required;
        if (editData.cert_source === 'letsencrypt') {
            document.querySelector('input[name="app-cert"][value="letsencrypt"]').checked = true;
        } else {
            document.querySelector('input[name="app-cert"][value="upload"]').checked = true;
        }
        toggleAppCert();
    } else {
        document.getElementById('app-name').readOnly = false;
    }

    clearMsg('resource-msg');
    document.getElementById('app-form-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideAppForm() {
    document.getElementById('app-form-card').style.display = 'none';
    document.getElementById('app-form').reset();
    document.getElementById('app-name').readOnly = false;
    _cloudVerified = null;
    clearMsg('resource-msg');
}

// ── Wizard navigation ──

function goToWizardStep(step) {
    var s1 = document.getElementById('wizard-step-1');
    var s2 = document.getElementById('wizard-step-2');
    var p1 = document.getElementById('wizard-panel-1');
    var p2 = document.getElementById('wizard-panel-2');
    if (step === 1) {
        if (s1) s1.classList.add('active');
        if (s2) s2.classList.remove('active');
        if (p1) p1.style.display = '';
        if (p2) p2.style.display = 'none';
    } else {
        if (s1) { s1.classList.remove('active'); s1.classList.add('done'); }
        if (s2) s2.classList.add('active');
        if (p1) p1.style.display = 'none';
        if (p2) p2.style.display = '';
    }
}

function skipCloudLink() {
    _cloudVerified = null;
    document.getElementById('app-cloud-cid-final').value = '';
    document.getElementById('app-cloud-secret-final').value = '';
    document.getElementById('app-cloud-app-id').value = '';
    document.getElementById('app-cloud-desc').value = '';
    var summary = document.getElementById('cloud-app-summary');
    if (summary) summary.style.display = 'none';
    goToWizardStep(2);
}

async function verifyCloudApp() {
    var clientId = document.getElementById('app-cloud-client-id').value.trim();
    var secret = document.getElementById('app-cloud-secret').value.trim();
    var api = document.getElementById('app-cloud-api').value.trim();
    var resultDiv = document.getElementById('cloud-verify-result');

    if (!clientId || !secret) {
        resultDiv.style.display = '';
        resultDiv.className = 'error-msg';
        resultDiv.textContent = 'Client ID and Client Secret are required.';
        return;
    }

    var btn = document.getElementById('verify-cloud-btn');
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    resultDiv.style.display = 'none';

    try {
        var r = await postJSON('/api/resources/verify-cloud', {
            client_id: clientId,
            client_secret: secret,
            api_hostname: api
        });
        var data = await r.json();
        if (r.ok) {
            _cloudVerified = data;
            resultDiv.style.display = '';
            resultDiv.className = 'success-msg';
            resultDiv.innerHTML = '<strong>Verified!</strong> Cloud app: ' + esc(data.name || '—') +
                ' (' + esc((data.type || 'web').toUpperCase()) + ')';

            // Fill hidden fields
            document.getElementById('app-cloud-app-id').value = data.id || '';
            document.getElementById('app-cloud-cid-final').value = clientId;
            document.getElementById('app-cloud-secret-final').value = secret;
            document.getElementById('app-cloud-desc').value = data.description || '';

            // Auto-fill name & type in step 2
            if (data.name) document.getElementById('app-name').value = data.name;
            if (data.type) {
                document.getElementById('app-type').value = data.type;
                document.getElementById('app-internal-url-group').style.display = data.type === 'web' ? '' : 'none';
                document.getElementById('app-hosts-group').style.display = (data.type === 'ssh' || data.type === 'rdp') ? '' : 'none';
            }
            if (data.require_mfa) document.getElementById('app-mfa').checked = true;

            // Show cloud app summary on step 2
            var summary = document.getElementById('cloud-app-summary');
            if (summary) {
                summary.style.display = 'flex';
                document.getElementById('cloud-app-name-display').textContent = data.name || 'Application';
                document.getElementById('cloud-app-meta-display').textContent =
                    (data.type || 'web').toUpperCase() + (data.description ? ' • ' + data.description : '');
            }

            // Move to step 2 after a brief delay
            setTimeout(function () { goToWizardStep(2); }, 600);
        } else {
            resultDiv.style.display = '';
            resultDiv.className = 'error-msg';
            resultDiv.textContent = data.error || 'Verification failed. Check your credentials.';
        }
    } catch (ex) {
        resultDiv.style.display = '';
        resultDiv.className = 'error-msg';
        resultDiv.textContent = 'Cannot reach gateway. Check your connection.';
    }
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Verify &amp; Continue';
}

async function toggleAppEnabled(name, enabled) {
    try {
        var r = await postJSON('/api/resources/toggle', { name: name, enabled: enabled });
        if (r.ok) {
            // Update local list
            _appList.forEach(function (a) { if (a.name === name) a.enabled = enabled; });
            renderApplications(_appList);
        }
    } catch (ex) {
        console.error('Toggle failed', ex);
    }
}

function addHostRow(host, ports) {
    var list = document.getElementById('app-hosts-list');
    var row = document.createElement('div');
    row.className = 'host-row';
    row.innerHTML =
        '<input class="host-input" placeholder="hostname or IP" value="' + esc(host || '') + '">' +
        '<input class="ports-input" placeholder="22" value="' + esc(ports || '') + '">' +
        '<button type="button" class="btn-icon-sm" onclick="this.parentNode.remove()" title="Remove">&times;</button>';
    list.appendChild(row);
}

function toggleAppCert() {
    var val = document.querySelector('input[name="app-cert"]:checked').value;
    document.getElementById('app-cert-upload-panel').style.display = val === 'upload' ? '' : 'none';
    document.getElementById('app-cert-le-panel').style.display = val === 'letsencrypt' ? '' : 'none';
}

function onAppFileSelect(input, labelId) {
    var lbl = document.getElementById(labelId);
    if (lbl) lbl.textContent = input.files.length ? input.files[0].name : 'No file chosen';
}

async function loadApplications() {
    try {
        var data = await apiJSON('/api/resources');
        _appList = Array.isArray(data) ? data : [];
        renderApplications(_appList);
    } catch (e) {
        console.error(e);
    }
}

function filterApps(filter) {
    _appFilter = filter;
    var btns = document.querySelectorAll('.app-filter');
    btns.forEach(function (b) {
        b.classList.toggle('active', b.getAttribute('data-filter') === filter);
    });
    renderApplications(_appList);
}

function renderApplications(list) {
    var filtered = _appFilter === 'all' ? list : list.filter(function (r) { return r.type === _appFilter; });
    var countEl = document.getElementById('resource-count');
    if (countEl) countEl.textContent = filtered.length;

    var content = document.getElementById('resources-content');
    if (!content) return;

    if (list.length === 0) {
        content.innerHTML =
            '<div class="empty-state">' +
            '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>' +
            '<p style="margin-top:12px;font-size:13px;">No applications configured yet</p>' +
            '<p style="font-size:12px;color:var(--text-muted);margin-top:4px;">Click <strong>Add New…</strong> to protect your first application</p>' +
            '</div>';
        return;
    }

    if (filtered.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>No ' + esc(_appFilter) + ' applications found</p></div>';
        return;
    }

    var html = '<div class="app-cards">';
    filtered.forEach(function (r) {
        var typeLabel = { web: 'Web', ssh: 'SSH', rdp: 'RDP' }[r.type] || r.type || 'Web';
        var typeClass = { web: 'blue', ssh: 'green', rdp: 'yellow' }[r.type] || 'blue';
        var target = r.type === 'web'
            ? (r.internal_url || r.internal_ip || '—')
            : ((r.internal_hosts && r.internal_hosts.length) ? r.internal_hosts.length + ' host(s)' : r.internal_ip || '—');
        var certLabel = r.cert_source === 'letsencrypt' ? "Let's Encrypt" : (r.cert_source === 'upload' ? 'Uploaded' : '—');
        var isEnabled = r.enabled !== false;
        var disabledClass = isEnabled ? '' : ' app-card-disabled';
        var cloudLinked = r.cloud_client_id ? true : false;

        html += '<div class="app-card' + disabledClass + '">' +
            '<div class="app-card-header">' +
            '<div style="display:flex;align-items:center;gap:8px;flex:1;min-width:0;">' +
            '<div class="app-card-title">' + esc(r.name) + '</div>' +
            (cloudLinked ? '<span class="badge-cloud-linked" title="Linked to Cloud: ' + esc(r.cloud_client_id) + '"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg></span>' : '') +
            '</div>' +
            '<div style="display:flex;align-items:center;gap:8px;">' +
            badge(typeClass, typeLabel) +
            '<button class="toggle-sm' + (isEnabled ? ' on' : '') + '" title="' + (isEnabled ? 'Disable' : 'Enable') + '" onclick="toggleAppEnabled(\'' + esc(r.name) + '\',' + (!isEnabled) + ')"></button>' +
            '</div>' +
            '</div>' +
            (r.description ? '<div class="app-card-desc">' + esc(r.description) + '</div>' : '') +
            '<div class="app-card-body">' +
            '<div class="app-card-row"><span>External URL</span><span>' + esc(r.external_url || '—') + '</span></div>' +
            '<div class="app-card-row"><span>Target</span><span>' + esc(target) + '</span></div>' +
            '<div class="app-card-row"><span>Certificate</span><span>' + esc(certLabel) + '</span></div>' +
            '<div class="app-card-row"><span>Session</span><span>' + (r.session_duration || 480) + ' min</span></div>' +
            '<div class="app-card-row"><span>MFA</span><span>' + (r.mfa_required ? 'Required' : 'Off') + '</span></div>' +
            '<div class="app-card-row"><span>Status</span><span>' + (isEnabled ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>') + '</span></div>' +
            '</div>' +
            '<div class="app-card-actions">' +
            '<button class="btn btn-secondary btn-sm" onclick="editApplication(\'' + esc(r.name) + '\')">Edit</button>' +
            '<button class="btn btn-danger btn-sm" onclick="removeApplication(\'' + esc(r.name) + '\')">Delete</button>' +
            '</div>' +
            '</div>';
    });
    html += '</div>';
    content.innerHTML = html;
}

function editApplication(name) {
    var app = _appList.find(function (r) { return r.name === name; });
    if (!app) return;
    showAppForm(app.type || 'web', app);
}

async function removeApplication(name) {
    if (!confirm('Delete application "' + name + '"? This cannot be undone.')) return;
    try {
        var r = await postJSON('/api/resources/remove', { name: name });
        if (r.ok) {
            showMsg('resource-msg', 'success', 'Application deleted');
            loadApplications();
        } else {
            showMsg('resource-msg', 'error', 'Failed to delete');
        }
    } catch (ex) {
        showMsg('resource-msg', 'error', 'Connection error');
    }
}

// ═══════════════════════════════════════════════════════════════
//  Certificates
// ═══════════════════════════════════════════════════════════════

function initCertificates() {
    checkAuth();
    loadCertificates();

    // CSR form
    var csrForm = document.getElementById('csr-form');
    if (csrForm) {
        csrForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('certs-msg');
            document.getElementById('csr-result').innerHTML = '';
            try {
                var r = await postJSON('/api/certs/generate-csr', {
                    common_name: document.getElementById('csr-cn').value,
                    organization: document.getElementById('csr-org').value,
                    country: document.getElementById('csr-country').value
                });
                var data = await r.json();
                if (r.ok) {
                    showMsg('certs-msg', 'success', 'CSR generated successfully');
                    var res = document.getElementById('csr-result');
                    if (res) {
                        res.innerHTML = '<div style="margin-top:16px"><div class="detail-row"><span>Key saved at</span><span>' + esc(data.key_path) + '</span></div><div class="pem-display">' + esc(data.csr_pem) + '</div></div>';
                    }
                } else {
                    showMsg('certs-msg', 'error', data.error || 'Failed to generate CSR');
                }
            } catch (ex) {
                showMsg('certs-msg', 'error', 'Connection error');
            }
        });
    }

    // Install mTLS form
    var mtlsForm = document.getElementById('mtls-form');
    if (mtlsForm) {
        mtlsForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('certs-msg');
            try {
                var formData = new FormData(mtlsForm);
                var r = await api('/api/certs/install-mtls', { method: 'POST', body: formData });
                var data = await r.json();
                if (r.ok) {
                    showMsg('certs-msg', 'success', 'mTLS certificate installed');
                    loadCertificates();
                } else {
                    showMsg('certs-msg', 'error', data.error || 'Failed to install certificate');
                }
            } catch (ex) {
                showMsg('certs-msg', 'error', 'Connection error');
            }
        });
    }

    // Upload SSL form
    var sslForm = document.getElementById('ssl-form');
    if (sslForm) {
        sslForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('certs-msg');
            try {
                var formData = new FormData(sslForm);
                var r = await api('/api/certs/upload-ssl', { method: 'POST', body: formData });
                var data = await r.json();
                if (r.ok) {
                    showMsg('certs-msg', 'success', 'SSL certificate uploaded');
                    loadCertificates();
                } else {
                    showMsg('certs-msg', 'error', data.error || 'Failed to upload certificate');
                }
            } catch (ex) {
                showMsg('certs-msg', 'error', 'Connection error');
            }
        });
    }
}

async function loadCertificates() {
    try {
        var st = await apiJSON('/api/certs/status');
        renderCertStatus(st);
    } catch (e) {
        console.error(e);
    }
}

function renderCertStatus(st) {
    // mTLS status
    var mtlsEl = document.getElementById('mtls-status');
    if (mtlsEl) {
        var html = '<div class="detail-row"><span>Status</span><span>' + badge(st.mtls_configured ? 'green' : 'muted', st.mtls_configured ? 'Configured' : 'Not configured') + '</span></div>';
        if (st.mtls_cert_path) html += '<div class="detail-row"><span>Certificate</span><span>' + esc(st.mtls_cert_path) + '</span></div>';
        if (st.mtls_key_path) html += '<div class="detail-row"><span>Key</span><span>' + esc(st.mtls_key_path) + '</span></div>';
        mtlsEl.innerHTML = html;
    }

    // SSL status
    var sslEl = document.getElementById('ssl-status');
    if (sslEl) {
        sslEl.innerHTML = '<div class="detail-row"><span>Status</span><span>' + badge(st.ssl_configured ? 'green' : 'muted', st.ssl_configured ? 'Configured' : 'Not configured') + '</span></div>';
    }
}

// ═══════════════════════════════════════════════════════════════
//  Authentication
// ═══════════════════════════════════════════════════════════════

function initAuthentication() {
    checkAuth();
    loadAuthentication();

    var form = document.getElementById('idp-form');
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('idp-msg');
            try {
                var r = await postJSON('/api/idp/configure', {
                    hostname: document.getElementById('idp-hostname').value,
                    auth_url: document.getElementById('idp-auth-url').value,
                    token_url: document.getElementById('idp-token-url').value,
                    userinfo_url: document.getElementById('idp-userinfo-url').value,
                    client_id: document.getElementById('idp-client-id').value,
                    client_secret: document.getElementById('idp-client-secret').value,
                    redirect_uri: document.getElementById('idp-redirect-uri').value,
                    scopes: document.getElementById('idp-scopes').value
                });
                if (r.ok) {
                    showMsg('idp-msg', 'success', 'IdP configuration saved');
                    loadAuthentication();
                } else {
                    var d = await r.json();
                    showMsg('idp-msg', 'error', d.error || 'Failed to save');
                }
            } catch (ex) {
                showMsg('idp-msg', 'error', 'Connection error');
            }
        });
    }
}

async function loadAuthentication() {
    try {
        var data = await apiJSON('/api/idp');
        renderIdPStatus(data);
        populateIdPForm(data);
    } catch (e) {
        console.error(e);
    }
}

function renderIdPStatus(data) {
    var el = document.getElementById('idp-status');
    if (!el) return;
    var html = '<div class="detail-row"><span>Configured</span><span>' + badge(data.configured ? 'green' : 'muted', data.configured ? 'Yes' : 'No') + '</span></div>';
    if (data.hostname) html += '<div class="detail-row"><span>Hostname</span><span>' + esc(data.hostname) + '</span></div>';
    el.innerHTML = html;
}

function populateIdPForm(data) {
    if (!data || !data.hostname) return;
    var fields = {
        'idp-hostname': data.hostname,
        'idp-auth-url': data.auth_url,
        'idp-token-url': data.token_url,
        'idp-userinfo-url': data.userinfo_url,
        'idp-client-id': data.client_id,
        'idp-client-secret': data.client_secret,
        'idp-redirect-uri': data.redirect_uri,
        'idp-scopes': data.scopes || 'openid profile email'
    };
    for (var id in fields) {
        var el = document.getElementById(id);
        if (el && fields[id]) el.value = fields[id];
    }
}

// ═══════════════════════════════════════════════════════════════
//  Network (formerly CGNAT)
// ═══════════════════════════════════════════════════════════════

var cgnatEnabled = false;

function initNetwork() {
    checkAuth();
    loadNetwork();

    var form = document.getElementById('cgnat-form');
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('cgnat-msg');
            try {
                var r = await postJSON('/api/cgnat/configure', {
                    enabled: cgnatEnabled,
                    pool_start: document.getElementById('cgnat-start').value,
                    pool_end: document.getElementById('cgnat-end').value,
                    subnet_mask: document.getElementById('cgnat-mask').value
                });
                if (r.ok) {
                    showMsg('cgnat-msg', 'success', 'CGNAT configuration saved');
                    loadNetwork();
                } else {
                    var d = await r.json();
                    showMsg('cgnat-msg', 'error', d.error || 'Failed to save');
                }
            } catch (ex) {
                showMsg('cgnat-msg', 'error', 'Connection error');
            }
        });
    }
}

function toggleCGNAT() {
    cgnatEnabled = !cgnatEnabled;
    var btn = document.getElementById('cgnat-toggle');
    if (btn) {
        if (cgnatEnabled) btn.classList.add('on');
        else btn.classList.remove('on');
    }
}

async function loadNetwork() {
    try {
        var data = await apiJSON('/api/cgnat');
        renderCGNATStatus(data);
        populateCGNATForm(data);
    } catch (e) {
        console.error(e);
    }
}

function renderCGNATStatus(data) {
    var el = document.getElementById('cgnat-status');
    if (!el) return;
    var html = '<div class="detail-row"><span>Enabled</span><span>' + badge(data.enabled ? 'green' : 'muted', data.enabled ? 'Active' : 'Disabled') + '</span></div>';
    if (data.pool_start) html += '<div class="detail-row"><span>Address Pool</span><span>' + esc(data.pool_start) + ' — ' + esc(data.pool_end) + '</span></div>';
    if (data.subnet_mask) html += '<div class="detail-row"><span>Subnet Mask</span><span>' + esc(data.subnet_mask) + '</span></div>';
    el.innerHTML = html;
}

function populateCGNATForm(data) {
    if (!data) return;
    cgnatEnabled = data.enabled || false;
    var btn = document.getElementById('cgnat-toggle');
    if (btn) {
        if (cgnatEnabled) btn.classList.add('on');
        else btn.classList.remove('on');
    }
    if (data.pool_start) document.getElementById('cgnat-start').value = data.pool_start;
    if (data.pool_end) document.getElementById('cgnat-end').value = data.pool_end;
    if (data.subnet_mask) document.getElementById('cgnat-mask').value = data.subnet_mask;
}

// ═══════════════════════════════════════════════════════════════
//  Sessions
// ═══════════════════════════════════════════════════════════════

function initSessions() {
    checkAuth();
    loadSessions();
    setInterval(loadSessions, 10000);
}

async function loadSessions() {
    try {
        var data = await apiJSON('/api/sessions');
        var list = Array.isArray(data) ? data : [];
        renderSessions(list);
    } catch (e) {
        console.error(e);
    }
}

function renderSessions(list) {
    var countEl = document.getElementById('session-count');
    if (countEl) countEl.textContent = list.length;

    var content = document.getElementById('sessions-content');
    if (!content) return;

    if (list.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>No active sessions.</p></div>';
        return;
    }

    var html = '<table class="data-table"><thead><tr><th>User</th><th>Source IP</th><th>Device</th><th>Created</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>';
    list.forEach(function (s) {
        html += '<tr><td>' + esc(s.username || s.user_id) + '</td><td>' + esc(s.source_ip || '—') + '</td><td>' + esc(s.device_id || '—') + '</td><td>' + formatTime(s.created_at) + '</td><td>' + formatTime(s.expires_at) + '</td><td>' + badge(s.active ? 'green' : 'red', s.active ? 'Active' : 'Expired') + '</td><td><button class="btn btn-danger btn-sm" onclick="revokeSession(\'' + esc(s.id) + '\')">Revoke</button></td></tr>';
    });
    html += '</tbody></table>';
    content.innerHTML = html;
}

async function revokeSession(id) {
    if (!confirm('Revoke this session?')) return;
    clearMsg('sessions-msg');
    try {
        var r = await postJSON('/api/sessions/revoke', { session_id: id });
        if (r.ok) {
            showMsg('sessions-msg', 'success', 'Session revoked');
            loadSessions();
        } else {
            var d = await r.json();
            showMsg('sessions-msg', 'error', d.error || 'Failed to revoke');
        }
    } catch (ex) {
        showMsg('sessions-msg', 'error', 'Connection error');
    }
}

// ═══════════════════════════════════════════════════════════════
//  Enrollment
// ═══════════════════════════════════════════════════════════════

function initEnrollment() {
    checkAuth();
    loadEnrollment();

    var form = document.getElementById('enroll-form');
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('enroll-msg');
            try {
                var cloudUrl = document.getElementById('enroll-cloud-url').value.trim();
                var token = document.getElementById('enroll-token').value.trim();
                if (!token) { showMsg('enroll-msg', 'error', 'Enrollment token is required'); return; }

                var payload = { token: token };
                if (cloudUrl) payload.cloud_url = cloudUrl;

                var r = await postJSON('/api/enrollment/enroll', payload);
                var data = await r.json();
                if (r.ok && data.status === 'enrolled') {
                    showMsg('enroll-msg', 'success', 'Enrolled successfully — gateway ID: ' + (data.gateway_id || ''));
                    loadEnrollment();
                } else {
                    showMsg('enroll-msg', 'error', data.message || data.error || 'Enrollment failed');
                }
            } catch (ex) {
                showMsg('enroll-msg', 'error', 'Connection error');
            }
        });
    }
}

async function loadEnrollment() {
    try {
        var data = await apiJSON('/api/enrollment/status');
        renderEnrollmentStatus(data);
    } catch (e) {
        console.error(e);
    }
}

function renderEnrollmentStatus(data) {
    var el = document.getElementById('enrollment-status');
    if (el) {
        var html = '<div class="detail-row"><span>Enrolled</span><span>' + badge(data.enrolled ? 'green' : 'muted', data.enrolled ? 'Yes' : 'No') + '</span></div>';
        if (data.cloud_url) html += '<div class="detail-row"><span>Cloud URL</span><span>' + esc(data.cloud_url) + '</span></div>';
        el.innerHTML = html;
    }

    var card = document.getElementById('enroll-form-card');
    if (card) {
        card.style.display = data.enrolled ? 'none' : '';
    }
}

// ═══════════════════════════════════════════════════════════════
//  Settings (formerly Configuration)
// ═══════════════════════════════════════════════════════════════

function initSettings() {
    checkAuth();
    loadSettings();
    loadAdminInfo();

    // General config form
    var form = document.getElementById('config-form');
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('config-msg');
            try {
                var r = await postJSON('/api/config/save', {
                    cloud_url: document.getElementById('cfg-cloud-url').value,
                    gateway_listen: document.getElementById('cfg-gw-listen').value,
                    portal_listen: document.getElementById('cfg-portal-listen').value,
                    admin_listen: document.getElementById('cfg-admin-listen').value,
                    mtls_cert: document.getElementById('cfg-mtls-cert').value,
                    mtls_key: document.getElementById('cfg-mtls-key').value,
                    mtls_ca: document.getElementById('cfg-mtls-ca').value,
                    ssl_cert: document.getElementById('cfg-ssl-cert').value,
                    ssl_key: document.getElementById('cfg-ssl-key').value
                });
                if (r.ok) {
                    showMsg('config-msg', 'success', 'Settings saved');
                    loadSettings();
                } else {
                    var d = await r.json();
                    showMsg('config-msg', 'error', d.error || 'Failed to save');
                }
            } catch (ex) {
                showMsg('config-msg', 'error', 'Connection error');
            }
        });
    }

    // Change password form
    var pwForm = document.getElementById('change-password-form');
    if (pwForm) {
        pwForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('change-pw-msg');
            var curPw = document.getElementById('cur-password').value;
            var newPw = document.getElementById('new-password').value;
            var newPw2 = document.getElementById('new-password-confirm').value;

            if (!curPw || !newPw) { showMsg('change-pw-msg', 'error', 'All fields are required'); return; }
            if (newPw.length < 8) { showMsg('change-pw-msg', 'error', 'Password must be at least 8 characters'); return; }
            if (newPw !== newPw2) { showMsg('change-pw-msg', 'error', 'New passwords do not match'); return; }

            try {
                var r = await postJSON('/api/settings/password', {
                    current_password: curPw,
                    new_password: newPw
                });
                if (r.ok) {
                    showMsg('change-pw-msg', 'success', 'Password changed successfully');
                    pwForm.reset();
                } else {
                    var d = await r.json();
                    showMsg('change-pw-msg', 'error', d.error || 'Failed to change password');
                }
            } catch (ex) {
                showMsg('change-pw-msg', 'error', 'Connection error');
            }
        });
    }
}

async function loadSettings() {
    try {
        var data = await apiJSON('/api/config');
        populateConfigForm(data);
    } catch (e) {
        console.error(e);
    }
}

async function loadAdminInfo() {
    try {
        var data = await apiJSON('/api/settings/admin');
        var el = document.getElementById('admin-email-display');
        if (el && data.email) el.textContent = data.email;
        var fqdnEl = document.getElementById('admin-fqdn-display');
        if (fqdnEl && data.fqdn) fqdnEl.textContent = data.fqdn;
        var enrollEl = document.getElementById('admin-enrolled-display');
        if (enrollEl) enrollEl.textContent = data.enrolled ? 'Connected' : 'Not connected';
        var dateEl = document.getElementById('admin-setup-date');
        if (dateEl && data.setup_date) dateEl.textContent = formatTime(data.setup_date);
    } catch (e) {
        console.error(e);
    }
}

async function loadIdPSettings() {
    try {
        var data = await apiJSON('/api/idp');
        var statusEl = document.getElementById('idp-status-display');
        if (statusEl) statusEl.textContent = data.configured ? 'Configured' : 'Not configured';
        var hostEl = document.getElementById('idp-hostname-display');
        if (hostEl && data.hostname) hostEl.textContent = data.hostname;

        // Pre-fill form fields
        var fields = {
            'idp-hostname': data.hostname,
            'idp-client-id': data.client_id,
            'idp-redirect-uri': data.redirect_uri,
            'idp-auth-url': data.auth_url,
            'idp-token-url': data.token_url,
            'idp-userinfo-url': data.userinfo_url,
            'idp-scopes': data.scopes
        };
        for (var id in fields) {
            var el = document.getElementById(id);
            if (el && fields[id]) el.value = fields[id];
        }
    } catch (e) {
        console.error(e);
    }
}

function populateConfigForm(data) {
    if (!data) return;
    var fields = {
        'cfg-cloud-url': data.cloud_url,
        'cfg-gw-listen': data.gateway_listen,
        'cfg-portal-listen': data.portal_listen,
        'cfg-admin-listen': data.admin_listen,
        'cfg-mtls-cert': data.mtls_cert,
        'cfg-mtls-key': data.mtls_key,
        'cfg-mtls-ca': data.mtls_ca,
        'cfg-ssl-cert': data.ssl_cert,
        'cfg-ssl-key': data.ssl_key
    };
    for (var id in fields) {
        var el = document.getElementById(id);
        if (el && fields[id]) el.value = fields[id];
    }
}

// ═══════════════════════════════════════════════════════════════
//  Policies
// ═══════════════════════════════════════════════════════════════

function initPolicies() {
    checkAuth();
    loadPolicies();
}

async function loadPolicies() {
    try {
        var data = await apiJSON('/api/policies');
        var list = Array.isArray(data) ? data : [];
        renderPolicies(list);
    } catch (e) {
        console.error(e);
    }
}

function renderPolicies(list) {
    var content = document.getElementById('policies-content');
    if (!content) return;

    if (list.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>No applications configured. Add applications first to define policies.</p></div>';
        return;
    }

    var html = '<table class="data-table"><thead><tr><th>Application</th><th>Protocol</th><th>Port</th><th>Tunnel IP</th><th>MFA Required</th><th></th></tr></thead><tbody>';
    list.forEach(function (p) {
        html += '<tr><td>' + esc(p.name) + '</td><td>' + badge('blue', p.protocol) + '</td><td>' + esc(p.port) + '</td><td>' + esc(p.tunnel_ip || '—') + '</td><td>' + (p.mfa_required ? badge('green', 'Enabled') : badge('muted', 'Disabled')) + '</td><td><button class="btn btn-sm" onclick="toggleMFA(\'' + esc(p.name) + '\',' + !p.mfa_required + ')">' + (p.mfa_required ? 'Disable MFA' : 'Enable MFA') + '</button></td></tr>';
    });
    html += '</tbody></table>';
    content.innerHTML = html;
}

async function toggleMFA(name, enable) {
    clearMsg('policies-msg');
    try {
        var r = await postJSON('/api/policies/save', { name: name, mfa_required: enable });
        if (r.ok) {
            showMsg('policies-msg', 'success', 'Policy updated for ' + name);
            loadPolicies();
        } else {
            var d = await r.json();
            showMsg('policies-msg', 'error', d.error || 'Failed to update policy');
        }
    } catch (ex) {
        showMsg('policies-msg', 'error', 'Connection error');
    }
}

// ═══════════════════════════════════════════════════════════════
//  Logs
// ═══════════════════════════════════════════════════════════════

function initLogs() {
    checkAuth();
    loadLogs();
    setInterval(loadLogs, 10000);
}

async function loadLogs() {
    try {
        var level = '';
        var limit = '100';
        var levelEl = document.getElementById('log-level-filter');
        var limitEl = document.getElementById('log-limit-filter');
        if (levelEl) level = levelEl.value;
        if (limitEl) limit = limitEl.value;

        var url = '/api/logs?limit=' + limit;
        if (level) url += '&level=' + level;

        var data = await apiJSON(url);
        var list = Array.isArray(data) ? data : [];
        renderLogs(list);
    } catch (e) {
        console.error(e);
    }
}

function renderLogs(list) {
    var countEl = document.getElementById('log-count');
    if (countEl) countEl.textContent = list.length;

    var content = document.getElementById('logs-content');
    if (!content) return;

    if (list.length === 0) {
        content.innerHTML = '<div class="empty-state"><p>No log entries yet.</p></div>';
        return;
    }

    var html = '<table class="data-table"><thead><tr><th>Timestamp</th><th>Level</th><th>Event</th><th>Message</th></tr></thead><tbody>';
    list.forEach(function (entry) {
        var levelBadge = 'muted';
        if (entry.level === 'info') levelBadge = 'green';
        else if (entry.level === 'warn') levelBadge = 'yellow';
        else if (entry.level === 'error') levelBadge = 'red';

        html += '<tr><td>' + formatTime(entry.timestamp) + '</td><td>' + badge(levelBadge, entry.level) + '</td><td><code>' + esc(entry.event) + '</code></td><td>' + esc(entry.message) + '</td></tr>';
    });
    html += '</tbody></table>';
    content.innerHTML = html;
}

// ═══════════════════════════════════════════════════════════════
//  Setup Wizard — 2-Step Setup
// ═══════════════════════════════════════════════════════════════

var wizardStep = 1;
var wizardData = { setupToken: '', fqdn: '', certMethod: 'upload' };

function wizardGoTo(step) {
    if (step < 1 || step > 2) return;

    // Hide current panel
    var cur = document.getElementById('wizard-step-' + wizardStep);
    if (cur) cur.classList.remove('active');

    // Update step indicators
    var steps = document.querySelectorAll('.setup-step');
    var connectors = document.querySelectorAll('.step-connector');
    steps.forEach(function (el) {
        var s = parseInt(el.dataset.step);
        el.classList.remove('active', 'done');
        if (s < step) el.classList.add('done');
        else if (s === step) el.classList.add('active');
    });
    connectors.forEach(function (el) {
        var after = parseInt(el.dataset.after);
        if (after < step) el.classList.add('filled');
        else el.classList.remove('filled');
    });

    wizardStep = step;

    // Show new panel
    var next = document.getElementById('wizard-step-' + step);
    if (next) {
        next.classList.remove('active');
        void next.offsetWidth;
        next.classList.add('active');
    }

    var screen = document.querySelector('.setup-screen');
    if (screen) screen.scrollTop = 0;
}

function initSetupWizard() {
    // Check if setup is already done
    fetch('/api/setup/status').then(function (r) { return r.json(); }).then(function (data) {
        if (data.completed) { window.location.href = '/login'; return; }
        // Pre-fill FQDN if available
        if (data.fqdn) {
            var fqdnEl = document.getElementById('w-fqdn');
            if (fqdnEl) fqdnEl.value = data.fqdn;
            wizardData.fqdn = data.fqdn;
        }
    });

    // ── Step 1: Token validation ──
    var form1 = document.getElementById('wizard-form-1');
    if (form1) {
        form1.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('wizard-msg-1');

            var tokenVal = document.getElementById('w-setup-token').value.trim();
            if (!tokenVal) { showMsg('wizard-msg-1', 'error', 'Setup token is required. Check the container logs.'); return; }

            var btn = document.getElementById('wizard-btn-1');
            if (btn) { btn.disabled = true; btn.textContent = 'Validating...'; }

            try {
                var r = await fetch('/api/setup/step/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Setup-Token': tokenVal },
                    body: JSON.stringify({})
                });
                var data = await r.json();
                if (!r.ok) {
                    showMsg('wizard-msg-1', 'error', data.error || 'Invalid setup token');
                    if (btn) { btn.disabled = false; btn.textContent = 'Continue'; }
                    return;
                }
                wizardData.setupToken = tokenVal;
                wizardGoTo(2);
            } catch (ex) {
                showMsg('wizard-msg-1', 'error', 'Connection error');
                if (btn) { btn.disabled = false; btn.textContent = 'Continue'; }
            }
        });
    }

    // ── Step 2: Certificate toggle ──
    var uploadRadio = document.getElementById('w-cert-upload');
    var leRadio = document.getElementById('w-cert-le');
    var uploadPanel = document.getElementById('w-cert-upload-panel');
    var lePanel = document.getElementById('w-cert-le-panel');

    function toggleCertPanels() {
        if (uploadRadio && uploadRadio.checked) {
            if (uploadPanel) uploadPanel.style.display = '';
            if (lePanel) lePanel.style.display = 'none';
        } else {
            if (uploadPanel) uploadPanel.style.display = 'none';
            if (lePanel) lePanel.style.display = '';
        }
    }
    if (uploadRadio) uploadRadio.addEventListener('change', toggleCertPanels);
    if (leRadio) leRadio.addEventListener('change', toggleCertPanels);

    // File input display
    ['w-cert-file', 'w-key-file'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', function () {
                var nameEl = document.getElementById(id + '-name');
                if (nameEl) nameEl.textContent = el.files.length ? el.files[0].name : 'No file chosen';
            });
        }
    });

    // ── Step 2: Form submit (hostname + certificate + finish) ──
    var form2 = document.getElementById('wizard-form-2');
    if (form2) {
        form2.addEventListener('submit', async function (e) {
            e.preventDefault();
            clearMsg('wizard-msg-2');

            var fqdn = document.getElementById('w-fqdn').value.trim();
            if (!fqdn) { showMsg('wizard-msg-2', 'error', 'Hostname is required'); return; }

            var btn = document.getElementById('wizard-btn-2');
            if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

            try {
                // Save FQDN
                var hdrs = { 'Content-Type': 'application/json', 'X-Setup-Token': wizardData.setupToken };
                var r1 = await fetch('/api/setup/step/network', {
                    method: 'POST',
                    headers: hdrs,
                    body: JSON.stringify({ fqdn: fqdn })
                });
                if (!r1.ok) {
                    var d1 = await r1.json();
                    showMsg('wizard-msg-2', 'error', d1.error || 'Failed to save hostname');
                    if (btn) { btn.disabled = false; btn.textContent = 'Complete Setup'; }
                    return;
                }
                wizardData.fqdn = fqdn;

                // Handle certificate
                var certSource = document.querySelector('input[name="w-cert-source"]:checked');
                if (certSource && certSource.value === 'upload') {
                    var certFileEl = document.getElementById('w-cert-file');
                    var keyFileEl = document.getElementById('w-key-file');
                    if (certFileEl && certFileEl.files.length && keyFileEl && keyFileEl.files.length) {
                        var certPEM = await certFileEl.files[0].text();
                        var keyPEM = await keyFileEl.files[0].text();
                        var r2 = await fetch('/api/setup/step/certificates', {
                            method: 'POST',
                            headers: hdrs,
                            body: JSON.stringify({ cert_pem: certPEM, key_pem: keyPEM })
                        });
                        if (!r2.ok) {
                            var d2 = await r2.json();
                            showMsg('wizard-msg-2', 'error', d2.error || 'Invalid certificate or key');
                            if (btn) { btn.disabled = false; btn.textContent = 'Complete Setup'; }
                            return;
                        }
                    }
                    wizardData.certMethod = 'upload';
                } else if (certSource && certSource.value === 'letsencrypt') {
                    var leAgree = document.getElementById('w-le-agree');
                    if (!leAgree || !leAgree.checked) {
                        showMsg('wizard-msg-2', 'error', 'You must agree to the Let\'s Encrypt Terms of Service');
                        if (btn) { btn.disabled = false; btn.textContent = 'Complete Setup'; }
                        return;
                    }
                    var r2le = await fetch('/api/setup/step/certificates', {
                        method: 'POST',
                        headers: hdrs,
                        body: JSON.stringify({ letsencrypt: true, fqdn: fqdn })
                    });
                    if (!r2le.ok) {
                        var d2le = await r2le.json();
                        console.warn('Let\'s Encrypt warning:', d2le);
                    }
                    wizardData.certMethod = 'letsencrypt';
                }

                // Finish setup and get session token
                if (btn) btn.textContent = 'Completing...';
                var rFinish = await fetch('/api/setup/step/finish', {
                    method: 'POST',
                    headers: hdrs,
                    body: JSON.stringify({})
                });
                var dFinish = await rFinish.json();
                if (!rFinish.ok) {
                    showMsg('wizard-msg-2', 'error', dFinish.error || 'Failed to complete setup');
                    if (btn) { btn.disabled = false; btn.textContent = 'Complete Setup'; }
                    return;
                }

                // Store CSRF token and redirect to admin interface
                if (dFinish.csrf_token) {
                    sessionStorage.setItem('csrfToken', dFinish.csrf_token);
                }
                window.location.href = '/';
            } catch (ex) {
                showMsg('wizard-msg-2', 'error', 'Connection error');
                if (btn) { btn.disabled = false; btn.textContent = 'Complete Setup'; }
            }
        });
    }
}

function updatePasswordStrength(pw, containerId) {
    var el = document.getElementById(containerId || 'pw-strength');
    if (!el) return;
    var score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    var bars = '';
    for (var i = 0; i < 4; i++) {
        var cls = '';
        if (i < score) {
            if (score <= 1) cls = 'weak';
            else if (score <= 3) cls = 'medium';
            else cls = 'strong';
        }
        bars += '<div class="pw-bar ' + cls + '"></div>';
    }
    el.innerHTML = bars;
}

// ═══════════════════════════════════════════════════════════════
//  Auto Init
// ═══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function () {
    var page = document.body.dataset.page;
    var initMap = {
        'login': initLogin,
        'setup-wizard': initSetupWizard,
        'dashboard': initDashboard,
        'applications': initApplications,
        'policies': initPolicies,
        'sessions': initSessions,
        'logs': initLogs,
        'certificates': initCertificates,
        'authentication': initAuthentication,
        'network': initNetwork,
        'enrollment': initEnrollment,
        'settings': initSettings
    };
    if (initMap[page]) initMap[page]();
});
