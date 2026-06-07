const AUTH_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let authState = { meta: {}, kerberosAuthFindings: [], kerberosAuthPrincipals: [] };
let authSortColumn = 'RiskScore';
let authSortDirection = 'desc';
let selectedAuthId = '';

const AUTH_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

function esc(value) {
  return window.ADPostureDashboard.esc(value);
}

function scoreClass(value) {
  return window.ADPostureDashboard.scoreClass(value);
}

function severityBadge(severity) {
  const cls = severity === 'Critical' || severity === 'High'
    ? 'badge-high'
    : severity === 'Medium'
      ? 'badge-med'
      : 'badge-low';
  return `<span class="badge ${cls}">${esc(severity || 'Informational')}</span>`;
}

function normalizeAuthState(raw) {
  const payload = raw || {};
  const findings = payload.kerberosAuthFindings || payload.KerberosAuthFindings || [];
  const seen = new Map();
  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    kerberosAuthPrincipals: payload.kerberosAuthPrincipals || payload.KerberosAuthPrincipals || [],
    kerberosAuthFindings: findings.map((row, index) => {
      const base = row.KerberosAuthFindingId || row.kerberosAuthFindingId || `auth-${String(index + 1).padStart(6, '0')}`;
      const count = seen.get(base) || 0;
      seen.set(base, count + 1);
      return {
        ...row,
        KerberosAuthFindingId: base,
        ServicePrincipalNames: row.ServicePrincipalNames || row.servicePrincipalNames || [],
        DelegationTargets: row.DelegationTargets || row.delegationTargets || [],
        EncryptionTypes: row.EncryptionTypes || row.encryptionTypes || [],
        ScoreComponents: row.ScoreComponents || row.scoreComponents || [],
        AttackTechniques: row.AttackTechniques || row.attackTechniques || [],
        Tags: row.Tags || row.tags || [],
        __DashboardAuthId: count ? `${base}#${count + 1}` : base
      };
    })
  };
}

async function loadData() {
  const payload = await window.ADPostureDashboard.loadAuditData(AUTH_DATA_URLS);
  if (payload) {
    authState = normalizeAuthState(payload);
    return true;
  }
  document.getElementById('auth-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit -IncludeKerberosAuthPosture, then Open-ADPostureDashboard -View KerberosAuthPosture, or load a *-dashboard.json file.';
  return false;
}

function authSearchBlob(row) {
  return [
    row.KerberosAuthFindingId, row.Domain, row.FindingType, row.RiskPattern, row.Severity,
    row.Principal, row.PrincipalSam, row.PrincipalDn, row.PrincipalSid, row.PrincipalClass,
    row.PrivilegeTier, row.AccountType, row.DelegationType, row.EncryptionSummary,
    (row.ServicePrincipalNames || []).join(' '), (row.DelegationTargets || []).join(' '),
    (row.EncryptionTypes || []).join(' '), row.Reason, row.Remediation, (row.Tags || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredAuthFindings() {
  const q = (document.getElementById('auth-search').value || '').toLowerCase();
  const type = document.getElementById('auth-type').value;
  const severity = document.getElementById('auth-severity').value;
  const delegation = document.getElementById('auth-delegation').value;
  const tag = document.getElementById('auth-tag').value;
  const tier = document.getElementById('auth-tier').value;

  return (authState.kerberosAuthFindings || []).filter(row => {
    if (type && row.FindingType !== type) return false;
    if (severity && row.Severity !== severity) return false;
    if (delegation && row.DelegationType !== delegation) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (tier && row.PrivilegeTier !== tier) return false;
    if (q && !authSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'Severity') return AUTH_SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function sortedAuthRows() {
  return filteredAuthFindings().sort((a, b) => {
    const av = getSortValue(a, authSortColumn);
    const bv = getSortValue(b, authSortColumn);
    if (av === bv) return 0;
    const result = av > bv ? 1 : -1;
    return authSortDirection === 'asc' ? result : -result;
  });
}

function setOptions(id, values, placeholder) {
  const el = document.getElementById(id);
  const current = el.value;
  el.innerHTML = `<option value="">${esc(placeholder)}</option>` + values.map(v => `<option>${esc(v)}</option>`).join('');
  if (values.includes(current)) el.value = current;
}

function renderKpis() {
  const rows = authState.kerberosAuthFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const roastable = rows.filter(row => ['KerberosAsRepRoastableAccount', 'KerberosRoastableServiceAccount'].includes(row.FindingType)).length;
  const delegation = rows.filter(row => row.DelegationType || (row.Tags || []).includes('Delegation')).length;
  const weakCrypto = rows.filter(row => (row.Tags || []).includes('WeakEncryption')).length;

  document.getElementById('auth-count').textContent = rows.length;
  document.getElementById('auth-critical').textContent = criticalHigh;
  document.getElementById('auth-roastable').textContent = roastable;
  document.getElementById('auth-delegation-count').textContent = delegation;
  document.getElementById('auth-crypto').textContent = weakCrypto;
  document.getElementById('auth-principals').textContent = (authState.kerberosAuthPrincipals || []).length;
  document.getElementById('auth-summary').textContent = `${filteredAuthFindings().length} visible / ${criticalHigh} critical or high / ${delegation} delegation`;

  setOptions('auth-type', [...new Set(rows.map(row => row.FindingType).filter(Boolean))].sort(), 'All finding types');
  setOptions('auth-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('auth-delegation', [...new Set(rows.map(row => row.DelegationType).filter(Boolean))].sort(), 'All delegation');
  setOptions('auth-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
  setOptions('auth-tier', [...new Set(rows.map(row => row.PrivilegeTier).filter(Boolean))].sort(), 'All tiers');
}

function renderAuthTable() {
  const tbody = document.querySelector('#auth-table tbody');
  const rows = sortedAuthRows();
  tbody.innerHTML = rows.length ? rows.map(row => {
    const selected = row.__DashboardAuthId === selectedAuthId ? ' class="selected-row"' : '';
    const spnTarget = [...(row.ServicePrincipalNames || []), ...(row.DelegationTargets || [])].slice(0, 4).join(', ');
    return `
      <tr${selected} data-auth-id="${esc(row.__DashboardAuthId)}" tabindex="0">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td><button type="button" class="link-button" data-open-auth="${esc(row.__DashboardAuthId)}">${esc(row.FindingType || 'Unknown')}</button><br><small class="sub">${esc(row.RiskPattern || '')}</small></td>
        <td class="wrap">${esc(row.Principal || '-')}<br><small class="sub">${esc(row.PrincipalDn || row.PrincipalSid || '')}</small></td>
        <td>${esc(row.DelegationType || '-')}</td>
        <td class="wrap"><small>${esc(spnTarget || '-')}</small></td>
        <td class="wrap"><small>${esc(row.EncryptionSummary || '-')}</small></td>
        <td class="wrap"><small>${esc(row.Reason || '-')}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="8" class="sub">No Kerberos/Auth findings match the current filters.</td></tr>';
}

function renderProfile() {
  const row = (authState.kerberosAuthFindings || []).find(item => item.__DashboardAuthId === selectedAuthId);
  const title = document.getElementById('auth-profile-title');
  const subtitle = document.getElementById('auth-profile-subtitle');
  const score = document.getElementById('auth-profile-score');
  const body = document.getElementById('auth-profile-body');

  if (!row) {
    title.textContent = 'Auth finding';
    subtitle.textContent = 'Select a row from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No Kerberos/Auth finding selected.';
    return;
  }

  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const spns = (row.ServicePrincipalNames || []).map(value => `<span class="uac-pill">${esc(value)}</span>`).join(' ');
  const targets = (row.DelegationTargets || []).map(value => `<span class="uac-pill">${esc(value)}</span>`).join(' ');
  const techniques = (row.AttackTechniques || []).map(value => `<span class="uac-pill">${esc([value.Id, value.Name].filter(Boolean).join(' - '))}</span>`).join(' ');
  const components = (row.ScoreComponents || []).map(component => `
    <tr>
      <td>${esc(component.Name || '-')}</td>
      <td>${esc(component.Value ?? '-')}</td>
      <td>${esc(component.Reason || '-')}</td>
    </tr>`).join('');

  title.textContent = `${row.FindingType || 'Auth finding'} on ${row.Principal || 'principal'}`;
  subtitle.textContent = [row.Domain, row.KerberosAuthFindingId, row.RiskPattern].filter(Boolean).join(' / ');
  score.innerHTML = `
    <span class="profile-score-label">Risk</span>
    <strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong>
    <span class="profile-severity">${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>Principal</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.Principal || '-')}</dd>
        <dt>Class</dt><dd>${esc(row.PrincipalClass || '-')}</dd>
        <dt>Type</dt><dd>${esc(row.AccountType || '-')}</dd>
        <dt>Tier</dt><dd>${esc(row.PrivilegeTier || '-')}</dd>
        <dt>SID</dt><dd>${esc(row.PrincipalSid || '-')}</dd>
        <dt>DN</dt><dd>${esc(row.PrincipalDn || '-')}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Authentication</strong>
      <dl class="profile-list">
        <dt>Pattern</dt><dd>${esc(row.RiskPattern || '-')}</dd>
        <dt>Delegation</dt><dd>${esc(row.DelegationType || '-')}</dd>
        <dt>Encryption</dt><dd>${esc(row.EncryptionSummary || '-')}</dd>
        <dt>SPNs</dt><dd>${spns || '<span class="sub">No SPNs recorded</span>'}</dd>
        <dt>Targets</dt><dd>${targets || '<span class="sub">No delegation targets recorded</span>'}</dd>
      </dl>
    </div>
    <div class="profile-block profile-wide">
      <strong>Evidence</strong>
      <dl class="profile-list">
        <dt>Reason</dt><dd>${esc(row.Reason || '-')}</dd>
        <dt>Remediation</dt><dd>${esc(row.Remediation || '-')}</dd>
        <dt>Score formula</dt><dd>${esc(row.ScoreFormula || '-')}</dd>
        <dt>ATT&CK</dt><dd>${techniques || '<span class="sub">No ATT&CK mapping recorded</span>'}</dd>
        <dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd>
      </dl>
      ${components ? `
        <div class="table-scroll compact-table-scroll">
          <table class="compact-table">
            <thead><tr><th>Component</th><th>Value</th><th>Reason</th></tr></thead>
            <tbody>${components}</tbody>
          </table>
        </div>` : ''}
    </div>`;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#auth-table th.sortable', authSortColumn, authSortDirection);
}

function renderAll() {
  renderKpis();
  updateSortHeaders();
  renderAuthTable();
  renderProfile();
  if (typeof window.updateSidebar === 'function') window.updateSidebar(authState.meta, (authState.kerberosAuthFindings || []).length);
}

document.querySelector('#auth-table tbody')?.addEventListener('click', event => {
  const row = event.target.closest('tr[data-auth-id]');
  if (!row) return;
  selectedAuthId = row.dataset.authId;
  renderAuthTable();
  renderProfile();
});

document.querySelector('#auth-table tbody')?.addEventListener('keydown', event => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const row = event.target.closest('tr[data-auth-id]');
  if (!row) return;
  selectedAuthId = row.dataset.authId;
  renderAuthTable();
  renderProfile();
});

['auth-search', 'auth-type', 'auth-severity', 'auth-delegation', 'auth-tag', 'auth-tier'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderAuthTable();
    renderProfile();
    renderKpis();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderAuthTable();
    renderProfile();
    renderKpis();
  });
});

document.getElementById('auth-clear')?.addEventListener('click', () => {
  ['auth-search', 'auth-type', 'auth-severity', 'auth-delegation', 'auth-tag', 'auth-tier'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  renderAll();
});

document.querySelectorAll('#auth-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (authSortColumn === column) {
      authSortDirection = authSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      authSortColumn = column;
      authSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    renderAuthTable();
  });
});

window.ADPostureDashboard.setupJsonImport({
  inputId: 'auth-file-input',
  hintId: 'auth-hint',
  onData: raw => {
    authState = normalizeAuthState(raw);
    renderAll();
  }
});

loadData().then(ok => {
  if (ok) {
    const hint = document.getElementById('auth-hint');
    const count = (authState.kerberosAuthFindings || []).length;
    if (count) {
      hint.style.display = 'none';
    } else {
      hint.textContent = 'No Kerberos/Auth risk findings loaded. Run an audit with -IncludeKerberosAuthPosture or load a dashboard JSON that contains kerberosAuthFindings.';
    }
  }
  renderAll();
  if (window.ADPostureTableTools) window.ADPostureTableTools.enhanceAll();
});
