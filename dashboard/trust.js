const TRUST_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let trustState = { meta: {}, trusts: [], trustFindings: [] };
let trustSortColumn = 'RiskScore';
let trustSortDirection = 'desc';
let selectedTrustId = '';

const TRUST_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

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

function boolLabel(value, goodWhenTrue) {
  const enabled = value === true || value === 'True' || value === 'true';
  const ok = goodWhenTrue ? enabled : !enabled;
  return `<span class="badge ${ok ? 'badge-low' : 'badge-high'}">${enabled ? 'On' : 'Off'}</span>`;
}

function normalizeTrustState(raw) {
  const payload = raw || {};
  const findings = payload.trustFindings || payload.TrustFindings || [];
  const seen = new Map();
  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    trusts: payload.trusts || payload.Trusts || [],
    trustFindings: findings.map((row, index) => {
      const base = row.TrustFindingId || row.trustFindingId || `trust-${String(index + 1).padStart(6, '0')}`;
      const count = seen.get(base) || 0;
      seen.set(base, count + 1);
      return {
        ...row,
        TrustFindingId: base,
        ScoreComponents: row.ScoreComponents || row.scoreComponents || [],
        AttackTechniques: row.AttackTechniques || row.attackTechniques || [],
        Tags: row.Tags || row.tags || [],
        __DashboardTrustId: count ? `${base}#${count + 1}` : base
      };
    })
  };
}

async function loadTrustData() {
  const payload = await window.ADPostureDashboard.loadAuditData(TRUST_DATA_URLS);
  if (payload) {
    trustState = normalizeTrustState(payload);
    return true;
  }
  document.getElementById('trust-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit -IncludeTrustPosture, then Open-ADPostureDashboard -View TrustPosture, or load a *-dashboard.json file.';
  return false;
}

function trustSearchBlob(row) {
  return [
    row.TrustFindingId, row.Domain, row.FindingType, row.RiskPattern, row.Severity,
    row.TrustName, row.TrustPartner, row.TrustDirection, row.TrustType, row.TrustAttributes,
    row.DistinguishedName, row.Reason, row.Remediation, (row.Tags || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredTrustFindings() {
  const q = (document.getElementById('trust-search').value || '').toLowerCase();
  const type = document.getElementById('trust-type').value;
  const severity = document.getElementById('trust-severity').value;
  const direction = document.getElementById('trust-direction').value;
  const tag = document.getElementById('trust-tag').value;

  return (trustState.trustFindings || []).filter(row => {
    if (type && row.FindingType !== type) return false;
    if (severity && row.Severity !== severity) return false;
    if (direction && row.TrustDirection !== direction) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (q && !trustSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'Severity') return TRUST_SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function sortedTrustRows() {
  return filteredTrustFindings().sort((a, b) => {
    const av = getSortValue(a, trustSortColumn);
    const bv = getSortValue(b, trustSortColumn);
    if (av === bv) return 0;
    const result = av > bv ? 1 : -1;
    return trustSortDirection === 'asc' ? result : -result;
  });
}

function setOptions(id, values, placeholder) {
  const el = document.getElementById(id);
  const current = el.value;
  el.innerHTML = `<option value="">${esc(placeholder)}</option>` + values.map(v => `<option>${esc(v)}</option>`).join('');
  if (values.includes(current)) el.value = current;
}

function renderKpis() {
  const rows = trustState.trustFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const sid = rows.filter(row => row.FindingType === 'TrustSidFilteringDisabled').length;
  const selective = rows.filter(row => row.FindingType === 'TrustSelectiveAuthenticationDisabled').length;
  const transitive = rows.filter(row => row.IsTransitive || row.ForestTransitive).length;

  document.getElementById('trust-count').textContent = rows.length;
  document.getElementById('trust-critical').textContent = criticalHigh;
  document.getElementById('trust-sid').textContent = sid;
  document.getElementById('trust-selective').textContent = selective;
  document.getElementById('trust-transitive').textContent = transitive;
  document.getElementById('trust-total').textContent = (trustState.trusts || []).length;
  document.getElementById('trust-summary').textContent = `${filteredTrustFindings().length} visible / ${criticalHigh} critical or high / ${sid + selective} boundary gaps`;

  setOptions('trust-type', [...new Set(rows.map(row => row.FindingType).filter(Boolean))].sort(), 'All finding types');
  setOptions('trust-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('trust-direction', [...new Set(rows.map(row => row.TrustDirection).filter(Boolean))].sort(), 'All directions');
  setOptions('trust-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
}

function renderTrustTable() {
  const tbody = document.querySelector('#trust-table tbody');
  const rows = sortedTrustRows();
  tbody.innerHTML = rows.length ? rows.map(row => {
    const selected = row.__DashboardTrustId === selectedTrustId ? ' class="selected-row"' : '';
    const controls = [
      `SID ${row.SIDFilteringEnabled ? 'on' : 'off'}`,
      `Selective ${row.SelectiveAuthentication ? 'on' : 'off'}`,
      `Transitive ${row.IsTransitive ? 'yes' : 'no'}`
    ].join(' / ');
    return `
      <tr${selected} data-trust-id="${esc(row.__DashboardTrustId)}" tabindex="0">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td><button type="button" class="link-button" data-open-trust="${esc(row.__DashboardTrustId)}">${esc(row.FindingType || 'Unknown')}</button><br><small class="sub">${esc(row.RiskPattern || '')}</small></td>
        <td class="wrap">${esc(row.TrustName || '-')}<br><small class="sub">${esc(row.TrustType || '')}</small></td>
        <td class="wrap">${esc(row.TrustPartner || '-')}<br><small class="sub">${esc(row.DistinguishedName || '')}</small></td>
        <td>${esc(row.TrustDirection || '-')}</td>
        <td class="wrap"><small>${esc(controls)}</small></td>
        <td class="wrap"><small>${esc(row.Reason || '-')}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="8" class="sub">No Trust findings match the current filters.</td></tr>';
}

function renderProfile() {
  const row = (trustState.trustFindings || []).find(item => item.__DashboardTrustId === selectedTrustId);
  const title = document.getElementById('trust-profile-title');
  const subtitle = document.getElementById('trust-profile-subtitle');
  const score = document.getElementById('trust-profile-score');
  const body = document.getElementById('trust-profile-body');

  if (!row) {
    title.textContent = 'Trust finding';
    subtitle.textContent = 'Select a row from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No trust finding selected.';
    return;
  }

  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const techniques = (row.AttackTechniques || []).map(value => `<span class="uac-pill">${esc([value.Id, value.Name].filter(Boolean).join(' - '))}</span>`).join(' ');
  const components = (row.ScoreComponents || []).map(component => `
    <tr>
      <td>${esc(component.Name || '-')}</td>
      <td>${esc(component.Value ?? '-')}</td>
      <td>${esc(component.Reason || '-')}</td>
    </tr>`).join('');

  title.textContent = `${row.FindingType || 'Trust finding'} on ${row.TrustName || 'trust'}`;
  subtitle.textContent = [row.Domain, row.TrustFindingId, row.RiskPattern].filter(Boolean).join(' / ');
  score.innerHTML = `
    <span class="profile-score-label">Risk</span>
    <strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong>
    <span class="profile-severity">${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>Trust boundary</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.TrustName || '-')}</dd>
        <dt>Partner</dt><dd>${esc(row.TrustPartner || '-')}</dd>
        <dt>Direction</dt><dd>${esc(row.TrustDirection || '-')}</dd>
        <dt>Type</dt><dd>${esc(row.TrustType || '-')}</dd>
        <dt>Attributes</dt><dd>${esc(row.TrustAttributes ?? '-')}</dd>
        <dt>DN</dt><dd>${esc(row.DistinguishedName || '-')}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Controls</strong>
      <dl class="profile-list">
        <dt>SID filtering</dt><dd>${boolLabel(row.SIDFilteringEnabled, true)}</dd>
        <dt>Selective auth</dt><dd>${boolLabel(row.SelectiveAuthentication, true)}</dd>
        <dt>Transitive</dt><dd>${boolLabel(row.IsTransitive, false)}</dd>
        <dt>Forest transitive</dt><dd>${boolLabel(row.ForestTransitive, false)}</dd>
        <dt>TGT delegation</dt><dd>${boolLabel(row.TGTDelegation, false)}</dd>
        <dt>Changed</dt><dd>${esc(row.WhenChanged || '-')}</dd>
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
  window.ADPostureDashboard.updateSortHeaders('#trust-table th.sortable', trustSortColumn, trustSortDirection);
}

function renderAll() {
  renderKpis();
  updateSortHeaders();
  renderTrustTable();
  renderProfile();
  if (typeof window.updateSidebar === 'function') window.updateSidebar(trustState.meta, (trustState.trustFindings || []).length);
}

document.querySelector('#trust-table tbody')?.addEventListener('click', event => {
  const row = event.target.closest('tr[data-trust-id]');
  if (!row) return;
  selectedTrustId = row.dataset.trustId;
  renderTrustTable();
  renderProfile();
});

document.querySelector('#trust-table tbody')?.addEventListener('keydown', event => {
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const row = event.target.closest('tr[data-trust-id]');
  if (!row) return;
  selectedTrustId = row.dataset.trustId;
  renderTrustTable();
  renderProfile();
});

['trust-search', 'trust-type', 'trust-severity', 'trust-direction', 'trust-tag'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderTrustTable();
    renderProfile();
    renderKpis();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderTrustTable();
    renderProfile();
    renderKpis();
  });
});

document.getElementById('trust-clear')?.addEventListener('click', () => {
  ['trust-search', 'trust-type', 'trust-severity', 'trust-direction', 'trust-tag'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  renderAll();
});

document.querySelectorAll('#trust-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (trustSortColumn === column) {
      trustSortDirection = trustSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      trustSortColumn = column;
      trustSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    renderTrustTable();
  });
});

window.ADPostureDashboard.setupJsonImport({
  inputId: 'trust-file-input',
  hintId: 'trust-hint',
  onData: raw => {
    trustState = normalizeTrustState(raw);
    renderAll();
  }
});

loadTrustData().then(ok => {
  if (ok) {
    const hint = document.getElementById('trust-hint');
    const count = (trustState.trustFindings || []).length;
    if (count) {
      hint.style.display = 'none';
    } else {
      hint.textContent = 'No Trust risk findings loaded. Run an audit with -IncludeTrustPosture or load a dashboard JSON that contains trustFindings.';
    }
  }
  renderAll();
  if (window.ADPostureTableTools) window.ADPostureTableTools.enhanceAll();
});
