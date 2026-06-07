const GPO_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let gpoState = { meta: {}, gpos: [], gpoLinks: [], gpoFindings: [] };
let gpoSortColumn = 'RiskScore';
let gpoSortDirection = 'desc';
let selectedGpoId = '';

const GPO_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };
const GPO_CONTEXT_ONLY_TYPES = new Set([
  'GpoEnforcedLink',
  'GpoDisabledLink',
  'GpoOrphanedLink',
  'GpoAllSettingsDisabled',
  'GpoSectionDisabled',
  'GpoScriptSettings'
]);

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

function truncate(value, max = 140) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function normalizeGpoState(raw) {
  const payload = raw || {};
  const seen = new Map();
  const gpoFindings = (payload.gpoFindings || payload.GpoFindings || [])
    .filter(row => !GPO_CONTEXT_ONLY_TYPES.has(row.FindingType))
    .map((row, index) => {
    const base = row.GpoFindingId || [
      row.Domain,
      row.FindingType,
      row.GpoGuid || row.GpoName || row.GpoDistinguishedName,
      row.ScopeDistinguishedName || row.ScopeName,
      index
    ].filter(Boolean).join('|');
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    return {
      ...row,
      __DashboardGpoId: count ? `${base}#${count + 1}` : base
    };
  });

  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    gpos: payload.gpos || payload.Gpos || [],
    gpoLinks: payload.gpoLinks || payload.GpoLinks || [],
    gpoFindings
  };
}

async function loadGpoData() {
  const payload = await window.ADPostureDashboard.loadAuditData(GPO_DATA_URLS);
  if (payload) {
    gpoState = normalizeGpoState(payload);
    return true;
  }

  document.getElementById('gpo-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit -IncludeGpoPosture, then Open-ADPostureDashboard -View GpoPosture, or load a *-dashboard.json file.';
  return false;
}

function gpoSearchBlob(row) {
  return [
    row.GpoFindingId, row.Domain, row.FindingType, row.Severity,
    row.GpoName, row.GpoGuid, row.GpoDistinguishedName, row.GpoStatus,
    row.GpoFileSysPath, row.GpoWmiFilter, row.ScopeName, row.ScopeDistinguishedName,
    row.ScopeObjectClass, row.LinkOptions, row.IsLinkDisabled, row.IsEnforced,
    row.ScopeTier, row.ScopeRiskContext, row.DelegatedRight, row.TrusteeName,
    row.TrusteeSid, row.TrusteeDistinguishedName, row.SourceAclFindingId,
    row.FileSystemPath, row.FileSystemRights, row.AccessControlType,
    row.Reason, row.Remediation, (row.Tags || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredGpoFindings() {
  const q = (document.getElementById('gpo-search').value || '').toLowerCase();
  const type = document.getElementById('gpo-type').value;
  const severity = document.getElementById('gpo-severity').value;
  const tag = document.getElementById('gpo-tag').value;
  const scope = document.getElementById('gpo-scope').value;
  const scopeTier = document.getElementById('gpo-scope-tier').value;

  return (gpoState.gpoFindings || []).filter(row => {
    if (type && row.FindingType !== type) return false;
    if (severity && row.Severity !== severity) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (scope && row.ScopeObjectClass !== scope) return false;
    if (scopeTier && row.ScopeTier !== scopeTier) return false;
    if (q && !gpoSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'Severity') return GPO_SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function compareGpo(a, b) {
  const aValue = getSortValue(a, gpoSortColumn);
  const bValue = getSortValue(b, gpoSortColumn);
  let cmp = 0;
  if (typeof aValue === 'number' && typeof bValue === 'number') {
    cmp = aValue - bValue;
  } else {
    cmp = String(aValue).localeCompare(String(bValue), 'en', { numeric: true });
  }
  return gpoSortDirection === 'asc' ? cmp : -cmp;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#gpo-table th.sortable', gpoSortColumn, gpoSortDirection);
}

function renderKpis() {
  const rows = gpoState.gpoFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const delegated = rows.filter(row => row.FindingType === 'GpoDelegationControl').length;
  const sysvolAcl = rows.filter(row => [
    'GpoSysvolAclWeak',
    'GpoSysvolAclUnvalidated',
    'GpoScriptFileAclWeak',
    'GpoScriptFolderAclWeak'
  ].includes(row.FindingType)).length;
  const scriptPaths = rows.filter(row => [
    'GpoExternalScriptPath',
    'GpoScriptMetadataUnparsed',
    'GpoRiskyScriptContent'
  ].includes(row.FindingType)).length;
  const externalPaths = rows.filter(row => row.FindingType === 'GpoExternalScriptPath').length;
  const integrity = rows.filter(row => [
    'GpoMissingSysvolPath',
    'GpoUnusualSysvolPath'
  ].includes(row.FindingType)).length;
  const settingsGpp = rows.filter(row => [
    'GpoRiskyUserRight',
    'GpoRiskySecurityOption',
    'GpoBroadSecurityFiltering',
    'GpoPreferenceCredential',
    'GpoPreferenceLocalAdmin',
    'GpoPreferenceScheduledTask',
    'GpoPreferenceServiceControl',
    'GpoPreferenceExternalPath'
  ].includes(row.FindingType)).length;
  const wmiLoopback = rows.filter(row => [
    'GpoWmiFilterDependency',
    'GpoLoopbackProcessing'
  ].includes(row.FindingType)).length;
  const gpos = (gpoState.gpos || []).length ||
    new Set(rows.map(row => row.GpoGuid || row.GpoDistinguishedName || row.GpoName).filter(Boolean)).size;

  document.getElementById('gpo-count').textContent = rows.length;
  document.getElementById('gpo-critical').textContent = criticalHigh;
  document.getElementById('gpo-delegated').textContent = delegated;
  document.getElementById('gpo-sysvol-acl').textContent = sysvolAcl;
  document.getElementById('gpo-script-paths').textContent = scriptPaths;
  document.getElementById('gpo-external-paths').textContent = externalPaths;
  document.getElementById('gpo-integrity').textContent = integrity;
  document.getElementById('gpo-settings-gpp').textContent = settingsGpp;
  document.getElementById('gpo-wmi-loopback').textContent = wmiLoopback;
  document.getElementById('gpo-unique').textContent = gpos;
}

function renderFilters() {
  const rows = gpoState.gpoFindings || [];
  const setOptions = (id, values, label) => {
    const el = document.getElementById(id);
    el.innerHTML = `<option value="">${label}</option>` +
      values.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  };

  setOptions('gpo-type', [...new Set(rows.map(row => row.FindingType).filter(Boolean))].sort(), 'All finding types');
  setOptions('gpo-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('gpo-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
  setOptions('gpo-scope', [...new Set(rows.map(row => row.ScopeObjectClass).filter(Boolean))].sort(), 'All scopes');
  setOptions('gpo-scope-tier', [...new Set(rows.map(row => row.ScopeTier).filter(Boolean))].sort(), 'All scope tiers');
}

function renderGpoTable() {
  const rows = filteredGpoFindings().sort(compareGpo);
  const tbody = document.querySelector('#gpo-table tbody');
  if (rows.length && !rows.some(row => row.__DashboardGpoId === selectedGpoId)) {
    selectedGpoId = rows[0].__DashboardGpoId || '';
  }
  if (!rows.length) selectedGpoId = '';

  document.getElementById('gpo-summary').textContent = `${rows.length} visible / ${(gpoState.gpoFindings || []).length} total`;
  tbody.innerHTML = rows.length ? rows.map(row => {
    const tags = (row.Tags || []).slice(0, 5).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
    const selected = row.__DashboardGpoId === selectedGpoId ? ' class="selected-row"' : '';
    const status = [row.GpoStatus, row.IsEnforced ? 'Enforced' : '', row.IsLinkDisabled ? 'Link disabled' : '']
      .filter(Boolean).join(' / ');
    const scopeText = [row.ScopeTier, row.ScopeRiskContext].filter(Boolean).join(' - ');
    return `
      <tr${selected} data-gpo-id="${esc(row.__DashboardGpoId)}" tabindex="0">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td><button type="button" class="link-button" data-open-gpo="${esc(row.__DashboardGpoId)}">${esc(row.FindingType || 'Unknown')}</button></td>
        <td class="wrap">${esc(row.GpoName || '-')}<br><small class="sub">${esc(row.GpoGuid || row.GpoDistinguishedName || '')}</small></td>
        <td class="wrap">${esc(row.TrusteeName || '-')}<br><small class="sub">${esc(row.DelegatedRight || row.SourceAclFindingId || '')}</small></td>
        <td class="wrap">${esc(row.ScopeName || '-')}<br><small class="sub">${esc(scopeText || row.ScopeObjectClass || '')}</small></td>
        <td class="wrap">${esc(status || '-')}</td>
        <td class="wrap">${tags || '<span class="sub">No tags</span>'}</td>
        <td class="wrap"><small title="${esc(row.Reason || '')}">${esc(truncate(row.Reason || '', 180))}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="9" class="sub">No GPO findings match the current filters.</td></tr>';

  const openGpo = gpoId => {
    selectedGpoId = gpoId || '';
    renderGpoTable();
    renderProfile();
    document.getElementById('gpo-profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  tbody.querySelectorAll('tr[data-gpo-id]').forEach(rowEl => {
    rowEl.addEventListener('click', () => openGpo(rowEl.dataset.gpoId));
    rowEl.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openGpo(rowEl.dataset.gpoId);
      }
    });
  });
}

function renderProfile() {
  const row = (gpoState.gpoFindings || []).find(item => item.__DashboardGpoId === selectedGpoId);
  const title = document.getElementById('gpo-profile-title');
  const subtitle = document.getElementById('gpo-profile-subtitle');
  const score = document.getElementById('gpo-profile-score');
  const body = document.getElementById('gpo-profile-body');

  if (!row) {
    title.textContent = 'GPO finding';
    subtitle.textContent = 'Select a row from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No GPO finding selected.';
    return;
  }

  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const status = [row.GpoStatus, row.IsEnforced ? 'Enforced link' : '', row.IsLinkDisabled ? 'Disabled link' : '']
    .filter(Boolean).join(' / ');

  title.textContent = `${row.FindingType || 'GPO finding'} on ${row.GpoName || row.GpoGuid || 'GPO'}`;
  subtitle.textContent = [row.Domain, row.GpoFindingId, row.ScopeName || row.ScopeObjectClass].filter(Boolean).join(' / ');
  score.innerHTML = `<strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong><span>${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>GPO</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.GpoName || '-')}</dd>
        <dt>GUID</dt><dd>${esc(row.GpoGuid || '-')}</dd>
        <dt>Status</dt><dd>${esc(status || '-')}</dd>
        <dt>WMI filter</dt><dd>${esc(row.GpoWmiFilter || '-')}</dd>
        <dt>DN</dt><dd>${esc(row.GpoDistinguishedName || '-')}</dd>
        <dt>SYSVOL</dt><dd>${esc(row.GpoFileSysPath || '-')}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Scope</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.ScopeName || '-')}</dd>
        <dt>Class</dt><dd>${esc(row.ScopeObjectClass || '-')}</dd>
        <dt>DN</dt><dd>${esc(row.ScopeDistinguishedName || '-')}</dd>
        <dt>Options</dt><dd>${esc(row.LinkOptions ?? '-')}</dd>
        <dt>Tier</dt><dd>${esc(row.ScopeTier || '-')}</dd>
        <dt>Context</dt><dd>${esc(row.ScopeRiskContext || '-')}</dd>
        <dt>Link</dt><dd>${row.IsEnforced ? '<span class="badge badge-high">Enforced</span>' : '<span class="badge badge-low">Not enforced</span>'} ${row.IsLinkDisabled ? '<span class="badge badge-med">Disabled</span>' : ''}</dd>
      </dl>
    </div>
    <div class="profile-block profile-wide">
      <strong>Evidence</strong>
      <dl class="profile-list gpo-profile-list">
        <dt>Finding</dt><dd>${esc(row.FindingType || '-')}</dd>
        <dt>Trustee</dt><dd>${esc(row.TrusteeName || '-')}</dd>
        <dt>Delegated right</dt><dd>${esc(row.DelegatedRight || '-')}</dd>
        <dt>File path</dt><dd>${esc(row.FileSystemPath || '-')}</dd>
        <dt>File rights</dt><dd>${esc(row.FileSystemRights || '-')}</dd>
        <dt>Inherited</dt><dd>${row.IsInherited ? 'Yes' : 'No'}</dd>
        <dt>Source ACL</dt><dd>${esc(row.SourceAclFindingId || '-')}</dd>
        <dt>Score formula</dt><dd>${esc(row.ScoreFormula || '-')}</dd>
        <dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd>
        <dt>Reason</dt><dd>${esc(row.Reason || '-')}</dd>
        <dt>Remediation</dt><dd>${esc(row.Remediation || 'Review the GPO configuration and document or remediate the finding.')}</dd>
      </dl>
    </div>`;
}

function renderAll() {
  renderKpis();
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(gpoState.meta, (gpoState.gpoFindings || []).length);
  }
  renderFilters();
  updateSortHeaders();
  renderGpoTable();
  renderProfile();
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'gpo-file',
  hintId: 'gpo-hint',
  onData: raw => {
    gpoState = normalizeGpoState(raw);
    selectedGpoId = '';
    renderAll();
  }
});

['gpo-search', 'gpo-type', 'gpo-severity', 'gpo-tag', 'gpo-scope', 'gpo-scope-tier'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderGpoTable();
    renderProfile();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderGpoTable();
    renderProfile();
  });
});

(function setupGpoClearFilters() {
  const clearBtn = document.getElementById('gpo-clear');
  if (!clearBtn) return;

  const filterIds = ['gpo-search', 'gpo-type', 'gpo-severity', 'gpo-tag', 'gpo-scope', 'gpo-scope-tier'];
  const hasActiveFilter = () => filterIds.some(id => {
    const el = document.getElementById(id);
    return el && el.value !== '';
  });
  const updateClearBtn = () => clearBtn.classList.toggle('visible', hasActiveFilter());

  filterIds.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', updateClearBtn);
    el.addEventListener('change', updateClearBtn);
  });

  clearBtn.addEventListener('click', () => {
    filterIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    selectedGpoId = '';
    updateClearBtn();
    renderGpoTable();
    renderProfile();
  });
})();

document.querySelectorAll('#gpo-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (gpoSortColumn === column) {
      gpoSortDirection = gpoSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      gpoSortColumn = column;
      gpoSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    renderGpoTable();
  });
});

loadGpoData().then(ok => {
  if (ok && (gpoState.gpoFindings || []).length) {
    document.getElementById('gpo-hint').style.display = 'none';
  } else if (ok) {
    document.getElementById('gpo-hint').textContent = 'No GPO findings loaded. Run an audit with -IncludeGpoPosture or load a dashboard JSON that contains gpoFindings.';
  }
  selectedGpoId = '';
  renderAll();
});
