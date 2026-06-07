const ACL_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let aclState = { meta: {}, aclFindings: [] };
let aclSortColumn = 'RiskScore';
let aclSortDirection = 'desc';
let selectedAclId = '';

const ACL_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

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

function normalizeAclState(raw) {
  const payload = raw || {};
  const seen = new Map();
  const aclFindings = (payload.aclFindings || payload.AclFindings || []).map((row, index) => {
    const base = row.AclFindingId || [
      row.Domain,
      row.NormalizedRight,
      row.TrusteeSid || row.TrusteeName,
      row.TargetObjectSid || row.TargetDistinguishedName || row.TargetName,
      index
    ].filter(Boolean).join('|');
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    return {
      ...row,
      __DashboardAclId: count ? `${base}#${count + 1}` : base
    };
  });

  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    aclFindings
  };
}

async function loadAclData() {
  const payload = await window.ADPostureDashboard.loadAuditData(ACL_DATA_URLS);
  if (payload) {
    aclState = normalizeAclState(payload);
    return true;
  }

  document.getElementById('acl-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit -IncludeAclPosture, then Open-ADPostureDashboard -View AclPosture, or load a *-dashboard.json file.';
  return false;
}

function aclSearchBlob(row) {
  return [
    row.AclFindingId, row.Domain, row.TargetName, row.TargetDistinguishedName,
    row.TargetCanonicalName,
    row.TargetObjectSid, row.TargetObjectClass, row.TrusteeName, row.TrusteeSid,
    row.TrusteeDistinguishedName, row.TrusteeObjectClass, row.RawTrustee,
    row.OwnerName, row.OwnerSid, row.OwnerDistinguishedName, row.OwnerObjectClass,
    row.UnresolvedTrustee, row.DriftState, row.NormalizedRight,
    row.ObjectTypeName, row.InheritedObjectTypeName, row.EvidenceType,
    row.Severity, row.Reason, row.Remediation, (row.Tags || []).join(' '),
    (row.ActiveDirectoryRights || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredAclFindings() {
  const q = (document.getElementById('acl-search').value || '').toLowerCase();
  const right = document.getElementById('acl-right').value;
  const severity = document.getElementById('acl-severity').value;
  const tag = document.getElementById('acl-tag').value;
  const drift = document.getElementById('acl-drift')?.value || '';
  const inherited = document.getElementById('acl-inherited').value;

  return (aclState.aclFindings || []).filter(row => {
    if (right && row.NormalizedRight !== right) return false;
    if (severity && row.Severity !== severity) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (drift && row.DriftState !== drift) return false;
    if (inherited && String(Boolean(row.IsInherited)) !== inherited) return false;
    if (q && !aclSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'Severity') return ACL_SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function compareAcl(a, b) {
  const aValue = getSortValue(a, aclSortColumn);
  const bValue = getSortValue(b, aclSortColumn);
  let cmp = 0;
  if (typeof aValue === 'number' && typeof bValue === 'number') {
    cmp = aValue - bValue;
  } else {
    cmp = String(aValue).localeCompare(String(bValue), 'en', { numeric: true });
  }
  return aclSortDirection === 'asc' ? cmp : -cmp;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#acl-table th.sortable', aclSortColumn, aclSortDirection);
}

function renderKpis() {
  const rows = aclState.aclFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const dcsync = rows.filter(row => row.NormalizedRight === 'DCSync' || (row.Tags || []).includes('DCSyncCapable')).length;
  const newCriticalHigh = rows.filter(row => row.DriftState === 'New' && (row.Severity === 'Critical' || row.Severity === 'High')).length;
  const direct = rows.filter(row => !row.IsInherited).length;
  const trustees = new Set(rows.map(row => row.TrusteeSid || row.TrusteeName).filter(Boolean)).size;
  const targets = new Set(rows.map(row => row.TargetObjectSid || row.TargetDistinguishedName || row.TargetName).filter(Boolean)).size;

  document.getElementById('acl-count').textContent = rows.length;
  document.getElementById('acl-critical').textContent = criticalHigh;
  document.getElementById('acl-dcsync').textContent = dcsync;
  document.getElementById('acl-new-high').textContent = newCriticalHigh;
  document.getElementById('acl-direct').textContent = direct;
  document.getElementById('acl-trustees').textContent = trustees;
  document.getElementById('acl-targets').textContent = targets;
}

function renderFilters() {
  const rows = aclState.aclFindings || [];
  const setOptions = (id, values, label) => {
    const el = document.getElementById(id);
    el.innerHTML = `<option value="">${label}</option>` +
      values.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  };

  setOptions('acl-right', [...new Set(rows.map(row => row.NormalizedRight).filter(Boolean))].sort(), 'All rights');
  setOptions('acl-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('acl-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
}

function renderAclTable() {
  const rows = filteredAclFindings().sort(compareAcl);
  const tbody = document.querySelector('#acl-table tbody');
  if (rows.length && !rows.some(row => row.__DashboardAclId === selectedAclId)) {
    selectedAclId = rows[0].__DashboardAclId || '';
  }
  if (!rows.length) {
    selectedAclId = '';
  }

  document.getElementById('acl-summary').textContent = `${rows.length} visible / ${(aclState.aclFindings || []).length} total`;
  tbody.innerHTML = rows.length ? rows.map(row => {
    const tags = (row.Tags || []).slice(0, 5).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
    const selected = row.__DashboardAclId === selectedAclId ? ' class="selected-row"' : '';
    return `
      <tr${selected} data-acl-id="${esc(row.__DashboardAclId)}" tabindex="0">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td><button type="button" class="link-button" data-open-acl="${esc(row.__DashboardAclId)}">${esc(row.NormalizedRight || 'Unknown')}</button></td>
        <td class="wrap">${esc(row.TrusteeName || '-')}<br><small class="sub">${esc(row.TrusteeSid || row.TrusteeDistinguishedName || '')}</small></td>
        <td class="wrap">${esc(row.TargetName || '-')}<br><small class="sub">${esc(row.TargetCanonicalName || row.TargetDistinguishedName || row.TargetObjectSid || '')}</small></td>
        <td>${row.AccessControlType === 'Owner' ? 'Owner' : row.IsInherited ? 'Inherited' : 'Direct'}</td>
        <td class="wrap">${tags || '<span class="sub">No tags</span>'}</td>
        <td class="wrap"><small>${esc(row.Reason || '')}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="8" class="sub">No ACL findings match the current filters.</td></tr>';

  const openAcl = aclId => {
    selectedAclId = aclId || '';
    renderAclTable();
    renderProfile();
    document.getElementById('acl-profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  tbody.querySelectorAll('tr[data-acl-id]').forEach(rowEl => {
    rowEl.addEventListener('click', () => openAcl(rowEl.dataset.aclId));
    rowEl.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openAcl(rowEl.dataset.aclId);
      }
    });
  });
}

function renderProfile() {
  const row = (aclState.aclFindings || []).find(item => item.__DashboardAclId === selectedAclId);
  const title = document.getElementById('acl-profile-title');
  const subtitle = document.getElementById('acl-profile-subtitle');
  const score = document.getElementById('acl-profile-score');
  const body = document.getElementById('acl-profile-body');

  if (!row) {
    title.textContent = 'ACL finding';
    subtitle.textContent = 'Select a row from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No ACL finding selected.';
    return;
  }

  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const rights = (row.ActiveDirectoryRights || []).map(right => `<span class="uac-pill">${esc(right)}</span>`).join(' ');
  const effectiveTrustees = (row.EffectiveTrusteesSample || []).map(item => {
    const label = [item.Name, item.ObjectClass, item.NestingDepth != null ? `depth ${item.NestingDepth}` : ''].filter(Boolean).join(' / ');
    return `<span class="uac-pill" title="${esc(item.Path || item.DistinguishedName || item.Sid || '')}">${esc(label)}</span>`;
  }).join(' ');
  const effectiveTrusteeText = row.EffectiveTrusteeCount
    ? `${Number(row.EffectiveTrusteeCount || 0)}${row.EffectiveTrusteesTruncated ? ' (sample shown)' : ''}`
    : '-';

  title.textContent = `${row.TrusteeName || 'Trustee'} -> ${row.NormalizedRight || 'ACL'} -> ${row.TargetName || 'target'}`;
  const scopeLabel = row.AccessControlType === 'Owner'
    ? 'Object owner'
    : row.IsInherited ? 'Inherited ACE' : 'Direct ACE';
  subtitle.textContent = [row.Domain, row.AclFindingId, scopeLabel].filter(Boolean).join(' / ');
  score.innerHTML = `
    <span class="profile-score-label">Risk</span>
    <strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong>
    <span class="profile-severity">${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>Trustee</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.TrusteeName || '-')}</dd>
        <dt>Class</dt><dd>${esc(row.TrusteeObjectClass || '-')}</dd>
        <dt>SID</dt><dd>${esc(row.TrusteeSid || '-')}</dd>
        <dt>DN</dt><dd>${esc(row.TrusteeDistinguishedName || '-')}</dd>
        <dt>Raw</dt><dd>${esc(row.RawTrustee || row.TrusteeName || '-')}</dd>
        <dt>Owner</dt><dd>${esc(row.OwnerName || (row.AccessControlType === 'Owner' ? row.TrusteeName : '') || '-')}</dd>
        <dt>Status</dt><dd>${row.UnresolvedTrustee ? '<span class="badge badge-high">Unresolved</span>' : '<span class="badge badge-low">Resolved/Named</span>'}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Target</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.TargetName || '-')}</dd>
        <dt>Class</dt><dd>${esc(row.TargetObjectClass || '-')}</dd>
        <dt>SID</dt><dd>${esc(row.TargetObjectSid || '-')}</dd>
        <dt>Canonical</dt><dd>${esc(row.TargetCanonicalName || '-')}</dd>
        <dt>DN</dt><dd>${esc(row.TargetDistinguishedName || '-')}</dd>
      </dl>
    </div>
    <div class="profile-block profile-wide">
      <strong>Evidence</strong>
      <dl class="profile-list acl-profile-list">
        <dt>Right</dt><dd>${esc(row.NormalizedRight || '-')}</dd>
        <dt>Evidence</dt><dd>${esc(row.EvidenceType || 'SensitiveAcl')}</dd>
        <dt>Drift</dt><dd>${esc(row.DriftState || 'Not compared')}</dd>
        <dt>Raw rights</dt><dd>${rights || '<span class="sub">No raw rights recorded</span>'}</dd>
        <dt>Effective trustees</dt><dd>${esc(effectiveTrusteeText)}</dd>
        <dt>Effective sample</dt><dd>${effectiveTrustees || '<span class="sub">No expanded effective trustees recorded</span>'}</dd>
        <dt>Object type</dt><dd>${esc(row.ObjectTypeName || row.ObjectType || '-')}</dd>
        <dt>Inherited object</dt><dd>${esc(row.InheritedObjectTypeName || row.InheritedObjectType || '-')}</dd>
        <dt>Inheritance</dt><dd>${esc(row.InheritanceType || (row.IsInherited ? 'Inherited' : 'Direct'))}</dd>
        <dt>Flags</dt><dd>${esc([row.ObjectFlags, row.InheritanceFlags, row.PropagationFlags].filter(Boolean).join(' / ') || '-')}</dd>
        <dt>Source descriptor</dt><dd>${esc(row.SourceDescriptorId || '-')}</dd>
        <dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd>
        <dt>Reason</dt><dd>${esc(row.Reason || '-')}</dd>
        <dt>Remediation</dt><dd>${esc(row.Remediation || 'Review and reduce the delegation to the least privilege required.')}</dd>
      </dl>
    </div>`;
}

function renderAll() {
  renderKpis();
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(aclState.meta, (aclState.aclFindings || []).length);
  }
  renderFilters();
  updateSortHeaders();
  renderAclTable();
  renderProfile();
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'acl-file',
  hintId: 'acl-hint',
  onData: raw => {
    aclState = normalizeAclState(raw);
    selectedAclId = '';
    renderAll();
  }
});

['acl-search', 'acl-right', 'acl-severity', 'acl-tag', 'acl-drift', 'acl-inherited'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderAclTable();
    renderProfile();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderAclTable();
    renderProfile();
  });
});

(function setupAclClearFilters() {
  const clearBtn = document.getElementById('acl-clear');
  if (!clearBtn) return;

  const filterIds = ['acl-search', 'acl-right', 'acl-severity', 'acl-tag', 'acl-drift', 'acl-inherited'];
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
    selectedAclId = '';
    updateClearBtn();
    renderAclTable();
    renderProfile();
  });
})();

document.querySelectorAll('#acl-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (aclSortColumn === column) {
      aclSortDirection = aclSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      aclSortColumn = column;
      aclSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    renderAclTable();
  });
});

loadAclData().then(ok => {
  if (ok && (aclState.aclFindings || []).length) {
    document.getElementById('acl-hint').style.display = 'none';
  } else if (ok) {
    document.getElementById('acl-hint').textContent = 'No ACL findings loaded. Run an audit with -IncludeAclPosture or load a dashboard JSON that contains aclFindings.';
  }
  selectedAclId = '';
  renderAll();
});
