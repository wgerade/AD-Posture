const OBJECT_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let objectState = { meta: {}, findings: [], objects: [], objectEvidence: [], objectRelationships: [], summary: {}, filterOptions: {} };
let objectSortColumn = 'RiskScore';
let objectSortDirection = 'desc';
let selectedObjectId = '';
let objectPage = 1;
const objectPageSize = 100;

const SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

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

function tierBadge(tier) {
  const value = tier || 'Unknown';
  const classes = { 'Tier 0': 'badge-tier0', 'Tier 1': 'badge-tier1', 'Tier 2': 'badge-tier2' };
  return `<span class="badge ${classes[value] || 'badge-excluded'}">${esc(value)}</span>`;
}

function getObjectName(row) {
  return row.DisplayName || row.SamAccountName || row.Name || row.ObjectId || 'Unknown object';
}

function getObjectEvidenceIds(row) {
  return Array.isArray(row.EvidenceIds) ? row.EvidenceIds : [];
}

function normalizeObjectState(raw) {
  const payload = raw || {};
  const findings = (payload.findings || payload.Findings || []).filter(isActionableFinding);
  const objects = (payload.objects || payload.Objects || []).filter(isActionableObject);
  const objectEvidence = payload.objectEvidence || payload.ObjectEvidence || [];
  const objectRelationships = payload.objectRelationships || payload.ObjectRelationships || [];

  const normalized = {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    findings,
    objects,
    objectEvidence,
    objectRelationships
  };

  if (!normalized.objects.length && findings.length) {
    return buildObjectStateFromFindings(normalized);
  }

  return normalized;
}

function isActionableFinding(finding) {
  if (!finding) return false;
  if (finding.IsExcluded || finding.isExcluded || finding.IsNativeIdentity || finding.IsRemediableIdentity === false) return false;
  if (isNativeArchitectureIdentity(finding.MemberSam || finding.MemberDisplay, finding.ObjectSid)) return false;
  return Number(finding.RiskScore || 0) > 0;
}

function isActionableObject(row) {
  if (!row) return false;
  if (row.IsExcluded || row.isExcluded || row.IsNativeIdentity || row.IsRemediableIdentity === false) return false;
  if (row.ObjectClass === 'sensitiveGroup' || row.AccountType === 'SensitiveGroup') return false;
  if (isNativeArchitectureIdentity(row.SamAccountName || row.DisplayName, row.ObjectSid)) return false;
  return Number(row.RiskScore || 0) > 0;
}

function isNativeArchitectureIdentity(name, sid) {
  const sidText = String(sid || '');
  if (/^S-1-5-32-/i.test(sidText)) return true;
  if (/^S-1-5-21-.+-(500|501|502|512|513|514|515|516|517|518|519|520|521|522|525|526|527|548|549|550|551|553|571|572)$/i.test(sidText)) return true;

  const text = String(name || '').trim();
  if (/^(administrator|guest|krbtgt)$/i.test(text)) return true;
  return /\b(domain admins|enterprise admins|schema admins|domain users|domain guests|domain computers|domain controllers|read-only domain controllers|cloneable domain controllers|group policy creator owners|cert publishers|key admins|enterprise key admins|protected users|account operators|server operators|print operators|backup operators)\b/i.test(text);
}

function buildObjectStateFromFindings(base) {
  const objectMap = new Map();
  const evidence = [];
  const relationships = [];

  (base.findings || []).filter(isActionableFinding).forEach((finding, index) => {
    const objectId = finding.ObjectSid || finding.MemberDn || finding.MemberSam || `finding-${index}`;
    const groupId = `sensitive-group:${finding.SensitiveGroup || 'unknown'}`;
    if (!objectMap.has(objectId)) {
      objectMap.set(objectId, {
        ObjectId: objectId,
        Domain: finding.Domain || base.meta.domain || '',
        ObjectClass: objectClassFromType(finding.AccountType),
        SamAccountName: finding.MemberSam || '',
        DisplayName: finding.MemberDisplay || finding.MemberSam || objectId,
        DistinguishedName: finding.MemberDn || '',
        ObjectSid: finding.ObjectSid || '',
        AccountType: finding.AccountType || 'Unknown',
        PrivilegeTier: finding.PrivilegeTier || 'Unknown',
        RiskScore: 0,
        Severity: 'Informational',
        Tags: tagsFromFinding(finding),
        EvidenceIds: [],
        RelationshipCount: 0,
        HighestEvidenceScore: 0,
        TopReason: finding.TechnicalRisk || finding.MembershipChain || '',
        RemediationDifficulty: finding.RemediationDifficulty || '',
        CleanupActions: finding.CleanupActions || ''
      });
    }

    const object = objectMap.get(objectId);
    const score = Number(finding.RiskScore || 0);
    const evidenceId = `fallback-ev-${String(index + 1).padStart(6, '0')}`;
    object.RiskScore = Number((object.RiskScore + score).toFixed(2));
    object.HighestEvidenceScore = Math.max(Number(object.HighestEvidenceScore || 0), score);
    object.EvidenceIds.push(evidenceId);
    object.RelationshipCount += 1;
    object.Severity = severityFromScore(object.RiskScore);
    object.Tags = [...new Set(object.Tags.concat(tagsFromFinding(finding)))].sort();

    evidence.push({
      EvidenceId: evidenceId,
      ObjectId: objectId,
      EvidenceType: 'SensitiveGroupMembership',
      SourceDomain: 'SensitiveGroups',
      Score: score,
      Severity: severityFromScore(score),
      Reason: finding.TechnicalRisk || `Sensitive group membership: ${finding.SensitiveGroup || 'Unknown'}`,
      Remediation: finding.CleanupActions || '',
      RelatedObjectId: groupId,
      RelatedObjectName: finding.SensitiveGroup || 'Unknown',
      PrivilegeTier: finding.PrivilegeTier || '',
      IsDirect: finding.IsDirect,
      NestingDepth: finding.NestingDepth,
      Path: finding.MembershipChain || '',
      ScoreComponents: finding.ScoreComponents || [],
      AttackTechniques: finding.AttackTechniques || []
    });

    relationships.push({
      FromObjectId: objectId,
      ToObjectId: groupId,
      RelationshipType: 'SensitiveGroupMembership',
      RelationshipName: finding.SensitiveGroup || 'Unknown',
      IsDirect: finding.IsDirect,
      NestingDepth: finding.NestingDepth,
      Path: finding.MembershipChain || '',
      EvidenceId: evidenceId
    });
  });

  return {
    ...base,
    objects: [...objectMap.values()].sort((a, b) => Number(b.RiskScore || 0) - Number(a.RiskScore || 0)),
    objectEvidence: evidence,
    objectRelationships: relationships
  };
}

function objectClassFromType(type) {
  const value = String(type || '').toLowerCase();
  if (value.startsWith('group')) return 'group';
  if (value.startsWith('computer')) return 'computer';
  if (value.startsWith('serviceaccount')) return 'serviceAccount';
  if (value) return 'user';
  return 'unknown';
}

function tagsFromFinding(finding) {
  const tags = [];
  if (finding.PrivilegeTier === 'Tier 0') tags.push('Tier0Exposure');
  if (finding.SensitiveGroup) tags.push('PrivilegedMembership');
  if (Number(finding.NestingDepth || 0) > 0 || finding.IsDirect === false) tags.push('IndirectPrivilege');
  if (finding.IsStale) tags.push('StaleIdentity');
  if (finding.PasswordNeverExpires) tags.push('PasswordNeverExpires');
  if (String(finding.AccountType || '').startsWith('ServiceAccount')) tags.push('ServiceAccount');
  if (String(finding.AccountType || '').startsWith('Group')) tags.push('NestedGroup');
  if (String(finding.AccountType || '').startsWith('Computer')) tags.push('ComputerIdentity');
  if (finding.IsDisabled) tags.push('DisabledIdentity');
  if (String(finding.UacActiveFlagNames || finding.UserAccountControlSummary || '').match(/DONT_REQ_PREAUTH|Pre-Auth/i)) tags.push('NoPreAuth');
  if (String(finding.UacActiveFlagNames || finding.UserAccountControlSummary || '').match(/TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION|Delegation/i)) tags.push('DelegationRisk');
  if (String(finding.UacActiveFlagNames || finding.UserAccountControlSummary || '').match(/USE_DES_KEY_ONLY|DES/i)) tags.push('WeakKerberos');
  return [...new Set(tags)].sort();
}

function severityFromScore(score) {
  const value = Number(score || 0);
  if (value >= 15) return 'Critical';
  if (value >= 5) return 'High';
  if (value > 0.5) return 'Medium';
  if (value > 0) return 'Low';
  return 'Informational';
}

async function loadObjectData() {
  const payload = await window.ADPostureDashboard.loadAuditData(OBJECT_DATA_URLS);
  if (payload) {
    objectState = normalizeObjectState(payload);
    return true;
  }

  document.getElementById('objects-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit, then Open-ADPostureDashboard -View ObjectRisk, or load a *-dashboard.json file.';
  return false;
}

function objectSearchBlob(row) {
  return [
    row.ObjectId, row.Domain, row.ObjectClass, row.SamAccountName, row.DisplayName,
    row.DistinguishedName, row.ObjectSid, row.AccountType, row.PrivilegeTier,
    row.Severity, row.TopReason, row.CleanupActions, (row.Tags || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredObjects() {
  const q = (document.getElementById('object-search').value || '').toLowerCase();
  const type = document.getElementById('object-type').value;
  const severity = document.getElementById('object-severity').value;
  const tier = document.getElementById('object-tier').value;
  const tag = document.getElementById('object-tag').value;

  return (objectState.objects || []).filter(row => {
    if (type && row.ObjectClass !== type && row.AccountType !== type) return false;
    if (severity && row.Severity !== severity) return false;
    if (tier && row.PrivilegeTier !== tier) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (q && !objectSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'EvidenceCount') return getObjectEvidenceIds(row).length;
  if (column === 'RelationshipCount') return Number(row.RelationshipCount || 0);
  if (column === 'Severity') return SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function compareObjects(a, b) {
  const aValue = getSortValue(a, objectSortColumn);
  const bValue = getSortValue(b, objectSortColumn);
  let cmp = 0;
  if (typeof aValue === 'number' && typeof bValue === 'number') {
    cmp = aValue - bValue;
  } else {
    cmp = String(aValue).localeCompare(String(bValue), 'en', { numeric: true });
  }
  return objectSortDirection === 'asc' ? cmp : -cmp;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#objects-table th.sortable', objectSortColumn, objectSortDirection);
}

function renderKpis() {
  const objects = objectState.objects || [];
  const evidence = objectState.objectEvidence || [];
  const relationships = objectState.objectRelationships || [];
  const criticalHigh = objects.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const tier0 = objects.filter(row => row.PrivilegeTier === 'Tier 0' || (row.Tags || []).includes('Tier0Exposure')).length;
  const highest = Math.max(0, ...objects.map(row => Number(row.RiskScore || 0)));

  document.getElementById('obj-count').textContent = objects.length;
  document.getElementById('obj-critical').textContent = criticalHigh;
  document.getElementById('obj-tier0').textContent = tier0;
  document.getElementById('obj-evidence').textContent = evidence.length;
  document.getElementById('obj-relationships').textContent = relationships.length;
  const highestEl = document.getElementById('obj-highest');
  highestEl.textContent = highest.toFixed(2);
  highestEl.className = `value ${scoreClass(highest)}`;
}

function renderFilters() {
  const objects = objectState.objects || [];
  const setOptions = (id, values, label) => {
    const el = document.getElementById(id);
    el.innerHTML = `<option value="">${label}</option>` +
      values.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  };

  const preserve = id => document.getElementById(id)?.value || '';
  const current = { type: preserve('object-type'), severity: preserve('object-severity'), tier: preserve('object-tier'), tag: preserve('object-tag') };
  setOptions('object-type', [...new Set(objects.map(row => row.ObjectClass || row.AccountType || 'Unknown'))].sort(), 'All object types');
  setOptions('object-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('object-tier', [...new Set(objects.map(row => row.PrivilegeTier).filter(Boolean))].sort(), 'All tiers');
  setOptions('object-tag', [...new Set(objects.flatMap(row => row.Tags || []))].sort(), 'All tags');
  document.getElementById('object-type').value = current.type;
  document.getElementById('object-severity').value = current.severity;
  document.getElementById('object-tier').value = current.tier;
  document.getElementById('object-tag').value = current.tag;
}

function renderObjectsTable() {
  const filtered = filteredObjects().sort(compareObjects);
  const totalPages = Math.max(1, Math.ceil(filtered.length / objectPageSize));
  objectPage = Math.min(Math.max(1, objectPage), totalPages);
  const start = (objectPage - 1) * objectPageSize;
  const rows = filtered.slice(start, start + objectPageSize);
  const tbody = document.querySelector('#objects-table tbody');
  if (rows.length && !rows.some(row => row.ObjectId === selectedObjectId)) {
    selectedObjectId = rows[0].ObjectId || '';
  }
  if (!rows.length) {
    selectedObjectId = '';
  }
  document.getElementById('object-summary').textContent =
    `${rows.length} on page / ${filtered.length} filtered / ${(objectState.objects || []).length} total`;
  tbody.innerHTML = rows.length ? rows.map(row => {
    const name = getObjectName(row);
    const tags = (row.Tags || []).slice(0, 6).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
    const selected = row.ObjectId === selectedObjectId ? ' class="selected-row"' : '';
    return `
      <tr${selected} data-object-id="${esc(row.ObjectId)}">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td class="wrap"><button type="button" class="link-button" data-open-object="${esc(row.ObjectId)}">${esc(name)}</button><br><small class="sub">${esc(row.SamAccountName || row.ObjectSid || row.ObjectId)}</small></td>
        <td>${esc(row.ObjectClass || row.AccountType || 'Unknown')}</td>
        <td>${tierBadge(row.PrivilegeTier)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td>${getObjectEvidenceIds(row).length}</td>
        <td>${esc(row.RelationshipCount || 0)}</td>
        <td class="wrap">${tags || '<span class="sub">No tags</span>'}</td>
        <td class="wrap"><small>${esc(row.TopReason || row.CleanupActions || '')}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="9" class="sub">No objects match the current filters.</td></tr>';

  tbody.querySelectorAll('[data-open-object]').forEach(button => {
    button.addEventListener('click', event => {
      event.stopPropagation();
      selectedObjectId = button.dataset.openObject || '';
      renderObjectsTable();
      renderProfile();
      document.getElementById('object-profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
  tbody.querySelectorAll('tr[data-object-id]').forEach(row => {
    row.addEventListener('click', () => {
      selectedObjectId = row.dataset.objectId || '';
      renderObjectsTable();
      renderProfile();
      document.getElementById('object-profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
  renderObjectPagination();
}

function renderObjectPagination() {
  const totalPages = Math.max(1, Math.ceil(filteredObjects().length / objectPageSize));
  const pagination = document.getElementById('object-pagination');
  if (pagination) pagination.style.display = totalPages > 1 ? '' : 'none';
  const status = document.getElementById('object-page-status');
  if (status) status.textContent = `Page ${objectPage} of ${totalPages}`;
  const prev = document.getElementById('object-prev');
  const next = document.getElementById('object-next');
  if (prev) prev.disabled = objectPage <= 1;
  if (next) next.disabled = objectPage >= totalPages;
}

function relatedEvidence(objectId) {
  const direct = (objectState.objectEvidence || []).filter(row => row.ObjectId === objectId);
  if (direct.length) return direct;
  const object = (objectState.objects || []).find(row => row.ObjectId === objectId);
  const ids = new Set(getObjectEvidenceIds(object || {}));
  return (objectState.objectEvidence || []).filter(row => ids.has(row.EvidenceId));
}

function relatedRelationships(objectId, evidenceRows) {
  const evidenceIds = new Set((evidenceRows || []).map(row => row.EvidenceId));
  return (objectState.objectRelationships || []).filter(row =>
    row.FromObjectId === objectId || row.ToObjectId === objectId || evidenceIds.has(row.EvidenceId)
  );
}

function renderScoreComponents(components) {
  if (!components) return '';
  const rows = Array.isArray(components) ? components : Object.entries(components).map(([Name, Value]) => ({ Name, Value }));
  if (!rows.length) return '';
  return `<ul class="detail-list">${rows.map(item => {
    const name = item.Name || item.name || 'Factor';
    const value = item.Value ?? item.value ?? '';
    const reason = item.Reason || item.reason || '';
    return `<li><strong>${esc(name)}</strong>: ${esc(value)} <span class="sub">${esc(reason)}</span></li>`;
  }).join('')}</ul>`;
}

async function renderProfile() {
  const object = (objectState.objects || []).find(row => row.ObjectId === selectedObjectId);
  const title = document.getElementById('profile-title');
  const subtitle = document.getElementById('profile-subtitle');
  const score = document.getElementById('profile-score');
  const body = document.getElementById('profile-body');

  if (!object) {
    title.textContent = 'Object profile';
    subtitle.textContent = 'Select an object from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No object selected.';
    return;
  }

  let evidenceRows = relatedEvidence(object.ObjectId);
  let relationshipRows = relatedRelationships(object.ObjectId, evidenceRows);
  const tags = (object.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');

  title.textContent = getObjectName(object);
  subtitle.textContent = [object.ObjectClass || object.AccountType, object.Domain, object.ObjectSid || object.DistinguishedName]
    .filter(Boolean)
    .join(' / ');
  score.innerHTML = `
    <span class="profile-score-label">Risk</span>
    <strong class="${scoreClass(object.RiskScore)}">${Number(object.RiskScore || 0).toFixed(2)}</strong>
    <span class="profile-severity">${esc(object.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>Identity</strong>
      <dl class="profile-list">
        <dt>Account</dt><dd>${esc(object.SamAccountName || '-')}</dd>
        <dt>Tier</dt><dd>${tierBadge(object.PrivilegeTier)}</dd>
        <dt>DN</dt><dd>${esc(object.DistinguishedName || '-')}</dd>
        <dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Remediation focus</strong>
      <p class="sub">${esc(object.TopReason || 'No reason recorded.')}</p>
      <p class="sub">${esc(object.CleanupActions || 'Review the related evidence and define owner-approved action.')}</p>
    </div>
    <div class="profile-block profile-wide">
      <strong>Evidence</strong>
      <div class="table-scroll profile-table-scroll">
        <table class="profile-table">
          <thead><tr><th>Score</th><th>Type</th><th>Related object</th><th>Path</th><th>Reason</th></tr></thead>
          <tbody>${renderEvidenceRows(evidenceRows)}</tbody>
        </table>
      </div>
    </div>
    <div class="profile-block profile-wide">
      <strong>Relationships</strong>
      <div class="relationship-list-scroll">
        <div class="relationship-list">${renderRelationshipRows(relationshipRows)}</div>
      </div>
    </div>`;
}

function renderEvidenceRows(rows) {
  if (!rows.length) return '<tr><td colspan="5" class="sub">No evidence rows available for this object.</td></tr>';
  return rows.map(row => `
    <tr>
      <td class="${scoreClass(row.Score)}">${Number(row.Score || 0).toFixed(2)}</td>
      <td>${severityBadge(row.Severity)}<br><small class="sub">${esc(row.EvidenceType || '')}</small></td>
      <td class="wrap">${esc(row.RelatedObjectName || row.RelatedObjectId || '-')}</td>
      <td class="chain">${esc(row.Path || '-')}</td>
      <td class="wrap"><small>${esc(row.Reason || '')}</small>${renderScoreComponents(row.ScoreComponents)}</td>
    </tr>`).join('');
}

function renderRelationshipRows(rows) {
  if (!rows.length) return '<div class="empty-state">No relationship rows available.</div>';
  return rows.map(row => `
    <div class="relationship-item">
      <strong>${esc(row.RelationshipType || 'Relationship')}</strong>
      <span>${esc(row.RelationshipName || row.ToObjectId || '')}</span>
      <small class="chain">${esc(row.Path || `${row.FromObjectId || ''} -> ${row.ToObjectId || ''}`)}</small>
    </div>`).join('');
}

function renderAll() {
  renderKpis();
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(objectState.meta, (objectState.objects || []).length);
  }
  renderFilters();
  updateSortHeaders();
  renderObjectsTable();
  renderProfile();
}

function setObjectHint(message, visible = true) {
  const hint = document.getElementById('objects-hint');
  if (!hint) return;
  hint.textContent = message;
  hint.style.display = visible ? '' : 'none';
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'objects-file',
  hintId: 'objects-hint',
  onData: raw => {
    objectState = normalizeObjectState(raw);
    selectedObjectId = '';
    renderAll();
  }
});

['object-search', 'object-type', 'object-severity', 'object-tier', 'object-tag'].forEach(id => {
  const refresh = window.ADPostureDashboard.debounce(() => {
    objectPage = 1;
    renderObjectsTable();
    renderProfile();
  }, 150);
  document.getElementById(id)?.addEventListener('input', refresh);
  document.getElementById(id)?.addEventListener('change', () => {
    objectPage = 1;
    renderObjectsTable();
    renderProfile();
  });
});

document.querySelectorAll('#objects-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (objectSortColumn === column) {
      objectSortDirection = objectSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      objectSortColumn = column;
      objectSortDirection = ['RiskScore', 'EvidenceCount', 'RelationshipCount', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    objectPage = 1;
    renderObjectsTable();
  });
});

document.getElementById('object-prev')?.addEventListener('click', () => {
  if (objectPage <= 1) return;
  objectPage -= 1;
  renderObjectsTable();
  renderProfile();
});
document.getElementById('object-next')?.addEventListener('click', () => {
  objectPage += 1;
  renderObjectsTable();
  renderProfile();
});

loadObjectData().then(ok => {
  if (ok) {
    if ((objectState.objects || []).length) {
      setObjectHint('', false);
    } else {
      const evidenceCount = (objectState.objectEvidence || []).length;
      const relationshipCount = (objectState.objectRelationships || []).length;
      if (evidenceCount || relationshipCount || (objectState.findings || []).length) {
        setObjectHint('Dashboard data loaded, but no actionable objects remain after excluding native/default AD architecture rows.');
      } else {
        setObjectHint('Dashboard data loaded, but no object-risk findings are present. Run an audit that produces actionable findings or load a dashboard JSON with object data.');
      }
    }
  }
  selectedObjectId = (objectState.objects || [])[0]?.ObjectId || '';
  renderAll();
}).catch(error => {
  setObjectHint(`Could not load object dashboard data: ${error?.message || error}`);
});
