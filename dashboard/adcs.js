const ADCS_DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let adcsState = { meta: {}, adcsTemplates: [], adcsCas: [], adcsNtAuth: null, adcsFindings: [] };
let adcsSortColumn = 'RiskScore';
let adcsSortDirection = 'desc';
let selectedAdcsId = '';

const ADCS_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

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

function truncate(value, max = 150) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function normalizeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizeAdcsState(raw) {
  const payload = raw || {};
  const seen = new Map();
  const adcsFindings = (payload.adcsFindings || payload.AdcsFindings || []).map((row, index) => {
    const base = row.AdcsFindingId || [
      row.Domain,
      row.FindingType,
      row.TemplateDistinguishedName || row.TemplateShortName || row.TemplateName,
      row.Principal,
      index
    ].filter(Boolean).join('|');
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    return {
      ...row,
      ExtendedKeyUsage: normalizeArray(row.ExtendedKeyUsage),
      Tags: normalizeArray(row.Tags),
      PublishedCas: normalizeArray(row.PublishedCas),
      PublishedCaNames: normalizeArray(row.PublishedCaNames),
      AttackPath: normalizeArray(row.AttackPath),
      ScoreComponents: normalizeArray(row.ScoreComponents),
      __DashboardAdcsId: count ? `${base}#${count + 1}` : base
    };
  });

  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    adcsTemplates: payload.adcsTemplates || payload.AdcsTemplates || [],
    adcsCas: payload.adcsCas || payload.AdcsCas || [],
    adcsNtAuth: payload.adcsNtAuth || payload.AdcsNtAuth || null,
    adcsFindings
  };
}

async function loadAdcsData() {
  const payload = await window.ADPostureDashboard.loadAuditData(ADCS_DATA_URLS);
  if (payload) {
    adcsState = normalizeAdcsState(payload);
    return true;
  }

  document.getElementById('adcs-hint').textContent =
    'No embedded data found. Run Invoke-ADPostureAudit -IncludeAdcsPosture, then Open-ADPostureDashboard -View AdcsPosture, or load a *-dashboard.json file.';
  return false;
}

function adcsSearchBlob(row) {
  return [
    row.AdcsFindingId, row.Domain, row.FindingType, row.RiskPattern, row.Severity,
    row.EscTechnique,
    row.TemplateName, row.TemplateShortName, row.TemplateDistinguishedName,
    row.CaName, row.CaDistinguishedName, row.TargetObjectName, row.TargetDistinguishedName,
    (row.PublishedCaNames || []).join(' '),
    (row.AttackPath || []).join(' '),
    row.TemplateSchemaVersion, row.Principal, row.EnrolleeSuppliesSubject,
    row.ManagerApprovalRequired, row.RequiredRaSignatures, row.ExportablePrivateKey,
    (row.ExtendedKeyUsage || []).join(' '), row.Reason, row.Remediation,
    row.ScoreFormula, (row.Tags || []).join(' ')
  ].join(' ').toLowerCase();
}

function filteredAdcsFindings() {
  const q = (document.getElementById('adcs-search').value || '').toLowerCase();
  const type = document.getElementById('adcs-type').value;
  const pattern = document.getElementById('adcs-pattern').value;
  const severity = document.getElementById('adcs-severity').value;
  const tag = document.getElementById('adcs-tag').value;
  const principal = document.getElementById('adcs-principal').value;

  return (adcsState.adcsFindings || []).filter(row => {
    if (type && row.FindingType !== type) return false;
    if (pattern && row.RiskPattern !== pattern) return false;
    if (severity && row.Severity !== severity) return false;
    if (tag && !(row.Tags || []).includes(tag)) return false;
    if (principal && row.Principal !== principal) return false;
    if (q && !adcsSearchBlob(row).includes(q)) return false;
    return true;
  });
}

function getSortValue(row, column) {
  if (column === 'RiskScore') return Number(row.RiskScore || 0);
  if (column === 'Severity') return ADCS_SEVERITY_ORDER[row.Severity] || 0;
  return String(row[column] || '').toLowerCase();
}

function compareAdcs(a, b) {
  const aValue = getSortValue(a, adcsSortColumn);
  const bValue = getSortValue(b, adcsSortColumn);
  let cmp = 0;
  if (typeof aValue === 'number' && typeof bValue === 'number') {
    cmp = aValue - bValue;
  } else {
    cmp = String(aValue).localeCompare(String(bValue), 'en', { numeric: true });
  }
  return adcsSortDirection === 'asc' ? cmp : -cmp;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#adcs-table th.sortable', adcsSortColumn, adcsSortDirection);
}

function renderKpis() {
  const rows = adcsState.adcsFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const esc1 = rows.filter(row => row.FindingType === 'AdcsEsc1LikeTemplate' || row.RiskPattern === 'ESC1-like').length;
  const agent = rows.filter(row => row.FindingType === 'AdcsEnrollmentAgentBroadEnrollment').length;
  const exportable = rows.filter(row => row.FindingType === 'AdcsExportableAuthPrivateKey' || row.ExportablePrivateKey).length;
  const control = rows.filter(row => ['AdcsTemplateControlDelegation', 'AdcsCaObjectControlDelegation', 'AdcsNtAuthControlDelegation'].includes(row.FindingType)).length;
  const templates = (adcsState.adcsTemplates || []).length ||
    new Set(rows.map(row => row.TemplateDistinguishedName || row.TemplateShortName || row.TemplateName).filter(Boolean)).size;
  const cas = (adcsState.adcsCas || []).length ||
    new Set(rows.flatMap(row => row.PublishedCaNames || []).concat(rows.map(row => row.CaName)).filter(Boolean)).size;

  document.getElementById('adcs-count').textContent = rows.length;
  document.getElementById('adcs-critical').textContent = criticalHigh;
  document.getElementById('adcs-esc1').textContent = esc1;
  document.getElementById('adcs-agent').textContent = agent;
  document.getElementById('adcs-exportable').textContent = exportable;
  document.getElementById('adcs-control').textContent = control;
  document.getElementById('adcs-templates').textContent = templates;
  document.getElementById('adcs-cas').textContent = cas;
}

function publishedTargetText(row) {
  const caNames = normalizeArray(row.PublishedCaNames).filter(Boolean);
  if (caNames.length) return caNames.join(', ');
  if (row.CaName) return row.CaName;
  if (row.TargetObjectName && row.TargetObjectName !== row.TemplateName) return row.TargetObjectName;
  return 'Not published / unknown';
}

function renderFilters() {
  const rows = adcsState.adcsFindings || [];
  const setOptions = (id, values, label) => {
    const el = document.getElementById(id);
    el.innerHTML = `<option value="">${label}</option>` +
      values.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  };

  setOptions('adcs-type', [...new Set(rows.map(row => row.FindingType).filter(Boolean))].sort(), 'All finding types');
  setOptions('adcs-pattern', [...new Set(rows.map(row => row.RiskPattern).filter(Boolean))].sort(), 'All risk patterns');
  setOptions('adcs-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('adcs-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
  setOptions('adcs-principal', [...new Set(rows.map(row => row.Principal).filter(Boolean))].sort(), 'All principals');
}

function issuanceGateText(row) {
  const gates = [];
  gates.push(row.ManagerApprovalRequired ? 'Manager approval' : 'No manager approval');
  gates.push(Number(row.RequiredRaSignatures || 0) > 0 ? `${row.RequiredRaSignatures} RA signature(s)` : 'No RA signature');
  if (row.EnrolleeSuppliesSubject) gates.push('Subject/SAN supplied');
  if (row.ExportablePrivateKey) gates.push('Exportable key');
  return gates.join(' / ');
}

function renderAdcsTable() {
  const rows = filteredAdcsFindings().sort(compareAdcs);
  const tbody = document.querySelector('#adcs-table tbody');
  if (rows.length && !rows.some(row => row.__DashboardAdcsId === selectedAdcsId)) {
    selectedAdcsId = rows[0].__DashboardAdcsId || '';
  }
  if (!rows.length) selectedAdcsId = '';

  document.getElementById('adcs-summary').textContent = `${rows.length} visible / ${(adcsState.adcsFindings || []).length} total`;
  tbody.innerHTML = rows.length ? rows.map(row => {
    const tags = (row.Tags || []).slice(0, 5).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
    const selected = row.__DashboardAdcsId === selectedAdcsId ? ' class="selected-row"' : '';
    return `
      <tr${selected} data-adcs-id="${esc(row.__DashboardAdcsId)}" tabindex="0">
        <td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td>
        <td>${severityBadge(row.Severity)}</td>
        <td><button type="button" class="link-button" data-open-adcs="${esc(row.__DashboardAdcsId)}">${esc(row.FindingType || 'Unknown')}</button><br><small class="sub">${esc([row.EscTechnique, row.RiskPattern].filter(Boolean).join(' / '))}</small></td>
        <td class="wrap">${esc(row.TemplateName || row.TargetObjectName || '-')}<br><small class="sub">${esc(row.TemplateShortName || row.TemplateDistinguishedName || row.TargetDistinguishedName || '')}</small></td>
        <td class="wrap"><small>${esc(publishedTargetText(row))}</small></td>
        <td class="wrap">${esc(row.Principal || '-')}</td>
        <td class="wrap"><small>${esc(issuanceGateText(row))}</small></td>
        <td class="wrap">${tags || '<span class="sub">No tags</span>'}</td>
        <td class="wrap"><small title="${esc(row.Reason || '')}">${esc(truncate(row.Reason || '', 170))}</small></td>
      </tr>`;
  }).join('') : '<tr><td colspan="9" class="sub">No ADCS findings match the current filters.</td></tr>';

  const openAdcs = adcsId => {
    selectedAdcsId = adcsId || '';
    renderAdcsTable();
    renderProfile();
    document.getElementById('adcs-profile').scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  tbody.querySelectorAll('tr[data-adcs-id]').forEach(rowEl => {
    rowEl.addEventListener('click', () => openAdcs(rowEl.dataset.adcsId));
    rowEl.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openAdcs(rowEl.dataset.adcsId);
      }
    });
  });
}

function renderProfile() {
  const row = (adcsState.adcsFindings || []).find(item => item.__DashboardAdcsId === selectedAdcsId);
  const title = document.getElementById('adcs-profile-title');
  const subtitle = document.getElementById('adcs-profile-subtitle');
  const score = document.getElementById('adcs-profile-score');
  const body = document.getElementById('adcs-profile-body');

  if (!row) {
    title.textContent = 'ADCS finding';
    subtitle.textContent = 'Select a row from the queue.';
    score.textContent = '-';
    body.className = 'empty-state';
    body.textContent = 'No ADCS finding selected.';
    return;
  }

  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const eku = (row.ExtendedKeyUsage || []).map(value => `<span class="uac-pill">${esc(value)}</span>`).join(' ');
  const attackPath = (row.AttackPath || []).map(step => `<li>${esc(step)}</li>`).join('');
  const components = (row.ScoreComponents || []).map(component => `
    <tr>
      <td>${esc(component.Name || '-')}</td>
      <td>${esc(component.Value || '-')}</td>
      <td>${esc(component.Weight ?? '-')}</td>
    </tr>`).join('');

  title.textContent = `${row.FindingType || 'ADCS finding'} on ${row.TemplateName || row.CaName || row.TargetObjectName || row.TemplateShortName || 'PKI object'}`;
  subtitle.textContent = [row.Domain, row.AdcsFindingId, row.RiskPattern].filter(Boolean).join(' / ');
  score.innerHTML = `
    <span class="profile-score-label">Risk</span>
    <strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong>
    <span class="profile-severity">${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `
    <div class="profile-block">
      <strong>Template</strong>
      <dl class="profile-list">
        <dt>Name</dt><dd>${esc(row.TemplateName || '-')}</dd>
        <dt>Short name</dt><dd>${esc(row.TemplateShortName || '-')}</dd>
        <dt>Schema</dt><dd>${esc(row.TemplateSchemaVersion ?? '-')}</dd>
        <dt>DN</dt><dd>${esc(row.TemplateDistinguishedName || '-')}</dd>
        <dt>Published CA</dt><dd>${esc(publishedTargetText(row))}</dd>
        <dt>EKU</dt><dd>${eku || '<span class="sub">No EKU recorded</span>'}</dd>
      </dl>
    </div>
    <div class="profile-block">
      <strong>Issuance</strong>
      <dl class="profile-list">
        <dt>Principal</dt><dd>${esc(row.Principal || '-')}</dd>
        <dt>Subject/SAN</dt><dd>${row.EnrolleeSuppliesSubject ? '<span class="badge badge-high">Requester supplied</span>' : '<span class="badge badge-low">Template controlled</span>'}</dd>
        <dt>Approval</dt><dd>${row.ManagerApprovalRequired ? '<span class="badge badge-low">Required</span>' : '<span class="badge badge-high">Not required</span>'}</dd>
        <dt>RA signatures</dt><dd>${esc(row.RequiredRaSignatures ?? 0)}</dd>
        <dt>Private key</dt><dd>${row.ExportablePrivateKey ? '<span class="badge badge-med">Exportable</span>' : '<span class="badge badge-low">Not exportable</span>'}</dd>
        <dt>Target object</dt><dd>${esc(row.TargetObjectName || row.CaName || row.TemplateName || '-')}</dd>
        <dt>Target DN</dt><dd>${esc(row.TargetDistinguishedName || row.CaDistinguishedName || row.TemplateDistinguishedName || '-')}</dd>
      </dl>
    </div>
    <div class="profile-block profile-wide">
      <strong>Evidence</strong>
      <dl class="profile-list adcs-profile-list">
        <dt>Finding</dt><dd>${esc(row.FindingType || '-')}</dd>
        <dt>ESC</dt><dd>${esc(row.EscTechnique || '-')}</dd>
        <dt>Pattern</dt><dd>${esc(row.RiskPattern || '-')}</dd>
        <dt>Score formula</dt><dd>${esc(row.ScoreFormula || '-')}</dd>
        <dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd>
        <dt>Reason</dt><dd>${esc(row.Reason || '-')}</dd>
        <dt>Remediation</dt><dd>${esc(row.Remediation || 'Review the certificate template and reduce enrollment/control exposure.')}</dd>
      </dl>
      ${attackPath ? `<strong>Attack path</strong><ol class="profile-list adcs-attack-path">${attackPath}</ol>` : ''}
      ${components ? `
        <div class="table-scroll compact-table-scroll">
          <table class="compact-table">
            <thead><tr><th>Component</th><th>Value</th><th>Weight</th></tr></thead>
            <tbody>${components}</tbody>
          </table>
        </div>` : ''}
    </div>`;
}

function renderAll() {
  renderKpis();
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(adcsState.meta, (adcsState.adcsFindings || []).length);
  }
  renderFilters();
  updateSortHeaders();
  renderAdcsTable();
  renderProfile();
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'adcs-file',
  hintId: 'adcs-hint',
  onData: raw => {
    adcsState = normalizeAdcsState(raw);
    selectedAdcsId = '';
    renderAll();
  }
});

['adcs-search', 'adcs-type', 'adcs-pattern', 'adcs-severity', 'adcs-tag', 'adcs-principal'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderAdcsTable();
    renderProfile();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderAdcsTable();
    renderProfile();
  });
});

(function setupAdcsClearFilters() {
  const clearBtn = document.getElementById('adcs-clear');
  if (!clearBtn) return;

  const filterIds = ['adcs-search', 'adcs-type', 'adcs-pattern', 'adcs-severity', 'adcs-tag', 'adcs-principal'];
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
    selectedAdcsId = '';
    updateClearBtn();
    renderAdcsTable();
    renderProfile();
  });
})();

document.querySelectorAll('#adcs-table th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const column = th.dataset.sort;
    if (adcsSortColumn === column) {
      adcsSortDirection = adcsSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      adcsSortColumn = column;
      adcsSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc';
    }
    updateSortHeaders();
    renderAdcsTable();
  });
});

loadAdcsData().then(ok => {
  if (ok && (adcsState.adcsFindings || []).length) {
    document.getElementById('adcs-hint').style.display = 'none';
  } else if (ok) {
    const templateCount = (adcsState.adcsTemplates || []).length;
    const caCount = (adcsState.adcsCas || []).length;
    document.getElementById('adcs-hint').textContent = templateCount
      ? `No ADCS risk findings loaded. ${templateCount} certificate templates and ${caCount} enrollment services were collected.`
      : 'No ADCS findings loaded. Run an audit with -IncludeAdcsPosture or load a dashboard JSON that contains adcsFindings.';
  }
  selectedAdcsId = '';
  renderAll();
});
