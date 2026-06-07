let dnsState = { meta: {}, dnsFindings: [], dnsZones: [], dnsRecords: [] };
let dnsSortColumn = 'RiskScore';
let dnsSortDirection = 'desc';
let selectedDnsId = '';
const DNS_SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

function esc(value) { return window.ADPostureDashboard.esc(value); }
function scoreClass(value) { return window.ADPostureDashboard.scoreClass(value); }
function severityBadge(severity) { const cls = severity === 'Critical' || severity === 'High' ? 'badge-high' : severity === 'Medium' ? 'badge-med' : 'badge-low'; return `<span class="badge ${cls}">${esc(severity || 'Informational')}</span>`; }

function normalizeDnsState(raw) {
  const payload = raw || {};
  const findings = payload.dnsFindings || payload.DnsFindings || [];
  const seen = new Map();
  return {
    meta: window.ADPostureDashboard.normalizeMetadata(payload),
    dnsZones: payload.dnsZones || payload.DnsZones || [],
    dnsRecords: payload.dnsRecords || payload.DnsRecords || [],
    dnsFindings: findings.map((row, index) => {
      const base = row.DnsFindingId || row.dnsFindingId || `dns-${String(index + 1).padStart(6, '0')}`;
      const count = seen.get(base) || 0; seen.set(base, count + 1);
      return { ...row, DnsFindingId: base, ScoreComponents: row.ScoreComponents || row.scoreComponents || [], AttackTechniques: row.AttackTechniques || row.attackTechniques || [], Tags: row.Tags || row.tags || [], __DashboardDnsId: count ? `${base}#${count + 1}` : base };
    })
  };
}

async function loadDnsData() {
  const payload = await window.ADPostureDashboard.loadAuditData(['latest-dashboard.json', '../reports/latest-dashboard.json']);
  if (payload) { dnsState = normalizeDnsState(payload); return true; }
  document.getElementById('dns-hint').textContent = 'No embedded data found. Run Invoke-ADPostureAudit -IncludeDnsPosture, then Open-ADPostureDashboard -View DnsPosture.';
  return false;
}

function dnsSearchBlob(row) { return [row.DnsFindingId, row.Domain, row.FindingType, row.RiskPattern, row.Severity, row.ZoneName, row.RecordName, row.RecordType, row.RecordData, row.ParsedRecordType, row.ParsedRecordData, row.RecordParseStatus, row.Principal, row.DistinguishedName, row.Reason, row.Remediation, (row.Tags || []).join(' ')].join(' ').toLowerCase(); }
function filteredDnsFindings() {
  const q = (document.getElementById('dns-search').value || '').toLowerCase();
  const type = document.getElementById('dns-type').value;
  const severity = document.getElementById('dns-severity').value;
  const tag = document.getElementById('dns-tag').value;
  return (dnsState.dnsFindings || []).filter(row => (!type || row.FindingType === type) && (!severity || row.Severity === severity) && (!tag || (row.Tags || []).includes(tag)) && (!q || dnsSearchBlob(row).includes(q)));
}
function getSortValue(row, column) { if (column === 'RiskScore') return Number(row.RiskScore || 0); if (column === 'Severity') return DNS_SEVERITY_ORDER[row.Severity] || 0; return String(row[column] || '').toLowerCase(); }
function sortedDnsRows() { return filteredDnsFindings().sort((a, b) => { const av = getSortValue(a, dnsSortColumn); const bv = getSortValue(b, dnsSortColumn); if (av === bv) return 0; const result = av > bv ? 1 : -1; return dnsSortDirection === 'asc' ? result : -result; }); }
function setOptions(id, values, placeholder) { const el = document.getElementById(id); const current = el.value; el.innerHTML = `<option value="">${esc(placeholder)}</option>` + values.map(v => `<option>${esc(v)}</option>`).join(''); if (values.includes(current)) el.value = current; }

function renderKpis() {
  const rows = dnsState.dnsFindings || [];
  const criticalHigh = rows.filter(row => row.Severity === 'Critical' || row.Severity === 'High').length;
  const control = rows.filter(row => ['DnsZoneInsecureDynamicUpdate', 'DnsAclControlDelegation', 'DnsAdminsExposure'].includes(row.FindingType)).length;
  const hygiene = rows.filter(row => ['DnsWildcardRecord', 'DnsDanglingRecordCandidate', 'DnsStaleRecord', 'DnsZoneNoAgingScavenging'].includes(row.FindingType)).length;
  document.getElementById('dns-count').textContent = rows.length;
  document.getElementById('dns-critical').textContent = criticalHigh;
  document.getElementById('dns-control').textContent = control;
  document.getElementById('dns-hygiene').textContent = hygiene;
  document.getElementById('dns-zones').textContent = (dnsState.dnsZones || []).length;
  document.getElementById('dns-records').textContent = (dnsState.dnsRecords || []).length;
  document.getElementById('dns-summary').textContent = `${filteredDnsFindings().length} visible / ${criticalHigh} critical or high / ${control} control gaps`;
  setOptions('dns-type', [...new Set(rows.map(row => row.FindingType).filter(Boolean))].sort(), 'All finding types');
  setOptions('dns-severity', ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'All severities');
  setOptions('dns-tag', [...new Set(rows.flatMap(row => row.Tags || []))].sort(), 'All tags');
}

function renderDnsTable() {
  const tbody = document.querySelector('#dns-table tbody');
  const rows = sortedDnsRows();
  tbody.innerHTML = rows.length ? rows.map(row => `<tr${row.__DashboardDnsId === selectedDnsId ? ' class="selected-row"' : ''} data-dns-id="${esc(row.__DashboardDnsId)}" tabindex="0"><td class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</td><td>${severityBadge(row.Severity)}</td><td><button type="button" class="link-button">${esc(row.FindingType || 'Unknown')}</button><br><small class="sub">${esc(row.RiskPattern || '')}</small></td><td class="wrap">${esc(row.ZoneName || '-')}</td><td class="wrap">${esc(row.RecordName || '-')}<br><small class="sub">${esc(row.RecordData || '')}</small></td><td class="wrap">${esc(row.Principal || '-')}</td><td class="wrap"><small>${esc(row.Reason || '-')}</small></td></tr>`).join('') : '<tr><td colspan="7" class="sub">No DNS findings match the current filters.</td></tr>';
}

function renderProfile() {
  const row = (dnsState.dnsFindings || []).find(item => item.__DashboardDnsId === selectedDnsId);
  const title = document.getElementById('dns-profile-title'); const subtitle = document.getElementById('dns-profile-subtitle'); const score = document.getElementById('dns-profile-score'); const body = document.getElementById('dns-profile-body');
  if (!row) { title.textContent = 'DNS finding'; subtitle.textContent = 'Select a row from the queue.'; score.textContent = '-'; body.className = 'empty-state'; body.textContent = 'No DNS finding selected.'; return; }
  const tags = (row.Tags || []).map(tag => `<span class="uac-pill">${esc(tag)}</span>`).join(' ');
  const techniques = (row.AttackTechniques || []).map(value => `<span class="uac-pill">${esc([value.Id, value.Name].filter(Boolean).join(' - '))}</span>`).join(' ');
  title.textContent = `${row.FindingType || 'DNS finding'} ${row.ZoneName ? `in ${row.ZoneName}` : ''}`;
  subtitle.textContent = [row.Domain, row.DnsFindingId, row.RiskPattern].filter(Boolean).join(' / ');
  score.innerHTML = `<span class="profile-score-label">Risk</span><strong class="${scoreClass(row.RiskScore)}">${Number(row.RiskScore || 0).toFixed(2)}</strong><span class="profile-severity">${esc(row.Severity || '')}</span>`;
  body.className = 'object-profile-grid';
  body.innerHTML = `<div class="profile-block"><strong>DNS object</strong><dl class="profile-list"><dt>Zone</dt><dd>${esc(row.ZoneName || '-')}</dd><dt>Record</dt><dd>${esc(row.RecordName || '-')}</dd><dt>Type</dt><dd>${esc(row.RecordType || '-')}</dd><dt>Data</dt><dd>${esc(row.RecordData || '-')}</dd><dt>Parsed type</dt><dd>${esc(row.ParsedRecordType || '-')}</dd><dt>Parsed data</dt><dd>${esc(row.ParsedRecordData || '-')}</dd><dt>Parse status</dt><dd>${esc(row.RecordParseStatus || '-')}</dd><dt>Principal</dt><dd>${esc(row.Principal || '-')}</dd><dt>DN</dt><dd>${esc(row.DistinguishedName || '-')}</dd></dl></div><div class="profile-block profile-wide"><strong>Evidence</strong><dl class="profile-list"><dt>Reason</dt><dd>${esc(row.Reason || '-')}</dd><dt>Remediation</dt><dd>${esc(row.Remediation || '-')}</dd><dt>Score formula</dt><dd>${esc(row.ScoreFormula || '-')}</dd><dt>ATT&CK</dt><dd>${techniques || '<span class="sub">No ATT&CK mapping recorded</span>'}</dd><dt>Tags</dt><dd>${tags || '<span class="sub">No tags</span>'}</dd></dl></div>`;
}

function updateSortHeaders() { window.ADPostureDashboard.updateSortHeaders('#dns-table th.sortable', dnsSortColumn, dnsSortDirection); }
function renderAll() { renderKpis(); updateSortHeaders(); renderDnsTable(); renderProfile(); if (typeof window.updateSidebar === 'function') window.updateSidebar(dnsState.meta, (dnsState.dnsFindings || []).length); }
document.querySelector('#dns-table tbody')?.addEventListener('click', event => { const row = event.target.closest('tr[data-dns-id]'); if (!row) return; selectedDnsId = row.dataset.dnsId; renderDnsTable(); renderProfile(); });
['dns-search', 'dns-type', 'dns-severity', 'dns-tag'].forEach(id => { document.getElementById(id)?.addEventListener('input', renderAll); document.getElementById(id)?.addEventListener('change', renderAll); });
document.getElementById('dns-clear')?.addEventListener('click', () => { ['dns-search', 'dns-type', 'dns-severity', 'dns-tag'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; }); renderAll(); });
document.querySelectorAll('#dns-table th.sortable').forEach(th => { th.addEventListener('click', () => { const column = th.dataset.sort; if (dnsSortColumn === column) dnsSortDirection = dnsSortDirection === 'asc' ? 'desc' : 'asc'; else { dnsSortColumn = column; dnsSortDirection = ['RiskScore', 'Severity'].includes(column) ? 'desc' : 'asc'; } renderAll(); }); });
window.ADPostureDashboard.setupJsonImport({ inputId: 'dns-file-input', hintId: 'dns-hint', onData: raw => { dnsState = normalizeDnsState(raw); renderAll(); } });
loadDnsData().then(ok => { if (ok) { const hint = document.getElementById('dns-hint'); if ((dnsState.dnsFindings || []).length) hint.style.display = 'none'; else hint.textContent = 'No DNS risk findings loaded. Run an audit with -IncludeDnsPosture.'; } renderAll(); if (window.ADPostureTableTools) window.ADPostureTableTools.enhanceAll(); });
