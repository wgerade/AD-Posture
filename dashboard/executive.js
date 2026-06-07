function normalizeState(raw) {
  if (!raw) return null;
  const sourceMeta = raw.meta || {};
  const meta = window.ADPostureDashboard.normalizeMetadata(raw);
  const findingCollections = [
    raw.findings || raw.Findings || [],
    raw.aclFindings || raw.AclFindings || [],
    raw.gpoFindings || raw.GpoFindings || [],
    raw.adcsFindings || raw.AdcsFindings || [],
    raw.kerberosAuthFindings || raw.KerberosAuthFindings || [],
    raw.trustFindings || raw.TrustFindings || [],
    raw.dnsFindings || raw.DnsFindings || [],
    raw.identityRiskFindings || raw.IdentityRiskFindings || []
  ];
  return {
    meta: {
      ...meta,
      readiness: window.ADPostureDashboard.normalizeReadiness(meta.readiness),
      remediation: sourceMeta.remediation || raw.RemediationBreakdown || {},
      tierBreakdown: sourceMeta.tierBreakdown || raw.TierBreakdown || {}
    },
    groups: raw.groups || raw.GroupSummaries || [],
    findings: (raw.findings || raw.Findings || []).filter(f => !(f.IsExcluded || f.isExcluded)),
    allFindings: findingCollections.flat().filter(f => !(f.IsExcluded || f.isExcluded)),
    postureSummary: (raw.postureSummary || raw.PostureSummary || buildFallbackPostureSummary(raw)).filter(row => (row.PostureDomain || row.postureDomain) !== 'OS & DC Hardening')
  };
}

function esc(s) {
  return window.ADPostureDashboard.esc(s);
}

function scoreClass(score) {
  return window.ADPostureDashboard.scoreClass(score);
}

function buildFallbackPostureSummary(raw) {
  const domains = [
    ['Sensitive Groups', 'findings', 'Findings', true],
    ['Identity Risk', 'identityRiskFindings', 'IdentityRiskFindings', true],
    ['ACL', 'aclFindings', 'AclFindings'],
    ['GPO', 'gpoFindings', 'GpoFindings'],
    ['ADCS', 'adcsFindings', 'AdcsFindings'],
    ['Kerberos', 'kerberosAuthFindings', 'KerberosAuthFindings'],
    ['Trust', 'trustFindings', 'TrustFindings'],
    ['DNS', 'dnsFindings', 'DnsFindings']
  ];
  return domains.map(([domain, camel, pascal, alwaysCollected]) => {
    const rows = raw[camel] || raw[pascal] || [];
    const active = rows.filter(row => !(row.IsExcluded || row.isExcluded) && Number(row.RiskScore || row.riskScore || 0) > 0);
    return {
      PostureDomain: domain,
      CollectionStatus: alwaysCollected || Object.prototype.hasOwnProperty.call(raw, camel) || Object.prototype.hasOwnProperty.call(raw, pascal) ? 'Collected' : 'NotRequested',
      FindingCount: rows.length,
      ActiveFindingCount: active.length,
      CriticalHighCount: active.filter(row => ['Critical', 'High'].includes(row.Severity || row.severity) || Number(row.RiskScore || row.riskScore || 0) >= 10).length,
      RiskScore: active.reduce((sum, row) => sum + Number(row.RiskScore || row.riskScore || 0), 0)
    };
  });
}

function renderPostureSummary(rows) {
  const body = document.getElementById('exec-posture-body');
  body.innerHTML = (rows || []).map(row => {
    const status = row.CollectionStatus || row.collectionStatus || 'NotRequested';
    const score = Number(row.RiskScore ?? row.riskScore ?? 0);
    return `<tr>
      <td>${esc(row.PostureDomain || row.postureDomain || '-')}</td>
      <td>${statusBadge(status === 'Collected' ? 'Pass' : 'Review')} ${esc(status)}</td>
      <td>${esc(row.ActiveFindingCount ?? row.activeFindingCount ?? row.FindingCount ?? row.findingCount ?? 0)}</td>
      <td>${esc(row.CriticalHighCount ?? row.criticalHighCount ?? 0)}</td>
      <td class="${scoreClass(score)}">${score.toFixed(2)}</td>
    </tr>`;
  }).join('');
  const collected = (rows || []).filter(row => (row.CollectionStatus || row.collectionStatus) === 'Collected').length;
  document.getElementById('exec-coverage-summary').textContent = `${collected} of ${(rows || []).length} posture domains collected in this audit.`;
}

function renderMitre(findings) {
  const techniques = new Map();
  (findings || []).forEach(finding => {
    (finding.AttackTechniques || finding.attackTechniques || []).forEach(item => {
      const id = typeof item === 'string' ? item : item.Id || item.id || item.TechniqueId || item.techniqueId || 'Mapped';
      const name = typeof item === 'string' ? item : item.Name || item.name || '';
      const key = `${id}|${name}`;
      techniques.set(key, { id, name, count: (techniques.get(key)?.count || 0) + 1 });
    });
  });
  const rows = [...techniques.values()].sort((a, b) => b.count - a.count || String(a.id).localeCompare(String(b.id))).slice(0, 10);
  document.getElementById('exec-mitre').innerHTML = rows.length
    ? rows.map((row, index) => `<div class="rank-item"><span class="rank-num">${index + 1}</span><div class="rank-main"><strong>${esc(row.id)}</strong><span>${esc(row.name || 'Existing finding mapping')}</span></div><span class="rank-score">${row.count}</span></div>`).join('')
    : '<div class="empty-state">No ATT&CK mappings are present in the loaded findings.</div>';
}

function readinessClass(score) {
  if (score >= 90) return 'score-0';
  if (score >= 70) return 'score-low';
  if (score >= 50) return 'score-mid';
  return 'score-high';
}

function statusBadge(status) {
  const cls = status === 'Pass' ? 'badge-low' : status === 'Review' ? 'badge-med' : 'badge-high';
  return `<span class="badge ${cls}">${esc(status || 'Review')}</span>`;
}

function renderReadiness(readiness) {
  const score = readiness?.Score;
  const el = document.getElementById('exec-readiness');
  el.textContent = score != null ? `${score}/100` : '-';
  el.className = 'value ' + readinessClass(score ?? 0);
  const controls = (readiness?.Controls || []).filter(c => c.Status !== 'Pass').slice(0, 6);
  document.getElementById('exec-readiness-controls').innerHTML = controls.length
    ? controls.map(c => `
      <div class="scorecard-item">
        <div class="scorecard-head"><strong>${esc(c.Name)}</strong>${statusBadge(c.Status)}</div>
        <div class="scorecard-count">${esc(c.Count ?? 0)} / target ${esc(c.Target ?? 0)}</div>
        <p class="sub">${esc(c.Detail || '')}</p>
      </div>`).join('')
    : '<div class="scorecard-item"><strong>All controls passing</strong><p class="sub">No failed readiness controls in this payload.</p></div>';
}

let execActionSort = { columnIndex: 3, direction: 'desc' };
let execActionRows = [];

function compareActionRows(a, b) {
  const keys = ['action', 'members', 'findings', 'score'];
  const key = keys[execActionSort.columnIndex] || 'score';
  const av = a[key];
  const bv = b[key];
  const cmp = typeof av === 'number' && typeof bv === 'number'
    ? av - bv
    : String(av).localeCompare(String(bv), 'en', { numeric: true });
  return execActionSort.direction === 'asc' ? cmp : -cmp;
}

function paintActionRows() {
  const rows = execActionRows.slice().sort(compareActionRows).slice(0, 5);
  document.getElementById('exec-actions').innerHTML = rows.length
    ? rows.map(r => `<tr><td class="wrap">${esc(r.action)}</td><td>${r.members}</td><td>${r.findings}</td><td class="${scoreClass(r.score)}">${r.score.toFixed(2)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="sub">No remediation actions found.</td></tr>';
  document.querySelectorAll('#exec-actions-table th.sortable').forEach((th, index) => {
    th.classList.remove('sorted-asc', 'sorted-desc');
    th.removeAttribute('aria-sort');
    if (index === execActionSort.columnIndex) {
      th.classList.add(execActionSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
      th.setAttribute('aria-sort', execActionSort.direction === 'asc' ? 'ascending' : 'descending');
    }
  });
}

function renderTopActions(findings) {
  const byAction = new Map();
  findings.forEach(f => {
    const action = String(f.CleanupActions || 'Review business justification').split(';')[0].trim();
    if (!byAction.has(action)) {
      byAction.set(action, { action, members: new Set(), findings: 0, score: 0 });
    }
    const row = byAction.get(action);
    row.members.add(f.ObjectSid || f.MemberSam || f.MemberDn || f.MemberDisplay || 'Unknown');
    row.findings += 1;
    row.score += Number(f.RiskScore || 0);
  });
  execActionRows = [...byAction.values()].map(r => ({ ...r, members: r.members.size }));
  paintActionRows();
}

function setupExecutiveSort() {
  document.querySelectorAll('#exec-actions-table th.sortable').forEach((th, index) => {
    th.addEventListener('click', () => {
      execActionSort = {
        columnIndex: index,
        direction: execActionSort.columnIndex === index && execActionSort.direction === 'asc' ? 'desc' : 'asc'
      };
      paintActionRows();
    });
  });
}

async function init() {
  const raw = await window.ADPostureDashboard.loadAuditData(['latest-dashboard.json', '../reports/latest-dashboard.json']);

  const hint = document.getElementById('exec-hint');
  const state = normalizeState(raw);
  if (!state || (!state.findings.length && !state.groups.length)) {
    hint.textContent = 'No data loaded. Run Invoke-ADPostureAudit, then Open-ADPostureDashboard -View Executive.';
    return;
  }
  hint.style.display = 'none';

  const m = state.meta || {};
  const score = m.overallRiskScore ?? 0;
  const progress = score <= 0 ? 100 : Math.max(0, Math.min(100, 100 - (Math.log10(score + 1) / 2) * 100));

  document.getElementById('exec-domain').textContent = m.domain || '-';
  document.getElementById('exec-score').textContent = score.toFixed(2);
  document.getElementById('exec-score').className = 'value ' + scoreClass(score);
  document.getElementById('exec-progress').style.width = progress + '%';
  const progressLabel = document.getElementById('exec-progress-label');
  if (progressLabel) {
    const pct = Math.round(progress);
    progressLabel.textContent = pct >= 100
      ? 'Target reached - score at 0'
      : `${pct}% toward target (current score: ${score.toFixed(2)})`;
  }
  document.getElementById('exec-actionable').textContent = m.actionableCount ?? 0;
  document.getElementById('exec-exceptions').textContent = `${m.approvedExceptionCount ?? 0} active / ${m.expiredExceptionCount ?? 0} expired`;
  renderReadiness(m.readiness);
  renderTopActions(state.findings || []);
  renderPostureSummary(state.postureSummary || []);
  renderMitre(state.allFindings || []);

  const r = m.remediation || {};
  document.getElementById('exec-low').textContent = r.Low ?? r.low ?? 0;
  document.getElementById('exec-med').textContent = r.Medium ?? r.medium ?? 0;
  document.getElementById('exec-high').textContent = r.High ?? r.high ?? 0;

  const topGroups = (state.groups || [])
    .sort((a, b) => (b.AggregateRiskScore || 0) - (a.AggregateRiskScore || 0))
    .slice(0, 5);

  document.getElementById('exec-top-groups').innerHTML = topGroups.map((g, index) => `
    <div class="rank-item">
      <span class="rank-num">${index + 1}</span>
      <div class="rank-main">
        <strong>${esc(g.SensitiveGroup)}</strong>
        <span>${g.MemberCount} members</span>
      </div>
      <span class="rank-score">${(g.AggregateRiskScore || 0).toFixed(2)}</span>
    </div>`).join('');

  const critical = (state.allFindings || []).filter(f => ['Critical', 'High'].includes(f.Severity) || Number(f.RiskScore || 0) >= 10).length;
  document.getElementById('exec-critical').textContent = critical;
  const tierBreakdown = m.tierBreakdown || {};
  const tier0 = tierBreakdown['Tier 0'] ?? tierBreakdown.Tier0 ?? 0;

  let status = 'Controlled';
  let msg = 'Privileged access posture within acceptable parameters.';
  if (score >= 15) { status = 'Critical Exposure'; msg = 'Elevated cumulative exposure - prioritize Tier 0 reduction.'; }
  else if (score >= 5 || tier0 > 0) { status = 'Elevated Risk'; msg = 'Moderate cumulative exposure - a time-bound remediation plan is recommended.'; }

  document.getElementById('exec-status').textContent = status;
  document.getElementById('exec-message').textContent = msg;

  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(m, null);
  }

  const ringFill = document.getElementById('score-ring-fill');
  const ringNum = document.getElementById('ring-num');
  const progressFill = document.getElementById('score-progress-fill');
  const progressPct = document.getElementById('score-progress-pct');
  const ringColor = score > 15 ? 'var(--danger)' : score > 5 ? 'var(--warn)' : 'var(--ok)';
  const ringOffset = (188.5 * (1 - Math.min(1, score / 100))).toFixed(2);
  if (ringFill) {
    ringFill.style.strokeDashoffset = ringOffset;
    ringFill.style.stroke = ringColor;
  }
  if (ringNum) {
    ringNum.textContent = score.toFixed(1);
    ringNum.style.color = ringColor;
  }
  if (progressFill) progressFill.style.width = progress + '%';
  if (progressPct) progressPct.textContent = Math.round(progress) + '% toward zero';
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'exec-file',
  hintId: 'exec-hint',
  onData: raw => {
    window.__AD_AUDIT_DATA__ = raw;
    init();
  }
});

document.getElementById('exec-print')?.addEventListener('click', () => window.print());

setupExecutiveSort();
init();
