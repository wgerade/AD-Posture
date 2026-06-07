const DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

let state = { meta: {}, groups: [], findings: [], monitoring: [], exceptions: [], objects: [], objectEvidence: [], objectRelationships: [], remediationPlaybooks: [] };
let sortColumn = 'RiskScore';
let sortDirection = 'desc';
let genericSortState = {};
let currentScript = '';
let currentScriptFileName = 'ad-remediation-script.txt';
const scopeStorageKey = `adaudit_action_scope_${location.pathname.split('/').pop() || 'index.html'}`;
let activeScope = (() => {
  try {
    return sessionStorage.getItem(scopeStorageKey) || 'remediable';
  } catch (_) {
    return 'remediable';
  }
})();
let showDashboardPanel = null;

const DIFFICULTY_ORDER = { Low: 1, Medium: 2, High: 3 };
const TIER_COLORS = { 'Tier 0': '#ef4444', 'Tier 1': '#f59e0b', 'Tier 2': '#3b82f6' };
const DIFFICULTY_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#ef4444' };
const TYPE_COLORS = { User: '#60a5fa', ServiceAccount: '#a78bfa', Computer: '#34d399', Group: '#f472b6', Unknown: '#94a3b8' };

function normalizeState(raw) {
  if (!raw) return { meta: {}, groups: [], findings: [] };
  const sourceMeta = raw.meta || {};
  const meta = window.ADPostureDashboard.normalizeMetadata(raw);
  const remediation = sourceMeta.remediation || raw.RemediationBreakdown || {};
  return {
    meta: {
      ...meta,
      readiness: window.ADPostureDashboard.normalizeReadiness(meta.readiness),
      remediation,
      tierBreakdown: sourceMeta.tierBreakdown || raw.TierBreakdown || {}
    },
    groups: raw.groups || raw.GroupSummaries || [],
    findings: (raw.findings || raw.Findings || []).filter(f => !(f.IsExcluded || f.isExcluded)),
    monitoring: raw.monitoring || raw.Monitoring || [],
    exceptions: raw.exceptions || raw.ApprovedExceptions || [],
    objects: raw.objects || raw.Objects || [],
    objectEvidence: raw.objectEvidence || raw.ObjectEvidence || [],
    objectRelationships: raw.objectRelationships || raw.ObjectRelationships || [],
    remediationPlaybooks: raw.remediationPlaybooks || raw.RemediationPlaybooks || []
  };
}

async function loadData() {
  const payload = await window.ADPostureDashboard.loadAuditData(DATA_URLS);
  if (payload) {
    state = normalizeState(payload);
    return true;
  }

  const hint = document.getElementById('load-hint');
  if (hint) {
    hint.textContent = window.ADPostureDashboard?.noDataMessage?.() ||
      'No audit report loaded. Import a dashboard JSON file or run Open-ADPostureDashboard after the audit finishes.';
    hint.classList.add('error');
  }
  return false;
}

function scoreClass(v) {
  return window.ADPostureDashboard.scoreClass(v);
}

function readinessClass(score) {
  if (score >= 90) return 'score-0';
  if (score >= 70) return 'score-low';
  if (score >= 50) return 'score-mid';
  return 'score-high';
}

function difficultyBadge(d) {
  const m = { Low: 'badge-low', Medium: 'badge-med', High: 'badge-high' };
  return `<span class="badge ${m[d] || 'badge-med'}">${d}</span>`;
}

function statusBadge(status) {
  const cls = status === 'Pass' ? 'badge-low' : status === 'Review' ? 'badge-med' : 'badge-high';
  return `<span class="badge ${cls}">${esc(status || 'Review')}</span>`;
}

function tierBadge(tier) {
  const t = tier || 'Tier 2';
  const m = { 'Tier 0': 'badge-tier0', 'Tier 1': 'badge-tier1', 'Tier 2': 'badge-tier2' };
  return `<span class="badge ${m[t] || 'badge-tier2'}">${esc(t)}</span>`;
}

function countBy(rows, getKey) {
  return rows.reduce((acc, row) => {
    const key = getKey(row) || 'Unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function renderLegend(el, entries, colors) {
  el.innerHTML = entries.map(([label, value]) => `
    <div class="legend-item">
      <span class="swatch" style="background:${colors[label] || '#64748b'}"></span>
      <span>${esc(label)}</span>
      <strong>${value}</strong>
    </div>`).join('');
}

function renderBarList(el, entries, colors, maxValue) {
  const max = maxValue || Math.max(1, ...entries.map(([, value]) => value));
  el.innerHTML = entries.map(([label, value]) => {
    const width = Math.max(3, Math.round((value / max) * 100));
    return `
      <div class="bar-row">
        <div class="bar-label"><span>${esc(label)}</span><strong>${value}</strong></div>
        <div class="bar-track"><span style="width:${width}%;background:${colors[label] || '#3b82f6'}"></span></div>
      </div>`;
  }).join('');
}

function renderInsights() {
  const findings = filteredFindings();
  const tierCounts = countBy(findings, f => f.PrivilegeTier || 'Tier 2');
  const tierEntries = ['Tier 0', 'Tier 1', 'Tier 2'].map(t => [t, tierCounts[t] || 0]);
  const total = Math.max(1, tierEntries.reduce((sum, [, value]) => sum + value, 0));
  const t0 = tierEntries[0][1];
  const t1 = tierEntries[1][1];
  const t0Deg = Math.round((t0 / total) * 360);
  const t1Deg = Math.round(((t0 + t1) / total) * 360);
  document.getElementById('tier-donut').style.background =
    `conic-gradient(${TIER_COLORS['Tier 0']} 0 ${t0Deg}deg, ${TIER_COLORS['Tier 1']} ${t0Deg}deg ${t1Deg}deg, ${TIER_COLORS['Tier 2']} ${t1Deg}deg 360deg)`;
  renderLegend(document.getElementById('tier-legend'), tierEntries, TIER_COLORS);

  const difficultyCounts = countBy(findings, f => f.RemediationDifficulty || 'Medium');
  renderBarList(
    document.getElementById('difficulty-chart'),
    ['High', 'Medium', 'Low'].map(d => [d, difficultyCounts[d] || 0]),
    DIFFICULTY_COLORS
  );

  const typeCounts = countBy(findings, f => (f.AccountType || 'Unknown').split(' ')[0]);
  const typeEntries = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]);
  renderBarList(document.getElementById('account-type-chart'), typeEntries, TYPE_COLORS);

  const topGroups = (state.groups || [])
    .slice()
    .sort((a, b) => (b.AggregateRiskScore || 0) - (a.AggregateRiskScore || 0))
    .slice(0, 6)
    .map(g => [g.SensitiveGroup || 'Unknown', Number(g.AggregateRiskScore || 0)]);
  renderBarList(document.getElementById('top-groups-chart'), topGroups, {});

  const maxScore = Math.max(0, ...findings.map(f => f.RiskScore || 0));
  document.getElementById('insight-summary').textContent =
    `${findings.length} visible findings / ${t0} Tier 0 / max score ${maxScore.toFixed(2)}`;
}

function esc(s) {
  return window.ADPostureDashboard.esc(s);
}

function highlightPS(rawText) {
  const cmdlets = 'Remove-ADGroupMember|Get-ADUser|Get-ADGroup|Set-ADUser|Disable-ADAccount|Enable-ADAccount|Add-ADGroupMember|Get-ADServiceAccount|Get-ADComputer|New-ADPostureRemediationScript';
  const keywords = 'param|if|else|elseif|foreach|function|return|try|catch|throw|switch|begin|process|end|finally|break|continue';
  const tokenPattern = new RegExp(`"[^"]*"|'[^']*'|\\$[A-Za-z_]\\w*|\\b(?:${cmdlets})\\b|\\b(?:${keywords})\\b|\\s-\\w+`, 'g');

  function highlightCode(code) {
    return code.replace(tokenPattern, token => {
      if (token.startsWith('"') || token.startsWith("'")) {
        return `<span class="ps-string">${esc(token)}</span>`;
      }
      if (token.startsWith('$')) {
        return `<span class="ps-var">${esc(token)}</span>`;
      }
      if (/^\s-/.test(token)) {
        return `${token[0]}<span class="ps-flag">${esc(token.slice(1))}</span>`;
      }
      if (new RegExp(`^(?:${cmdlets})$`).test(token)) {
        return `<span class="ps-cmdlet">${esc(token)}</span>`;
      }
      return `<span class="ps-keyword">${esc(token)}</span>`;
    });
  }

  return String(rawText || '').split('\n').map(line => {
    const commentIndex = line.indexOf('#');
    if (commentIndex === -1) return highlightCode(line);
    const code = line.slice(0, commentIndex);
    const comment = line.slice(commentIndex);
    return `${highlightCode(code)}<span class="ps-comment">${esc(comment)}</span>`;
  }).join('\n');
}

function getSortValue(f, key) {
  switch (key) {
    case 'RiskScore':
      return f.RiskScore ?? 0;
    case 'RemediationDifficulty':
      return DIFFICULTY_ORDER[f.RemediationDifficulty] ?? 99;
    case 'PrivilegeTier':
      return f.PrivilegeTier || 'Tier 2';
    case 'LastLogonDays':
      return f.LastLogonDays ?? f.DaysSinceLogon ?? (f.LastLogonDisplay === 'N/A' ? -1 : 99999);
    case 'PasswordLastSetDays':
      return f.PasswordLastSetDays ?? (f.PasswordLastSetDisplay === 'N/A' ? -1 : 99999);
    case 'WhenCreatedDays':
      return f.WhenCreatedDays ?? (f.WhenCreatedDisplay === 'N/A' ? -1 : 99999);
    case 'PasswordNeverExpires':
      return f.PasswordNeverExpires ? 1 : 0;
    case 'UserAccountControlSummary':
      return (f.UserAccountControlSummary || f.UserAccountControlFlags || '').toString().toLowerCase();
    case 'UserAccountControl':
      return f.UserAccountControl ?? -1;
    case 'AccountStatus':
      return f.AccountStatus || (f.IsDisabled ? 'Disabled' : 'Active');
    case 'NativeIdentityCategory':
      return f.NativeIdentityCategory || (f.IsNativeIdentity ? 'Native AD identity' : 'Custom');
    case 'WhyThisMatters':
      return whyThisMatters(f).toLowerCase();
    case 'TechnicalRisk':
      return (f.TechnicalRisk || '').toString().toLowerCase();
    default:
      return (f[key] ?? '').toString().toLowerCase();
  }
}

function compareFindings(a, b) {
  const va = getSortValue(a, sortColumn);
  const vb = getSortValue(b, sortColumn);
  let cmp = 0;
  if (typeof va === 'number' && typeof vb === 'number') {
    cmp = va - vb;
  } else {
    cmp = String(va).localeCompare(String(vb), 'en', { numeric: true });
  }
  return sortDirection === 'asc' ? cmp : -cmp;
}

function updateSortHeaders() {
  window.ADPostureDashboard.updateSortHeaders('#findings-table th.sortable', sortColumn, sortDirection);
}

function setupSortHandlers() {
  document.querySelectorAll('#findings-table th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortColumn === col) {
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
      } else {
        sortColumn = col;
        const numericCols = ['RiskScore', 'LastLogonDays', 'PasswordLastSetDays', 'WhenCreatedDays',
          'PasswordNeverExpires', 'UserAccountControlSummary', 'RemediationDifficulty'];
        sortDirection = numericCols.includes(col) ? 'desc' : 'asc';
      }
      updateSortHeaders();
      renderFindings();
    });
  });
}

function getCellSortValue(cell) {
  const text = (cell.textContent || '').trim();
  const numeric = Number(text.replace(/,/g, '').match(/-?\d+(\.\d+)?/)?.[0]);
  return Number.isFinite(numeric) && /^[-\d\s.,/]+$/.test(text) ? numeric : text.toLowerCase();
}

function compareCellValues(a, b, direction) {
  let cmp = 0;
  if (typeof a === 'number' && typeof b === 'number') {
    cmp = a - b;
  } else {
    cmp = String(a).localeCompare(String(b), 'en', { numeric: true });
  }
  return direction === 'asc' ? cmp : -cmp;
}

function sortGenericTable(tableId, columnIndex, direction) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.tBodies[0];
  if (!tbody) return;
  const rows = Array.from(tbody.rows);
  rows.sort((a, b) => compareCellValues(
    getCellSortValue(a.cells[columnIndex]),
    getCellSortValue(b.cells[columnIndex]),
    direction
  ));
  rows.forEach(row => tbody.appendChild(row));

  table.querySelectorAll('th.sortable').forEach((th, index) => {
    th.classList.remove('sorted-asc', 'sorted-desc');
    th.removeAttribute('aria-sort');
    if (index === columnIndex) {
      th.classList.add(direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
      th.setAttribute('aria-sort', direction === 'asc' ? 'ascending' : 'descending');
    }
  });
}

function setupGenericSortHandlers() {
  ['actions-table', 'groups-table', 'accounts-table'].forEach(tableId => {
    const table = document.getElementById(tableId);
    if (!table) return;
    table.querySelectorAll('th.sortable').forEach((th, index) => {
      th.addEventListener('click', () => {
        const current = genericSortState[tableId] || {};
        const direction = current.columnIndex === index && current.direction === 'asc' ? 'desc' : 'asc';
        genericSortState[tableId] = { columnIndex: index, direction };
        sortGenericTable(tableId, index, direction);
      });
    });
  });
}

function applyGenericSorts() {
  Object.entries(genericSortState).forEach(([tableId, state]) => {
    sortGenericTable(tableId, state.columnIndex, state.direction);
  });
}

function statusCell(f) {
  const status = f.AccountStatus || (f.IsDisabled ? 'Disabled' : 'Active');
  const cls = status === 'Active' ? 'status-active' : 'status-disabled';
  return `<span class="${cls}">${esc(status)}</span>`;
}

function dateCell(display, usDate, days) {
  if (display && display !== 'N/A') return esc(display);
  if (usDate != null && days != null) return `${esc(usDate)} (${days} days)`;
  if (usDate) return esc(usDate);
  return 'N/A';
}

function pwdNeverExpiresCell(f) {
  if (f.AccountType === 'Group' || (f.UserAccountControl == null && f.PasswordNeverExpires == null)) return 'N/A';
  return f.PasswordNeverExpires ? 'Yes' : 'No';
}

function uacCell(f) {
  const summary = f.UserAccountControlSummary || f.UserAccountControlFlags;
  if (!summary || summary === 'N/A') {
    if (f.UserAccountControl == null) return 'N/A';
    return `<span class="sub">Raw: ${f.UserAccountControl}</span>`;
  }

  const parts = String(summary).split(',').map(x => x.trim()).filter(Boolean);
  const labels = parts.length ? parts : [summary];
  return labels.map(label => `<span class="uac-pill">${esc(label)}</span>`).join(' ');
}

function scoreExplanationCell(f) {
  const formula = f.ScoreFormula || '';
  const components = f.ScoreComponents || [];
  if (!components.length && !formula) return '<span class="sub">Run a new audit to populate score details.</span>';
  const items = components.map(c => `
    <li><strong>${esc(c.Name)}</strong>: ${esc(c.Value)} <span class="sub">(${esc(c.Type)} - ${esc(c.Reason)})</span></li>`).join('');
  return `<details class="score-detail"><summary>${esc((f.RiskScore ?? 0).toFixed(2))} calculated</summary><ul>${items}</ul><small class="sub">${esc(formula)}</small></details>`;
}

function attackCell(f) {
  const techniques = f.AttackTechniques || [];
  const tech = techniques.map(t => `<span class="attack-pill">${esc(t.Id)} ${esc(t.Name)}</span>`).join(' ');
  const risk = f.TechnicalRisk || 'Sensitive group membership requires validation';
  return `<div class="wrap"><small>${esc(risk)}</small><div class="attack-list">${tech}</div></div>`;
}

function identityOriginCell(f) {
  const category = f.NativeIdentityCategory || (f.IsNativeIdentity ? 'Native AD identity' : 'Custom');
  const reason = f.NativeIdentityReason || (f.IsNativeIdentity ? 'Native AD/Windows principal' : 'Customer-managed identity');
  const cls = f.IsNativeIdentity ? 'badge-excluded' : 'badge-tier2';
  return `<span class="badge ${cls}">${esc(category)}</span><br><small class="sub">${esc(reason)}</small>`;
}

function scoreCell(f) {
  const score = f.RiskScore ?? 0;
  const formula = f.ScoreFormula || '';
  const components = f.ScoreComponents || [];
  const details = components.length
    ? components.map(c => `<li><strong>${esc(c.Name)}</strong>: ${esc(c.Value)} <span class="sub">(${esc(c.Type)} - ${esc(c.Reason)})</span></li>`).join('')
    : '<li class="sub">Run a new audit to populate score components.</li>';
  return `
    <details class="score-detail score-drilldown">
      <summary class="${scoreClass(score)}">${score.toFixed(2)}</summary>
      <ul>${details}</ul>
      <small class="sub">${esc(formula || 'Base * account type * nesting * directness * account state + UAC bonus')}</small>
    </details>`;
}

function scoreDetailHtml(f) {
  const formula = f.ScoreFormula || 'Base * account type * nesting * directness * account state + UAC bonus';
  const components = f.ScoreComponents || [];
  const details = components.length
    ? components.map(c => `<li><strong>${esc(c.Name)}</strong>: ${esc(c.Value)} <span class="sub">(${esc(c.Type)} - ${esc(c.Reason)})</span></li>`).join('')
    : '<li class="sub">Run a new audit to populate score components.</li>';
  return `<ul class="detail-list">${details}</ul><small class="sub">${esc(formula)}</small>`;
}

function whyThisMatters(f) {
  if (f.IsNativeIdentity || f.IsRemediableIdentity === false) {
    return 'Native AD identity: monitor separately; removal may be unsupported or architecture-owned.';
  }
  if ((f.PrivilegeTier || '') === 'Tier 0') {
    return 'Tier 0 path can lead to identity control plane compromise.';
  }
  if (f.UacPrivilegedConcernCount > 0) {
    return 'Privileged UAC flags increase credential or delegation risk.';
  }
  if (f.NestingDepth > 0 || f.IsDirect === false) {
    return 'Nested access hides privilege origin and makes reviews harder.';
  }
  if (f.IsStale && !f.IsDisabled) {
    return 'Enabled stale identity increases takeover window.';
  }
  if ((f.AccountType || '').startsWith('ServiceAccount')) {
    return 'Privileged service identity can create persistent operational access.';
  }
  return 'Sensitive group membership should have explicit ownership and business need.';
}

function getSearchBlob(f) {
  const attacks = (f.AttackTechniques || []).map(t => `${t.Id} ${t.Name} ${t.Tactic}`).join(' ');
  return [
    f.MemberSam, f.MemberDisplay, f.MemberDn, f.ObjectSid, f.SensitiveGroup,
    f.PrivilegeTier, f.AccountType, f.NativeIdentityCategory, f.NativeIdentityReason,
    f.MembershipChain, f.UserAccountControlSummary, f.UserAccountControlFlags,
    f.UacActiveFlagNames, f.TechnicalRisk, f.CleanupActions, f.Notes, attacks
  ].join(' ').toLowerCase();
}

function renderScoreRing(score) {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(1, Number(score || 0) / 100);
  const color = score > 15 ? 'var(--danger)' : score > 5 ? 'var(--warn)' : 'var(--ok)';
  const progress = score <= 0
    ? 100
    : Math.max(0, Math.min(100, 100 - (Math.log10(score + 1) / 2) * 100));

  const fill = document.getElementById('score-ring-fill');
  const num = document.getElementById('ring-num');
  const progressFill = document.getElementById('score-progress-fill');
  const progressPct = document.getElementById('score-progress-pct');

  if (fill) {
    fill.style.strokeDashoffset = (circumference * (1 - pct)).toFixed(2);
    fill.style.stroke = color;
  }
  if (num) {
    num.textContent = Number(score || 0).toFixed(1);
    num.style.color = color;
  }
  if (progressFill) progressFill.style.width = progress.toFixed(1) + '%';
  if (progressFill) progressFill.style.background = color;
  if (progressPct) progressPct.textContent = Math.round(progress) + '% toward zero';
}

function getActionRows(limit = 20) {
  const byAction = new Map();
  filteredFindings().filter(f => !(f.IsExcluded || f.isExcluded)).forEach(f => {
    const action = String(f.CleanupActions || 'Review business justification').split(';')[0].trim();
    if (!byAction.has(action)) {
      byAction.set(action, { action, members: new Set(), findings: 0, score: 0, accounts: new Set() });
    }
    const row = byAction.get(action);
    row.members.add(f.ObjectSid || f.MemberSam || f.MemberDn || f.MemberDisplay || 'Unknown');
    row.accounts.add(f.MemberSam || f.MemberDisplay || 'Unknown');
    row.findings += 1;
    row.score += Number(f.RiskScore || 0);
  });
  return [...byAction.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

function renderNextBestAction() {
  const el = document.getElementById('next-action');
  if (!el) return;
  const row = getActionRows(1)[0];
  if (!row) {
    el.innerHTML = `
      <div class="next-action-label">Recommended first fix</div>
      <div class="next-action-title">No fix matches this view</div>
      <div class="next-action-meta">Clear filters or switch scope to see monitor-only items.</div>`;
    return;
  }
  const accounts = [...row.accounts].slice(0, 3).join(', ');
  el.innerHTML = `
    <div class="next-action-label">Recommended first fix</div>
    <div class="next-action-title">${esc(row.action)}</div>
    <div class="next-action-stats">
      <span><strong>${row.score.toFixed(2)}</strong> score drop</span>
      <span><strong>${row.members.size}</strong> accounts</span>
      <span><strong>${row.findings}</strong> paths</span>
    </div>
    <div class="next-action-accounts">${esc(accounts || 'No account preview')}</div>
    <button type="button" class="next-action-button" data-panel-target="actions-panel">Open fix queue</button>`;
}

function scopeLabel(scope) {
  const labels = {
    remediable: 'Fix now',
    actionable: 'Needs review',
    native: 'Monitor only',
    all: 'All items'
  };
  return labels[scope] || scope || 'Fix now';
}

function persistActiveScope() {
  try {
    sessionStorage.setItem(scopeStorageKey, activeScope);
  } catch (_) {
    /* Scope remains active for this render when storage is unavailable. */
  }
}

function renderFilterSummary() {
  const el = document.getElementById('filter-summary');
  if (!el) return;
  const search = document.getElementById('search')?.value || '';
  const group = document.getElementById('filter-group')?.value || '';
  const diff = document.getElementById('filter-difficulty')?.value || '';
  const type = document.getElementById('filter-type')?.value || '';
  const tier = document.getElementById('filter-tier')?.value || '';
  const chips = [
    activeScope && activeScope !== 'remediable' ? ['scope', 'Scope', scopeLabel(activeScope)] : null,
    search ? ['search', 'Search', search] : null,
    group ? ['filter-group', 'Group', group] : null,
    diff ? ['filter-difficulty', 'Difficulty', diff] : null,
    type ? ['filter-type', 'Type', type] : null,
    tier ? ['filter-tier', 'Tier', tier] : null
  ].filter(Boolean);
  const visible = filteredFindings().length;

  if (!chips.length) {
    el.innerHTML = `<span class="filter-count">Showing ${visible} ${scopeLabel(activeScope).toLowerCase()} findings</span>`;
    return;
  }

  el.innerHTML = `
    <span class="filter-count">Showing ${visible} findings</span>
    ${chips.map(([id, label, value]) => `<button type="button" class="filter-chip" data-clear-filter="${esc(id)}" title="Remove ${esc(label)} filter"><strong>${esc(label)}</strong>${esc(value)}<span aria-hidden="true">x</span></button>`).join('')}
    <button type="button" class="filter-clear" id="clear-filters">Clear filters</button>`;
}

function clearOneFilter(id) {
  if (id === 'scope') {
    activeScope = 'remediable';
    persistActiveScope();
    document.querySelectorAll('#filter-scope .scope-option').forEach(item => {
      const isActive = item.dataset.scope === 'remediable';
      item.classList.toggle('active', isActive);
      item.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });
    renderOperationalViews();
    return;
  }
  const el = document.getElementById(id);
  if (el) el.value = '';
  renderOperationalViews();
}

function clearFilters() {
  ['search', 'filter-group', 'filter-difficulty', 'filter-type', 'filter-tier'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  activeScope = 'remediable';
  persistActiveScope();
  document.querySelectorAll('#filter-scope .scope-option').forEach(item => {
    const isActive = item.dataset.scope === 'remediable';
    item.classList.toggle('active', isActive);
    item.setAttribute('aria-pressed', isActive ? 'true' : 'false');
  });
  renderOperationalViews();
}

function renderKpis() {
  const m = state.meta || {};
  document.getElementById('kpi-time').textContent = m.timestamp ? new Date(m.timestamp).toLocaleString('en-US') : '-';
  const score = m.overallRiskScore ?? 0;
  const el = document.getElementById('kpi-score');
  el.textContent = score.toFixed(2);
  el.className = 'score-kpi-val value ' + scoreClass(score);
  const status = score > 15 ? 'Critical Exposure' : score > 5 ? 'Elevated Risk' : 'Controlled';
  const statusClass = score > 15 ? 'score-high' : score > 5 ? 'score-mid' : 'score-0';
  document.querySelector('.score-kpi-sub').innerHTML = `
    <span class="score-context"><em>Domain</em><strong>${esc(m.domain || '-')}</strong></span>
    <span class="score-context"><em>Target</em><strong>${esc((m.targetScore ?? 0).toFixed(0))}</strong></span>
    <span class="score-context"><em>Status</em><strong class="${statusClass}">${status}</strong></span>`;
  const readiness = m.readiness || {};
  const readinessEl = document.getElementById('kpi-readiness');
  readinessEl.innerHTML = readiness.Score != null
    ? `<span class="metric-number">${esc(readiness.Score)}</span><span class="metric-unit">/100</span>`
    : '-';
  readinessEl.className = 'kpi-val value ' + readinessClass(readiness.Score ?? 0);
  const controls = readiness.Controls || readiness.controls || [];
  const controlsNeedingAttention = controls.filter(control => !['Pass', 'Passed', 'Controlled', 'Healthy'].includes(control.Status || control.status)).length;
  const readinessSub = document.getElementById('kpi-readiness-sub');
  if (readinessSub) readinessSub.textContent = `${controlsNeedingAttention} controls need attention`;
  document.getElementById('kpi-actionable').innerHTML = `<span class="metric-number">${esc(m.actionableCount ?? 0)}</span>`;
  document.getElementById('kpi-exceptions').innerHTML = `
    <span class="metric-pair"><em>Active</em><strong>${esc(m.approvedExceptionCount ?? 0)}</strong></span>
    <span class="metric-pair"><em>Expired</em><strong>${esc(m.expiredExceptionCount ?? 0)}</strong></span>`;
  document.getElementById('kpi-exceptions').className = 'kpi-val metric-composite';
  const r = m.remediation || {};
  document.getElementById('kpi-remediation').innerHTML = `
    <span class="metric-chip danger">High <strong>${esc(r.High ?? r.high ?? 0)}</strong></span>
    <span class="metric-chip warn">Medium <strong>${esc(r.Medium ?? r.medium ?? 0)}</strong></span>
    <span class="metric-chip ok">Low <strong>${esc(r.Low ?? r.low ?? 0)}</strong></span>`;
  const tiers = m.tierBreakdown || {};
  document.getElementById('kpi-tiering').innerHTML = `
    <span class="metric-pair"><em>T0</em><strong>${esc(tiers['Tier 0'] ?? tiers.Tier0 ?? 0)}</strong></span>
    <span class="metric-pair"><em>T1</em><strong>${esc(tiers['Tier 1'] ?? tiers.Tier1 ?? 0)}</strong></span>
    <span class="metric-pair"><em>T2</em><strong>${esc(tiers['Tier 2'] ?? tiers.Tier2 ?? 0)}</strong></span>`;
  document.getElementById('kpi-tiering').className = 'kpi-val metric-composite';
  renderScoreRing(score);
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(m, (state.findings || []).length);
  }
}

function renderReadiness() {
  const readiness = (state.meta || {}).readiness || {};
  const meter = document.getElementById('readiness-meter');
  const grid = document.getElementById('scorecard-grid');
  if (!meter || !grid) return;

  if (readiness.Score == null) {
    meter.textContent = 'No readiness data';
    grid.innerHTML = '<div class="empty-state"><strong>No readiness controls yet</strong><span>Run a fresh audit to generate control checks.</span></div>';
    return;
  }

  meter.innerHTML = `<strong class="${readinessClass(readiness.Score)}">${readiness.Score}/100</strong><span>${esc(readiness.Level || '')}</span>`;
  grid.innerHTML = (readiness.Controls || []).map(c => `
    <div class="scorecard-item">
      <div class="scorecard-head">
        <strong>${esc(c.Name)}</strong>
        ${statusBadge(c.Status)}
      </div>
      <div class="scorecard-count">${esc(c.Count ?? 0)} / target ${esc(c.Target ?? 0)}</div>
      <p class="sub">${esc(c.Detail || '')}</p>
    </div>`).join('');
}

function renderGroupChart() {
  const tbody = document.querySelector('#groups-table tbody');
  tbody.innerHTML = '';
  const groups = (state.groups || [])
    .sort((a, b) => (b.AggregateRiskScore || 0) - (a.AggregateRiskScore || 0))
  const maxAggregate = Math.max(1, ...groups.map(g => g.AggregateRiskScore || 0));
  groups
    .forEach(g => {
      const tr = document.createElement('tr');
      const agg = g.AggregateRiskScore ?? 0;
      const width = Math.max(2, Math.round((agg / maxAggregate) * 100));
      tr.innerHTML = `
        <td>${esc(g.SensitiveGroup)}</td>
        <td>${esc(g.Tier)}</td>
        <td>${tierBadge(g.PrivilegeTier)}</td>
        <td>${g.MemberCount}</td>
        <td class="${scoreClass(agg)}">${agg.toFixed(2)}</td>
        <td><div class="chart-bar"><span style="width:${width}%"></span></div></td>`;
      tbody.appendChild(tr);
    });
}

function filteredFindings() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  const group = document.getElementById('filter-group').value;
  const diff = document.getElementById('filter-difficulty').value;
  const type = document.getElementById('filter-type').value;
  const tier = document.getElementById('filter-tier').value;
  const scope = activeScope || 'remediable';
  const active = state.findings || [];
  const monitoring = state.monitoring || [];
  const source = scope === 'native'
    ? monitoring.filter(f => f.IsNativeIdentity || f.IsRemediableIdentity === false || f.IsExcluded)
    : scope === 'all'
      ? active.concat(monitoring)
      : active;
  return source.filter(f => {
    if (scope === 'remediable' && (f.IsNativeIdentity || f.IsRemediableIdentity === false)) return false;
    if (group && f.SensitiveGroup !== group) return false;
    if (diff && f.RemediationDifficulty !== diff) return false;
    if (type && !(f.AccountType || '').startsWith(type)) return false;
    if (tier && f.PrivilegeTier !== tier) return false;
    if (q) {
      if (!getSearchBlob(f).includes(q)) return false;
    }
    return true;
  });
}

function renderAccountImpact() {
  const tbody = document.querySelector('#accounts-table tbody');
  if (!tbody) return;
  const byAccount = new Map();
  filteredFindings().filter(f => !(f.IsExcluded || f.isExcluded)).forEach(f => {
    const key = f.ObjectSid || f.MemberDn || f.MemberSam || f.MemberDisplay || 'Unknown';
    if (!byAccount.has(key)) {
      byAccount.set(key, { account: f.MemberSam || f.MemberDisplay || 'Unknown', type: f.AccountType || 'Unknown', groups: new Set(), paths: 0, score: 0, reasons: [] });
    }
    const row = byAccount.get(key);
    row.groups.add(f.SensitiveGroup || 'Unknown');
    row.paths += 1;
    row.score += Number(f.RiskScore || 0);
    row.reasons.push(whyThisMatters(f));
  });
  const rows = [...byAccount.values()].sort((a, b) => b.score - a.score).slice(0, 20);
  tbody.innerHTML = rows.length ? rows.map(r => `
    <tr>
      <td>${esc(r.account)}</td>
      <td>${esc(r.type)}</td>
      <td>${r.paths}</td>
      <td class="wrap">${esc([...r.groups].join(', '))}</td>
      <td class="${scoreClass(r.score)}">${r.score.toFixed(2)}</td>
      <td class="wrap"><small>${esc([...new Set(r.reasons)].slice(0, 2).join(' '))}</small></td>
    </tr>`).join('') : '<tr><td colspan="6"><div class="table-empty">No accounts match these filters. Clear filters to restore the queue.</div></td></tr>';
}

function renderActionImpact() {
  const tbody = document.querySelector('#actions-table tbody');
  if (!tbody) return;
  const rows = getActionRows(20);
  tbody.innerHTML = rows.length ? rows.map(r => `
    <tr>
      <td class="wrap">${esc(r.action)}</td>
      <td>${r.members.size}</td>
      <td>${r.findings}</td>
      <td class="${scoreClass(r.score)}">${r.score.toFixed(2)}</td>
      <td class="wrap"><small>${esc([...r.accounts].slice(0, 6).join(', '))}</small></td>
    </tr>`).join('') : '<tr><td colspan="5"><div class="table-empty">No fix batches match these filters. Clear filters or switch scope.</div></td></tr>';
}

function renderOperationalViews() {
  renderInsights();
  renderAccountImpact();
  renderActionImpact();
  renderFindings();
  renderPlaybooks();
  renderNextBestAction();
  renderFilterSummary();
  applyGenericSorts();
}

function renderPlaybooks() {
  const tbody = document.querySelector('#playbooks-table tbody');
  if (!tbody) return;
  const playbooks = state.remediationPlaybooks || [];
  tbody.innerHTML = playbooks.slice(0, 50).map(pb => `
    <tr id="${esc(pb.PlaybookId || pb.playbookId || '')}">
      <td>${esc(pb.FindingDomain || pb.findingDomain || '-')}</td>
      <td>${esc(pb.FindingType || pb.findingType || '-')}<br><small class="sub">${esc(pb.FindingId || pb.findingId || '')}</small></td>
      <td>${pb.CanGenerateScript || pb.canGenerateScript ? '<span class="badge good">WhatIf script</span>' : `<span class="badge warn">Blocked</span><br><small class="sub">${esc(pb.BlockedReason || pb.blockedReason || '')}</small>`}</td>
      <td class="wrap"><small>${esc(pb.ExpectedImpact || pb.expectedImpact || '')}</small></td>
      <td><button class="secondary action-playbook" data-playbook="${esc(pb.PlaybookId || pb.playbookId || '')}">Open</button></td>
    </tr>`).join('') || '<tr><td colspan="5"><div class="table-empty">No playbooks were generated for this report.</div></td></tr>';

  tbody.querySelectorAll('[data-playbook]').forEach(button => {
    button.addEventListener('click', () => showPlaybook(button.dataset.playbook));
  });
}

function showPlaybook(playbookId) {
  const pb = (state.remediationPlaybooks || []).find(item => (item.PlaybookId || item.playbookId) === playbookId);
  if (!pb) return;
  const steps = (pb.ValidationSteps || pb.validationSteps || []).map(s => `# - ${s}`).join('\n');
  const evidence = (pb.EvidenceRequirements || pb.evidenceRequirements || []).map(s => `# - ${s}`).join('\n');
  const body = pb.WhatIfScript || pb.whatIfScript || `# No deterministic mutation script was generated.\n# Blocked reason: ${pb.BlockedReason || pb.blockedReason || 'Review required.'}`;
  currentScript = `# AD Posture safe playbook: ${pb.PlaybookId || pb.playbookId}\n# Domain: ${pb.FindingDomain || pb.findingDomain}\n# Finding: ${pb.FindingType || pb.findingType}\n\n# Validation before change:\n${steps}\n\n${body}\n\n# Evidence after review/change:\n${evidence}`;
  currentScriptFileName = `ad-playbook-${safeFilePart(pb.PlaybookId || pb.playbookId)}.txt`;
  const scriptPanel = document.getElementById('script-panel');
  if (scriptPanel) scriptPanel.hidden = false;
  document.getElementById('script-output').innerHTML = highlightPS(currentScript);
  document.getElementById('copy-script').disabled = false;
  document.getElementById('download-script').disabled = false;
  document.getElementById('script-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderFindings() {
  const tbody = document.querySelector('#findings-table tbody');
  tbody.innerHTML = '';
  const rows = filteredFindings().sort(compareFindings);
  rows
    .forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${scoreCell(f)}</td>
        <td>${esc(f.MemberSam)}<br><small class="sub">${esc(f.MemberDisplay || '')}</small></td>
        <td>${esc(f.SensitiveGroup)}</td>
        <td>${tierBadge(f.PrivilegeTier)}</td>
        <td>${esc(f.AccountType)}</td>
        <td>${statusCell(f)}</td>
        <td class="chain wrap">${esc(f.MembershipChain || '-')}</td>
        <td class="wrap"><small>${esc(whyThisMatters(f))}</small></td>
        <td>${difficultyBadge(f.RemediationDifficulty)}</td>
        <td class="wrap action-cell"><small>${esc(f.CleanupActions || '')}</small></td>
        <td>
          <details class="row-detail">
            <summary>Open</summary>
            <div class="finding-detail-grid">
              <div><strong>Score factors</strong>${scoreDetailHtml(f)}</div>
              <div><strong>Technical risk</strong>${attackCell(f)}</div>
              <div><strong>Identity origin</strong>${identityOriginCell(f)}</div>
              <div><strong>Account control</strong><div>${uacCell(f)}</div></div>
              <div><strong>Activity</strong><small class="sub">Last logon: ${dateCell(f.LastLogonDisplay, f.LastLogonUsDate, f.LastLogonDays)}<br>Password: ${dateCell(f.PasswordLastSetDisplay, f.PasswordLastSetUsDate, f.PasswordLastSetDays)}<br>Never expires: ${pwdNeverExpiresCell(f)}<br>Created: ${dateCell(f.WhenCreatedDisplay, f.WhenCreatedUsDate, f.WhenCreatedDays)}</small></div>
              <div><strong>Full action</strong><small class="sub">${esc(f.CleanupActions || 'Review business justification')}</small></div>
            </div>
          </details>
        </td>
        <td>
          <button class="action-script" data-remediate="${esc(f.MemberSam)}"${canGenerateRemediation(f) ? '' : ' disabled'} title="${esc(remediationAvailabilityReason(f))}">Script</button>
          ${f.PlaybookId ? `<a class="mini-link" href="#playbooks-panel" data-open-playbook="${esc(f.PlaybookId)}">Playbook</a>` : ''}
        </td>`;
      tbody.appendChild(tr);
      tr.querySelector('[data-remediate]')?.addEventListener('click', () => generateRemediation(f));
      tr.querySelector('[data-open-playbook]')?.addEventListener('click', event => {
        event.preventDefault();
        showPlaybook(event.currentTarget.dataset.openPlaybook);
      });
    });

  if (!tbody.children.length) {
    tbody.innerHTML = '<tr><td colspan="12"><div class="table-empty">No access paths match the current filters.</div></td></tr>';
    return;
  }

}

function populateFilters() {
  const sel = document.getElementById('filter-group');
  const groups = [...new Set((state.findings || []).concat(state.monitoring || []).map(f => f.SensitiveGroup))].sort();
  sel.innerHTML = '<option value="">All groups</option>' +
    groups.map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('');
}

function powershellLiteral(value) {
  return `'${String(value || '').replace(/'/g, "''")}'`;
}

function canGenerateRemediation(finding) {
  if (finding.CanGenerateRemediationScript === false) return false;
  if (finding.TruncatedNesting) return false;
  if (finding.DirectParentGroupDn) return true;
  return finding.IsDirect === true || String(finding.IsDirect).toLowerCase() === 'true';
}

function remediationAvailabilityReason(finding) {
  if (canGenerateRemediation(finding)) return 'Generate a reviewed WhatIf remediation script';
  return finding.RemediationBlockedReason || 'A direct parent group could not be proven for this access path.';
}

function generateRemediation(finding) {
  if (!canGenerateRemediation(finding)) return;
  const member = finding.MemberSam;
  const group = finding.SensitiveGroup;
  const removalGroup = finding.DirectParentGroupDn || group;
  const script = `# Paste in PowerShell (with ADPosture module imported):
New-ADPostureRemediationScript -SensitiveGroup ${powershellLiteral(group)} -RemovalGroupIdentity ${powershellLiteral(removalGroup)} -MemberSamAccountName ${powershellLiteral(member)} -WhatIfOnly
# The generated script validates direct membership in the removal group before changing AD.`;
  currentScript = script;
  currentScriptFileName = `ad-remediation-${safeFilePart(group)}-${safeFilePart(member)}.txt`;
  const scriptPanel = document.getElementById('script-panel');
  if (scriptPanel) scriptPanel.hidden = false;
  document.getElementById('script-output').innerHTML = highlightPS(script);
  document.getElementById('copy-script').disabled = false;
  document.getElementById('download-script').disabled = false;
  document.getElementById('script-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function safeFilePart(value) {
  return String(value || 'item')
    .replace(/[^a-z0-9_-]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'item';
}

function downloadCurrentScript() {
  if (!currentScript) return;
  const blob = new Blob([currentScript], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = currentScriptFileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function setupScriptActions() {
  document.getElementById('copy-script')?.addEventListener('click', async (event) => {
    if (!currentScript) return;
    const button = event.currentTarget;
    await window.ADPostureDashboard?.copyText?.(currentScript, button);
  });
  document.getElementById('download-script')?.addEventListener('click', downloadCurrentScript);
}

function setupScopeToggle() {
  document.querySelectorAll('#filter-scope .scope-option').forEach(btn => {
    const isActive = btn.dataset.scope === activeScope;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    btn.addEventListener('click', () => {
      activeScope = btn.dataset.scope || 'remediable';
      persistActiveScope();
      document.querySelectorAll('#filter-scope .scope-option').forEach(item => {
        item.classList.toggle('active', item === btn);
        item.setAttribute('aria-pressed', item === btn ? 'true' : 'false');
      });
      renderOperationalViews();
    });
  });
}

function setupTabs() {
  const viewLinks = document.querySelectorAll('.view-switch .view-link, .topbar-tab[data-panel]');
  const panels = Array.from(viewLinks)
    .map(link => document.getElementById(link.dataset.panel || (link.getAttribute('href') || '').slice(1)))
    .filter(Boolean);
  if (!viewLinks.length || !panels.length) return;

  viewLinks.forEach(link => link.setAttribute('role', 'tab'));

  function showPanel(targetId) {
    panels.forEach(panel => {
      const isTarget = panel.id === targetId;
      panel.classList.toggle('panel-hidden', !isTarget);
      if (isTarget) {
        panel.removeAttribute('hidden');
      } else {
        panel.setAttribute('hidden', '');
      }
    });
    viewLinks.forEach(link => {
      const isTarget = (link.dataset.panel || (link.getAttribute('href') || '').slice(1)) === targetId;
      link.classList.toggle('active', isTarget);
      link.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    });
    try {
      sessionStorage.setItem('adaudit_tab_v2_' + (location.pathname.split('/').pop() || 'index.html'), targetId);
    } catch (_) {
      /* Keep tabs functional when sessionStorage is unavailable. */
    }
  }
  showDashboardPanel = showPanel;

  viewLinks.forEach(link => {
    link.addEventListener('click', event => {
      event.preventDefault();
      showPanel(link.dataset.panel || link.getAttribute('href').slice(1));
    });
  });

  let savedTab = '';
  try {
    savedTab = sessionStorage.getItem('adaudit_tab_v2_' + (location.pathname.split('/').pop() || 'index.html')) || '';
  } catch (_) {
    savedTab = '';
  }
  const firstId = panels[0]?.id;
  const preferredId = document.getElementById('actions-panel') ? 'actions-panel' : firstId;
  const targetId = savedTab && document.getElementById(savedTab) ? savedTab : preferredId;
  if (targetId) showPanel(targetId);
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'file-input',
  hintId: 'load-hint',
  onData: raw => {
    state = normalizeState(raw);
    renderAll();
  }
});

['search', 'filter-group', 'filter-difficulty', 'filter-type', 'filter-tier'].forEach(id => {
  document.getElementById(id)?.addEventListener('input', () => {
    renderOperationalViews();
  });
  document.getElementById(id)?.addEventListener('change', () => {
    renderOperationalViews();
  });
});

document.addEventListener('click', event => {
  if (event.target?.id === 'clear-filters') {
    clearFilters();
  }
  const clearFilter = event.target?.closest?.('[data-clear-filter]')?.dataset?.clearFilter;
  if (clearFilter) {
    clearOneFilter(clearFilter);
  }
  const panelTrigger = event.target?.closest?.('[data-panel-target]');
  const panelTarget = panelTrigger?.dataset?.panelTarget;
  if (panelTarget && showDashboardPanel) {
    showDashboardPanel(panelTarget);
    document.getElementById(panelTarget)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
});

function renderAll() {
  renderKpis();
  renderReadiness();
  renderInsights();
  renderAccountImpact();
  renderActionImpact();
  renderGroupChart();
  populateFilters();
  updateSortHeaders();
  renderFindings();
  renderPlaybooks();
  renderNextBestAction();
  renderFilterSummary();
  applyGenericSorts();
}

function openLinkedPlaybook() {
  const params = new URLSearchParams(location.search);
  const playbookId = params.get('playbook');
  const findingId = params.get('finding');
  const target = playbookId || (state.remediationPlaybooks || []).find(pb => (pb.FindingId || pb.findingId) === findingId)?.PlaybookId;
  if (!target) return;
  setTimeout(() => showPlaybook(target), 50);
}

loadData().then(ok => {
  setupSortHandlers();
  setupGenericSortHandlers();
  setupScriptActions();
  setupScopeToggle();
  setupTabs();
  renderAll();
  openLinkedPlaybook();
  if (ok) {
    document.getElementById('load-hint').style.display = 'none';
  }
}).catch(error => {
  const hint = document.getElementById('load-hint');
  if (hint) {
    hint.textContent = `Could not build the Action Plan: ${error?.message || error}`;
    hint.classList.add('error');
    hint.style.display = '';
  }
});
