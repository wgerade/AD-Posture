const URLS = ['timeline-comparison.json', '../reports/timeline-comparison.json'];
const sortState = {};

function applyTimeline(data) {
  const hint = document.getElementById('timeline-hint');
  if (!data) {
    hint.textContent = 'Run Compare-ADPostureSnapshots -UseLatestTwo after 2+ audits, or load a JSON file.';
    return;
  }
  hint.style.display = 'none';
  const emptyEl = document.getElementById('timeline-empty');
  if (emptyEl) emptyEl.style.display = 'none';

  const delta = data.ScoreDelta ?? 0;
  document.getElementById('score-before').textContent = (data.ScoreBefore ?? 0).toFixed(2);
  document.getElementById('score-after').textContent = (data.ScoreAfter ?? 0).toFixed(2);
  const deltaEl = document.getElementById('score-delta');
  deltaEl.textContent = (delta >= 0 ? '+' : '') + delta.toFixed(2);
  deltaEl.className = 'value ' + (delta <= 0 ? 'score-0' : 'score-high');

  document.getElementById('added-count').textContent = data.AddedCount ?? 0;
  document.getElementById('removed-count').textContent = data.RemovedCount ?? 0;
  document.getElementById('changed-count').textContent = data.ChangedCount ?? 0;
  document.getElementById('acl-added-count').textContent = data.AclAddedCount ?? 0;
  document.getElementById('acl-new-high-count').textContent = data.AclNewCriticalHighCount ?? 0;
  document.getElementById('acl-removed-count').textContent = data.AclRemovedCount ?? 0;
  document.getElementById('timeline-delta-summary').textContent =
    `${data.AddedCount ?? 0} memberships added, ${data.RemovedCount ?? 0} removed, ${data.ChangedCount ?? 0} score changes, ${data.AclAddedCount ?? 0} ACL findings added, and ${data.AclRemovedCount ?? 0} ACL findings removed.`;

  renderTable('#added-table', data.Added, 'Added');
  renderTable('#removed-table', data.Removed, 'Removed');
  renderAclTable('#acl-added-table', data.AclAdded, 'New');
  renderAclTable('#acl-removed-table', data.AclRemoved, 'Missing');
  renderChanges(data.Changed || []);
  applySorts();

  const hist = data.History || [];
  const chart = document.getElementById('history-chart');
  const maxScore = Math.max(1, ...hist.map(h => Number(h.score || 0)));
  const first = hist[0]?.score ?? data.ScoreBefore ?? 0;
  const last = hist[hist.length - 1]?.score ?? data.ScoreAfter ?? 0;
  const movement = Number(last || 0) - Number(first || 0);
  document.getElementById('timeline-summary').textContent = hist.length
    ? `${hist.length} snapshots / ${(movement >= 0 ? '+' : '')}${movement.toFixed(2)} score movement from first to latest.`
    : 'No history snapshots available in this comparison payload.';
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar({
      domain: data.Domain || data.domain || '',
      timestamp: hist[hist.length - 1]?.timestamp || data.Timestamp || data.CurrentTimestamp || '',
      overallRiskScore: data.ScoreAfter ?? 0,
      targetScore: data.TargetScore ?? data.targetScore ?? 0
    }, (data.AddedCount ?? 0) + (data.AclAddedCount ?? 0));
  }
  chart.innerHTML = hist.map(h => `
    <div class="trend-item">
      <div class="trend-meta">
        <strong>${new Date(h.timestamp).toLocaleDateString('en-US')}</strong>
        <span>${(h.score ?? 0).toFixed(2)}</span>
      </div>
      <div class="bar-track"><span style="width:${Math.max(2, Math.round((Number(h.score || 0) / maxScore) * 100))}%"></span></div>
      <small class="sub">Actionable: ${h.actionable ?? 0} / ACL: ${h.aclFindings ?? 0}</small>
    </div>`).join('');
}

async function loadTimeline() {
  if (window.__AD_TIMELINE_DATA__) {
    return window.__AD_TIMELINE_DATA__;
  }
  for (const u of URLS) {
    try {
      const r = await fetch(u);
      if (r.ok) return r.json();
    } catch (_) {}
  }
  return null;
}

function renderTable(sel, rows, label) {
  const tbody = document.querySelector(`${sel} tbody`);
  tbody.innerHTML = '';
  (rows || []).forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${label}</td>
      <td>${esc(f.SensitiveGroup)}</td>
      <td>${esc(f.MemberSam)}</td>
      <td class="chain">${esc(f.MembershipChain || '-')}</td>
      <td>${(f.RiskScore ?? 0).toFixed(2)}</td>`;
    tbody.appendChild(tr);
  });
}

function renderChanges(changes) {
  const tbody = document.querySelector('#changed-table tbody');
  tbody.innerHTML = '';
  changes.forEach(c => {
    const f = c.Finding;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(f.SensitiveGroup)}</td>
      <td>${esc(f.MemberSam)}</td>
      <td>${esc(c.Before)} -> ${esc(c.After)}</td>
      <td class="chain">${esc(f.MembershipChain || '-')}</td>`;
    tbody.appendChild(tr);
  });
}

function renderAclTable(sel, rows, label) {
  const tbody = document.querySelector(`${sel} tbody`);
  if (!tbody) return;
  tbody.innerHTML = '';
  (rows || []).forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(f.DriftState || label)}</td>
      <td>${esc(f.NormalizedRight)}</td>
      <td>${esc(f.TrusteeName || f.TrusteeSid)}</td>
      <td class="chain">${esc(f.TargetName || f.TargetDistinguishedName || '-')}</td>
      <td>${(f.RiskScore ?? 0).toFixed(2)}</td>`;
    tbody.appendChild(tr);
  });
}

function esc(s) {
  return window.ADPostureDashboard.esc(s);
}

function getCellSortValue(cell) {
  const text = (cell.textContent || '').trim();
  const numeric = Number(text.replace(/,/g, '').match(/-?\d+(\.\d+)?/)?.[0]);
  return Number.isFinite(numeric) && /^[-\d\s.,>/]+$/.test(text) ? numeric : text.toLowerCase();
}

function sortTable(tableId, columnIndex, direction) {
  const table = document.getElementById(tableId);
  const tbody = table?.tBodies[0];
  if (!tbody) return;
  Array.from(tbody.rows)
    .sort((a, b) => {
      const av = getCellSortValue(a.cells[columnIndex]);
      const bv = getCellSortValue(b.cells[columnIndex]);
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        : String(av).localeCompare(String(bv), 'en', { numeric: true });
      return direction === 'asc' ? cmp : -cmp;
    })
    .forEach(row => tbody.appendChild(row));

  table.querySelectorAll('th.sortable').forEach((th, index) => {
    th.classList.remove('sorted-asc', 'sorted-desc');
    th.removeAttribute('aria-sort');
    if (index === columnIndex) {
      th.classList.add(direction === 'asc' ? 'sorted-asc' : 'sorted-desc');
      th.setAttribute('aria-sort', direction === 'asc' ? 'ascending' : 'descending');
    }
  });
}

function setupSortHandlers() {
  ['added-table', 'removed-table', 'changed-table', 'acl-added-table', 'acl-removed-table'].forEach(tableId => {
    document.querySelectorAll(`#${tableId} th.sortable`).forEach((th, index) => {
      th.addEventListener('click', () => {
        const current = sortState[tableId] || {};
        const direction = current.columnIndex === index && current.direction === 'asc' ? 'desc' : 'asc';
        sortState[tableId] = { columnIndex: index, direction };
        sortTable(tableId, index, direction);
      });
    });
  });
}

function applySorts() {
  Object.entries(sortState).forEach(([tableId, state]) => sortTable(tableId, state.columnIndex, state.direction));
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'timeline-file',
  hintId: 'timeline-hint',
  onData: applyTimeline
});

setupSortHandlers();
loadTimeline().then(applyTimeline);
