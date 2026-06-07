const DATA_URLS = [
  'latest-dashboard.json',
  '../reports/latest-dashboard.json'
];

function esc(s) {
  return window.ADPostureDashboard.esc(s);
}

function normalizeState(raw) {
  if (!raw) return { meta: {}, exceptions: [] };
  return {
    meta: window.ADPostureDashboard.normalizeMetadata(raw),
    exceptions: raw.exceptions || raw.ApprovedExceptions || []
  };
}

async function loadData() {
  return normalizeState(await window.ADPostureDashboard.loadAuditData(DATA_URLS));
}

function badge(status) {
  const cls = status === 'Expired' ? 'badge-high' : 'badge-low';
  return `<span class="badge ${cls}">${esc(status || 'Active')}</span>`;
}

function isExpiringSoon(value) {
  if (!value) return false;
  const expires = new Date(value);
  if (Number.isNaN(expires.getTime())) return false;
  const now = new Date();
  const days = (expires.getTime() - now.getTime()) / 86400000;
  return days >= 0 && days <= 30;
}

function exceptionScope(row) {
  if (row.SensitiveGroup) return row.SensitiveGroup;
  if (row.GpoName) return `GPO: ${row.GpoName}`;
  if (row.TargetName) return `ACL target: ${row.TargetName}`;
  if (row.ScopeName) return `Scope: ${row.ScopeName}`;
  return row.FindingType || row.EvidenceType || row.ApprovedExceptionId || '-';
}

function exceptionSubject(row) {
  if (row.MemberSam || row.MemberDisplay) {
    return `${esc(row.MemberSam || '-')}${row.MemberDisplay ? `<br><small class="sub">${esc(row.MemberDisplay)}</small>` : ''}`;
  }
  if (row.GpoFindingId) {
    const parts = [row.FindingType, row.DelegatedRight, row.ScopeName].filter(Boolean).join(' / ');
    return `${esc(parts || row.GpoFindingId)}<br><small class="sub">${esc(row.FileSystemPath || row.GpoGuid || '')}</small>`;
  }
  if (row.AclFindingId) {
    const parts = [row.NormalizedRight, row.TrusteeName, row.TargetName].filter(Boolean).join(' / ');
    return `${esc(parts || row.AclFindingId)}<br><small class="sub">${esc(row.TargetDistinguishedName || row.TrusteeSid || '')}</small>`;
  }
  return esc(row.ApprovedExceptionId || '-');
}

const sortState = {};

function getCellSortValue(cell) {
  const text = (cell.textContent || '').trim();
  const numeric = Number(text.replace(/,/g, '').match(/-?\d+(\.\d+)?/)?.[0]);
  return Number.isFinite(numeric) && /^[-\d\s.,/]+$/.test(text) ? numeric : text.toLowerCase();
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
  ['exceptions-review-table'].forEach(tableId => {
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

function render(state) {
  const active = (state.exceptions || []).filter(x => (x.ApprovedExceptionStatus || 'Active') !== 'Expired').length;
  const expired = (state.exceptions || []).filter(x => x.ApprovedExceptionStatus === 'Expired').length;
  const expiring = (state.exceptions || []).filter(x => x.ApprovedExceptionStatus !== 'Expired' && isExpiringSoon(x.ApprovedExceptionExpiresAt)).length;
  const acceptedScore = (state.exceptions || []).reduce((sum, x) => sum + Number(x.RiskScore || 0), 0);
  const missingGovernance = (state.exceptions || []).filter(x =>
    !x.ApprovedExceptionOwner || !x.ApprovedExceptionApprovedBy || !x.ApprovedExceptionTicket || !x.ApprovedExceptionReason
  ).length;
  document.getElementById('exc-active').textContent = active;
  document.getElementById('exc-expired').textContent = expired;
  document.getElementById('exc-expiring').textContent = expiring;
  document.getElementById('exc-score').textContent = acceptedScore.toFixed(2);
  document.getElementById('exc-missing').textContent = missingGovernance;
  const reviewTarget = document.getElementById('exc-review-target');
  const reviewCount = expired + expiring + missingGovernance;
  reviewTarget.textContent = reviewCount ? `${reviewCount} need review` : 'No reviews due';
  reviewTarget.className = `value ${reviewCount ? 'danger' : 'ok'}`;

  const exceptionsBody = document.querySelector('#exceptions-review-table tbody');
  exceptionsBody.innerHTML = (state.exceptions || []).length
    ? (state.exceptions || []).map(f => `
      <tr>
        <td>${badge(f.ApprovedExceptionStatus)}</td>
        <td>${esc(exceptionScope(f))}</td>
        <td>${exceptionSubject(f)}</td>
        <td>${Number(f.RiskScore || 0).toFixed(2)}</td>
        <td>${esc(f.ApprovedExceptionOwner || '-')}</td>
        <td>${esc(f.ApprovedExceptionApprovedBy || '-')}</td>
        <td>${esc(f.ApprovedExceptionTicket || '-')}</td>
        <td>${esc(f.ApprovedExceptionExpiresAt || 'No expiry')}</td>
        <td class="wrap">${esc(f.ApprovedExceptionReason || f.ExclusionReason || '-')}</td>
      </tr>`).join('')
    : '<tr><td colspan="9" class="sub">No approved exceptions found.</td></tr>';
  applySorts();
  if (typeof window.updateSidebar === 'function') {
    window.updateSidebar(state.meta, (state.exceptions || []).length);
  }
}

window.ADPostureDashboard.setupJsonImport({
  inputId: 'exceptions-file',
  hintId: 'exceptions-hint',
  onData: raw => render(normalizeState(raw))
});

document.getElementById('exceptions-print')?.addEventListener('click', () => window.print());
setupSortHandlers();

loadData().then(state => {
  if ((state.exceptions || []).length) {
    document.getElementById('exceptions-hint').style.display = 'none';
  } else {
    document.getElementById('exceptions-hint').textContent = 'No approved business exceptions loaded. Add governed exceptions or load a dashboard JSON with approved exceptions.';
  }
  render(state);
});
