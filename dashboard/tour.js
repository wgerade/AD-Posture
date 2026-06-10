/* AD Posture guided tour for the existing dashboard UI. */
(function () {
  'use strict';

  const page = document.body?.dataset?.page || location.pathname.split('/').pop() || 'index.html';
  const storageKey = 'adposture_tour_state';
  const orderedPages = ['index.html', 'objects.html', 'adcs.html', 'auth.html', 'trusts.html', 'dns.html', 'gpo.html', 'acl.html', 'exceptions.html', 'timeline.html', 'executive.html'];

  const pageLabels = {
    'index.html': 'Action Plan',
    'objects.html': 'AD Objects',
    'adcs.html': 'ADCS',
    'auth.html': 'Kerberos',
    'trusts.html': 'Trusts',
    'trust.html': 'Trusts',
    'dns.html': 'DNS',
    'gpo.html': 'GPO',
    'acl.html': 'ACL',
    'exceptions.html': 'Exceptions',
    'timeline.html': 'Timeline',
    'executive.html': 'Executive'
  };

  const pageSteps = {
    'index.html': [
      ['.score-hero', 'Exposure score', 'Shows the current cumulative AD posture score, target score, domain, and the first recommended remediation priority.'],
      ['.kpi-grid', 'Action plan KPIs', 'Summarizes readiness, actionable findings, privilege tier exposure, and exception status from the loaded dashboard dataset.'],
      ['.topbar-tabs', 'Action Plan sections', 'Switches between Fix now, Insights, Readiness, Accounts, Groups, and Paths without changing the underlying report data.'],
      ['#actions-panel', 'Fix now', 'Batches findings by remediation action so operators can reduce risk with the smallest review surface first.'],
      ['#insights-panel', 'Insights', 'Visualizes privilege tiers, remediation effort, account types, and top groups by exposure.'],
      ['#readiness-panel', 'Readiness scorecard', 'Converts technical findings into control-oriented status for remediation planning.'],
      ['#accounts-panel', 'Account exposure', 'Ranks identities that appear through multiple sensitive paths.'],
      ['#groups-panel', 'Group exposure', 'Ranks sensitive groups by aggregate exposure score.'],
      ['#members-panel', 'Access paths', 'Shows every operational finding with score math, UAC context, ATT&CK mapping, dates, and remediation guidance.'],
      ['#script-panel', 'Remediation script preview', 'Generates review-ready PowerShell snippets for deterministic changes; ambiguous work remains blocked for manual review.']
    ],
    'objects.html': [
      ['.grid', 'Object metrics', 'Summarizes object inventory, critical/high objects, Tier 0 objects, evidence rows, relationships, and highest score.'],
      ['#objects-table', 'AD object queue', 'Lists users, groups, computers, GPOs, OUs, and other objects by cumulative risk and evidence count.'],
      ['#object-profile', 'Object profile', 'Opens a selected object profile with evidence, relationships, tags, and remediation context.']
    ],
    'adcs.html': [
      ['.grid', 'ADCS metrics', 'Summarizes certificate services posture, risky templates, CA exposure, and published enrollment paths.'],
      ['table', 'ADCS findings', 'Reviews risky certificate templates, CA configuration, enrollment control, and ESC-style exposure patterns.']
    ],
    'auth.html': [
      ['.grid', 'Kerberos metrics', 'Summarizes authentication posture such as roastable principals, weak encryption, delegation, and privileged service accounts.'],
      ['table', 'Kerberos findings', 'Shows Kerberos/Auth findings with principal context, score, reason, and recommended remediation.']
    ],
    'trusts.html': [
      ['.grid', 'Trust metrics', 'Summarizes cross-domain or cross-forest trust posture and trust boundary risk.'],
      ['table', 'Trust findings', 'Reviews SID filtering, selective authentication, direction, type, and cross-boundary exposure.']
    ],
    'trust.html': [
      ['.grid', 'Trust metrics', 'Summarizes cross-domain or cross-forest trust posture and trust boundary risk.'],
      ['table', 'Trust findings', 'Reviews SID filtering, selective authentication, direction, type, and cross-boundary exposure.']
    ],
    'dns.html': [
      ['.grid', 'DNS metrics', 'Summarizes DNS zone and record posture such as insecure dynamic updates, wildcard records, and stale entries.'],
      ['table', 'DNS findings', 'Reviews zone configuration, records, parsed evidence, risk reason, and remediation guidance.']
    ],
    'gpo.html': [
      ['.grid', 'GPO metrics', 'Summarizes policy control paths, scope risk, scripts, preferences, links, and WMI filter dependencies.'],
      ['table', 'GPO findings', 'Shows GPO delegation, SYSVOL, preferences, scope, and remediation details.']
    ],
    'acl.html': [
      ['.grid', 'ACL metrics', 'Summarizes dangerous ACEs, unexpected owners, inheritance, drift, and sensitive targets.'],
      ['table', 'ACL findings', 'Reviews trustees, rights, targets, ownership, and why each delegated control path matters.']
    ],
    'exceptions.html': [
      ['.grid', 'Exception metrics', 'Summarizes approved, expired, and monitored exceptions tied to owners, approvers, tickets, and expiry dates.'],
      ['table', 'Exceptions table', 'Separates approved exception handling from normal remediation so accepted risk remains visible.']
    ],
    'timeline.html': [
      ['.grid', 'Timeline metrics', 'Shows score movement, added findings, removed findings, and changed risk since the previous assessment.'],
      ['table', 'Timeline comparison', 'Explains what changed between snapshots and helps validate remediation impact over time.']
    ],
    'executive.html': [
      ['.grid', 'Executive summary', 'Presents leadership-level risk, trend, and remediation status without requiring detailed AD investigation context.'],
      ['table', 'Executive evidence', 'Summarizes the reportable business story for audit, security leadership, and remediation owners.']
    ]
  };

  let state = { active: false, pageIndex: Math.max(0, orderedPages.indexOf(page)), stepIndex: 0 };
  let card;
  let backdrop;

  function installStyles() {
    if (document.getElementById('adposture-tour-style')) return;
    const style = document.createElement('style');
    style.id = 'adposture-tour-style';
    style.textContent = `
      .tour-start-button{margin-left:.5rem;border:1px solid var(--border,#2b3b55);background:var(--surface-2,#142033);color:var(--text,#e5eefb);border-radius:999px;padding:.55rem .8rem;font-weight:700;cursor:pointer}
      .tour-start-button:hover{filter:brightness(1.12)}
      .tour-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.62);z-index:9990;pointer-events:none}
      .tour-focus{position:relative;z-index:9992;outline:3px solid #38bdf8;outline-offset:4px;box-shadow:0 0 0 8px rgba(56,189,248,.18)!important;border-radius:10px}
      .tour-card{position:fixed;right:18px;bottom:18px;z-index:9993;width:min(440px,calc(100vw - 36px));border:1px solid rgba(56,189,248,.45);background:var(--surface,#0b1220);color:var(--text,#e5eefb);border-radius:16px;padding:16px;box-shadow:0 24px 80px rgba(0,0,0,.45)}
      .tour-card small{color:var(--muted,#93a4ba);font-weight:800;text-transform:uppercase;letter-spacing:.08em}
      .tour-card h3{margin:.45rem 0;font-size:1.05rem}.tour-card p{color:var(--muted,#93a4ba);line-height:1.55;margin:.25rem 0 1rem}.tour-actions{display:flex;gap:.5rem;justify-content:flex-end;flex-wrap:wrap}.tour-actions button{border:1px solid var(--border,#2b3b55);border-radius:999px;padding:.55rem .75rem;background:var(--surface-2,#142033);color:var(--text,#e5eefb);font-weight:700;cursor:pointer}.tour-actions button.primary{background:#2563eb;border-color:#2563eb}.tour-actions button:disabled{opacity:.45;cursor:not-allowed}
    `;
    document.head.appendChild(style);
  }

  function addButton() {
    const container = document.querySelector('.topbar-right') || document.querySelector('.topbar') || document.body;
    if (!container || container.querySelector('[data-adposture-tour-start]')) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'tour-start-button';
    button.dataset.adpostureTourStart = 'true';
    button.textContent = 'Start tour';
    button.addEventListener('click', () => startTour(false));
    container.prepend(button);
  }

  function commonSteps() {
    return [
      ['.sidebar', 'Navigation shell', 'This is the real AD Posture navigation used by the generated dashboard. The tour does not replace the UI; it explains the existing screens.'],
      ['.sb-domain', 'Loaded dataset context', 'Shows the domain and last run timestamp from the loaded audit or synthetic demo dataset.'],
      ['.security-banner', 'Local data warning', 'The dashboard is designed for local use because posture evidence may include sensitive AD paths, SIDs, DNs, and remediation intent.'],
      ['.toolbar, .topbar-tabs, .topbar-right', 'Filters and page controls', 'Each screen keeps its native filters, import control, tabs, and table interactions.']
    ];
  }

  function stepsForCurrentPage() {
    return commonSteps().concat(pageSteps[page] || [
      ['.content', pageLabels[page] || 'Dashboard screen', 'This screen is part of the existing AD Posture dashboard and is included in the guided tour.']
    ]);
  }

  function getTarget(selector) {
    return selector.split(',').map(s => document.querySelector(s.trim())).find(Boolean) || document.querySelector('.content') || document.body;
  }

  function persist() {
    try { sessionStorage.setItem(storageKey, JSON.stringify(state)); } catch (_) { /* no-op */ }
  }

  function readPersisted() {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
      if (parsed?.active) state = { ...state, ...parsed, pageIndex: Math.max(0, orderedPages.indexOf(page)) };
    } catch (_) { /* no-op */ }
  }

  function startTour(continued) {
    state.active = true;
    state.pageIndex = Math.max(0, orderedPages.indexOf(page));
    if (!continued) state.stepIndex = 0;
    persist();
    renderStep();
  }

  function endTour() {
    state.active = false;
    state.stepIndex = 0;
    try { sessionStorage.removeItem(storageKey); } catch (_) { /* no-op */ }
    document.querySelectorAll('.tour-focus').forEach(el => el.classList.remove('tour-focus'));
    backdrop?.remove();
    card?.remove();
    backdrop = null;
    card = null;
  }

  function goToPage(nextPage) {
    state.stepIndex = 0;
    state.active = true;
    persist();
    location.href = nextPage;
  }

  function renderStep() {
    installStyles();
    document.querySelectorAll('.tour-focus').forEach(el => el.classList.remove('tour-focus'));
    const steps = stepsForCurrentPage();
    const step = steps[Math.min(state.stepIndex, steps.length - 1)];
    const target = getTarget(step[0]);
    target.classList.add('tour-focus');
    target.scrollIntoView({ block: 'center', behavior: 'smooth' });

    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.className = 'tour-backdrop';
      document.body.appendChild(backdrop);
    }
    if (!card) {
      card = document.createElement('div');
      card.className = 'tour-card';
      card.setAttribute('role', 'dialog');
      card.setAttribute('aria-live', 'polite');
      document.body.appendChild(card);
    }

    const pageNumber = orderedPages.indexOf(page) + 1;
    const isLastStepOnPage = state.stepIndex >= steps.length - 1;
    const hasNextPage = orderedPages.indexOf(page) < orderedPages.length - 1;
    card.innerHTML = `
      <small>${pageLabels[page] || page} • screen ${pageNumber} of ${orderedPages.length} • step ${state.stepIndex + 1} of ${steps.length}</small>
      <h3>${step[1]}</h3>
      <p>${step[2]}</p>
      <div class="tour-actions">
        <button type="button" data-tour-stop>Close</button>
        <button type="button" data-tour-prev ${state.stepIndex === 0 ? 'disabled' : ''}>Back</button>
        <button type="button" class="primary" data-tour-next>${isLastStepOnPage ? (hasNextPage ? 'Next screen' : 'Finish') : 'Next'}</button>
      </div>
    `;

    card.querySelector('[data-tour-stop]').addEventListener('click', endTour);
    card.querySelector('[data-tour-prev]').addEventListener('click', () => {
      if (state.stepIndex > 0) {
        state.stepIndex -= 1;
        persist();
        renderStep();
      }
    });
    card.querySelector('[data-tour-next]').addEventListener('click', () => {
      if (!isLastStepOnPage) {
        state.stepIndex += 1;
        persist();
        renderStep();
        return;
      }
      const index = orderedPages.indexOf(page);
      if (index >= 0 && index < orderedPages.length - 1) goToPage(orderedPages[index + 1]);
      else endTour();
    });
  }

  function init() {
    installStyles();
    addButton();
    readPersisted();
    if (state.active) setTimeout(() => startTour(true), 250);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
