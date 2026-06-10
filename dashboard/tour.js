/* AD Posture guided tour for the existing dashboard UI. */
(function () {
  'use strict';

  const page = document.body?.dataset?.page || location.pathname.split('/').pop() || 'index.html';
  const storageKey = 'adposture_tour_state';
  const autoStartDismissedKey = 'adposture_tour_autostart_dismissed';
  const orderedPages = ['index.html', 'objects.html', 'adcs.html', 'auth.html', 'trusts.html', 'dns.html', 'gpo.html', 'acl.html', 'exceptions.html', 'timeline.html', 'executive.html'];

  const pageLabels = {
    'index.html': 'Action Plan',
    'objects.html': 'AD Objects',
    'adcs.html': 'ADCS',
    'auth.html': 'Kerberos',
    'trusts.html': 'Trusts',
    'dns.html': 'DNS',
    'gpo.html': 'GPO',
    'acl.html': 'ACL',
    'exceptions.html': 'Exceptions',
    'timeline.html': 'Timeline',
    'executive.html': 'Executive'
  };

  const curatedSteps = {
    'index.html': [
      ['.content', 'Action Plan overview', 'This is the main remediation workspace. It summarizes exposure, prioritizes fixes, and links operational findings to safe remediation actions.'],
      ['.score-hero', 'Exposure score and first fix', 'Start here to understand the current score, the target, and the highest-priority action to reduce exposure.'],
      ['.kpi-grid', 'Executive posture indicators', 'These cards summarize readiness, actionable findings, tier exposure, and exception status.'],
      ['.topbar-tabs', 'Action Plan sections', 'Use these tabs to move between fix batches, insight charts, readiness, accounts, groups, and access paths.'],
      ['#actions-panel', 'Fix now queue', 'Grouped remediation moves are sorted by score reduction so the operator can act on the highest-impact fixes first.'],
      ['#readiness-panel', 'Readiness scorecard', 'This translates technical findings into control status for remediation planning and stakeholder reporting.'],
      ['#accounts-panel', 'Account exposure', 'This view ranks identities that appear across multiple sensitive paths.'],
      ['#groups-panel', 'Group exposure', 'This view identifies which sensitive groups are driving the largest aggregate exposure.'],
      ['#members-panel', 'Access paths', 'This is the detailed operational queue with member, group, tier, chain, reason, difficulty, and remediation context.'],
      ['#playbooks-panel', 'Safe playbooks', 'This centralizes remediation work across sensitive groups, ACL, GPO, ADCS, DNS, and related findings.']
    ],
    'objects.html': [
      ['.content', 'AD Objects overview', 'This page consolidates object-level exposure across users, groups, computers, GPOs, OUs, and related evidence.'],
      ['.grid', 'Object metrics', 'These cards show the number of objects, critical/high exposure, Tier 0 scope, evidence rows, relationships, and highest score.'],
      ['#objects-table', 'Object risk queue', 'Objects are ranked by cumulative risk so investigation can start with the identities and resources that matter most.'],
      ['#object-profile', 'Object profile', 'Selecting an object opens its evidence, relationships, tags, and remediation context.']
    ],
    'adcs.html': [
      ['.content', 'ADCS overview', 'This page reviews certificate services posture, including risky templates, CA exposure, enrollment risk, and control delegation.'],
      ['.grid', 'ADCS metrics', 'These cards summarize certificate template and CA exposure using the loaded synthetic or imported data.'],
      ['table', 'ADCS findings', 'Findings highlight certificate template escalation paths, authentication EKUs, enrollment permissions, and recommended remediation.']
    ],
    'auth.html': [
      ['.content', 'Kerberos overview', 'This page focuses on Kerberos and authentication exposure for service accounts and privileged identities.'],
      ['.grid', 'Kerberos metrics', 'These cards summarize roastable principals, weak encryption, delegation exposure, and privileged service-account risk.'],
      ['table', 'Kerberos findings', 'Findings include principal context, delegation type, SPNs, encryption exposure, score, reason, and remediation guidance.']
    ],
    'trusts.html': [
      ['.content', 'Trusts overview', 'This page reviews cross-boundary exposure between domains or forests.'],
      ['.grid', 'Trust metrics', 'These cards summarize trust direction, type, filtering, authentication controls, and boundary risk.'],
      ['table', 'Trust findings', 'Findings highlight SID filtering, selective authentication, bidirectional paths, and remediation guidance.']
    ],
    'dns.html': [
      ['.content', 'DNS overview', 'This page reviews DNS posture and control paths that can affect internal routing and discovery.'],
      ['.grid', 'DNS metrics', 'These cards summarize insecure dynamic updates, wildcard records, stale records, and zone-level exposure.'],
      ['table', 'DNS findings', 'Findings include zone, record, parsed evidence, principal, risk reason, and remediation guidance.']
    ],
    'gpo.html': [
      ['.content', 'GPO overview', 'This page reviews policy control paths that can affect privileged computers and users.'],
      ['.grid', 'GPO metrics', 'These cards summarize GPO delegation, credential exposure, scripts, links, scope, and WMI filter dependencies.'],
      ['table', 'GPO findings', 'Findings show policy name, scope, delegated right, severity, reason, score formula, and remediation.']
    ],
    'acl.html': [
      ['.content', 'ACL overview', 'This page reviews dangerous permissions, unexpected owners, inheritance, and sensitive object control paths.'],
      ['.grid', 'ACL metrics', 'These cards summarize ACL exposure by severity, target, trustee, ownership, and remediation surface.'],
      ['table', 'ACL findings', 'Findings show trustee, target, right, inheritance, reason, score, and remediation guidance.']
    ],
    'exceptions.html': [
      ['.content', 'Exceptions overview', 'This page separates accepted risk from normal remediation so exceptions remain governed, visible, and time-bound.'],
      ['.grid', 'Exception metrics', 'These cards show active exceptions, expired exceptions, expiring exceptions, accepted exposure, missing governance, and review target.'],
      ['#exceptions-review-table', 'Approved exceptions table', 'Each exception includes status, scope, finding, score, owner, approver, ticket, expiry, and reason.']
    ],
    'timeline.html': [
      ['.content', 'Timeline overview', 'This page compares posture snapshots to show whether remediation is reducing exposure over time.'],
      ['#timeline-delta-summary', 'Delta summary', 'This explains the score movement between the previous and current assessment.'],
      ['.grid', 'Timeline metrics', 'These cards show previous score, current score, delta, added members, removed members, changed scores, and ACL movement.'],
      ['#history-chart', 'Exposure trend', 'The trend view shows score movement across captured audits.'],
      ['#timeline-added', 'Added since baseline', 'Newly introduced exposure appears here for investigation.'],
      ['#timeline-removed', 'Removed findings', 'Remediated items appear here to show progress.'],
      ['#timeline-changed', 'Risk score changes', 'Changed findings show where exposure increased or decreased without being fully added or removed.']
    ],
    'executive.html': [
      ['.content', 'Executive overview', 'This page converts technical AD posture evidence into a leadership-ready risk and remediation summary.'],
      ['.grid', 'Executive indicators', 'These cards summarize score, readiness, finding count, exceptions, and remediation priority for quick reporting.'],
      ['#exec-actions-table', 'Top remediation moves', 'This table groups the highest-impact remediation actions for leadership and planning conversations.'],
      ['#exec-top-groups', 'Top groups by exposure', 'This ranking shows which groups contribute most to the current exposure picture.'],
      ['.executive-methodology', 'Interpretation', 'This section clarifies that the score is an internal prioritization index, not a certification or external benchmark.']
    ]
  };

  let state = { active: false, stepIndex: 0 };
  let card;
  let backdrop;
  let activeTarget;

  function installStyles() {
    if (document.getElementById('adposture-tour-style')) return;
    const style = document.createElement('style');
    style.id = 'adposture-tour-style';
    style.textContent = `
      .tour-start-button{margin-left:.5rem;border:1px solid var(--border,#2b3b55);background:var(--surface-2,#142033);color:var(--text,#e5eefb);border-radius:999px;padding:.55rem .8rem;font-weight:700;cursor:pointer}
      .tour-start-button:hover{filter:brightness(1.12)}
      .tour-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.46);z-index:9990;pointer-events:none}
      .tour-focus{position:relative;z-index:9992;outline:3px solid #38bdf8;outline-offset:4px;box-shadow:0 0 0 8px rgba(56,189,248,.18)!important;border-radius:10px}
      .tour-card{position:fixed;z-index:9993;width:min(430px,calc(100vw - 28px));max-height:min(360px,calc(100vh - 28px));overflow:auto;border:1px solid rgba(56,189,248,.45);background:var(--surface,#0b1220);color:var(--text,#e5eefb);border-radius:16px;padding:14px 16px;box-shadow:0 20px 70px rgba(0,0,0,.42);transition:top .18s ease,left .18s ease,opacity .12s ease}
      .tour-card[data-placement="right"]{border-left:4px solid #38bdf8}.tour-card[data-placement="left"]{border-right:4px solid #38bdf8}.tour-card[data-placement="bottom"]{border-top:4px solid #38bdf8}.tour-card[data-placement="top"]{border-bottom:4px solid #38bdf8}
      .tour-card small{color:var(--muted,#93a4ba);font-weight:800;text-transform:uppercase;letter-spacing:.08em}.tour-card h3{margin:.35rem 0;font-size:1.05rem}.tour-card p{color:var(--muted,#93a4ba);line-height:1.5;margin:.2rem 0 .85rem}.tour-actions{display:flex;gap:.5rem;justify-content:flex-end;flex-wrap:wrap}.tour-actions button{border:1px solid var(--border,#2b3b55);border-radius:999px;padding:.55rem .75rem;background:var(--surface-2,#142033);color:var(--text,#e5eefb);font-weight:700;cursor:pointer}.tour-actions button.primary{background:#2563eb;border-color:#2563eb}.tour-actions button:disabled{opacity:.45;cursor:not-allowed}
      @media (max-width:700px){.tour-card{width:calc(100vw - 16px);padding:12px}.tour-actions{justify-content:flex-start}}
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

  function stepsForCurrentPage() {
    return (curatedSteps[page] || curatedSteps['index.html']).filter(step => getTarget(step[0]));
  }

  function getTarget(selector) {
    return selector.split(',').map(s => document.querySelector(s.trim())).find(Boolean) || null;
  }

  function persist() {
    try { sessionStorage.setItem(storageKey, JSON.stringify(state)); } catch (_) { /* no-op */ }
  }

  function readPersisted() {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
      if (parsed?.active) state = { ...state, ...parsed };
    } catch (_) { /* no-op */ }
  }

  function hasAutoStartBeenDismissed() {
    try { return sessionStorage.getItem(autoStartDismissedKey) === '1'; }
    catch (_) { return false; }
  }

  function markAutoStartDismissed() {
    try { sessionStorage.setItem(autoStartDismissedKey, '1'); }
    catch (_) { /* no-op */ }
  }

  function startTour(continued) {
    state.active = true;
    if (!continued) state.stepIndex = 0;
    persist();
    renderStep();
  }

  function endTour() {
    state.active = false;
    state.stepIndex = 0;
    markAutoStartDismissed();
    try { sessionStorage.removeItem(storageKey); } catch (_) { /* no-op */ }
    document.querySelectorAll('.tour-focus').forEach(el => el.classList.remove('tour-focus'));
    backdrop?.remove();
    card?.remove();
    backdrop = null;
    card = null;
    activeTarget = null;
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
    if (!steps.length) return endTour();
    state.stepIndex = Math.min(state.stepIndex, steps.length - 1);
    const step = steps[state.stepIndex];
    const target = getTarget(step[0]) || document.querySelector('.content') || document.body;
    activeTarget = target;
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

    const pageNumber = Math.max(1, orderedPages.indexOf(page) + 1);
    const isLastStepOnPage = state.stepIndex >= steps.length - 1;
    const hasNextPage = orderedPages.indexOf(page) >= 0 && orderedPages.indexOf(page) < orderedPages.length - 1;
    card.style.opacity = '0';
    card.innerHTML = `
      <small>${pageLabels[page] || page} • screen ${pageNumber} of ${orderedPages.length} • step ${state.stepIndex + 1} of ${steps.length}</small>
      <h3>${escapeHtml(step[1])}</h3>
      <p>${escapeHtml(step[2])}</p>
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

    window.setTimeout(() => positionCard(target), 220);
  }

  function positionCard(target) {
    if (!card || !target) return;
    const margin = 14;
    const gap = 14;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const targetRect = target.getBoundingClientRect();
    const cardRect = card.getBoundingClientRect();

    const space = {
      right: viewportWidth - targetRect.right - gap - margin,
      left: targetRect.left - gap - margin,
      bottom: viewportHeight - targetRect.bottom - gap - margin,
      top: targetRect.top - gap - margin
    };

    const placements = [
      { name: 'right', fits: space.right >= cardRect.width, left: targetRect.right + gap, top: center(targetRect.top, targetRect.bottom, cardRect.height) },
      { name: 'left', fits: space.left >= cardRect.width, left: targetRect.left - cardRect.width - gap, top: center(targetRect.top, targetRect.bottom, cardRect.height) },
      { name: 'bottom', fits: space.bottom >= cardRect.height, left: center(targetRect.left, targetRect.right, cardRect.width), top: targetRect.bottom + gap },
      { name: 'top', fits: space.top >= cardRect.height, left: center(targetRect.left, targetRect.right, cardRect.width), top: targetRect.top - cardRect.height - gap }
    ];

    let placement = placements.find(option => option.fits);
    if (!placement) {
      const largest = Object.entries(space).sort((a, b) => b[1] - a[1])[0]?.[0] || 'bottom';
      placement = placements.find(option => option.name === largest) || placements[2];
    }

    const left = clamp(placement.left, margin, viewportWidth - cardRect.width - margin);
    const top = clamp(placement.top, margin, viewportHeight - cardRect.height - margin);
    card.dataset.placement = placement.name;
    card.style.left = `${left}px`;
    card.style.top = `${top}px`;
    card.style.transform = 'none';
    card.style.opacity = '1';
  }

  function center(start, end, size) {
    return start + ((end - start) / 2) - (size / 2);
  }

  function clamp(value, min, max) {
    if (max < min) return min;
    return Math.max(min, Math.min(max, value));
  }

  function escapeHtml(value) {
    return String(value || '').replace(/[&<>"']/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  function init() {
    installStyles();
    addButton();
    readPersisted();
    if (state.active) {
      setTimeout(() => startTour(true), 350);
      return;
    }
    if (page === 'index.html' && !hasAutoStartBeenDismissed()) {
      setTimeout(() => startTour(false), 700);
    }
  }

  window.addEventListener('resize', () => {
    if (state.active && activeTarget) positionCard(activeTarget);
  });
  window.addEventListener('scroll', () => {
    if (state.active && activeTarget) window.requestAnimationFrame(() => positionCard(activeTarget));
  }, true);

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
