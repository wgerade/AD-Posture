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
    'trust.html': 'Trusts',
    'dns.html': 'DNS',
    'gpo.html': 'GPO',
    'acl.html': 'ACL',
    'exceptions.html': 'Exceptions',
    'timeline.html': 'Timeline',
    'executive.html': 'Executive'
  };

  const pageNarrative = {
    'index.html': 'Action Plan is the operator landing page: score, readiness, filters, remediation batches, accounts, groups, access paths, and safe scripts.',
    'objects.html': 'AD Objects consolidates identities, groups, computers, GPOs, OUs, and posture evidence into object-level profiles.',
    'adcs.html': 'ADCS reviews certificate templates, published CAs, enrollment exposure, control delegation, and ESC-style attack paths.',
    'auth.html': 'Kerberos highlights roastable principals, weak encryption, delegation exposure, and privileged service accounts.',
    'trusts.html': 'Trusts reviews cross-boundary relationships, SID filtering, selective authentication, trust direction, and trust type.',
    'trust.html': 'Trusts reviews cross-boundary relationships, SID filtering, selective authentication, trust direction, and trust type.',
    'dns.html': 'DNS reviews zone configuration, dynamic updates, wildcard records, stale records, and control-path risk.',
    'gpo.html': 'GPO reviews policy delegation, SYSVOL evidence, preference exposure, scripts, links, scope, and WMI filter dependencies.',
    'acl.html': 'ACL reviews dangerous ACEs, unexpected owners, inheritance, drift, effective trustees, and sensitive targets.',
    'exceptions.html': 'Exceptions separates accepted risk from active remediation with owner, approver, ticket, reason, and expiry context.',
    'timeline.html': 'Timeline compares snapshots so teams can explain score movement, new exposure, remediated findings, and changed risk.',
    'executive.html': 'Executive converts technical posture evidence into a leadership-ready risk and remediation summary.'
  };

  const manualSteps = {
    'index.html': [
      ['.score-hero', 'Exposure score', 'Current cumulative AD posture score, target score, domain, progress toward zero, and the first recommended fix.'],
      ['.kpi-grid', 'Action Plan KPIs', 'Readiness, actionable findings, tier exposure, exceptions, and report timing from the loaded dataset.'],
      ['.topbar-tabs', 'Action Plan tabs', 'The existing tabs expose Fix now, Insights, Readiness, Accounts, Groups, and Paths in the real dashboard.'],
      ['#actions-panel', 'Fix now', 'Batches remediation actions by score reduction and review surface.'],
      ['#insights-panel', 'Insights', 'Visual summary of tiering, effort, account mix, and top groups by exposure.'],
      ['#readiness-panel', 'Readiness scorecard', 'Control-oriented status for remediation planning.'],
      ['#accounts-panel', 'Account exposure', 'Identities ranked by repeated appearance across sensitive paths.'],
      ['#groups-panel', 'Group exposure', 'Sensitive groups ranked by aggregate exposure.'],
      ['#members-panel', 'Access paths', 'Operational findings with score, member, group, tier, chain, reason, fix, and details.'],
      ['#playbooks-panel', 'Safe playbooks', 'Cross-domain remediation queue for sensitive group, ACL, GPO, ADCS, DNS, and related findings.'],
      ['#script-panel', 'Remediation script', 'Review-ready PowerShell output for deterministic changes, with unsafe or ambiguous cases blocked.']
    ],
    'objects.html': [
      ['.grid', 'Object metrics', 'Object count, critical/high objects, Tier 0 objects, evidence rows, relationships, and highest score.'],
      ['#objects-table', 'AD object queue', 'Object-level risk queue sorted by cumulative score.'],
      ['#object-profile', 'Object profile', 'Selected-object evidence, relationships, tags, and remediation context.']
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
      .tour-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.50);z-index:9990;pointer-events:none}
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

  function commonSteps() {
    return [
      ['.sidebar', 'Navigation shell', 'This is the existing AD Posture dashboard navigation. The tour is only a walkthrough layer; it does not replace the current HTML.'],
      ['.sb-domain', 'Dataset context', 'Shows the domain, last run timestamp, score target, and progress context from the loaded report data.'],
      ['.topbar', 'Current screen controls', 'The real topbar stays available for imports, filters, tabs, theme switching, and page-specific actions.'],
      ['.security-banner', 'Local data warning', 'The dashboard can contain sensitive AD evidence such as DNs, SIDs, privileged paths, ownership, and remediation intent.']
    ];
  }

  function dynamicContentSteps() {
    const steps = [];
    const seen = new Set();
    const candidates = Array.from(document.querySelectorAll('.grid, .kpi-grid, .score-hero, .toolbar, .topbar-tabs, section.panel, .focus-panel, table, .object-profile'));

    candidates.forEach((element, index) => {
      if (!element || !isUseful(element) || seen.has(element)) return;
      seen.add(element);
      if (!element.id) element.dataset.tourAutoId = element.dataset.tourAutoId || `auto-${index}`;
      const selector = element.id ? `#${cssEscape(element.id)}` : `[data-tour-auto-id="${element.dataset.tourAutoId}"]`;
      steps.push([selector, titleFor(element), textFor(element, titleFor(element))]);
    });

    return steps;
  }

  function stepsForCurrentPage() {
    const first = [
      ['.content', pageLabels[page] || 'Dashboard screen', pageNarrative[page] || 'This screen is part of the existing AD Posture dashboard and is included in the guided tour.']
    ];
    const merged = first.concat(commonSteps(), manualSteps[page] || [], dynamicContentSteps());
    return dedupeSteps(merged).filter(step => getTarget(step[0]));
  }

  function dedupeSteps(steps) {
    const used = new Set();
    return steps.filter(step => {
      const target = getTarget(step[0]);
      if (!target) return false;
      const key = target.id || target.dataset.tourAutoId || step[0];
      if (used.has(key)) return false;
      used.add(key);
      return true;
    });
  }

  function isUseful(element) {
    if (element.hidden) return false;
    if (element.offsetParent === null && element.tagName !== 'TABLE') return false;
    const text = (element.textContent || '').trim();
    return text.length > 0 || element.querySelector('tbody, input, select, button');
  }

  function titleFor(element) {
    const heading = element.querySelector('h1,h2,h3,.page-title,.kpi-label,.score-kpi-label');
    if (heading?.textContent?.trim()) return heading.textContent.trim();
    if (element.matches('table')) return 'Data table';
    if (element.matches('.toolbar')) return 'Filters';
    if (element.matches('.topbar-tabs')) return 'Tabs';
    if (element.matches('.grid,.kpi-grid')) return 'Summary cards';
    if (element.matches('.score-hero')) return 'Exposure summary';
    return pageLabels[page] || 'Dashboard content';
  }

  function textFor(element, title) {
    const sub = element.querySelector('.sub,p');
    if (sub?.textContent?.trim()) return sub.textContent.trim();
    if (element.matches('table')) return `This table is part of the ${pageLabels[page] || 'current'} screen and displays the loaded fake/demo or imported report data.`;
    if (element.matches('.toolbar')) return 'These filters are native to the current screen and change the real table content, not a separate tour copy.';
    if (element.matches('.grid,.kpi-grid')) return `These cards summarize the loaded ${pageLabels[page] || 'dashboard'} dataset.`;
    return `${title} is an existing element of the real ${pageLabels[page] || 'dashboard'} screen.`;
  }

  function cssEscape(value) {
    if (window.CSS?.escape) return CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
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
