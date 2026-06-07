/**
 * Shared dashboard shell behaviors.
 */
(function () {
  'use strict';

  function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function esc(value) {
    if (value == null) return '';
    return String(value).replace(/[&<>"']/g, char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[char]));
  }

  function scoreClass(value) {
    const score = Number(value || 0);
    if (score <= 0.5) return 'score-0';
    if (score < 5) return 'score-low';
    if (score < 15) return 'score-mid';
    return 'score-high';
  }

  function normalizeMetadata(payload) {
    const source = payload || {};
    const meta = source.meta || source.Meta || {};
    return {
      domain: meta.domain ?? source.Domain ?? '',
      forest: meta.forest ?? source.Forest ?? '',
      timestamp: meta.timestamp ?? source.Timestamp ?? '',
      overallRiskScore: meta.overallRiskScore ?? source.OverallRiskScore ?? 0,
      targetScore: meta.targetScore ?? source.TargetScore ?? 0,
      actionableCount: meta.actionableCount ?? source.ActionableCount ?? 0,
      approvedExceptionCount: meta.approvedExceptionCount ?? source.ApprovedExceptionCount ?? 0,
      expiredExceptionCount: meta.expiredExceptionCount ?? source.ExpiredExceptionCount ?? 0,
      readiness: meta.readiness || source.ReadinessScorecard || null
    };
  }

  function normalizeReadiness(value) {
    const readiness = value || {};
    return {
      ...readiness,
      Controls: readiness.Controls || readiness.controls || []
    };
  }

  const themeKey = 'adaudit_theme';
  const storedTheme = (() => {
    try {
      return localStorage.getItem(themeKey);
    } catch (_) {
      return null;
    }
  })();
  const initialTheme = storedTheme === 'light' || storedTheme === 'dark' ? storedTheme : 'dark';
  document.documentElement.dataset.theme = initialTheme;

  function setTheme(theme) {
    const nextTheme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nextTheme;
    try {
      localStorage.setItem(themeKey, nextTheme);
    } catch (_) {
      /* Keep the theme for this render only when storage is unavailable. */
    }
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.textContent = nextTheme === 'light' ? 'Switch to dark' : 'Switch to light';
      button.setAttribute('aria-pressed', nextTheme === 'light' ? 'true' : 'false');
    });
  }

  const currentFile = document.body?.dataset?.page || location.pathname.split('/').pop() || 'index.html';
  const filterStoragePrefix = `adaudit_filters_${currentFile}_`;
  const sidebarKey = 'adaudit_sidebar_collapsed';

  function applySidebarState(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    document.querySelectorAll('[data-sidebar-toggle]').forEach(button => {
      button.setAttribute('aria-pressed', collapsed ? 'true' : 'false');
      button.textContent = collapsed ? 'Expand menu' : 'Collapse menu';
    });
  }

  const initialSidebarCollapsed = (() => {
    try { return sessionStorage.getItem(sidebarKey) === '1'; }
    catch (_) { return false; }
  })();
  applySidebarState(initialSidebarCollapsed);

  document.querySelectorAll('.sidebar').forEach(sidebar => {
    if (sidebar.querySelector('[data-sidebar-toggle]')) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'sidebar-toggle';
    button.dataset.sidebarToggle = 'true';
    button.addEventListener('click', () => {
      const collapsed = !document.body.classList.contains('sidebar-collapsed');
      applySidebarState(collapsed);
      try { sessionStorage.setItem(sidebarKey, collapsed ? '1' : '0'); }
      catch (_) { /* Collapse still works for this page load. */ }
    });
    sidebar.querySelector('.sb-header')?.appendChild(button);
    applySidebarState(document.body.classList.contains('sidebar-collapsed'));
  });

  document.querySelectorAll('.sb-item[href], nav a[href]').forEach(link => {
    const linkFile = (link.getAttribute('href') || '').split('/').pop();
    if (linkFile === currentFile) {
      link.classList.add('active');
      link.setAttribute('aria-current', 'page');
    }
  });

  const banner = document.querySelector('.security-banner');
  const storageKey = `adaudit_banner_dismissed_${currentFile}`;
  if (banner) {
    try {
      if (sessionStorage.getItem(storageKey)) {
        banner.style.display = 'none';
      }
    } catch (_) {
      /* Session storage can be unavailable in restricted browser contexts. */
    }

    if (banner.style.display !== 'none' && !banner.querySelector('.security-banner-close')) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = 'x';
      button.className = 'link-button security-banner-close';
      button.setAttribute('aria-label', 'Dismiss security notice');
      button.addEventListener('click', () => {
        banner.style.display = 'none';
        try {
          sessionStorage.setItem(storageKey, '1');
        } catch (_) {
          /* Dismiss for this render only when storage is unavailable. */
        }
      });
      banner.prepend(button);
    }
  }

  document.querySelectorAll('.topbar-right').forEach(container => {
    if (container.querySelector('[data-theme-toggle]')) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'theme-toggle';
    button.dataset.themeToggle = 'true';
    button.addEventListener('click', () => {
      setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
    });
    container.prepend(button);
  });
  setTheme(initialTheme);

  window.updateSidebar = function (meta, findingsCount) {
    if (!meta) return;

    const domainEl = document.getElementById('sb-domain');
    const lastRunEl = document.getElementById('sb-lastrun');
    const progressEl = document.getElementById('sb-progress');
    const targetEl = document.getElementById('sb-target');

    if (domainEl) domainEl.textContent = meta.domain || meta.Domain || '-';

    const timestamp = meta.timestamp || meta.Timestamp;
    if (lastRunEl && timestamp) {
      lastRunEl.textContent = 'Last run: ' + new Date(timestamp).toLocaleString('en-US', {
        month: 'numeric',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    }

    if (progressEl) {
      const score = Number(meta.overallRiskScore ?? meta.OverallRiskScore ?? 0);
      const pct = score <= 0
        ? 100
        : Math.max(0, Math.min(100, 100 - (Math.log10(score + 1) / 2) * 100));
      progressEl.style.width = pct.toFixed(1) + '%';
    }

    if (targetEl) {
      const target = Number(meta.targetScore ?? meta.TargetScore ?? 0);
      targetEl.textContent = Number.isFinite(target) ? target.toFixed(2) : '0.00';
      targetEl.classList.toggle('ok', target <= 0);
    }

    showDataAgeBanner(timestamp);
  };

  function showDataAgeBanner(timestamp) {
    if (!timestamp) return;
    const parsed = new Date(timestamp);
    if (Number.isNaN(parsed.getTime())) return;

    const ageDays = Math.floor((Date.now() - parsed.getTime()) / 86400000);
    let staleBanner = document.querySelector('[data-stale-data-banner]');
    if (ageDays <= 7) {
      staleBanner?.remove();
      return;
    }

    if (!staleBanner) {
      staleBanner = document.createElement('div');
      staleBanner.className = 'security-banner stale-data-banner';
      staleBanner.dataset.staleDataBanner = 'true';
      document.body.prepend(staleBanner);
    }
    staleBanner.textContent = `Data is stale: last audit was ${ageDays} days ago. Re-run Invoke-ADPostureAudit before using this view for decisions.`;
  }

  let auditDataPromise;

  async function loadAuditData(urls = ['latest-dashboard.json', '../reports/latest-dashboard.json']) {
    if (window.__AD_AUDIT_DATA__) return window.__AD_AUDIT_DATA__;
    if (!auditDataPromise) {
      auditDataPromise = (async () => {
        for (const url of urls) {
          try {
            const response = await fetch(url);
            if (response.ok) return response.json();
          } catch (_) {
            /* file:// and unavailable fallbacks are expected. */
          }
        }
        return null;
      })();
    }
    return auditDataPromise;
  }

  function showPageImportNotice(fileName, hintId) {
    const hint = document.getElementById(hintId);
    if (!hint) return;
    hint.textContent = `Audit report imported for this page only: ${fileName}. It was not stored in this browser.`;
    hint.classList.remove('error');
    hint.classList.add('success');
    hint.style.display = '';
  }

  function setupJsonImport({ inputId, hintId, onData }) {
    document.getElementById(inputId)?.addEventListener('change', async event => {
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        const parsed = JSON.parse(await file.text());
        await onData(parsed);
        showPageImportNotice(file.name, hintId);
      } catch (error) {
        const hint = document.getElementById(hintId);
        if (hint) {
          hint.textContent = `Could not import report: ${error?.message || error}`;
          hint.classList.add('error');
          hint.style.display = '';
        }
      } finally {
        event.target.value = '';
      }
    });
  }

  async function copyText(text, button) {
    const original = button?.textContent;
    try {
      await navigator.clipboard.writeText(String(text || ''));
      if (button) button.textContent = 'Copied';
      return true;
    } catch (_) {
      if (button) button.textContent = 'Copy failed';
      return false;
    } finally {
      if (button) setTimeout(() => { button.textContent = original; }, 1800);
    }
  }

  function updateSortHeaders(selector, column, direction) {
    document.querySelectorAll(selector).forEach(header => {
      const active = header.dataset.sort === column;
      header.classList.toggle('sorted-asc', active && direction === 'asc');
      header.classList.toggle('sorted-desc', active && direction === 'desc');
      if (active) header.setAttribute('aria-sort', direction === 'asc' ? 'ascending' : 'descending');
      else header.removeAttribute('aria-sort');
    });
  }

  window.ADPostureDashboard = {
    debounce,
    esc,
    scoreClass,
    normalizeMetadata,
    normalizeReadiness,
    loadAuditData,
    setupJsonImport,
    showPageImportNotice,
    copyText,
    updateSortHeaders,
    actionPlanLink(findingOrPlaybook) {
      const playbookId = findingOrPlaybook?.PlaybookId || findingOrPlaybook?.playbookId;
      const findingId = findingOrPlaybook?.FindingId || findingOrPlaybook?.findingId;
      const query = playbookId ? `playbook=${encodeURIComponent(playbookId)}` : findingId ? `finding=${encodeURIComponent(findingId)}` : '';
      return `index.html${query ? `?${query}` : '#actions-panel'}`;
    },
    noDataMessage() {
      return [
        'No audit report loaded.',
        '',
        'Next step:',
        '  Import-Module .\\ADPosture.psd1 -Force',
        '  Invoke-ADPostureAudit -Verbose',
        '  Open-ADPostureDashboard -View Current',
        '',
        'Or import an existing dashboard JSON file.'
      ].join('\n');
    },
    showDataAgeBanner
  };

  function restorePersistentFilters() {
    document.querySelectorAll('input[id], select[id], textarea[id]').forEach(control => {
      const type = (control.getAttribute('type') || '').toLowerCase();
      if (type === 'file' || type === 'button' || type === 'submit' || type === 'reset' || type === 'hidden') return;

      const key = filterStoragePrefix + control.id;
      try {
        const stored = sessionStorage.getItem(key);
        if (stored !== null) control.value = stored;
      } catch (_) {
        return;
      }

      const save = () => {
        try {
          sessionStorage.setItem(key, control.value || '');
        } catch (_) {
          /* Filters still work when storage is unavailable. */
        }
      };
      control.addEventListener('input', save);
      control.addEventListener('change', save);
    });
  }

  restorePersistentFilters();

  document.addEventListener('click', event => {
    const clearButton = event.target?.closest?.('.btn-clear-filters, #clear-filters, [data-clear-filter]');
    if (!clearButton) return;
    setTimeout(() => {
      document.querySelectorAll('input[id], select[id], textarea[id]').forEach(control => {
        const type = (control.getAttribute('type') || '').toLowerCase();
        if (type === 'file' || type === 'button' || type === 'submit' || type === 'reset' || type === 'hidden') return;
        try {
          sessionStorage.setItem(filterStoragePrefix + control.id, control.value || '');
        } catch (_) {
          /* Ignore storage cleanup failures. */
        }
      });
    }, 0);
  });

})();
