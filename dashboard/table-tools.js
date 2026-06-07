(function () {
  const STORAGE_PREFIX = 'adaudit_table_widths_';
  const resizeState = new Map();
  const sortState = new Map();
  let observerStarted = false;
  let enhanceQueued = false;

  function tableKey(table) {
    if (!table.id) {
      table.id = `table-${Math.random().toString(36).slice(2, 10)}`;
    }
    return table.id;
  }

  function storageKey(table) {
    return `${STORAGE_PREFIX}${tableKey(table)}`;
  }

  function loadStoredWidths(table) {
    const key = tableKey(table);
    if (resizeState.has(key)) return resizeState.get(key);
    try {
      const stored = localStorage.getItem(storageKey(table));
      if (!stored) return null;
      const parsed = JSON.parse(stored);
      if (!parsed || typeof parsed !== 'object') return null;
      resizeState.set(key, parsed);
      return parsed;
    } catch (_) {
      return null;
    }
  }

  function saveStoredWidths(table, widths) {
    resizeState.set(tableKey(table), widths);
    try {
      localStorage.setItem(storageKey(table), JSON.stringify(widths));
    } catch (_) {
      /* Column resizing still works when storage is unavailable. */
    }
  }

  function getCellValue(row, columnIndex) {
    const text = (row.cells[columnIndex]?.textContent || '').trim();
    const numberMatch = text.replace(/,/g, '').match(/^-?\d+(\.\d+)?/);
    if (numberMatch) return Number(numberMatch[0]);
    const date = Date.parse(text);
    if (!Number.isNaN(date) && /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4}/.test(text)) return date;
    return text.toLowerCase();
  }

  function sortTableByVisibleColumn(table, columnIndex) {
    const tbody = table.tBodies[0];
    if (!tbody) return;

    const key = tableKey(table);
    const current = sortState.get(key) || {};
    const direction = current.columnIndex === columnIndex && current.direction === 'asc' ? 'desc' : 'asc';
    sortState.set(key, { columnIndex, direction });

    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => {
      const aValue = getCellValue(a, columnIndex);
      const bValue = getCellValue(b, columnIndex);
      let result = 0;
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        result = aValue - bValue;
      } else {
        result = String(aValue).localeCompare(String(bValue), undefined, { numeric: true, sensitivity: 'base' });
      }
      return direction === 'asc' ? result : -result;
    });

    rows.forEach(row => tbody.appendChild(row));
    table.querySelectorAll('thead th').forEach((th, index) => {
      if (th.dataset.tableToolsSort !== 'generic') return;
      th.classList.toggle('sorted-asc', index === columnIndex && direction === 'asc');
      th.classList.toggle('sorted-desc', index === columnIndex && direction === 'desc');
      if (index === columnIndex) th.setAttribute('aria-sort', direction === 'asc' ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
    });
  }

  function applyColumnWidth(table, columnIndex, width) {
    const widths = loadStoredWidths(table) || {};
    widths[columnIndex] = width;
    saveStoredWidths(table, widths);

    Array.from(table.rows).forEach(row => {
      const cell = row.cells[columnIndex];
      if (!cell) return;
      cell.style.width = `${width}px`;
      cell.style.minWidth = `${width}px`;
    });

    const allWidths = Array.from(table.tHead?.rows[0]?.cells || []).map((cell, index) => {
      return widths[index] || Math.ceil(cell.getBoundingClientRect().width);
    });
    const total = allWidths.reduce((sum, value) => sum + value, 0);
    if (total > 0) {
      table.style.width = `${total}px`;
      table.style.maxWidth = 'none';
    }
  }

  function restoreColumnWidths(table) {
    const widths = loadStoredWidths(table);
    if (!widths) return;
    Object.entries(widths).forEach(([index, width]) => applyColumnWidth(table, Number(index), Number(width)));
  }

  function resetColumnWidth(table, columnIndex) {
    const widths = loadStoredWidths(table) || {};
    delete widths[columnIndex];
    saveStoredWidths(table, widths);

    Array.from(table.rows).forEach(row => {
      const cell = row.cells[columnIndex];
      if (!cell) return;
      cell.style.width = '';
      cell.style.minWidth = '';
    });

    if (!Object.keys(widths).length) {
      table.style.width = '';
      table.style.maxWidth = '';
      try {
        localStorage.removeItem(storageKey(table));
      } catch (_) {
        /* Ignore storage cleanup failures. */
      }
    }
  }

  function addResizeHandle(table, th, columnIndex) {
    if (th.querySelector(':scope > .column-resize-handle')) return;
    const handle = document.createElement('span');
    handle.className = 'column-resize-handle';
    handle.setAttribute('aria-hidden', 'true');
    handle.title = 'Drag to resize column. Double-click to reset.';
    th.appendChild(handle);

    handle.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
    });

    handle.addEventListener('dblclick', event => {
      event.preventDefault();
      event.stopPropagation();
      resetColumnWidth(table, columnIndex);
    });

    handle.addEventListener('pointerdown', event => {
      event.preventDefault();
      event.stopPropagation();
      const startX = event.clientX;
      const startWidth = Math.ceil(th.getBoundingClientRect().width);
      const minWidth = 56;
      handle.setPointerCapture?.(event.pointerId);
      document.body.classList.add('resizing-column');

      const onMove = moveEvent => {
        const nextWidth = Math.max(minWidth, startWidth + moveEvent.clientX - startX);
        applyColumnWidth(table, columnIndex, nextWidth);
      };
      const onUp = () => {
        document.removeEventListener('pointermove', onMove);
        document.removeEventListener('pointerup', onUp);
        document.body.classList.remove('resizing-column');
      };

      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp, { once: true });
    });
  }

  function enhanceTable(table) {
    if (!table || !table.tHead || !table.tBodies.length) return;
    table.classList.add('enhanced-table');
    restoreColumnWidths(table);

    Array.from(table.tHead.rows[0]?.cells || []).forEach((th, columnIndex) => {
      addResizeHandle(table, th, columnIndex);

      if (!th.classList.contains('sortable')) {
        th.classList.add('sortable');
        th.dataset.tableToolsSort = 'generic';
      }

      if (th.dataset.tableToolsSort === 'generic' && th.dataset.tableToolsBound !== 'true') {
        th.dataset.tableToolsBound = 'true';
        th.addEventListener('click', () => sortTableByVisibleColumn(table, columnIndex));
      }
    });
  }

  function enhanceTables() {
    enhanceQueued = false;
    document.querySelectorAll('table').forEach(enhanceTable);
  }

  function queueEnhance() {
    if (enhanceQueued) return;
    enhanceQueued = true;
    requestAnimationFrame(enhanceTables);
  }

  function startObserver() {
    if (observerStarted) return;
    observerStarted = true;
    const observer = new MutationObserver(queueEnhance);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  window.ADPostureTableTools = {
    enhance: enhanceTables
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      enhanceTables();
      startObserver();
    });
  } else {
    enhanceTables();
    startObserver();
  }
})();
