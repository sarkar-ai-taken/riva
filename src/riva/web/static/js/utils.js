/* RIVA UI Utility Functions */

function esc(s) {
  if (s == null) return '\u2014';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function statusBadge(status) {
  const cls = 'badge badge-' + status;
  const label = status.replace('_', ' ');
  return '<span class="' + cls + '">' + label + '</span>';
}

function severityBadge(severity) {
  const cls = 'badge severity-' + severity;
  return '<span class="' + cls + '">' + esc(severity) + '</span>';
}

function renderSparklineSVG(values, color, width, height) {
  if (!values || values.length < 2) return '';
  const max = Math.max(...values, 0.1);
  const step = width / (values.length - 1);
  const points = values.map(function(v, i) {
    const x = (i * step).toFixed(1);
    const y = (height - (v / max) * (height - 4) - 2).toFixed(1);
    return x + ',' + y;
  }).join(' ');
  return '<svg class="sparkline" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '">' +
    '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" points="' + points + '"/>' +
    '</svg>';
}

function getColor(name) {
  return getComputedStyle(document.documentElement).getPropertyValue('--' + name).trim();
}

/* Table sorting */
function makeSortable(table) {
  if (!table) return;
  var headers = table.querySelectorAll('th');
  headers.forEach(function(th, colIdx) {
    th.addEventListener('click', function() {
      var tbody = table.querySelector('tbody');
      if (!tbody) return;
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var asc = th.dataset.sortDir !== 'asc';
      th.dataset.sortDir = asc ? 'asc' : 'desc';

      rows.sort(function(a, b) {
        var aVal = a.cells[colIdx] ? a.cells[colIdx].textContent.trim() : '';
        var bVal = b.cells[colIdx] ? b.cells[colIdx].textContent.trim() : '';
        var aNum = parseFloat(aVal);
        var bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) {
          return asc ? aNum - bNum : bNum - aNum;
        }
        return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      });

      rows.forEach(function(row) { tbody.appendChild(row); });
    });
  });
}
