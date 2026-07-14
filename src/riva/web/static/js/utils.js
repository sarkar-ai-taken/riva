/* RIVA UI Utility Functions */

function esc(s) {
  if (s == null) return '\u2014';
  var d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function statusBadge(status) {
  var cls = 'badge badge-' + status;
  var label = status.replace('_', ' ');
  return '<span class="' + cls + '">' + label + '</span>';
}

function sandboxBadge(agent) {
  var sb = agent.sandbox;
  if (!sb || agent.status !== 'running') return '<span class="badge badge-not_found">\u2014</span>';
  if (sb.is_sandboxed) {
    var label = sb.runtime || sb.sandbox_type || 'sandboxed';
    var cid = sb.container_id ? ' (' + sb.container_id + ')' : '';
    var cls = sb.sandbox_type === 'container' ? 'badge-running' : 'badge-installed';
    return '<span class="badge ' + cls + '">\u25a3 ' + esc(label) + cid + '</span>';
  }
  return '<span class="badge severity-high">Host</span>';
}

function severityBadge(severity) {
  var cls = 'badge severity-' + severity;
  return '<span class="' + cls + '">' + esc(severity) + '</span>';
}

/* Sparkline counter for unique gradient IDs */
var _sparklineId = 0;

function renderSparklineSVG(values, color, width, height) {
  if (!values || values.length < 2) return '';
  var max = Math.max.apply(null, values.concat([0.1]));
  var step = width / (values.length - 1);
  var points = values.map(function(v, i) {
    var x = (i * step).toFixed(1);
    var y = (height - (v / max) * (height - 4) - 2).toFixed(1);
    return x + ',' + y;
  }).join(' ');

  // Build area polygon (line + bottom edge) for gradient fill
  var firstX = '0';
  var lastX = ((values.length - 1) * step).toFixed(1);
  var areaPoints = points + ' ' + lastX + ',' + height + ' ' + firstX + ',' + height;

  var uid = 'spark-grad-' + (++_sparklineId);

  return '<svg class="sparkline" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '">' +
    '<defs>' +
    '<linearGradient id="' + uid + '" x1="0" y1="0" x2="0" y2="1">' +
    '<stop offset="0%" stop-color="' + color + '" stop-opacity="0.25"/>' +
    '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/>' +
    '</linearGradient>' +
    '</defs>' +
    '<polygon fill="url(#' + uid + ')" points="' + areaPoints + '"/>' +
    '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" points="' + points + '"/>' +
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

      // Remove sort direction from sibling headers
      headers.forEach(function(h) { if (h !== th) delete h.dataset.sortDir; });

      rows.sort(function(a, b) {
        // Prefer an explicit data-sort value (raw number behind formatted
        // text like "738.8M"); fall back to the visible cell text.
        var aCell = a.cells[colIdx];
        var bCell = b.cells[colIdx];
        var aVal = aCell ? (aCell.dataset.sort !== undefined ? aCell.dataset.sort : aCell.textContent.trim()) : '';
        var bVal = bCell ? (bCell.dataset.sort !== undefined ? bCell.dataset.sort : bCell.textContent.trim()) : '';
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
