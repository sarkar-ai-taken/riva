/* RIVA UI Render Functions */

function renderToolBars(tools, maxCount) {
  if (!tools || !tools.length) return '<p class="empty-msg">No tool data</p>';
  var mc = maxCount || Math.max.apply(null, tools.map(function(t) { return t.call_count; }).concat([1]));
  return '<div class="bar-chart">' + tools.slice(0, 10).map(function(t) {
    var pct = (t.call_count / mc * 100).toFixed(1);
    return '<div class="bar-row">' +
      '<span class="bar-label" title="' + esc(t.tool_name) + '">' + esc(t.tool_name) + '</span>' +
      '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
      '<span class="bar-count">' + t.call_count + '</span></div>';
  }).join('') + '</div>';
}

function renderDailyChart(daily, width, height) {
  if (!daily || daily.length < 2) return '';
  var maxT = Math.max.apply(null, daily.map(function(d) { return d.total_tokens; }).concat([1]));
  var step = width / (daily.length - 1);
  var points = daily.map(function(d, i) {
    var x = (i * step).toFixed(1);
    var y = (height - (d.total_tokens / maxT) * (height - 4) - 2).toFixed(1);
    return x + ',' + y;
  }).join(' ');
  var color = getColor('purple');
  var firstX = '0';
  var lastX = ((daily.length - 1) * step).toFixed(1);
  var areaPoints = points + ' ' + lastX + ',' + height + ' ' + firstX + ',' + height;
  var uid = 'daily-grad-' + (++_sparklineId);
  return '<div class="sparkline-container">' +
    '<div class="sparkline-label">Daily Tokens</div>' +
    '<svg class="sparkline" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '">' +
    '<defs><linearGradient id="' + uid + '" x1="0" y1="0" x2="0" y2="1">' +
    '<stop offset="0%" stop-color="' + color + '" stop-opacity="0.25"/>' +
    '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/>' +
    '</linearGradient></defs>' +
    '<polygon fill="url(#' + uid + ')" points="' + areaPoints + '"/>' +
    '<polyline fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" points="' + points + '"/>' +
    '</svg></div>';
}

/* --- Overview Tab --- */
function renderAgentTable(agents) {
  var wrap = document.getElementById('agent-table-wrap');
  if (!agents.length) { wrap.innerHTML = '<p class="empty-msg">No agents detected</p>'; return; }
  var h = '<table id="tbl-agents"><thead><tr><th>Agent</th><th>Status</th><th>Sandbox</th><th>PID</th><th>CPU %</th><th>Memory</th><th>Launched By</th><th>Uptime</th><th>Working Dir</th></tr></thead><tbody>';
  agents.forEach(function(a) {
    var launchType = (a.launcher && a.launcher.launch_type) || 'unknown';
    var launchCls = 'launch-' + launchType;
    h += '<tr><td>' + esc(a.name) + '</td><td>' + statusBadge(a.status) + '</td><td>' + sandboxBadge(a) + '</td><td>' + esc(a.pid) + '</td>' +
      '<td>' + a.cpu_percent.toFixed(1) + '</td><td>' + esc(a.memory_formatted) + '</td>' +
      '<td><span class="' + launchCls + '">' + esc(a.launched_by || '-') + '</span></td>' +
      '<td>' + esc(a.uptime_formatted) + '</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(a.working_directory) + '">' + esc(a.working_directory) + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
  makeSortable(document.getElementById('tbl-agents'));
}

function renderAgentCards(agents, histories) {
  var el = document.getElementById('agent-cards');
  var running = agents.filter(function(a) { return a.status === 'running'; });
  if (!running.length) { el.innerHTML = '<p class="empty-msg">No running agents</p>'; return; }
  el.innerHTML = running.map(function(a) {
    var key = a.name + ':' + a.pid;
    var hist = (histories || {})[key];
    var sparkHtml = '';
    if (hist) {
      sparkHtml =
        '<div class="sparkline-container"><div class="sparkline-label">CPU %</div>' + renderSparklineSVG(hist.cpu_history, getColor('green'), 340, 40) + '</div>' +
        '<div class="sparkline-container"><div class="sparkline-label">Memory MB</div>' + renderSparklineSVG(hist.memory_history, getColor('accent'), 340, 40) + '</div>';
    }
    var launchType = (a.launcher && a.launcher.launch_type) || 'unknown';
    var launchCls = 'launch-' + launchType;
    return '<div class="card"><h3>' + esc(a.name) + ' ' + statusBadge(a.status) + '</h3>' +
      '<div class="card-row"><span class="label">PID</span><span class="value">' + esc(a.pid) + '</span></div>' +
      '<div class="card-row"><span class="label">Sandbox</span><span class="value">' + sandboxBadge(a) + '</span></div>' +
      '<div class="card-row"><span class="label">Launched By</span><span class="value ' + launchCls + '">' + esc(a.launched_by || '-') + '</span></div>' +
      '<div class="card-row"><span class="label">Binary</span><span class="value">' + esc(a.binary_path) + '</span></div>' +
      '<div class="card-row"><span class="label">API</span><span class="value">' + esc(a.api_domain) + '</span></div>' +
      '<div class="card-row"><span class="label">CPU</span><span class="value">' + a.cpu_percent.toFixed(1) + '%</span></div>' +
      '<div class="card-row"><span class="label">Memory</span><span class="value">' + esc(a.memory_formatted) + '</span></div>' +
      '<div class="card-row"><span class="label">Uptime</span><span class="value">' + esc(a.uptime_formatted) + '</span></div>' +
      sparkHtml + '</div>';
  }).join('');
}

/* --- Network Tab --- */
function renderNetworkTable(networkData) {
  var wrap = document.getElementById('network-table-wrap');
  if (!networkData || !networkData.length) {
    wrap.innerHTML = '<p class="empty-msg">No running agents with network connections</p>';
    return;
  }

  var h = '';
  networkData.forEach(function(snap) {
    h += '<h3 style="margin:16px 0 8px;font-size:14px;color:var(--accent)">' + esc(snap.agent) + ' (PID ' + snap.pid + ') \u2014 ' + snap.connection_count + ' connections</h3>';
    if (!snap.connections.length) {
      h += '<p class="empty-msg">No connections</p>';
      return;
    }
    h += '<table><thead><tr><th>Local</th><th>Remote</th><th>Status</th><th>Hostname</th><th>Service</th><th>TLS</th></tr></thead><tbody>';
    snap.connections.forEach(function(c) {
      var statusCls = c.status === 'ESTABLISHED' ? 'conn-established' : c.status === 'CLOSE_WAIT' ? 'conn-close-wait' : c.status === 'TIME_WAIT' ? 'conn-time-wait' : '';
      var tls = c.is_tls ? '<span style="color:var(--green)">Yes</span>' : '<span style="color:var(--text-dim)">No</span>';
      h += '<tr><td>' + esc(c.local_addr + ':' + c.local_port) + '</td>' +
        '<td>' + esc(c.remote_addr + ':' + c.remote_port) + '</td>' +
        '<td class="' + statusCls + '">' + esc(c.status) + '</td>' +
        '<td>' + esc(c.hostname) + '</td>' +
        '<td>' + esc(c.known_service) + '</td>' +
        '<td>' + tls + '</td></tr>';
    });
    h += '</tbody></table>';
  });
  wrap.innerHTML = h;
}

/* --- Security Tab --- */
function renderAuditDashboard(auditData) {
  var wrap = document.getElementById('audit-results-wrap');
  if (!auditData || !auditData.length) {
    wrap.innerHTML = '<p class="empty-msg">No audit results yet. Click "Run Audit" above.</p>';
    return;
  }

  // Summary cards
  var pass_count = auditData.filter(function(r) { return r.status === 'pass'; }).length;
  var warn_count = auditData.filter(function(r) { return r.status === 'warn'; }).length;
  var fail_count = auditData.filter(function(r) { return r.status === 'fail'; }).length;

  var h = '<div class="stat-row">' +
    '<div class="stat-card"><div class="stat-value" style="color:var(--green)">' + pass_count + '</div><div class="stat-label">Passed</div></div>' +
    '<div class="stat-card"><div class="stat-value" style="color:var(--yellow)">' + warn_count + '</div><div class="stat-label">Warnings</div></div>' +
    '<div class="stat-card"><div class="stat-value" style="color:var(--red)">' + fail_count + '</div><div class="stat-label">Failed</div></div>' +
    '</div>';

  h += '<table id="tbl-audit"><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Category</th><th>Detail</th></tr></thead><tbody>';
  auditData.forEach(function(r) {
    var statusCls = r.status === 'pass' ? 'badge-running' : r.status === 'warn' ? 'badge-installed' : 'severity-high';
    h += '<tr><td>' + esc(r.check) + '</td>' +
      '<td><span class="badge ' + statusCls + '">' + esc(r.status) + '</span></td>' +
      '<td>' + severityBadge(r.severity) + '</td>' +
      '<td>' + esc(r.category) + '</td>' +
      '<td>' + esc(r.detail) + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
  makeSortable(document.getElementById('tbl-audit'));
}

/* --- Usage Tab --- */
function renderStatsTable(stats) {
  var wrap = document.getElementById('stats-table-wrap');
  if (!stats.length) { wrap.innerHTML = '<p class="empty-msg">No usage data</p>'; return; }
  var h = '<table id="tbl-stats"><thead><tr><th>Agent</th><th>Status</th><th>Total Tokens</th><th>Sessions</th><th>Messages</th><th>Tool Calls</th><th>Period</th></tr></thead><tbody>';
  stats.forEach(function(s) {
    var period = (s.time_range_start && s.time_range_end) ? esc(s.time_range_start) + ' \u2014 ' + esc(s.time_range_end) : '\u2014';
    h += '<tr><td>' + esc(s.name) + '</td><td>' + statusBadge(s.status) + '</td>' +
      '<td>' + esc(s.total_tokens_formatted) + '</td><td>' + s.total_sessions + '</td>' +
      '<td>' + s.total_messages + '</td><td>' + s.total_tool_calls + '</td><td>' + period + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
  makeSortable(document.getElementById('tbl-stats'));
}

function renderStatsCards(stats) {
  var el = document.getElementById('stats-cards');
  var withData = stats.filter(function(s) { return s.total_tokens > 0; });
  if (!withData.length) { el.innerHTML = '<p class="empty-msg">No detailed usage data</p>'; return; }
  el.innerHTML = withData.map(function(s) {
    var modelsHtml = '';
    var modelKeys = Object.keys(s.models || {});
    if (modelKeys.length) {
      modelsHtml = '<div style="margin-top:10px"><div class="sparkline-label">Model Token Breakdown</div><table style="font-size:12px"><thead><tr><th>Model</th><th>Input</th><th>Output</th><th>Cache Read</th><th>Cache Create</th><th>Total</th></tr></thead><tbody>';
      modelKeys.forEach(function(mid) {
        var m = s.models[mid];
        modelsHtml += '<tr><td>' + esc(mid) + '</td><td>' + m.input_tokens + '</td><td>' + m.output_tokens + '</td><td>' + m.cache_read_input_tokens + '</td><td>' + m.cache_creation_input_tokens + '</td><td>' + m.total_tokens + '</td></tr>';
      });
      modelsHtml += '</tbody></table></div>';
    }
    var toolMax = s.top_tools.length ? Math.max.apply(null, s.top_tools.map(function(t) { return t.call_count; })) : 1;
    return '<div class="card"><h3>' + esc(s.name) + '</h3>' +
      '<div class="card-row"><span class="label">Tokens</span><span class="value">' + esc(s.total_tokens_formatted) + '</span></div>' +
      '<div class="card-row"><span class="label">Sessions</span><span class="value">' + s.total_sessions + '</span></div>' +
      '<div class="card-row"><span class="label">Messages</span><span class="value">' + s.total_messages + '</span></div>' +
      modelsHtml +
      '<div style="margin-top:10px"><div class="sparkline-label">Top Tools</div>' + renderToolBars(s.top_tools, toolMax) + '</div>' +
      renderDailyChart(s.daily_activity, 340, 50) +
      '</div>';
  }).join('');
}

function renderHistoricalChart(snapshots) {
  var wrap = document.getElementById('history-chart-wrap');
  if (!snapshots || !snapshots.length) {
    wrap.innerHTML = '<p class="empty-msg">No historical data. Start the web server to begin recording.</p>';
    return;
  }

  // Group by agent
  var agents = {};
  snapshots.forEach(function(s) {
    var name = s.agent_name || 'Unknown';
    if (!agents[name]) agents[name] = [];
    agents[name].push(s);
  });

  var h = '';
  Object.keys(agents).forEach(function(name) {
    var data = agents[name].reverse();
    var cpuVals = data.map(function(s) { return s.cpu_percent || 0; });
    var memVals = data.map(function(s) { return s.memory_mb || 0; });

    h += '<div class="card" style="margin-bottom:16px"><h3>' + esc(name) + '</h3>';
    h += '<div class="sparkline-container"><div class="sparkline-label">CPU % (historical)</div>' +
      renderSparklineSVG(cpuVals, getColor('green'), 600, 50) + '</div>';
    h += '<div class="sparkline-container"><div class="sparkline-label">Memory MB (historical)</div>' +
      renderSparklineSVG(memVals, getColor('accent'), 600, 50) + '</div>';
    h += '</div>';
  });
  wrap.innerHTML = h;
}

/* --- Config Tab --- */
function renderEnvTable(envVars) {
  var wrap = document.getElementById('env-table-wrap');
  if (!envVars.length) { wrap.innerHTML = '<p class="empty-msg">No AI environment variables found</p>'; return; }
  var h = '<table><thead><tr><th>Variable</th><th>Value</th><th>Length</th></tr></thead><tbody>';
  envVars.forEach(function(e) {
    h += '<tr><td>' + esc(e.name) + '</td><td style="font-family:monospace">' + esc(e.value) + '</td><td>' + esc(e.raw_length) + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
}

function renderRegistryTable(agents) {
  var wrap = document.getElementById('registry-table-wrap');
  if (!agents.length) { wrap.innerHTML = '<p class="empty-msg">No agents in registry</p>'; return; }
  var h = '<table><thead><tr><th>Agent</th><th>Binaries</th><th>Config Dir</th><th>API Domain</th><th>Installed</th></tr></thead><tbody>';
  agents.forEach(function(a) {
    var inst = a.installed ? '<span class="badge badge-running">yes</span>' : '<span class="badge badge-not_found">no</span>';
    h += '<tr><td>' + esc(a.name) + '</td><td>' + esc((a.binaries||[]).join(', ')) + '</td><td>' + esc(a.config_dir) + '</td><td>' + esc(a.api_domain) + '</td><td>' + inst + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
}

/* --- Forensics Tab --- */
function renderForensicTrends(trends) {
  var wrap = document.getElementById('forensic-trends-wrap');
  if (!trends || !trends.total_sessions) {
    wrap.innerHTML = '<p class="empty-msg">No trend data available</p>';
    return;
  }

  var effPct = (trends.avg_efficiency * 100).toFixed(0);
  var deadPct = (trends.dead_end_rate * 100).toFixed(0);

  var h = '<div class="stat-row">' +
    '<div class="stat-card"><div class="stat-value">' + trends.total_sessions + '</div><div class="stat-label">Sessions</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + trends.total_turns + '</div><div class="stat-label">Turns</div></div>' +
    '<div class="stat-card"><div class="stat-value">' + (trends.total_tokens || 0).toLocaleString() + '</div><div class="stat-label">Tokens</div></div>' +
    '<div class="stat-card"><div class="stat-value"><div class="efficiency-bar"><div class="efficiency-fill" style="width:' + effPct + '%"></div></div>' + effPct + '%</div><div class="stat-label">Avg Efficiency</div></div>' +
    '<div class="stat-card"><div class="stat-value" style="color:' + (trends.dead_end_rate > 0.2 ? 'var(--red)' : 'var(--yellow)') + '">' + deadPct + '%</div><div class="stat-label">Dead-End Rate</div></div>' +
    '</div>';

  // Top tools bar chart
  if (trends.top_tools && trends.top_tools.length) {
    h += '<div style="margin-top:16px"><h3 style="font-size:14px;color:var(--text-dim);margin-bottom:8px">Top Tools Across Sessions</h3>';
    h += renderToolBars(trends.top_tools);
    h += '</div>';
  }

  wrap.innerHTML = h;
}

function renderForensicSessions(sessions) {
  var wrap = document.getElementById('forensic-sessions-wrap');
  if (!sessions || !sessions.length) {
    wrap.innerHTML = '<p class="empty-msg">No sessions found</p>';
    return;
  }

  var h = '<table id="tbl-forensic-sessions"><thead><tr><th>Slug</th><th>Project</th><th>Modified</th><th>Size</th></tr></thead><tbody>';
  sessions.forEach(function(s) {
    var slug = s.slug || s.session_id.substring(0, 12);
    var project = (s.project || '').replace(/-/g, '/').replace(/^\//, '');
    if (project.length > 50) project = '...' + project.slice(-47);
    var modified = s.modified_time ? new Date(s.modified_time).toLocaleString() : '\u2014';
    var sizeKb = s.size_bytes ? (s.size_bytes / 1024).toFixed(0) + ' KB' : '\u2014';
    var id = s.slug || s.session_id;
    h += '<tr class="forensic-session-row" onclick="window.loadForensicSession(\'' + esc(id) + '\')" style="cursor:pointer">' +
      '<td style="color:var(--accent);font-weight:600">' + esc(slug) + '</td>' +
      '<td>' + esc(project) + '</td>' +
      '<td>' + esc(modified) + '</td>' +
      '<td>' + esc(sizeKb) + '</td></tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
  makeSortable(document.getElementById('tbl-forensic-sessions'));
}

function renderForensicDetail(data) {
  var wrap = document.getElementById('forensic-detail-wrap');
  var s = data.session;

  var h = '<button class="btn forensic-back-btn" onclick="window.forensicBackToList()">&larr; Back to sessions</button>';

  // Summary card
  var effPct = ((s.efficiency || 0) * 100).toFixed(0);
  h += '<div class="card" style="margin-top:12px"><h3>' + esc(s.slug || s.session_id) + '</h3>';
  h += '<div class="card-row"><span class="label">Model</span><span class="value">' + esc(s.model) + '</span></div>';
  h += '<div class="card-row"><span class="label">Duration</span><span class="value">' + esc(s.duration) + '</span></div>';
  h += '<div class="card-row"><span class="label">Branch</span><span class="value">' + esc(s.git_branch) + '</span></div>';
  h += '<div class="card-row"><span class="label">Turns</span><span class="value">' + s.turns + '</span></div>';
  h += '<div class="card-row"><span class="label">Actions</span><span class="value">' + s.actions + '</span></div>';
  h += '<div class="card-row"><span class="label">Tokens</span><span class="value">' + (s.tokens || 0).toLocaleString() + '</span></div>';
  h += '<div class="card-row"><span class="label">Files Read</span><span class="value">' + s.files_read + '</span></div>';
  h += '<div class="card-row"><span class="label">Files Written</span><span class="value">' + s.files_written + '</span></div>';
  h += '<div class="card-row"><span class="label">Dead Ends</span><span class="value" style="color:' + (s.dead_ends > 0 ? 'var(--yellow)' : 'var(--text)') + '">' + s.dead_ends + '</span></div>';
  h += '<div class="card-row"><span class="label">Efficiency</span><span class="value"><div class="efficiency-bar" style="display:inline-block;width:80px;vertical-align:middle"><div class="efficiency-fill" style="width:' + effPct + '%"></div></div> ' + effPct + '%</span></div>';
  h += '</div>';

  // Patterns section
  if (data.patterns && data.patterns.length) {
    h += '<div class="card" style="margin-top:12px"><h3>Patterns</h3>';
    var byType = {};
    data.patterns.forEach(function(p) {
      if (!byType[p.pattern_type]) byType[p.pattern_type] = [];
      byType[p.pattern_type].push(p);
    });
    var labels = { dead_end: 'Dead Ends', search_thrash: 'Search Thrashing', retry_loop: 'Retry Loops', write_without_read: 'Write Without Read' };
    Object.keys(byType).forEach(function(ptype) {
      var plist = byType[ptype];
      var label = labels[ptype] || ptype;
      h += '<div style="margin-bottom:8px"><strong style="color:var(--accent)">' + esc(label) + '</strong> (' + plist.length + ')';
      plist.forEach(function(p) {
        var color = p.severity === 'warning' ? 'var(--yellow)' : 'var(--text-dim)';
        h += '<div style="padding-left:12px;color:' + color + ';font-size:12px">' + esc(p.description) + '</div>';
      });
      h += '</div>';
    });
    h += '</div>';
  }

  // Timeline section
  if (data.timeline && data.timeline.length) {
    h += '<div class="card" style="margin-top:12px"><h3>Timeline</h3><div class="forensic-timeline">';
    data.timeline.forEach(function(turn) {
      var deadCls = turn.is_dead_end ? ' dead-end' : '';
      h += '<div class="forensic-event' + deadCls + '">';
      h += '<div class="forensic-event-header">';
      h += '<span class="forensic-event-time">' + esc(turn.timestamp_start ? turn.timestamp_start.substring(11, 19) : '') + '</span>';
      h += '<span class="forensic-event-label">Turn ' + turn.index + '</span>';
      if (turn.duration) h += '<span style="color:var(--text-dim);font-size:11px">' + esc(turn.duration) + '</span>';
      if (turn.is_dead_end) h += '<span class="badge severity-medium" style="margin-left:6px">dead end</span>';
      h += '</div>';
      h += '<div class="forensic-event-prompt">' + esc(turn.prompt) + '</div>';

      if (turn.actions && turn.actions.length) {
        turn.actions.forEach(function(a) {
          var failCls = a.success ? '' : ' fail';
          var dur = a.duration_ms ? ' [' + (a.duration_ms / 1000).toFixed(1) + 's]' : '';
          h += '<div class="forensic-event forensic-action' + failCls + '">';
          h += '<span class="forensic-event-time">' + esc(a.timestamp ? a.timestamp.substring(11, 19) : '') + '</span>';
          h += '<span class="forensic-tool-name">' + esc(a.tool_name) + '</span> ';
          h += '<span style="color:var(--text-dim)">' + esc(a.input_summary) + '</span>';
          h += '<span style="color:var(--text-dim);font-size:11px">' + dur + '</span>';
          if (!a.success) h += ' <span class="badge severity-high">FAIL</span>';
          h += '</div>';
        });
      }
      h += '</div>';
    });
    h += '</div></div>';
  }

  // Files section
  if (s.files_modified && s.files_modified.length || s.files_read_only && s.files_read_only.length) {
    h += '<div class="card" style="margin-top:12px"><h3>Files</h3>';
    if (s.files_modified && s.files_modified.length) {
      h += '<div style="margin-bottom:8px"><strong style="color:var(--green)">Modified (' + s.files_modified.length + ')</strong>';
      s.files_modified.forEach(function(f) {
        h += '<div style="padding-left:12px;font-family:monospace;font-size:12px;color:var(--green)">W  ' + esc(f) + '</div>';
      });
      h += '</div>';
    }
    if (s.files_read_only && s.files_read_only.length) {
      h += '<div><strong style="color:var(--text-dim)">Read Only (' + s.files_read_only.length + ')</strong>';
      var readFiles = s.files_read_only.slice(0, 30);
      readFiles.forEach(function(f) {
        h += '<div style="padding-left:12px;font-family:monospace;font-size:12px;color:var(--text-dim)">R  ' + esc(f) + '</div>';
      });
      if (s.files_read_only.length > 30) {
        h += '<div style="padding-left:12px;color:var(--text-dim);font-size:12px">... and ' + (s.files_read_only.length - 30) + ' more</div>';
      }
      h += '</div>';
    }
    h += '</div>';
  }

  // Decisions section
  if (data.decisions && data.decisions.length) {
    h += '<div class="card" style="margin-top:12px"><h3>Decisions (' + data.decisions.length + ')</h3>';
    data.decisions.forEach(function(d, i) {
      var deadLabel = d.is_dead_end ? ' <span class="badge severity-medium">backtracked</span>' : '';
      h += '<div class="accordion" id="acc-decision-' + i + '">' +
        '<div class="accordion-header" onclick="this.parentElement.classList.toggle(\'open\')">' +
        '<span>Decision ' + (i + 1) + ' (Turn ' + d.turn_index + ')' + deadLabel + '</span>' +
        '<span class="accordion-arrow">&#9654;</span></div>' +
        '<div class="accordion-body">';
      h += '<div style="margin-bottom:6px"><strong>Actions:</strong> ' + esc(d.actions.join(', ')) + '</div>';
      h += '<div style="margin-bottom:6px"><strong>Reasoning:</strong> <span style="color:var(--text-dim)">' + esc(d.thinking_preview) + '</span></div>';
      if (d.files && d.files.length) {
        h += '<div><strong>Files:</strong> ' + esc(d.files.slice(0, 5).join(', ')) + '</div>';
      }
      h += '</div></div>';
    });
    h += '</div>';
  }

  wrap.innerHTML = h;
}

function renderConfigs(configs) {
  var wrap = document.getElementById('config-wrap');
  if (!configs.length) { wrap.innerHTML = '<p class="empty-msg">No installed agent configurations</p>'; return; }
  wrap.innerHTML = configs.map(function(c, i) {
    var keys = Object.keys(c.config || {}).sort();
    var tbody = '';
    keys.forEach(function(k) {
      var v = c.config[k];
      if (typeof v === 'object') v = JSON.stringify(v, null, 2);
      if (String(v).length > 200) v = String(v).substring(0, 200) + '...';
      tbody += '<tr><td style="font-weight:600;white-space:nowrap">' + esc(k) + '</td><td style="font-family:monospace;white-space:pre-wrap;word-break:break-all">' + esc(v) + '</td></tr>';
    });
    return '<div class="accordion" id="acc-' + i + '">' +
      '<div class="accordion-header" onclick="this.parentElement.classList.toggle(\'open\')">' +
      '<span>' + esc(c.name) + '</span><span class="accordion-arrow">&#9654;</span></div>' +
      '<div class="accordion-body"><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>' + tbody + '</tbody></table></div></div>';
  }).join('');
}
