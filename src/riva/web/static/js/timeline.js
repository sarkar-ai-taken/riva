/* RIVA Timeline — Time-Travel Replay Component */

(function() {
  window.rivaTimeline = {
    active: false,
    timestamp: null,
    buckets: [],
    playing: false,
    playSpeed: 1000,
    _playInterval: null
  };

  var slider = document.getElementById('timeline-slider');
  var liveBtn = document.getElementById('timeline-live-btn');
  var playBtn = document.getElementById('timeline-play-btn');
  var label = document.getElementById('timeline-label');
  var bucketsEl = document.getElementById('timeline-buckets');

  function formatTimestamp(ts) {
    var d = new Date(ts * 1000);
    var now = Date.now();
    var diff = now - d.getTime();
    var mins = Math.floor(diff / 60000);
    var hours = Math.floor(diff / 3600000);

    var timeStr = d.toLocaleTimeString();
    var relative = '';
    if (mins < 1) relative = 'just now';
    else if (mins < 60) relative = mins + 'm ago';
    else if (hours < 24) relative = hours + 'h ago';
    else relative = Math.floor(hours / 24) + 'd ago';

    return timeStr + ' (' + relative + ')';
  }

  function renderBuckets(buckets) {
    if (!buckets || buckets.length === 0) {
      bucketsEl.innerHTML = '';
      return;
    }

    var maxAgents = 1;
    for (var i = 0; i < buckets.length; i++) {
      if (buckets[i].agent_count > maxAgents) maxAgents = buckets[i].agent_count;
    }

    var html = '';
    for (var i = 0; i < buckets.length; i++) {
      var b = buckets[i];
      var h = Math.max(2, Math.round((b.agent_count / maxAgents) * 20));
      var cls = b.orphan_count > 0 ? 'timeline-bucket has-orphan' : 'timeline-bucket';
      html += '<div class="' + cls + '" style="height:' + h + 'px" title="' +
        'Agents: ' + b.agent_count +
        ', CPU: ' + b.total_cpu + '%' +
        ', Mem: ' + b.total_memory + ' MB' +
        (b.orphan_count > 0 ? ', Orphans: ' + b.orphan_count : '') +
        '"></div>';
    }
    bucketsEl.innerHTML = html;
  }

  async function fetchTimeline() {
    try {
      var res = await fetch('/api/timeline?hours=1&bucket=60');
      if (!res.ok) return;
      var data = await res.json();
      var buckets = data.buckets || [];
      window.rivaTimeline.buckets = buckets;
      renderBuckets(buckets);

      if (buckets.length > 0) {
        slider.min = 0;
        slider.max = buckets.length - 1;
        if (!window.rivaTimeline.active) {
          slider.value = buckets.length - 1;
        }
      }
    } catch (e) {}
  }

  async function replayAt(ts) {
    try {
      var res = await fetch('/api/replay?t=' + ts);
      if (!res.ok) return;
      var data = await res.json();

      // Re-render overview tables with historical data
      var agents = (data.state || []).map(function(s) {
        return {
          name: s.agent_name || '?',
          status: s.status || 'unknown',
          pid: s.pid,
          cpu_percent: s.cpu_percent || 0,
          memory_mb: s.memory_mb || 0,
          memory_formatted: (s.memory_mb || 0).toFixed(1) + ' MB',
          uptime_seconds: s.uptime_seconds || 0,
          uptime_formatted: '',
          working_directory: '',
          child_count: s.child_count || 0,
          tree_cpu_percent: s.tree_cpu_percent || 0,
          tree_memory_mb: s.tree_memory_mb || 0,
          connection_count: s.connection_count || 0,
          children: s.children || [],
          network_connections: s.network_connections || []
        };
      });

      if (typeof renderAgentTable === 'function') renderAgentTable(agents);
      if (typeof renderAgentCards === 'function') renderAgentCards(agents, {});

      // Render orphans if any
      var orphans = data.orphans || [];
      var orphanSection = document.getElementById('sec-orphans');
      var orphanWrap = document.getElementById('orphan-table-wrap');
      if (orphans.length > 0 && orphanSection && orphanWrap) {
        orphanSection.style.display = '';
        var html = '<table><tr><th>Agent</th><th>PID</th><th>Name</th><th>Original Parent</th><th>CPU %</th><th>Memory MB</th></tr>';
        for (var i = 0; i < orphans.length; i++) {
          var o = orphans[i];
          html += '<tr><td>' + (o.agent_name || '?') + '</td><td>' + (o.orphan_pid || '?') +
            '</td><td>' + (o.orphan_name || '?') + '</td><td>' + (o.original_parent_pid || '?') +
            '</td><td>' + (o.cpu_percent || 0).toFixed(1) + '</td><td>' + (o.memory_mb || 0).toFixed(1) + '</td></tr>';
        }
        html += '</table>';
        orphanWrap.innerHTML = html;
      } else if (orphanSection) {
        orphanSection.style.display = 'none';
      }
    } catch (e) {}
  }

  function goLive() {
    window.rivaTimeline.active = false;
    window.rivaTimeline.timestamp = null;
    stopPlaying();
    liveBtn.classList.add('active');
    label.textContent = 'Live';
    var buckets = window.rivaTimeline.buckets;
    if (buckets.length > 0) {
      slider.value = buckets.length - 1;
    }
    // Hide orphan section when going live
    var orphanSection = document.getElementById('sec-orphans');
    if (orphanSection) orphanSection.style.display = 'none';
  }

  function scrubTo(index) {
    var buckets = window.rivaTimeline.buckets;
    if (!buckets || index < 0 || index >= buckets.length) return;

    var ts = buckets[index].timestamp;
    window.rivaTimeline.active = true;
    window.rivaTimeline.timestamp = ts;
    liveBtn.classList.remove('active');
    label.textContent = formatTimestamp(ts);
    slider.value = index;
    replayAt(ts);
  }

  function startPlaying() {
    window.rivaTimeline.playing = true;
    playBtn.innerHTML = '&#9646;&#9646;';
    var idx = parseInt(slider.value, 10);
    window.rivaTimeline._playInterval = setInterval(function() {
      idx++;
      var buckets = window.rivaTimeline.buckets;
      if (idx >= buckets.length) {
        goLive();
        return;
      }
      scrubTo(idx);
    }, window.rivaTimeline.playSpeed);
  }

  function stopPlaying() {
    window.rivaTimeline.playing = false;
    playBtn.innerHTML = '&#9654;';
    if (window.rivaTimeline._playInterval) {
      clearInterval(window.rivaTimeline._playInterval);
      window.rivaTimeline._playInterval = null;
    }
  }

  // Event listeners
  slider.addEventListener('input', function() {
    var idx = parseInt(this.value, 10);
    var buckets = window.rivaTimeline.buckets;
    if (idx >= buckets.length - 1 && !window.rivaTimeline.playing) {
      goLive();
    } else {
      scrubTo(idx);
    }
  });

  liveBtn.addEventListener('click', function() {
    goLive();
  });

  playBtn.addEventListener('click', function() {
    if (window.rivaTimeline.playing) {
      stopPlaying();
    } else {
      startPlaying();
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.target.tagName === 'INPUT' && e.target.type !== 'range') return;

    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      var idx = parseInt(slider.value, 10) - 1;
      if (idx >= 0) scrubTo(idx);
    } else if (e.key === 'ArrowRight') {
      e.preventDefault();
      var idx = parseInt(slider.value, 10) + 1;
      var buckets = window.rivaTimeline.buckets;
      if (idx < buckets.length) {
        scrubTo(idx);
      } else {
        goLive();
      }
    } else if (e.key === ' ' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      if (window.rivaTimeline.playing) {
        stopPlaying();
      } else {
        startPlaying();
      }
    }
  });

  // Initial fetch and periodic refresh
  fetchTimeline();
  setInterval(fetchTimeline, 30000);
})();
