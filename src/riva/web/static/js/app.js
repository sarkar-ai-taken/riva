/* RIVA Dashboard — Sidebar Nav, Theme System & Polling Orchestration */

(function() {
  var connected = true;
  var lastHistories = {};
  var currentTab = 'overview';

  /* --- Sidebar --- */
  var sidebar = document.getElementById('sidebar');
  var sidebarToggle = document.getElementById('sidebar-toggle');
  var backdrop = document.getElementById('sidebar-backdrop');

  function initSidebar() {
    var collapsed = localStorage.getItem('riva-sidebar-collapsed') === 'true';
    if (collapsed) sidebar.classList.add('collapsed');

    sidebarToggle.addEventListener('click', function() {
      var isMobile = window.innerWidth <= 900;
      if (isMobile) {
        sidebar.classList.toggle('mobile-open');
        backdrop.classList.toggle('visible', sidebar.classList.contains('mobile-open'));
      } else {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('riva-sidebar-collapsed', sidebar.classList.contains('collapsed'));
      }
    });

    backdrop.addEventListener('click', function() {
      sidebar.classList.remove('mobile-open');
      backdrop.classList.remove('visible');
    });
  }

  /* --- Tab/Nav Router --- */
  function initTabs() {
    var navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(function(item) {
      item.addEventListener('click', function() {
        var target = this.dataset.tab;
        switchTab(target);
        // Close mobile sidebar on nav click
        if (window.innerWidth <= 900) {
          sidebar.classList.remove('mobile-open');
          backdrop.classList.remove('visible');
        }
      });
    });
  }

  function switchTab(tabName) {
    currentTab = tabName;
    document.querySelectorAll('.nav-item').forEach(function(item) {
      item.classList.toggle('active', item.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-panel').forEach(function(panel) {
      panel.classList.toggle('active', panel.id === 'tab-' + tabName);
    });
  }

  /* --- Theme Management --- */
  function initTheme() {
    var saved = localStorage.getItem('riva-theme') || 'dark';
    applyTheme(saved);

    document.querySelectorAll('.theme-option').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var theme = this.dataset.themeValue;
        applyTheme(theme);
        localStorage.setItem('riva-theme', theme);
      });
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);

    // Update meta theme-color for browser chrome
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      if (theme === 'light') {
        meta.content = '#f5f7fa';
      } else if (theme === 'system') {
        meta.content = window.matchMedia('(prefers-color-scheme: light)').matches ? '#f5f7fa' : '#0a0e14';
      } else {
        meta.content = '#0a0e14';
      }
    }

    // Update active state on theme buttons
    document.querySelectorAll('.theme-option').forEach(function(btn) {
      btn.classList.toggle('active', btn.dataset.themeValue === theme);
    });
  }

  /* --- Settings Panel --- */
  function initSettings() {
    var panel = document.getElementById('settings-panel');
    var overlay = document.getElementById('settings-overlay');
    var profile = document.getElementById('sidebar-profile');
    var closeBtn = document.getElementById('settings-close');

    function openSettings() {
      panel.classList.add('open');
      overlay.classList.add('open');
    }
    function closeSettings() {
      panel.classList.remove('open');
      overlay.classList.remove('open');
    }

    profile.addEventListener('click', openSettings);
    closeBtn.addEventListener('click', closeSettings);
    overlay.addEventListener('click', closeSettings);
  }

  /* --- Connection Status --- */
  function setConnection(ok) {
    connected = ok;
    var cls = ok ? 'live' : 'offline';
    var txt = ok ? 'Live' : 'Offline';
    document.getElementById('conn-dot').className = 'status-dot ' + cls;
    document.getElementById('conn-text').textContent = txt;
    document.getElementById('conn-dot-footer').className = 'status-dot ' + cls;
    document.getElementById('conn-text-footer').textContent = ok ? 'Connected' : 'Disconnected';
  }

  function updateTimestamp() {
    document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
  }

  /* --- Polling --- */
  async function pollFast() {
    // Skip polling when timeline replay is active
    if (window.rivaTimeline && window.rivaTimeline.active) return;
    try {
      var fetches = [
        fetch('/api/agents'),
        fetch('/api/agents/history')
      ];
      // Also fetch network if on network tab
      if (currentTab === 'network') {
        fetches.push(fetch('/api/network'));
      }

      var responses = await Promise.all(fetches);
      if (!responses[0].ok || !responses[1].ok) throw new Error('fetch failed');

      var agentsData = await responses[0].json();
      var histData = await responses[1].json();
      lastHistories = histData.histories || {};

      renderAgentTable(agentsData.agents || []);
      renderAgentCards(agentsData.agents || [], lastHistories);

      if (currentTab === 'network' && responses[2] && responses[2].ok) {
        var netData = await responses[2].json();
        renderNetworkTable(netData.network || []);
      }

      setConnection(true);
      updateTimestamp();
    } catch (e) {
      setConnection(false);
    }
  }

  async function pollSlow() {
    try {
      var fetches = [
        fetch('/api/stats'),
        fetch('/api/env'),
        fetch('/api/registry'),
        fetch('/api/config')
      ];

      var responses = await Promise.all(fetches);

      if (responses[0].ok) { var d = await responses[0].json(); renderStatsTable(d.stats || []); renderStatsCards(d.stats || []); }
      if (responses[1].ok) { var d = await responses[1].json(); renderEnvTable(d.env_vars || []); }
      if (responses[2].ok) { var d = await responses[2].json(); renderRegistryTable(d.agents || []); }
      if (responses[3].ok) { var d = await responses[3].json(); renderConfigs(d.configs || []); }

      // Fetch historical data for usage tab
      if (currentTab === 'usage') {
        try {
          var histRes = await fetch('/api/history?hours=1');
          if (histRes.ok) {
            var histData = await histRes.json();
            renderHistoricalChart(histData.snapshots || []);
          }
        } catch (e) {}
      }

      // Fetch forensic data when on forensics tab
      if (currentTab === 'forensics') {
        try {
          var fSessions = await fetch('/api/forensic/sessions');
          if (fSessions.ok) {
            var fData = await fSessions.json();
            renderForensicSessions(fData.sessions || []);
          }
        } catch (e) {}
        try {
          var fTrends = await fetch('/api/forensic/trends');
          if (fTrends.ok) {
            var tData = await fTrends.json();
            renderForensicTrends(tData.trends || {});
          }
        } catch (e) {}
      }

      // Fetch skills data when on skills tab
      if (currentTab === 'skills') {
        try {
          var skRes = await fetch('/api/skills');
          if (skRes.ok) {
            var skData = await skRes.json();
            renderSkills(skData.skills || []);
          }
        } catch (e) {}
      }

      // Fetch events when on events tab
      if (currentTab === 'events') {
        try {
          await pollEvents();
        } catch (e) {}
      }

      setConnection(true);
      updateTimestamp();
    } catch (e) {
      setConnection(false);
    }
  }

  /* --- Audit Button --- */
  window.runAudit = async function(includeNetwork, clickedBtn) {
    var url = '/api/audit';
    if (includeNetwork) url += '?network=true';
    var buttons = document.querySelectorAll('.audit-btn');
    try {
      buttons.forEach(function(b) {
        b.disabled = true;
        b.classList.remove('btn-primary');
      });
      if (clickedBtn) clickedBtn.classList.add('btn-primary');
      var res = await fetch(url);
      if (res.ok) {
        var data = await res.json();
        renderAuditDashboard(data.audit || []);
      }
    } catch (e) {
      // ignore
    } finally {
      buttons.forEach(function(b) { b.disabled = false; });
    }
  };

  /* --- Forensic Session Drill-in --- */
  window.loadForensicSession = async function(id) {
    var detailSection = document.getElementById('sec-forensic-detail');
    var sessionsSection = document.getElementById('sec-forensic-sessions');
    var trendsSection = document.getElementById('sec-forensic-trends');
    var wrap = document.getElementById('forensic-detail-wrap');

    wrap.innerHTML = '<p class="empty-msg">Loading session...</p>';
    detailSection.style.display = 'block';
    sessionsSection.style.display = 'none';
    trendsSection.style.display = 'none';

    try {
      var res = await fetch('/api/forensic/session/' + encodeURIComponent(id));
      if (res.ok) {
        var data = await res.json();
        renderForensicDetail(data);
      } else {
        wrap.innerHTML = '<p class="empty-msg">Session not found</p>';
      }
    } catch (e) {
      wrap.innerHTML = '<p class="empty-msg">Failed to load session</p>';
    }
  };

  window.forensicBackToList = function() {
    document.getElementById('sec-forensic-detail').style.display = 'none';
    document.getElementById('sec-forensic-sessions').style.display = 'block';
    document.getElementById('sec-forensic-trends').style.display = 'block';
  };

  /* --- Skill file open --- */
  document.addEventListener('click', function(e) {
    var link = e.target.closest('.skill-link');
    if (!link) return;
    e.preventDefault();
    var path = link.getAttribute('data-path');
    if (!path) return;
    fetch('/api/open-file', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path: path})
    });
  });

  /* --- Event → Forensic session link --- */
  document.addEventListener('click', function(e) {
    var link = e.target.closest('.event-session-link');
    if (!link) return;
    e.preventDefault();
    var sessionId = link.getAttribute('data-session');
    if (!sessionId) return;
    switchTab('forensics');
    window.loadForensicSession(sessionId);
  });

  /* --- Skill Send Modal --- */
  (function() {
    var modal = document.getElementById('skill-send-modal');
    var overlay = document.getElementById('skill-send-overlay');
    var closeBtn = document.getElementById('skill-send-close');
    var submitBtn = document.getElementById('send-submit');
    var resultEl = document.getElementById('send-result');

    function openModal(skillName, sourceAgent) {
      document.getElementById('send-skill-name').value = skillName;
      document.getElementById('send-source-agent').value = sourceAgent;
      document.getElementById('send-target-workspace').value = '';
      document.getElementById('send-target-agent').value = '';
      resultEl.innerHTML = '';
      modal.classList.add('open');
      overlay.classList.add('open');
      document.getElementById('send-target-workspace').focus();
    }
    function closeModal() {
      modal.classList.remove('open');
      overlay.classList.remove('open');
    }

    closeBtn.addEventListener('click', closeModal);
    overlay.addEventListener('click', closeModal);

    document.addEventListener('click', function(e) {
      var btn = e.target.closest('.skill-send-btn');
      if (!btn) return;
      e.preventDefault();
      openModal(btn.dataset.skill, btn.dataset.agent);
    });

    submitBtn.addEventListener('click', async function() {
      var skillName = document.getElementById('send-skill-name').value;
      var targetWorkspace = document.getElementById('send-target-workspace').value.trim();
      var targetAgent = document.getElementById('send-target-agent').value;
      var sourceAgent = document.getElementById('send-source-agent').value;

      if (!targetWorkspace) {
        resultEl.innerHTML = '<span style="color:var(--red)">Enter a target workspace path.</span>';
        return;
      }

      resultEl.innerHTML = '<span style="color:var(--text-dim)">Exporting...</span>';
      submitBtn.disabled = true;

      try {
        var body = { skill_name: skillName, target_workspace: targetWorkspace };
        if (sourceAgent) body.source_agent = sourceAgent;
        if (targetAgent) body.target_agent = targetAgent;

        var res = await fetch('/api/skills/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        var data = await res.json();
        if (data.ok) {
          resultEl.innerHTML = '<span style="color:var(--green)">' + esc(data.message) + '</span>';
        } else {
          resultEl.innerHTML = '<span style="color:var(--red)">' + esc(data.error) + '</span>';
        }
      } catch (err) {
        resultEl.innerHTML = '<span style="color:var(--red)">Request failed</span>';
      } finally {
        submitBtn.disabled = false;
      }
    });
  })();

  /* --- Events Tab Polling & Filters --- */
  async function pollEvents() {
    var agentFilter = document.getElementById('events-agent-filter');
    var typeFilter = document.getElementById('events-type-filter');
    var hoursFilter = document.getElementById('events-hours-filter');

    var params = new URLSearchParams();
    params.set('limit', '200');
    if (agentFilter && agentFilter.value) params.set('agent', agentFilter.value);
    if (typeFilter && typeFilter.value) params.set('type_prefix', typeFilter.value);
    if (hoursFilter && hoursFilter.value) params.set('hours', hoursFilter.value);

    var res = await fetch('/api/events?' + params.toString());
    if (res.ok) {
      var data = await res.json();
      renderEvents(data.events || []);
    }
  }

  // Auto-poll events every 3s when the events tab is active
  setInterval(function() {
    if (currentTab === 'events') {
      pollEvents().catch(function() {});
    }
  }, 3000);

  // Re-fetch on filter change
  ['events-agent-filter', 'events-type-filter', 'events-hours-filter'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', function() { pollEvents(); });
  });

  /* --- Init --- */
  initSidebar();
  initTabs();
  initTheme();
  initSettings();
  pollFast();
  pollSlow();

  setInterval(pollFast, 2000);
  setInterval(pollSlow, 30000);
})();
