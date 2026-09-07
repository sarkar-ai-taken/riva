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
    window.rivaOpenSettings = openSettings;
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
        fetch(window.rivaApiUrl('/agents')),
        fetch(window.rivaApiUrl('/agents/history'))
      ];
      // Also fetch network if on network tab
      if (currentTab === 'network') {
        fetches.push(fetch(window.rivaApiUrl('/network')));
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
        fetch(window.rivaApiUrl('/stats')),
        fetch(window.rivaApiUrl('/env')),
        fetch(window.rivaApiUrl('/registry')),
        fetch(window.rivaApiUrl('/config'))
      ];

      var responses = await Promise.all(fetches);

      if (responses[0].ok) { var d = await responses[0].json(); renderStatsTable(d.stats || []); renderStatsCards(d.stats || []); }
      if (responses[1].ok) { var d = await responses[1].json(); renderEnvTable(d.env_vars || []); }
      if (responses[2].ok) { var d = await responses[2].json(); renderRegistryTable(d.agents || []); }
      if (responses[3].ok) { var d = await responses[3].json(); renderConfigs(d.configs || []); }

      // Autoload: fetch every tab's data so switching tabs is instant.
      // The active tab still gets 2s updates via pollFast where applicable.
      try {
        var histRes = await fetch(window.rivaApiUrl('/history?hours=1'));
        if (histRes.ok) {
          var histData = await histRes.json();
          renderHistoricalChart(histData.snapshots || []);
        }
      } catch (e) {}

      try {
        var fSessions = await fetch(window.rivaApiUrl('/forensic/sessions'));
        if (fSessions.ok) {
          var fData = await fSessions.json();
          renderForensicSessions(fData.sessions || []);
        }
      } catch (e) {}
      try {
        var fTrends = await fetch(window.rivaApiUrl('/forensic/trends'));
        if (fTrends.ok) {
          var tData = await fTrends.json();
          renderForensicTrends(tData.trends || {});
        }
      } catch (e) {}

      try {
        var skRes = await fetch(window.rivaApiUrl('/skills'));
        if (skRes.ok) {
          var skData = await skRes.json();
          renderSkills(skData.skills || []);
        }
      } catch (e) {}

      try {
        await pollEvents();
      } catch (e) {}

      // Preload the network tab too (pollFast refreshes it while viewing).
      try {
        var netRes = await fetch(window.rivaApiUrl('/network'));
        if (netRes.ok) {
          var netData = await netRes.json();
          renderNetworkTable(netData.network || []);
        }
      } catch (e) {}

      setConnection(true);
      updateTimestamp();
    } catch (e) {
      setConnection(false);
    }
  }

  /* --- Audit Button --- */
  window.runAudit = async function(includeNetwork, clickedBtn) {
    var url = window.rivaApiUrl('/audit');
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
      var res = await fetch(window.rivaApiUrl('/forensic/session/' + encodeURIComponent(id)));
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
    fetch(window.rivaApiUrl('/open-file'), {
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

        var res = await fetch(window.rivaApiUrl('/skills/send'), {
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

    var res = await fetch(window.rivaApiUrl('/events?' + params.toString()));
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

  /* --- Server Link (one machine, many servers) --- */
  function initServerLink() {
    var unlinkedEl = document.getElementById('link-unlinked');
    var linkedEl = document.getElementById('link-linked');
    if (!unlinkedEl || !linkedEl) return;

    var listEl = document.getElementById('link-list');
    var urlInput = document.getElementById('link-server-url');
    var addLabel = document.getElementById('link-add-label');
    var defaultHint = document.getElementById('link-default-hint');
    var startBtn = document.getElementById('link-start-btn');
    var pairingEl = document.getElementById('link-pairing');
    var codeEl = document.getElementById('link-code');
    var approveLink = document.getElementById('link-approve-url');
    var pairingStatus = document.getElementById('link-pairing-status');
    var errorEl = document.getElementById('link-error');

    var pollTimer = null;
    var userEditedUrl = false;

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = 'block';
    }
    function clearError() {
      errorEl.style.display = 'none';
      errorEl.textContent = '';
    }
    function esc(str) {
      return String(str == null ? '' : str).replace(/[&<>"']/g, function(c) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
      });
    }

    function fmtAgo(ts) {
      if (!ts) return 'never';
      var secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
      if (secs < 60) return secs + 's ago';
      if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
      return Math.floor(secs / 3600) + 'h ago';
    }

    function norm(u) { return (u || '').trim().replace(/\/+$/, '').toLowerCase(); }

    function renderStatus(data) {
      var links = (data && data.links) || [];
      var bubble = document.getElementById('settings-link-bubble');
      if (bubble) bubble.classList.toggle('visible', links.length === 0);

      // Default URL: prefill until the user types, and never suggest a server
      // that is already linked.
      var def = (data && data.default_server_url) || 'https://rivalabs.ai';
      var alreadyDefault = links.some(function(l) { return norm(l.server_url) === norm(def); });
      urlInput.placeholder = def;
      if (!userEditedUrl) urlInput.value = alreadyDefault ? '' : def;
      defaultHint.textContent = data && data.dev_mode
        ? 'Dev mode (RIVA_DEV): defaults to your local server at ' + def + '.'
        : (alreadyDefault ? 'Add another server, e.g. one your company hosts.' : 'Default: the hosted Riva service at ' + def + '.');
      addLabel.textContent = links.length ? 'Add another server' : 'Server URL';

      if (!links.length) {
        linkedEl.style.display = 'none';
        listEl.innerHTML = '';
        return;
      }
      linkedEl.style.display = 'block';
      listEl.innerHTML = links.map(function(l, i) {
        var tag = (links.length > 1 && i === 0) ? ' <span class="settings-hint" style="display:inline">(primary)</span>' : '';
        return '<div class="link-status-card" data-url="' + esc(l.server_url) + '">' +
          '<div class="link-status-row"><span class="status-dot live"></span>' +
          '<span>Linked to <strong>' + esc(l.server_url) + '</strong>' + tag + '</span></div>' +
          '<div class="link-detail"><span>Tenant</span><code>' + esc(l.tenant_id) + '</code></div>' +
          '<div class="link-detail"><span>API key</span><code>' + esc(l.api_key_masked) + '</code></div>' +
          '<div class="link-detail"><span>Sync</span><span>' + (l.last_synced ? ('Last synced ' + fmtAgo(l.last_synced)) : 'Syncing…') + '</span></div>' +
          '<div class="link-card-actions">' +
          '<button class="btn link-sync-btn">Sync now</button>' +
          '<button class="btn btn-danger link-unlink-btn">Unlink</button>' +
          '</div></div>';
      }).join('');
    }

    async function refreshStatus() {
      try {
        var res = await fetch(window.rivaApiUrl('/link/status'));
        if (res.ok) renderStatus(await res.json());
      } catch (e) { /* ignore */ }
    }

    function resetStartBtn() {
      startBtn.disabled = false;
      startBtn.textContent = 'Link to Server';
    }

    async function tryRedeem(serverUrl, token) {
      try {
        var res = await fetch(window.rivaApiUrl('/link/redeem'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ server_url: serverUrl, pairing_token: token })
        });
        var data = await res.json();
        if (res.ok && data.linked) {
          if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
          pairingEl.style.display = 'none';
          resetStartBtn();
          userEditedUrl = false;
          await refreshStatus();
          return true;
        }
      } catch (e) { /* keep polling */ }
      return false;
    }

    urlInput.addEventListener('input', function() { userEditedUrl = true; });

    startBtn.addEventListener('click', async function() {
      clearError();
      var serverUrl = (urlInput.value || urlInput.placeholder || '').trim();
      if (!serverUrl) { showError('Enter a server URL.'); return; }

      startBtn.disabled = true;
      startBtn.textContent = 'Requesting…';
      pairingEl.style.display = 'none';

      try {
        var res = await fetch(window.rivaApiUrl('/link/start'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ server_url: serverUrl })
        });
        var data = await res.json();
        if (!res.ok) { showError(data.error || 'Link failed.'); resetStartBtn(); return; }

        // Show approval affordances if the server requires it.
        if (data.code) { codeEl.textContent = data.code; codeEl.style.display = 'block'; }
        else { codeEl.style.display = 'none'; }
        if (data.approve_url) {
          approveLink.href = data.approve_url;
          approveLink.style.display = 'inline';
          // Open the server's login/approve page right away — the user signs
          // in there, confirms the code matches, and approves.
          try { window.open(data.approve_url, '_blank', 'noopener'); } catch (e) { /* popup blocked — link stays visible */ }
        }
        else { approveLink.style.display = 'none'; }
        pairingEl.style.display = 'block';
        startBtn.textContent = 'Waiting for approval…';

        // Attempt redeem immediately (auto-approve), then poll.
        var done = await tryRedeem(serverUrl, data.pairing_token);
        if (!done) {
          var attempts = 0;
          pollTimer = setInterval(async function() {
            attempts++;
            if (attempts > 60) { clearInterval(pollTimer); pollTimer = null; pairingStatus.textContent = 'Approval timed out.'; resetStartBtn(); return; }
            await tryRedeem(serverUrl, data.pairing_token);
          }, 2000);
        }
      } catch (e) {
        showError('Request failed.');
        resetStartBtn();
      }
    });

    // Per-server Sync / Unlink (delegated: cards are re-rendered on refresh).
    listEl.addEventListener('click', async function(e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      var card = btn.closest('.link-status-card');
      var serverUrl = card && card.getAttribute('data-url');
      if (!serverUrl) return;
      var prev = btn.textContent;
      btn.disabled = true;
      try {
        if (btn.classList.contains('link-sync-btn')) {
          btn.textContent = 'Syncing…';
          await fetch(window.rivaApiUrl('/link/sync'), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_url: serverUrl })
          });
        } else if (btn.classList.contains('link-unlink-btn')) {
          btn.textContent = 'Unlinking…';
          await fetch(window.rivaApiUrl('/link/unlink'), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_url: serverUrl })
          });
          userEditedUrl = false;
        }
      } catch (err) { /* ignore */ }
      btn.disabled = false;
      btn.textContent = prev;
      await refreshStatus();
    });

    var bubble = document.getElementById('settings-link-bubble');
    if (bubble) {
      bubble.addEventListener('click', function(e) {
        e.stopPropagation();
        if (window.rivaOpenSettings) window.rivaOpenSettings();
        var section = document.getElementById('server-link-section');
        if (section) {
          section.scrollIntoView({ behavior: 'smooth', block: 'start' });
          section.classList.remove('flash-highlight');
          void section.offsetWidth; // restart the animation
          section.classList.add('flash-highlight');
        }
      });
    }

    refreshStatus();
    // Keep the linked-status view fresh (last-synced ticks) every 10s.
    setInterval(refreshStatus, 10000);
  }

  /* --- Init --- */
  initSidebar();
  initTabs();
  initTheme();
  initSettings();
  initServerLink();
  pollFast();
  pollSlow();

  setInterval(pollFast, 2000);
  setInterval(pollSlow, 30000);
})();
