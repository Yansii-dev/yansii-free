// sidepanel.js — scan results, crawler, AI chat
const $ = id => document.getElementById(id);
try {
  window.addEventListener("error", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "sidepanel", error: { message: e.message, stack: e.error && e.error.stack, url: location.href } }); } catch {} });
  window.addEventListener("unhandledrejection", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "sidepanel", error: { message: "Unhandled rejection: " + (e.reason && (e.reason.message || e.reason)), stack: e.reason && e.reason.stack, url: location.href } }); } catch {} });
} catch {}
const DEBUG = false;
const dbg = (...a) => { if (DEBUG) console.log("%c[YANSII SP]", "color:#e8403a;font-weight:bold", ...a); };

function toast(message, type = "info", duration = 3000) {
  const el = document.createElement("div");
  el.className = `yansii-toast yansii-toast-${type}`;
  el.textContent = message;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => { el.classList.remove("show"); setTimeout(() => el.remove(), 300); }, duration);
}

let currentScan = null, activeSeverity = "all";
let crawlData = { results: [], running: false };
let pmFindings = [], pmAnalysisCache = {};

// ═══ TABS ═══
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    $("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "scan") refreshPm();
  });
});
chrome.storage.session.get("openTab", d => {
  if (d.openTab) {
    document.querySelector(`[data-tab="${d.openTab}"]`)?.click();
    chrome.storage.session.remove("openTab");
  }
});

// ═══ COLLAPSIBLE SECTIONS ═══
$("pmToggle").addEventListener("click", () => {
  $("pmSection").classList.toggle("hidden");
  $("pmArrow").classList.toggle("open");
  $("pmArrow").textContent = $("pmSection").classList.contains("hidden") ? "▸" : "▾";
  if (!$("pmSection").classList.contains("hidden")) refreshPm();
});

$("notesToggle").addEventListener("click", () => {
  $("notesSection").classList.toggle("hidden");
  $("notesArrow").classList.toggle("open");
  $("notesArrow").textContent = $("notesSection").classList.contains("hidden") ? "▸" : "▾";
});

// ═══ ACTIVITY (last 10 for the current domain) — collapsed by default ═══
function spCurrentDomain() { try { return new URL((currentScan && currentScan.url) || "").hostname; } catch { return null; } }
async function renderSidepanelActivity() {
  const box = $("activityLog"); if (!box) return;
  const resp = await new Promise(r => chrome.runtime.sendMessage({ type: "GET_ACTIVITY_LOG" }, r));
  const log = (resp && resp.log) || [];
  const dom = spCurrentDomain();
  const filtered = log.filter(e => !dom || e.domain === dom).slice(-10).reverse();
  const icon = { info: "ℹ️", success: "✅", warning: "⚠️", error: "❌", debug: "·" };
  const color = { info: "#8b949e", success: "#3fb950", warning: "#d29922", error: "#e8403a", debug: "#6e7681" };
  box.innerHTML = filtered.map(e =>
    `<div style="padding:1px 0"><span style="color:#6e7681">${new Date(e.timestamp).toTimeString().slice(0, 8)}</span> ${icon[e.level] || "·"} <span style="color:${color[e.level] || "#c9d1d9"}">${esc(e.message)}</span></div>`
  ).join("") || '<div style="color:#6e7681">No recent activity for this page.</div>';
}
$("activityToggle").addEventListener("click", () => {
  $("activitySection").classList.toggle("hidden");
  $("activityArrow").classList.toggle("open");
  $("activityArrow").textContent = $("activitySection").classList.contains("hidden") ? "▸" : "▾";
  if (!$("activitySection").classList.contains("hidden")) renderSidepanelActivity();
});

// ═══ SCAN TAB ═══
$("runScan").addEventListener("click", () => {
  $("runScan").textContent = "⏳ Scanning…";
  chrome.runtime.sendMessage({ type: "REQUEST_SCAN" });
});

// Listen for results from background
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_RESULTS") {
    currentScan = msg.payload;
    renderScanResults(currentScan);
  }
  if (msg.type === "LOG_ENTRY" && $("activitySection") && !$("activitySection").classList.contains("hidden")) {
    renderSidepanelActivity();
  }
  if (msg.type === "ANALYZE_SELECTION") {
    if (typeof sendAIMessage !== "function") { toast("AI analysis is a Pro feature. Upgrade at yansii.in/pricing", "warning"); return; }
    switchTab("ai");
    sendAIMessage(`Analyze for vulns:\n\n${msg.text}\n\nURL: ${msg.url}`);
  }

  // ── Crawl events ──
  if (msg.type?.startsWith("CRAWL_")) {
    dbg("📡 Received:", msg.type, msg.payload?.url || msg.payload?.status || "");
  }
  if (msg.type === "CRAWL_PAGE_START") {
    addCrawlLogEntry(msg.payload.url, msg.payload.depth, msg.payload.mode);
  }
  if (msg.type === "CRAWL_PAGE_DONE") {
    crawlData.results.push(msg.payload.page);
    updateCrawlStats(msg.payload.stats, msg.payload.queue);
    updateCrawlLogEntry(msg.payload.page.url, msg.payload.page.mode, msg.payload.page.findings);
  }
  if (msg.type === "CRAWL_PAGE_ERROR") {
    dbg("❌ Crawl error:", msg.payload.url, msg.payload.error);
    updateCrawlLogEntry(msg.payload.url, msg.payload.mode, [], msg.payload.error);
  }
  if (msg.type === "CRAWL_STATUS") {
    dbg("📊 Status:", msg.payload.status, "pages:", msg.payload.stats?.pages, "queue:", msg.payload.queue);
    if (msg.payload.stats) updateCrawlStats(msg.payload.stats, msg.payload.queue || 0);
    if (msg.payload.status === "done") {
      if (msg.payload.totalResults) crawlData.results = msg.payload.totalResults;
      finishCrawlUI();
    } else if (msg.payload.status === "paused") {
      $("crawlStatus").textContent = "Paused";
      $("crawlStatus").className = "crawl-status-text paused";
    } else if (msg.payload.status === "running") {
      $("crawlStatus").textContent = "Crawling…";
      $("crawlStatus").className = "crawl-status-text running";
    }
  }
});

// Restore last scan from session
chrome.storage.session.get("latestScan", d => {
  if (d.latestScan) { currentScan = d.latestScan; renderScanResults(currentScan); }
});

function renderScanResults(scan) {
  $("runScan").textContent = "▶ Scan Page";
  $("scanTime").textContent = new Date(scan.timestamp).toLocaleTimeString();
  const s = scan.summary;
  $("cCrit").textContent = s.critical;
  $("cHigh").textContent = s.high;
  $("cMed").textContent = s.medium;
  $("cLow").textContent = s.low;
  $("cInfo").textContent = s.info;
  $("scanSummary").classList.remove("hidden");
  renderFindings(scan.findings);
}

function renderFindings(findings) {
  const container = $("findings");
  let filtered = findings;
  if (activeSeverity !== "all") filtered = filtered.filter(f => f.severity === activeSeverity);
  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state"><p>${findings.length === 0 ? "No findings." : "No match for filter."}</p></div>`;
    return;
  }
  const so = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => so[a.severity] - so[b.severity]);

  container.innerHTML = filtered.map((f, i) => {
    // Passive scan findings are unverified ("detected") by default. Per the detection-accuracy
    // rules, unverified findings must NOT show an alarming red/orange severity badge — they show
    // a neutral grey INDICATOR (with the underlying severity as a muted hint) so users don't
    // mistake a passive pattern match for a confirmed vulnerability.
    const vs = f.verificationStatus || "detected";
    const sevBadge = vs === "verified"
      ? `<span class="sev-badge sev-${f.severity}">${esc(f.severity)}</span>`
      : `<span class="sev-badge" style="background:#30363d;color:#adbac7" title="Passive detection — not verified (underlying severity: ${esc(f.severity)})">INDICATOR</span><span class="sev-hint" style="font-size:9px;color:#6e7681;margin-left:4px">${esc(f.severity)}</span>`;
    return `<div class="finding">
      <div class="finding-header" data-action="toggle-finding" data-index="${i}">
        ${sevBadge}
        <span class="finding-type">${esc(f.type)}</span>
        <span class="finding-toggle" id="toggle-${i}">▸</span>
      </div>
      <div class="finding-body" id="body-${i}">
        ${f.subtype ? `<div class="field"><div class="field-label">Sub-Type</div><div class="field-value"><span class="subtype-badge">${esc(f.subtype)}</span></div></div>` : ""}
        <div class="field"><div class="field-label">Detail</div><div class="field-value">${esc(f.detail)}</div></div>
        ${f.location ? `<div class="field"><div class="field-label">Location</div><div class="field-value">${esc(f.location)}</div></div>` : ""}
        ${suggestionHtml(f.suggestion)}
        <button class="ai-analyze-btn" data-action="analyze-finding" data-index="${i}">◈ AI Analysis</button>
      </div>
    </div>`;
  }).join("");
}

// ── Event delegation for scan findings ──
$("findings").addEventListener("click", e => {
  const toggle = e.target.closest("[data-action='toggle-finding']");
  if (toggle) {
    const i = toggle.dataset.index;
    const body = $("body-" + i);
    const arrow = $("toggle-" + i);
    body.classList.toggle("open");
    arrow.textContent = body.classList.contains("open") ? "▾" : "▸";
    return;
  }
  const aiBtn = e.target.closest("[data-action='analyze-finding']");
  if (aiBtn) {
    const i = parseInt(aiBtn.dataset.index);
    if (!currentScan) return;
    let f = currentScan.findings;
    if (activeSeverity !== "all") f = f.filter(x => x.severity === activeSeverity);
    f.sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 })[a.severity] - ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 })[b.severity]);
    const fi = f[i]; if (!fi) return;
    if (typeof sendAIMessage !== "function") { toast("AI analysis is a Pro feature. Upgrade at yansii.in/pricing", "warning"); return; }
    switchTab("ai");
    sendAIMessage(`Deep analysis:\n\n${JSON.stringify(fi, null, 2)}\n\nExplain risk, suggest payloads, describe exploitation.`);
  }
});

// Severity filter
$("filterBar").addEventListener("click", e => {
  const b = e.target.closest(".filter");
  if (!b) return;
  document.querySelectorAll(".filter").forEach(f => f.classList.remove("active"));
  b.classList.add("active");
  activeSeverity = b.dataset.sev;
  if (currentScan) renderFindings(currentScan.findings);
});

// Export
$("exportBtn").addEventListener("click", () => {
  if (!currentScan) { toast("No scan results. Click Scan Page first.", "warning"); return; }
  dl(JSON.stringify(currentScan, null, 2), "application/json", `yansii-scan-${new Date().toISOString().slice(0, 10)}.json`);
});

// ═══ POSTMESSAGE SECTION ═══
function refreshPm() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (!tabs[0]) return;
    chrome.runtime.sendMessage({ type: "recollect", tabId: tabs[0].id });
    setTimeout(() => {
      chrome.runtime.sendMessage({ type: "getPmFindings", tabId: tabs[0].id }, r => {
        if (!r) return;
        pmFindings = r.findings || [];
        pmAnalysisCache = r.analysisCache || {};
        $("pmCount").textContent = pmFindings.length + " handler" + (pmFindings.length !== 1 ? "s" : "");
        renderPmFindings();
      });
    }, 300);
  });
}

$("pmRefresh").addEventListener("click", refreshPm);
$("pmTraffic").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "getGlobalLog" }, r => {
    if (!r) return;
    const traffic = r.globalTraffic || {};
    let all = [];
    for (const d in traffic) all.push(...traffic[d].map(t => ({ ...t, domain: d })));
    all.sort((a, b) => b.timestamp - a.timestamp);
    const html = all.slice(0, 200).map(t =>
      `<div class="traffic-entry"><span class="dir ${t.direction}">${t.direction.toUpperCase()}</span> <span style="color:var(--fg2)">${esc(t.origin || "self")} → ${esc(t.domain)}</span><br><span style="color:var(--fg)">${esc((t.preview || "").slice(0, 150))}</span></div>`
    ).join("");
    const overlay = document.createElement("div");
    overlay.className = "traffic-overlay";
    overlay.innerHTML = `<div class="toolbar"><button class="tool-btn" id="closeTraffic">✕ Close</button><div class="spacer"></div><span class="scan-time">${all.length} messages</span></div><div class="findings" style="flex:1;overflow-y:auto">${html || "<div class='empty-state'>No traffic captured yet.</div>"}</div>`;
    const pmPanel = $("pmSection");
    pmPanel.style.position = "relative";
    pmPanel.appendChild(overlay);
    overlay.querySelector("#closeTraffic").addEventListener("click", () => overlay.remove());
  });
});

function renderPmFindings() {
  const container = $("pmFindings");
  if (pmFindings.length === 0) {
    container.innerHTML = `<div class="empty-state"><p style="font-size:11px">No postMessage handlers found. Reload the page to capture.</p></div>`;
    return;
  }
  container.innerHTML = pmFindings.map((r, i) => {
    const a = r.analysis || {};
    const cached = pmAnalysisCache[keyOfPm(r)];
    const verdict = cached ? cached.verdict : "none";
    const vClass = verdict === "likely_vulnerable" ? "vuln" : verdict === "needs_review" ? "review" : verdict === "likely_safe" ? "safe" : "none";
    const sinks = a.sinks?.length ? a.sinks.join(", ") : "none";
    const originBad = !a.originCompared;
    return `<div class="pm-card">
      <div class="pm-header" data-action="toggle-pm" data-index="${i}">
        <span class="pm-verdict ${vClass}">${cached ? esc(verdict) : "unscanned"}</span>
        <span class="pm-title">${originBad ? "⚠ " : ""}${esc(r.frameUrl || "?")}</span>
        <span class="pm-sinks">${sinks}</span>
      </div>
      <div class="pm-body" id="pm-body-${i}">
        <div class="field"><div class="field-label">Origin Check</div><div class="field-value">${a.originCompared ? "✅ Yes" : "❌ NO — any origin can send messages"}</div></div>
        <div class="field"><div class="field-label">Sinks</div><div class="field-value">${sinks}</div></div>
        ${r.parentUrl ? `<div class="field"><div class="field-label">Parent (iframe)</div><div class="field-value">${esc(r.parentUrl)}</div></div>` : ""}
        <div class="field"><div class="field-label">Handler Source</div><div class="pm-source">${esc(r.source || "[none]")}</div></div>
        ${cached ? `<div class="pm-analysis-box">
          <div class="verdict ${vClass}">${esc(verdict)} (${esc(cached.confidence || "?")}%)</div>
          ${cached.data_flow ? `<div>Sink: ${cached.data_flow.reaches_sink ? "✅ " + esc(cached.data_flow.sink || "?") : "none"}</div><div>${esc(cached.data_flow.tainted_path || "")}</div>` : ""}
          <div style="margin-top:4px">${esc(cached.notes || "")}</div>
          ${cached.test_payload ? `<div style="margin-top:4px;color:var(--blue);font-size:9px">Probe: ${esc(cached.test_payload.slice(0, 200))}</div>` : ""}
        </div>` : ""}
        <div class="pm-actions">
          <button class="pm-btn primary" data-action="analyze-pm" data-index="${i}">◈ ${cached ? "Re-analyze" : "Analyze"}</button>
          ${cached && (verdict === "likely_vulnerable" || verdict === "needs_review") ? `<button class="pm-btn" data-action="verify-pm" data-index="${i}">⚡ Verify</button><button class="pm-btn" data-action="doc-pm" data-index="${i}">📄 Doc</button>` : ""}
        </div>
      </div>
    </div>`;
  }).join("");
}

// PM event delegation
$("pmFindings").addEventListener("click", e => {
  const toggleEl = e.target.closest("[data-action='toggle-pm']");
  if (toggleEl) {
    const i = toggleEl.dataset.index;
    $("pm-body-" + i).classList.toggle("open");
    return;
  }
  const analyzeEl = e.target.closest("[data-action='analyze-pm']");
  if (analyzeEl) { analyzePm(parseInt(analyzeEl.dataset.index), analyzeEl); return; }
  const verifyEl = e.target.closest("[data-action='verify-pm']");
  if (verifyEl) { verifyPm(parseInt(verifyEl.dataset.index)); return; }
  const docEl = e.target.closest("[data-action='doc-pm']");
  if (docEl) { docPm(parseInt(docEl.dataset.index)); return; }
});

function keyOfPm(r) { return (r.frameUrl || "") + (r.source || "").slice(0, 400); }

async function analyzePm(i, btn) {
  const r = pmFindings[i]; if (!r) return;
  const tabId = await getTabId();
  if (btn) { btn.textContent = "Analyzing…"; btn.disabled = true; }
  chrome.runtime.sendMessage({ type: "analyzePm", record: r, tabId }, resp => {
    if (btn) { btn.textContent = "◈ Analyze"; btn.disabled = false; }
    if (resp?.ok) { pmAnalysisCache[keyOfPm(r)] = resp.result; renderPmFindings(); }
    else toast("Error: " + (resp?.error || "unknown"), "error");
  });
}
function verifyPm(i) {
  const r = pmFindings[i], a = pmAnalysisCache[keyOfPm(r)];
  chrome.runtime.sendMessage({ type: "startVerify", record: r, analysis: a });
}
function docPm(i) {
  const r = pmFindings[i], a = pmAnalysisCache[keyOfPm(r)];
  chrome.runtime.sendMessage({ type: "generateDoc", record: r, analysis: a, verifyResult: "not_confirmed", pocHtml: null }, resp => {
    if (resp?.ok) dl(resp.markdown, "text/markdown", `finding_${domainOf(r.frameUrl)}_${new Date().toISOString().slice(0, 10)}.md`);
  });
}
function domainOf(u) { try { return new URL(u).hostname; } catch { return "unknown"; } }
async function getTabId() { return new Promise(r => chrome.tabs.query({ active: true, currentWindow: true }, t => r(t[0]?.id || 0))); }

// ═══ CRAWL TAB ═══
$("crawlScope").addEventListener("change", () => {
  $("customScopeRow").style.display = $("crawlScope").value === "custom" ? "" : "none";
});

$("startCrawl").addEventListener("click", () => {
  dbg("Crawl button clicked");
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    dbg("tabs.query result:", tabs);
    if (!tabs[0]) {
      dbg("No active tab, trying lastFocusedWindow…");
      chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs2 => {
        if (tabs2[0]) startCrawlWithUrl(tabs2[0].url);
        else { dbg("ERROR: No tab found."); }
      });
      return;
    }
    dbg("Starting crawl from:", tabs[0].url);
    startCrawlWithUrl(tabs[0].url);
  });
});

function startCrawlWithUrl(startUrl) {
  const config = {
    startUrl,
    scope: $("crawlScope").value,
    scopeRegex: $("crawlScopeRegex")?.value || "",
    authMode: $("crawlAuth").value,
    speed: $("crawlSpeed").value,
    maxDepth: Math.max(1, Math.min(20, parseInt($("crawlDepth").value, 10) || 5)),
    maxPages: $("crawlMaxPages").value,
    scanMode: "full"
  };
  dbg("Crawl config:", JSON.stringify(config));
  crawlData = { results: [], running: true };
  $("crawlProgress").classList.remove("hidden");
  $("crawlPageMax").textContent = config.maxPages;
  $("crawlLog").innerHTML = "";
  $("startCrawl").style.display = "none";
  $("pauseCrawl").style.display = "";
  $("stopCrawl").style.display = "";
  $("exportCrawl").style.display = "none";
  $("crawlStatus").textContent = "Starting…";
  $("crawlStatus").className = "crawl-status-text running";

  // Send CRAWL_START to background
  chrome.runtime.sendMessage({ type: "CRAWL_START", config }, resp => {
    dbg("CRAWL_START sendMessage callback:", resp);
  });
  dbg("CRAWL_START sent to background");
}

$("pauseCrawl").addEventListener("click", () => {
  if ($("pauseCrawl").textContent.includes("Pause")) {
    chrome.runtime.sendMessage({ type: "CRAWL_PAUSE" });
    $("pauseCrawl").textContent = "▶ Resume";
  } else {
    chrome.runtime.sendMessage({ type: "CRAWL_RESUME" });
    $("pauseCrawl").textContent = "⏸ Pause";
  }
});
$("stopCrawl").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CRAWL_STOP" });
  finishCrawlUI();
});
$("exportCrawl").addEventListener("click", () => {
  if (crawlData.results.length) dl(JSON.stringify(crawlData.results, null, 2), "application/json", `yansii-crawl-${new Date().toISOString().slice(0, 10)}.json`);
});

function updateCrawlStats(s, q) {
  $("crawlPageCount").textContent = s.pages;
  $("crawlQueueCount").textContent = q;
  $("crawlFindingCount").textContent = s.findings;
  const max = parseInt($("crawlPageMax").textContent) || 50;
  $("crawlBar").style.width = Math.min(100, (s.pages / max) * 100) + "%";
}

function addCrawlLogEntry(url, depth, mode) {
  const log = $("crawlLog");
  const id = "c-" + btoa(unescape(encodeURIComponent(url + mode))).replace(/[^a-z0-9]/gi, "").slice(0, 20);
  if (document.getElementById(id)) return;
  const e = document.createElement("div");
  e.className = "crawl-entry";
  e.id = id;
  e.innerHTML = `<div class="ce-url">${esc(url)}</div><div class="ce-status"><span class="ce-badge ${mode === "auth" ? "auth-tag" : "noauth-tag"}">${mode}</span><span class="ce-badge pending">d=${depth} scanning…</span></div>`;
  log.prepend(e);
}

function updateCrawlLogEntry(url, mode, findings, error) {
  const id = "c-" + btoa(unescape(encodeURIComponent(url + mode))).replace(/[^a-z0-9]/gi, "").slice(0, 20);
  const e = document.getElementById(id);
  if (!e) return;
  const st = e.querySelector(".ce-status");
  if (error) {
    st.innerHTML = `<span class="ce-badge" style="background:#2d0a0c;color:var(--accent)">Error</span>`;
    return;
  }
  const t = findings.length;
  const cr = findings.filter(f => f.severity === "critical").length;
  const hi = findings.filter(f => f.severity === "high").length;
  st.innerHTML = `<span class="ce-badge ${mode === "auth" ? "auth-tag" : "noauth-tag"}">${mode}</span>${t === 0 ? '<span class="ce-badge clean">Clean</span>' : `<span class="ce-badge has-findings">${t}</span>${cr ? `<span style="color:var(--accent);font-size:9px;font-weight:600">${cr}C</span>` : ""}${hi ? `<span style="color:var(--orange);font-size:9px;font-weight:600">${hi}H</span>` : ""}`}`;
  e.onclick = () => {
    if (!t) return;
    currentScan = {
      url, timestamp: new Date().toISOString(), title: url, findings,
      summary: { total: t, critical: cr, high: hi, medium: findings.filter(f => f.severity === "medium").length, low: findings.filter(f => f.severity === "low").length, info: findings.filter(f => f.severity === "info").length }
    };
    switchTab("scan");
    renderScanResults(currentScan);
  };
}

function finishCrawlUI() {
  $("crawlStatus").textContent = "Done";
  $("crawlStatus").className = "crawl-status-text done";
  $("startCrawl").style.display = "";
  $("startCrawl").textContent = "⥁ Restart";
  $("pauseCrawl").style.display = "none";
  $("stopCrawl").style.display = "none";
  $("exportCrawl").style.display = "";
}

// Restore the last completed crawl when the side panel is reopened (item 3.6)
chrome.runtime.sendMessage({ type: "GET_CRAWL_HISTORY" }, resp => {
  const h = resp?.history;
  if (!h || !Array.isArray(h.results) || !h.results.length) return;
  if (crawlData.running) return; // a live crawl is in progress; don't clobber it
  crawlData.results = h.results;
  $("crawlProgress")?.classList.remove("hidden");
  if ($("crawlLog")) {
    $("crawlLog").innerHTML = "";
    for (const p of h.results) { addCrawlLogEntry(p.url, p.depth, p.mode); updateCrawlLogEntry(p.url, p.mode, p.findings || []); }
  }
  updateCrawlStats(h.stats || { pages: h.results.length, findings: 0 }, 0);
  if ($("crawlStatus")) { $("crawlStatus").textContent = "Last crawl · " + new Date(h.timestamp).toLocaleString(); $("crawlStatus").className = "crawl-status-text done"; }
  if ($("exportCrawl")) $("exportCrawl").style.display = "";
});


// ═══ NOTES ═══
chrome.storage.local.get("notes", d => { if (d.notes) $("notesArea").value = d.notes; });
$("notesArea").addEventListener("input", () => chrome.storage.local.set({ notes: $("notesArea").value }));
$("clearNotes").addEventListener("click", () => { $("notesArea").value = ""; chrome.storage.local.set({ notes: "" }); toast("Notes cleared", "success"); });
$("copyNotes").addEventListener("click", () => navigator.clipboard.writeText($("notesArea").value));

// ═══ UTILS ═══
function switchTab(t) {
  document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
  document.querySelector(`[data-tab="${t}"]`).classList.add("active");
  $("panel-" + t).classList.add("active");
}
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
// P8: show 2-3 verification steps; hide the full payload cheat sheet behind a collapsed expander.
function suggestionHtml(text) {
  if (!text) return "";
  const s = String(text), lines = s.split("\n");
  if (s.length <= 240 || lines.filter(l => l.trim()).length <= 3) return `<div class="suggestion">💡 ${esc(s)}</div>`;
  const concise = []; let i = 0;
  for (; i < lines.length && concise.length < 3; i++) { if (lines[i].trim()) concise.push(lines[i]); }
  const advanced = lines.slice(i).join("\n").trim();
  return `<div class="suggestion">💡 ${esc(concise.join("\n"))}` +
    (advanced ? `<details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px">Show advanced payloads</summary><pre style="white-space:pre-wrap;margin-top:4px">${esc(advanced)}</pre></details>` : "") +
    `</div>`;
}
function dl(content, type, name) {
  const b = new Blob([content], { type });
  const u = URL.createObjectURL(b);
  const a = document.createElement("a");
  a.href = u; a.download = name; a.click();
  URL.revokeObjectURL(u);
}

