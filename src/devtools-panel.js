// devtools-panel.js — DevTools panel logic (external file: the extension CSP
// `script-src 'self'` blocks inline <script>, which left the panel stuck on "Loading…").
const $ = id => document.getElementById(id);

document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".panel").forEach(x => x.classList.remove("active"));
  t.classList.add("active");
  $("p-" + t.dataset.t).classList.add("active");
}));

// Attribute-safe escaper (escapes quotes too, so title="${esc(x)}" can't break out).
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function refresh() {
  chrome.runtime.sendMessage({ type: "getGlobalFindings" }, r => {
    if (!r || !r.G) return;
    const G = r.G;
    // Header count uses the SHARED tier logic — only tier-3 (confirmed) crit/high count,
    // matching the dashboard's "no false criticals" promise (not raw severity).
    const c = window.yansiiTierCounts(G.findings);
    $("stats").textContent = `${c.total} findings · ${c.crit} confirmed critical · ${c.high} confirmed high · ${Object.keys(G.findings).length} domains`;

    // Findings — same tier-display rules as the dashboard (tier-1 grey "potential",
    // tier-2 yellow "review", tier-3 real severity + "observed"). Sort by tier then severity.
    const tierRank = { 3: 0, 2: 1, 1: 2 };
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    let fhtml = "";
    for (const d in G.findings) {
      const sorted = G.findings[d].slice().sort((a, b) =>
        (tierRank[a.tier || 1] - tierRank[b.tier || 1]) ||
        (sevRank[a.finding.severity] - sevRank[b.finding.severity]));
      for (const e of sorted.slice(0, 50)) {
        const t = window.yansiiTierDisplay(e);
        fhtml += `<div class="row"><span class="sev ${t.sevClass}">${esc(t.sevText)}</span><span class="tstatus">${esc(t.label)}</span><span class="type">${esc(e.finding.type)}</span><span class="url" title="${esc(e.url)}">${esc(e.url)}</span><span class="cvss">${t.tier === 3 ? esc(e.cvss?.score || "?") : ""}</span></div>`;
      }
    }
    $("p-findings").innerHTML = fhtml || '<div class="empty">No findings yet.</div>';

    // Requests
    let rhtml = "";
    for (const d in G.requests) for (const r of G.requests[d].slice(-100)) rhtml += `<div class="row"><span style="color:${r.status < 400 ? 'var(--green)' : 'var(--red)'}">${esc(r.status)}</span><span style="color:var(--mut)">${esc(r.method)}</span><span class="url" style="flex:1" title="${esc(r.url)}">${esc(r.url)}</span><span style="color:var(--mut);font-size:9px">${esc(r.audit || 0)} issues</span></div>`;
    $("p-requests").innerHTML = rhtml || '<div class="empty">No requests yet.</div>';

    // WebSocket
    let whtml = "";
    for (const d in G.wsTraffic) for (const e of G.wsTraffic[d].slice(-100)) whtml += `<div class="row ws-row"><span class="dir ${esc(e.direction || '')}">${esc((e.event || "").toUpperCase())}</span><span class="url" style="flex:1">${esc(e.url)}</span><span style="color:var(--mut)">${esc((e.data || "").slice(0, 100))}</span></div>`;
    $("p-ws").innerHTML = whtml || '<div class="empty">No WebSocket traffic.</div>';

    // Workers
    let wohtml = "";
    for (const d in G.workerEvents) for (const e of G.workerEvents[d].slice(-50)) wohtml += `<div class="row worker-row"><span style="color:var(--purple)">${esc(e.type)}</span><span>${esc(e.event)}</span><span class="url" style="flex:1">${esc(e.url)}</span>${e.data ? `<span style="color:var(--mut)">${esc(e.data.slice(0, 80))}</span>` : ""}</div>`;
    $("p-workers").innerHTML = wohtml || '<div class="empty">No worker events.</div>';

    // postMessage
    let pmhtml = "";
    for (const d in G.pmLog) for (const p of G.pmLog[d]) pmhtml += `<div class="row"><span class="sev ${p.record.analysis?.originCompared ? 'info' : 'high'}">${p.record.analysis?.originCompared ? "✓" : "⚠"}</span><span class="type">postMessage</span><span class="url" style="flex:1">${esc(p.record.frameUrl)}</span><span style="color:var(--purple);font-size:9px">${esc((p.record.analysis?.sinks || []).join(","))}</span></div>`;
    $("p-pm").innerHTML = pmhtml || '<div class="empty">No handlers.</div>';
  });
}

refresh();
setInterval(refresh, 5000);
