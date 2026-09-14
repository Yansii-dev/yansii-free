// diagnostics.js — build-agnostic self-check + runtime error viewer
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
function send(msg) { return new Promise(r => { try { chrome.runtime.sendMessage(msg, resp => { void chrome.runtime.lastError; r(resp); }); } catch { r(null); } }); }

let lastReport = "";

async function loadBuildInfo() {
  try {
    const res = await fetch(chrome.runtime.getURL("build-info.json"));
    const info = await res.json();
    $("stamp").innerHTML = `Build: <b>${esc(info.build)}</b> · v<b>${esc(info.version)}</b> · id <b>${esc(info.buildId)}</b> · built ${esc(info.builtAt)}`;
    return info;
  } catch {
    $("stamp").innerHTML = `Build: <b class="warn">unknown</b> (build-info.json missing — this may be an unbuilt/dev copy)`;
    return { build: "unknown", version: "?", buildId: "?", builtAt: "?" };
  }
}

async function runChecks() {
  const checks = [];
  // 1) service worker responds
  const t0 = Date.now();
  const ping = await send({ type: "PING" });
  checks.push({ ok: !!(ping && ping.ok), label: "Service worker responds", detail: ping && ping.ok ? `${Date.now() - t0}ms` : "no response (SW may be asleep/crashed)" });
  // 2) storage accessible
  let storageOk = false, storageDetail = "";
  try { await new Promise((res, rej) => chrome.storage.local.get(["enabled"], r => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(r))); storageOk = true; }
  catch (e) { storageDetail = e.message; }
  checks.push({ ok: storageOk, label: "Local storage accessible", detail: storageDetail });
  // 3) diagnostics payload
  const diag = await send({ type: "GET_DIAGNOSTICS" });
  checks.push({ ok: !!diag, label: "Diagnostics channel", detail: diag ? "ok" : "no response" });
  // 4) AI key configured (client-side)
  let aiConfigured = false;
  try { const s = await new Promise(r => chrome.storage.local.get(["apiKey", "provider"], r)); aiConfigured = !!(s.apiKey && s.provider); } catch {}
  checks.push({ ok: true, warn: !aiConfigured, label: "AI provider configured", detail: aiConfigured ? "yes" : "no (AI features disabled — scanners & ⚡ Verify still work)" });
  // 5) CSP integrity — extension CSP is `script-src 'self'`, so any inline <script> in an
  // extension page is silently blocked (leaving that page dead). Runtime error logs don't
  // catch this, so scan every page for inline scripts.
  const HTML_PAGES = ["src/dashboard.html", "src/devtools-panel.html", "src/devtools.html", "src/diagnostics.html", "src/popup.html", "src/sidepanel.html", "src/verify.html"];
  const inlineHits = [];
  for (const pg of HTML_PAGES) {
    try {
      const html = await (await fetch(chrome.runtime.getURL(pg))).text();
      const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
      let m; while ((m = re.exec(html))) { if (m[1].trim()) { inlineHits.push(pg.replace("src/", "")); break; } }
    } catch {}
  }
  checks.push({ ok: inlineHits.length === 0, label: "No CSP-blocked inline scripts", detail: inlineHits.length ? `BLOCKED (page dead): ${inlineHits.join(", ")} — move to an external .js` : "all pages use external scripts" });

  $("checks").innerHTML = checks.map(c => {
    const cls = c.ok ? (c.warn ? "warn" : "ok") : "bad";
    const icon = c.ok ? (c.warn ? "warn" : "ok") : "bad";
    return `<div class="check"><span class="dot ${icon}"></span><span>${esc(c.label)}</span><span class="muted" style="margin-left:auto">${esc(c.detail || "")}</span></div>`;
  }).join("");
  return { diag, aiConfigured };
}

function renderState(diag, aiConfigured) {
  if (!diag) { $("state").innerHTML = '<span class="bad">No diagnostics available.</span>'; return; }
  const rows = [
    ["Extension", diag.enabled ? '<span class="ok">Enabled</span>' : '<span class="bad">Disabled</span>'],
    ["Auto-scan", diag.scanPaused ? '<span class="warn">Paused</span>' : '<span class="ok">Active</span>'],
    ["License tier", esc(diag.license && diag.license.tier) + (diag.license && diag.license.trialDays != null ? ` (${diag.license.trialDays}d trial)` : "")],
    ["AI configured", aiConfigured ? '<span class="ok">Yes</span>' : '<span class="warn">No</span>'],
    ["Safe mode", diag.safeMode ? '<span class="warn">On (passive only)</span>' : "Off"],
    ["Scope", (diag.scope && diag.scope.length) ? esc(diag.scope.join(", ")) : '<span class="muted">all domains (no scope set)</span>'],
    ["Domains with findings", diag.domains],
    ["Total findings", diag.totalFindings],
    ["postMessage handlers", diag.pmHandlers],
    ["Confirmed bugs", diag.confirmedBugs],
    ["Learned false-positives", diag.falsePositivePatterns],
    ["Bridge", diag.bridge && diag.bridge.connected ? `<span class="ok">Connected</span> ${esc(diag.bridge.url)}` : (diag.bridge && diag.bridge.url ? `Not connected (${esc(diag.bridge.url)})` : '<span class="muted">not configured</span>')],
  ];
  $("state").innerHTML = rows.map(([k, v]) => `<div class="row"><span class="k">${esc(k)}</span><span>${v}</span></div>`).join("");
}

async function renderErrors() {
  const r = await send({ type: "GET_ERRORS" });
  const errs = (r && r.errors) || [];
  $("errCount").textContent = errs.length ? `(${errs.length})` : "(none)";
  if (!errs.length) { $("errors").innerHTML = '<div class="muted">No runtime errors recorded. 🎉</div>'; return errs; }
  $("errors").innerHTML = errs.map(e =>
    `<div class="err"><div><span class="src">[${esc(e.source)}]</span> <span class="msg">${esc(e.message)}</span></div>` +
    `<div class="meta">${esc(new Date(e.ts).toLocaleTimeString())}${e.url ? " · " + esc(e.url) : ""}</div>` +
    (e.stack ? `<pre>${esc(e.stack)}</pre>` : "") + `</div>`
  ).join("");
  return errs;
}

async function refreshAll() {
  const info = await loadBuildInfo();
  const { diag, aiConfigured } = await runChecks();
  renderState(diag, aiConfigured);
  const errs = await renderErrors();
  lastReport = [
    `YANSII Diagnostics`,
    `Build: ${info.build} v${info.version} (${info.buildId}) built ${info.builtAt}`,
    diag ? `Enabled:${diag.enabled} Paused:${diag.scanPaused} Tier:${diag.license && diag.license.tier} Safe:${diag.safeMode} AI:${aiConfigured}` : "diag: n/a",
    diag ? `Domains:${diag.domains} Findings:${diag.totalFindings} PM:${diag.pmHandlers} Confirmed:${diag.confirmedBugs} FP-learned:${diag.falsePositivePatterns}` : "",
    diag ? `Scope: ${(diag.scope || []).join(", ") || "all"}` : "",
    ``,
    `Errors (${errs.length}):`,
    ...errs.map(e => `  [${e.source}] ${e.message}${e.url ? " @ " + e.url : ""}`),
  ].join("\n");
}

$("refresh").addEventListener("click", refreshAll);
$("clearErrors").addEventListener("click", async () => { await send({ type: "CLEAR_ERRORS" }); renderErrors(); });
$("copyReport").addEventListener("click", () => {
  navigator.clipboard.writeText(lastReport).then(
    () => { $("copyReport").textContent = "✓ Copied"; setTimeout(() => $("copyReport").textContent = "📋 Copy report", 1500); },
    () => { $("copyReport").textContent = "clipboard blocked"; }
  );
});

refreshAll();
