// background.js — YANSII service worker
// All data stored locally. AI calls only to user-configured provider.

let DEBUG = false;
function dbg(...a) { if (DEBUG) console.log("[YANSII BG]", ...a); }
function dbgOk(...a) { if (DEBUG) console.log("[YANSII BG] ✓", ...a); }
function dbgWarn(...a) { if (DEBUG) console.warn("[YANSII BG] ⚠", ...a); }
let enabled = true, dirty = false, flushTimer = null;
let scanPausedState = false;
try { chrome.storage.sync.get(["scanPaused"], r => { scanPausedState = r.scanPaused === true; updateBadge(); }); } catch {}
try { chrome.storage.sync.get(["maxRequestsPerSec"], r => { if (r.maxRequestsPerSec) G.maxRequestsPerSec = r.maxRequestsPerSec; }); } catch {}

// ── Runtime error collector (for the Diagnostics view) ──
// Ephemeral, capped ring buffer of the most recent runtime errors from any context.
const RUNTIME_ERRORS = [];
function recordError(source, message, stack) {
  if (!message) return;
  RUNTIME_ERRORS.push({ source: source || "background", message: String(message).slice(0, 500), stack: (stack || "").slice(0, 800), ts: Date.now(), url: "" });
  if (RUNTIME_ERRORS.length > 100) RUNTIME_ERRORS.splice(0, RUNTIME_ERRORS.length - 100);
}
try {
  self.addEventListener("error", e => recordError("background", e.message || (e.error && e.error.message), e.error && e.error.stack));
  self.addEventListener("unhandledrejection", e => recordError("background", "Unhandled rejection: " + (e.reason && (e.reason.message || e.reason)), e.reason && e.reason.stack));
} catch {}

// ── BUG FIX: Noise domain skip list (Bug 2) ──
const NOISE_DOMAINS = new Set([
  // Analytics & Tracking
  "google-analytics.com","googletagmanager.com","doubleclick.net",
  "facebook.net","fbcdn.net","hubspot.com","hotjar.com",
  "cloudflare.com","cloudflareinsights.com","sentry.io",
  "datadoghq.com","newrelic.com","segment.io","amplitude.com",
  "mixpanel.com","intercom.io","drift.com","zendesk.com",
  // Google + CDNs
  "google.com","gstatic.com","googleapis.com","googlesyndication.com",
  "google-analytics.com","fonts.googleapis.com","fonts.gstatic.com",
  "cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com",
  // Social & Ads
  "connect.facebook.net","platform.twitter.com","ads-twitter.com",
  "snap.licdn.com","bat.bing.com","clarity.ms","browser.sentry-cdn.com",
  // User's own AI providers (BYOK model) — don't scan your own API keys
  "api.anthropic.com","api.openai.com","api.groq.com","openrouter.ai"
]);

function isNoiseDomain(domain) {
  if (!domain) return false;
  domain = domain.toLowerCase();
  if (NOISE_DOMAINS.has(domain)) return true;
  for (const nd of NOISE_DOMAINS) {
    if (domain.endsWith("." + nd)) return true;
  }
  return false;
}

// ── BUG FIX: Tracking cookie skip list (Bug 3) ──
const TRACKING_COOKIES = new Set([
  "_ga","_gid","_gat","_gat_gtag","_fbp","_fbc","_gcl_au","_gcl_aw",
  "_hjid","_hjSessionUser","_hjSession","_hjAbsoluteSessionInProgress",
  "__hssc","__hssrc","__hstc","hubspotutk",
  "_uetsid","_uetvid","_clck","_clsk",
  "__cfduid","cf_clearance","__cf_bm",
  "_pk_id","_pk_ses","_pk_ref",
  "intercom-id","intercom-session",
  "amplitude_id","ajs_anonymous_id","ajs_user_id",
  "mp_mixpanel__c","distinct_id",
  "NID","1P_JAR","CONSENT","APISID","SAPISID","SSID","SID","HSID",
  "_dc_gtm_UA","__utma","__utmb","__utmc","__utmz","__utmv",
  "OptanonConsent","OptanonAlertBoxClosed","CookieConsent"
]);
// Analytics/ads/consent cookies are noise for a security audit — filtered by exact name or
// common prefix (GA4 _ga_XXX, _gat_XXX, GTM, Facebook, Matomo, etc.).
function isTrackingCookie(name) {
  if (!name) return true;
  if (TRACKING_COOKIES.has(name)) return true;
  return /^(_ga_|_gat_|_gid$|_gcl_|__utm|_hj|__hs|_uet|_clck$|_clsk$|_pk_|mp_|ajs_|_fbp$|_fbc$|__cf|amplitude_|_dc_gtm_)/.test(name);
}

// ── Global Persistent State ──
let G = {
  findings: {},       // domain -> [{finding,url,timestamp,source,hash,cvss,screenshotUrl}]
  pmLog: {},          // domain -> [{record,url,timestamp}]
  pmAnalysis: {},     // key -> analysis
  pmTraffic: {},      // domain -> [{entry}]
  requests: {},       // domain -> [{url,method,status,headers,audit,timestamp}]
  wsTraffic: {},      // domain -> [{entry}]
  apiTraffic: {},     // domain -> [{url,method,requestHeaders,requestBody,status,responseHeaders,responseBody,timestamp}]
  workerEvents: {},   // domain -> [{entry}]
  confirmedBugs: [],  // [{type,url,domain,details,doc,timestamp}]
  customRules: [],    // [{id,name,pattern,category,severity,enabled}]
  templates: [],      // [{id,name,matchers,severity,category}]
  webhookUrl: "",     // Slack/Discord webhook URL
  screenshots: {},    // hash -> dataUrl
  verifyLog: [],      // [{hash,domain,url,type,category,timestamp}]
  safeMode: false,
  targetScope: [],    // ["*.example.com", "api.target.com"]
  customHeaders: [],  // [{name, value}]
  customHeadersEnabled: false,
  falsePositivePatterns: [], // [{sig, type, category, subtype, domain, ts}] — learned from user "false positive" dismissals
  crawlHistory: null, // last completed crawl: {results, stats, startUrl, timestamp}
  activityLog: [],    // [{id,timestamp,level,category,message,domain,detail}] — max 500, free+pro
  logVersion: "",     // cleared when the extension version changes
  lightweightMode: false, // performance: run only essential scanners
  maxRequestsPerSec: 5,   // rate limit for target fetches (crawler + active validation)
};


// Per-tab ephemeral
const pmByTab = {}, pmAnalysisByTab = {}, pendingJobs = {}, verifyPorts = {};

// ── Custom Headers helpers ──
function getCustomHeaders() {
  if (!G.customHeadersEnabled || !G.customHeaders?.length) return {};
  const h = {};
  for (const {name, value} of G.customHeaders) { if (name && value) h[name] = value; }
  return h;
}

// ── Global rate limiter (Feature 1) ──
// Sliding 1-second window applied to all target fetches (crawler + active validation).
// AI-provider calls do NOT go through here (they are not target traffic).
let _rlTimestamps = [];
let _rlWarned = 0;
async function waitForRateLimit() {
  const cap = Math.max(1, Math.min(50, parseInt(G.maxRequestsPerSec, 10) || 5));
  for (;;) {
    const now = Date.now();
    _rlTimestamps = _rlTimestamps.filter(t => now - t < 1000);
    if (_rlTimestamps.length < cap) { _rlTimestamps.push(now); return; }
    const waitMs = Math.max(5, 1000 - (now - _rlTimestamps[0]) + 5);
    // Log at most ~1 wait notice per second to avoid flooding the activity log
    if (now - _rlWarned > 1000) { _rlWarned = now; ylog("info", "system", "Rate limit: waiting (" + cap + " req/s cap)"); }
    await new Promise(r => setTimeout(r, waitMs));
  }
}
async function rateLimitedFetch(url, options) {
  await waitForRateLimit();
  dbg("[rate-limited fetch]", url);
  return fetch(url, options);
}

async function fetchWithHeaders(url, opts = {}) {
  await waitForRateLimit(); // all target fetches (validators/verifiers) are rate-limited
  const ch = getCustomHeaders();
  if (Object.keys(ch).length) {
    opts.headers = { ...ch, ...(opts.headers || {}) };
  }
  return fetch(url, opts);
}

async function updateCustomHeaderRules() {
  const ruleIds = Array.from({length: 50}, (_, i) => i + 1000);
  try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ruleIds }); } catch(e) { dbgWarn("DNR remove error:", e.message); }
  if (!G.customHeadersEnabled || !G.customHeaders?.length) { dbg("Custom header rules cleared"); return; }
  const rules = G.customHeaders.filter(h => h.name && h.value).map((h, i) => ({
    id: 1000 + i,
    priority: 1,
    action: { type: "modifyHeaders", requestHeaders: [{ header: h.name, operation: "set", value: h.value }] },
    condition: { urlFilter: "*", resourceTypes: ["main_frame","sub_frame","xmlhttprequest","script","stylesheet","image","font","other"] }
  }));
  if (rules.length) {
    try { await chrome.declarativeNetRequest.updateDynamicRules({ addRules: rules }); dbg("Custom header rules set:", rules.length); } catch(e) { dbgWarn("DNR add error:", e.message); }
  }
}

function isInScope(urlOrDomain) {
  let scope = G.targetScope;
  if (!scope || !scope.length) return true;
  if (typeof scope === "string") scope = scope.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
  if (!scope.length) return true;
  let domain;
  try { domain = new URL(urlOrDomain).hostname; } catch { domain = urlOrDomain; }
  domain = domain.toLowerCase();
  for (const pat of scope) {
    const p = pat.trim().toLowerCase();
    if (!p) continue;
    if (p === domain) return true;
    if (p.startsWith("*.") && (domain === p.slice(2) || domain.endsWith("." + p.slice(2)))) return true;
    if (domain === p || domain.endsWith("." + p)) return true;
  }
  return false;
}

// Independent scope gatekeeper for ANY active test (replay, param probe, active verify).
// Defense in depth: a separate check from the passive scope filter — YANSII must NEVER
// actively test a target outside the user's authorized scope. Returns true if allowed.
function gatekeepScope(url, testName) {
  if (!url) return true;
  if (isInScope(url)) return true;
  ylog("warning", "system", "Test blocked: out of scope: " + url + (testName ? " [" + testName + "]" : ""));
  return false;
}

// Restore
chrome.storage.local.get(["enabled", "G"], r => {
  if (r.enabled === false) enabled = false;
  if (r.G) Object.assign(G, r.G);
  if (G.targetScope && G.targetScope.length) chrome.storage.sync.set({ targetScope: G.targetScope });
  if (typeof initPatternMemory === "function") { initPatternMemory(); schedulePatternCleanup(); }
  updateBadge();
  // Activity log: clear on version change (avoid stale entries), then log startup
  try {
    const _curVer = chrome.runtime.getManifest().version;
    if (!G.activityLog) G.activityLog = [];
    if (G.logVersion !== _curVer) { G.activityLog = []; G.logVersion = _curVer; }
    ylog("info", "system", "YANSII v" + _curVer + " started");
    if (G.targetScope && G.targetScope.length) ylog("info", "system", "Scope set: " + G.targetScope.join(", "));
  } catch {}
});

function scheduleFlush() {
  dirty = true;
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    if (dirty) {
      // Trim (reduced limits for memory — Bug 9 fix)
      for (const d in G.findings) if (G.findings[d].length > 500) G.findings[d] = G.findings[d].slice(-500);
      for (const d in G.requests) if (G.requests[d].length > 300) G.requests[d] = G.requests[d].slice(-300);
      for (const d in G.wsTraffic) if (G.wsTraffic[d].length > 100) G.wsTraffic[d] = G.wsTraffic[d].slice(-100);
      for (const d in G.apiTraffic) if ((G.apiTraffic[d] || []).length > 100) G.apiTraffic[d] = G.apiTraffic[d].slice(-100);
      // Auto-trim when total findings exceed 5000
      let totalFindings = 0;
      for (const d in G.findings) totalFindings += G.findings[d].length;
      if (totalFindings > 5000) {
        for (const d in G.findings) {
          if (G.findings[d].length > 200) G.findings[d] = G.findings[d].slice(-200);
        }
      }
      const ssKeys = Object.keys(G.screenshots || {});
      if (ssKeys.length > 20) { for (const k of ssKeys.slice(0, ssKeys.length - 20)) delete G.screenshots[k]; }
      for (const d in G.pmLog) if (G.pmLog[d].length > 500) G.pmLog[d] = G.pmLog[d].slice(-500);
      for (const d in G.pmTraffic) if ((G.pmTraffic[d] || []).length > 500) G.pmTraffic[d] = G.pmTraffic[d].slice(-500);
      if (G.pmAnalysis) { const pKeys = Object.keys(G.pmAnalysis); if (pKeys.length > 50) { for (const k of pKeys.slice(0, pKeys.length - 50)) delete G.pmAnalysis[k]; } }
      if (G.verifyLog && G.verifyLog.length > 300) G.verifyLog = G.verifyLog.slice(-300);
      chrome.storage.local.set({ G }, () => {
        if (chrome.runtime.lastError) dbgWarn("Storage flush failed:", chrome.runtime.lastError.message);
      });
      dirty = false;
    }
  }, 3000);
}

const BADGE_COLORS = { critical: "#e8403a", high: "#d29922", medium: "#f0883e", low: "#58a6ff", info: "#3fb950" };

// Badge shows the finding count for the domain of a given tab (or the active tab),
// colored by the worst severity found on that domain. When disabled, shows OFF globally.
function updateBadge(tabId) {
  if (!enabled) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#484f58" });
    return;
  }
  const applyTo = (tab) => {
    if (!tab || !tab.id) return;
    const domain = domainOf(tab.url || "");
    const entries = G.findings[domain] || [];
    const total = entries.length;
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    let maxSev = "info";
    for (const entry of entries) {
      const sev = entry.finding?.severity || "info";
      if ((sevOrder[sev] ?? 5) < (sevOrder[maxSev] ?? 5)) maxSev = sev;
    }
    try {
      if (scanPausedState) {
        // Paused indicator: grey badge; show count if any, otherwise a pause glyph.
        chrome.action.setBadgeText({ text: total > 0 ? String(total) : "⏸", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#484f58", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: total > 0 ? String(total) : "", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS[maxSev] || "#3fb950", tabId: tab.id });
      }
    } catch {}
  };
  if (tabId) {
    chrome.tabs.get(tabId, tab => { if (!chrome.runtime.lastError) applyTo(tab); });
  } else {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => { if (tabs && tabs[0]) applyTo(tabs[0]); });
  }
}

// Refresh badge when the user switches tabs or a tab navigates
chrome.tabs.onActivated.addListener(({ tabId }) => updateBadge(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => { if (info.status === "complete") updateBadge(tabId); });

const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const keyOf = r => (r.frameUrl || "") + (r.source || "").slice(0, 400);
const domainOf = url => { try { return new URL(url).hostname } catch { return "unknown" } };
// Only ever scan/store findings for real web origins. Excludes chrome-extension://
// (YANSII's own pages — whose hostname is the extension ID), chrome://, about:, file:, etc.
const isWebOrigin = url => { try { const p = new URL(url).protocol; return p === "http:" || p === "https:"; } catch { return false; } };

// ── Activity log (free + pro) ──
// Records what the extension is doing so hunters can see scanner/network/AI/crawl
// activity like a terminal. Capped at 500 entries, persisted with G, broadcast live.
let _logFlushTimer = null;
function ylog(level, category, message, domain, detail) {
  try {
    if (!G.activityLog) G.activityLog = [];
    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      timestamp: Date.now(),
      level: level || "info",
      category: category || "system",
      message: String(message || ""),
      domain: domain || null,
      detail: detail || null,
    };
    G.activityLog.push(entry);
    if (G.activityLog.length > 500) G.activityLog = G.activityLog.slice(-500);
    chrome.runtime.sendMessage({ type: "LOG_ENTRY", entry }).catch(() => {});
    // Debounced persist so high-frequency logging doesn't thrash storage
    if (!_logFlushTimer) { _logFlushTimer = setTimeout(() => { _logFlushTimer = null; scheduleFlush(); }, 4000); }
  } catch {}
}

// ── Periodic memory cleanup (performance) ──
const FINDING_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
function runMemoryCleanup() {
  try {
    let removed = 0;
    const cutoff = Date.now() - FINDING_MAX_AGE_MS;
    for (const d in G.findings) {
      const before = G.findings[d].length;
      G.findings[d] = G.findings[d].filter(e => (e.timestamp || Date.now()) >= cutoff);
      removed += before - G.findings[d].length;
      if (G.findings[d].length === 0) delete G.findings[d];
    }
    for (const d in (G.apiTraffic || {})) if (G.apiTraffic[d].length > 50) G.apiTraffic[d] = G.apiTraffic[d].slice(-50);
    if (G.activityLog && G.activityLog.length > 500) G.activityLog = G.activityLog.slice(-500);
    if (removed > 0) {
      scheduleFlush(); updateBadge();
      ylog("info", "system", "Cleanup: removed " + removed + " finding" + (removed === 1 ? "" : "s") + " older than 7 days");
    }
  } catch (e) { dbgWarn("Memory cleanup error:", e.message); }
}
setInterval(runMemoryCleanup, 30 * 60 * 1000);

// ══════════════════════════════════════════════════════════════════
// FINDING DEDUPLICATION (smart hash)
// ══════════════════════════════════════════════════════════════════
function hashFinding(f, url) {
  let hashInput;
  const domain = domainOf(url);
  if (f.category === "cookie-security") {
    const cookieName = ((f.detail || "").match(/Cookie "([^"]+)"/) || [])[1] || (f.detail || "").slice(0, 40);
    hashInput = (f.type || "") + "|" + (f.category || "") + "|" + cookieName + "|" + domain;
  } else if (f.category === "security-headers" || f.category === "cors" || (f.category === "info-disclosure" && /^Header —/.test(f.type || ""))) {
    // Missing security headers, CORS config, and Server/X-Powered-By disclosure are SITE-LEVEL
    // facts — the whole domain lacks (or leaks) them, so report each once per (type, domain),
    // attributed to the first route where it's seen, not repeated on every subsequent route.
    // A per-route header finding quadrupled the count (e.g. "No HSTS" ×49) and buried the real
    // findings; a hunter reports "example.com is missing HSTS" once.
    hashInput = (f.type || "") + "|" + (f.category || "") + "|" + (f.subtype || "") + "|" + domain;
  } else if (
    ["recon", "waf-bypass", "business-logic", "graphql", "technology"].includes(f.category) ||
    /Technology Detected|Login Link Missing|Repository Link|Email Addresses in Source|Endpoint Detected|Parameter Map|Upload Zone|Hidden Form Fields/i.test(f.type || "")
  ) {
    // P1: site-level facts (recon, technology, discovered endpoints, business-logic leads that
    // key off shared-layout forms) are DOMAIN-WIDE — the login link, GraphQL endpoint, tech
    // stack, and footer email are the same on every page. Dedup per (type, subtype, domain) so
    // they appear once, not once per route. This was the dominant multi-page cross-route bleed.
    hashInput = (f.type || "") + "|" + (f.category || "") + "|" + (f.subtype || "") + "|" + domain;
  } else if (f.location === "Cookie" || f.location === "Cookies") {
    // P1: cookie-derived findings are DOMAIN-WIDE (cookies aren't per-route). Dedup per
    // (type, cookie, domain) so they appear once, not once per route visited — this was the
    // largest cross-route bleed (a cookie finding stamped onto every route of a site).
    const cookieName = ((f.detail || "").match(/Cookie "([^"]+)"/) || [])[1] || (f.type || "");
    hashInput = (f.type || "") + "|" + (f.category || "") + "|" + cookieName + "|" + domain;
  } else {
    // P1: dedup by the finding's specific LOCATION (a form action, "Page source", "Inline
    // scripts") when it differs from the page URL, instead of by the page URL. Shared page
    // chrome (a header search form, a footer script) produces an identical finding on every
    // route; keying on its location collapses those to one instead of one-per-route, while
    // genuinely per-route findings (distinct actions/details) stay separate.
    const locus = (f.location && f.location !== url) ? f.location : (url || "");
    hashInput = (f.type || "") + "|" + (f.category || "") + "|" + (f.subtype || "") + "|" + (f.detail || "").slice(0, 80) + "|" + locus;
  }
  let h = 0;
  for (let i = 0; i < hashInput.length; i++) h = ((h << 5) - h + hashInput.charCodeAt(i)) | 0;
  return "h" + Math.abs(h).toString(36);
}

// Three-tier proof system labels
const TIER_LABELS = { 1: "detected", 2: "validated", 3: "confirmed" };
const TIER_STATUS = { 1: "detected", 2: "validated", 3: "confirmed" };

function validateFinding(finding, url) {
  // Reject findings without substantial detail
  if (!finding.detail || finding.detail.length < 10) return false;

  // 2FA Bypass: Only flag if evidence that 2FA exists
  if (finding.type?.includes("2FA") || finding.type?.includes("MFA")) {
    const detail = (finding.detail + finding.evidence).toLowerCase();
    if (!detail.includes("mfa") && !detail.includes("2fa") && !detail.includes("totp") && !detail.includes("otp")) {
      return false; // No evidence 2FA actually exists
    }
  }

  // DOM XSS: Check for source→sink chain, not just sink
  if (finding.category === "dom-xss" || finding.type?.includes("DOM")) {
    if (!finding.evidence?.includes("source") && !finding.evidence?.includes("sink chain")) {
      finding.severity = "low"; // Demote to low if no chain
    }
  }

  // Cookie HttpOnly severity adjustment
  if (finding.category === "cookie-security" && finding.type?.includes("HttpOnly")) {
    const isCookie = finding.detail?.includes("session") || finding.detail?.includes("auth") || finding.detail?.includes("token");
    const isTracking = finding.detail?.includes("_ga") || finding.detail?.includes("_fb") || finding.detail?.includes("_gat");
    if (isTracking) {
      return false; // Skip tracking cookie findings
    }
    if (!isCookie) {
      finding.severity = "info"; // Demote to info if not critical cookie
    }
  }

  return true;
}

// False-positive learning: when the user dismisses a finding, we remember a signature
// (type|category|subtype|domain) and suppress future matches on that same domain.
function fpSignature(finding, url) {
  return [finding.type || "", finding.category || "", finding.subtype || "", domainOf(url)].join("|");
}
function isLearnedFalsePositive(finding, url) {
  const pats = G.falsePositivePatterns;
  if (!pats || !pats.length) return false;
  const sig = fpSignature(finding, url);
  return pats.some(p => p.sig === sig);
}
function learnFalsePositive(finding, url) {
  if (!finding) return;
  G.falsePositivePatterns = G.falsePositivePatterns || [];
  const sig = fpSignature(finding, url);
  if (G.falsePositivePatterns.some(p => p.sig === sig)) return;
  G.falsePositivePatterns.push({ sig, type: finding.type || "", category: finding.category || "", subtype: finding.subtype || "", domain: domainOf(url), ts: Date.now() });
  if (G.falsePositivePatterns.length > 500) G.falsePositivePatterns = G.falsePositivePatterns.slice(-500);
}

// ══════════════════════════════════════════════════════════════════
// REPORTABILITY GUIDANCE (bug-bounty methodology — knowledge, not copied code)
// Passive detections are SIGNALS, not proof. A status code is never proof; a body
// diff showing another party's data is. These helpers annotate a finding with the
// proof gate that would upgrade it to a confirmed (tier-3) report and with how far
// the impact scales if confirmed — without asserting impact that hasn't been shown.
// ══════════════════════════════════════════════════════════════════
const CONFIRMATION_GATES = {
  "auth-bypass": "Confirm cross-account access: with Account A's session, request Account B's object ID — real only if the body returns B's private data. Re-test under (a) A's session, (b) NO auth, (c) B's session. If it only works with no auth it's 'missing auth' (a different, usually lower bug), not IDOR.",
  ssrf: "A DNS/OOB callback ALONE is informational. Confirm by returning internal content in the HTTP response (e.g. cloud metadata at 169.254.169.254, or an internal service body).",
  graphql: "GraphQL introspection ALONE is informational (a surface map). Confirm a resolver/mutation that accepts a client-supplied id and returns/modifies another account's data (resolvers often skip the auth the REST layer enforced).",
  "business-logic": "Confirm the manipulated outcome PERSISTS server-side (item actually purchased at the tampered price, coupon actually reused, balance actually negative). Client-side acceptance or a 200 is not enough.",
  "open-redirect": "Open redirect alone is low/informational. Confirm impact by chaining (e.g. OAuth redirect_uri → auth-code/token theft).",
};
function confirmationGate(finding) {
  const cat = (finding.category || "").toLowerCase();
  const t = (finding.type || "").toLowerCase();
  if (/idor|bola/.test(t) || cat === "auth-bypass") return CONFIRMATION_GATES["auth-bypass"];
  if (cat === "ssrf") return CONFIRMATION_GATES.ssrf;
  if (cat === "graphql" || /graphql/.test(t)) return CONFIRMATION_GATES.graphql;
  if (cat === "business-logic") return CONFIRMATION_GATES["business-logic"];
  if (cat === "open-redirect") return CONFIRMATION_GATES["open-redirect"];
  if (/cors/.test(t)) return "CORS `*`/origin-reflection alone is informational. Confirm a credentialed cross-origin request actually reads another user's PII.";
  return null;
}
// Impact quantification for access-control findings: enumerability determines scale.
function quantifyImpact(finding, url) {
  const cat = (finding.category || "").toLowerCase();
  const t = (finding.type || "").toLowerCase();
  const isAccessControl = cat === "auth-bypass" || /idor|bola/.test(t);
  if (!isAccessControl) return null;
  const hay = `${finding.location || ""} ${url || ""} ${finding.detail || ""}`;
  const seqId = /\/\d{1,10}(?:\/|$|[?#])/.test(hay) || /[?&](?:id|user_?id|account_?id|order_?id|invoice_?id|uid)=\d+/i.test(hay);
  const uuid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(hay);
  const relay = /graphql|node\(/i.test(hay) && /[A-Za-z0-9+/]{12,}={0,2}/.test(hay);
  if (seqId) return "Sequential/numeric ID — scriptable enumeration; if confirmed, likely affects ALL users (mass PII exposure in minutes).";
  if (relay) return "GraphQL/Relay global ID — alias batching enables mass enumeration in a single request.";
  if (uuid) return "UUID identifier — enumeration is harder; IDs still leak via invites, share links, password-reset flows, and web archives.";
  return "Establish whether the ID is attacker-guessable/enumerable to quantify scale of impact.";
}
// Sibling-endpoint rule: a confirmed access-control bug signals the same class of
// mistake on adjacent endpoints — highest-ROI next move.
function siblingHint(finding) {
  const cat = (finding.category || "").toLowerCase();
  const t = (finding.type || "").toLowerCase();
  if (!(cat === "auth-bypass" || /idor|bola/.test(t))) return null;
  return "Sibling-endpoint rule: broken access control here signals the same bug on adjacent endpoints. Test the same object-id pattern on siblings (e.g. /orders/{id}, /invoices/{id}, /messages/{id}, /export?id=), across EVERY HTTP verb, both /v1 and /v2, and GraphQL node().";
}

function addGlobalFinding(finding, url, source) {
  if (!finding || typeof finding !== "object") return false;
  if (!isWebOrigin(url)) return false; // never scan the extension's own pages / non-web origins
  if (!validateFinding(finding, url)) return false; // Pre-validate
  const domain = domainOf(url);
  if (!isInScope(domain)) return false;
  if (isNoiseDomain(domain)) { ylog("debug", "scan", "Finding filtered: noise domain", domain); return false; }
  if (isLearnedFalsePositive(finding, url)) { ylog("debug", "scan", "Finding filtered: learned false-positive", domain); return false; }
  const gl = (G.findings[domain] = G.findings[domain] || []);
  const hash = hashFinding(finding, url);
  if (gl.some(x => x.hash === hash)) { ylog("debug", "scan", "Finding filtered: duplicate", domain); return false; }
  const cvss = computeCVSS(finding);
  // ── Three-tier proof system ──
  // tier 1 = detected (passive pattern match), tier 2 = validated (active test suggests
  // real), tier 3 = confirmed (proof captured OR directly observable). A scanner may declare
  // finding.tier for directly-observable facts (cookie flags, security headers); otherwise
  // findings default to tier 1 and are only promoted by active validation (Phase 3).
  const tier = (finding.tier === 2 || finding.tier === 3) ? finding.tier : 1;
  const tierLabel = TIER_LABELS[tier];
  const verificationStatus = TIER_STATUS[tier];
  const confidence = tier === 3 ? 92 : tier === 2 ? 65 : 30; // numeric 0-100
  // For directly-observable tier-3 findings the observation itself is the proof.
  const evidence = (tier === 3)
    ? (finding.evidenceObj || { proof: finding.detail || "", technique: "passive-observation", request: null, response: null, timestamp: Date.now() })
    : null;
  // Keep a coarse string level for legacy filters
  const confidenceLevel = tier === 3 ? "high" : tier === 2 ? "medium" : "low";
  const entry = { finding, url, timestamp: Date.now(), source, hash, cvss, tier, tierLabel, verificationStatus, confidence, confidenceLevel, evidence };
  // Reportability guidance: how to confirm this into a payable report + impact scale.
  const gate = confirmationGate(finding);
  if (gate) entry.confirmationGate = gate;
  const impact = quantifyImpact(finding, url);
  if (impact) entry.impactNote = impact;
  const sibling = siblingHint(finding);
  if (sibling) entry.siblingHint = sibling;
  gl.push(entry);
  dbg(`📌 NEW FINDING on ${domain}: [${finding.severity}] ${finding.type}${finding.subtype?" ("+finding.subtype+")":""} — ${(finding.detail||"").slice(0,80)} (source:${source}, CVSS:${cvss.score})`);
  ylog("success", "scan", "Found: " + (finding.type || "finding") + (finding.severity ? " [" + finding.severity + "]" : ""), domain, (finding.detail || "").slice(0, 120));
  scheduleFlush();

  // Webhook notification for high/critical
  if ((finding.severity === "critical" || finding.severity === "high") && G.webhookUrl) {
    sendWebhook(finding, url, domain, cvss);
  }

  // Screenshot for critical findings
  if (finding.severity === "critical") {
    captureScreenshot(hash);
  }

  updateBadge();
  return true; // new finding
}

// ══════════════════════════════════════════════════════════════════
// CVSS 3.1 CALCULATOR
// ══════════════════════════════════════════════════════════════════
function computeCVSS(f) {
  // Simplified CVSS 3.1 base score based on finding attributes
  const cat = f.category || "";
  const sev = f.severity || "info";
  const sub = f.subtype || "";

  // Attack Vector: Network (most web vulns)
  const AV = 0.85; // Network

  // Attack Complexity
  let AC = 0.77; // Low
  if (/blind|time-based|second-order/i.test(sub)) AC = 0.44; // High

  // Privileges Required
  let PR = 0.85; // None
  if (/auth|login|session/i.test(cat)) PR = 0.62; // Low

  // User Interaction
  let UI = 0.85; // None
  if (/xss|csrf|clickjack|redirect/i.test(cat)) UI = 0.62; // Required

  // Scope
  let S = 1.0; // Unchanged
  if (/xss|ssrf|ssti|rce|command/i.test(cat)) S = 1.08; // Changed (can affect other components)

  // Impact
  let C = 0, I = 0, A = 0;
  if (sev === "critical") { C = 0.56; I = 0.56; A = 0.56; }
  else if (sev === "high") { C = 0.56; I = 0.22; A = 0; }
  else if (sev === "medium") { C = 0.22; I = 0.22; A = 0; }
  else if (sev === "low") { C = 0.22; I = 0; A = 0; }
  else { return { score: 0, vector: "N/A", rating: "None" }; }

  // Override for specific categories
  if (/rce|command-injection|deserialization/i.test(cat)) { C = 0.56; I = 0.56; A = 0.56; }
  if (/info-disclosure|secrets/i.test(cat)) { C = 0.56; I = 0; A = 0; }
  if (/sqli/i.test(cat)) { C = 0.56; I = 0.56; A = 0.22; }

  const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));
  let impact = S > 1 ? 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15) : 6.42 * ISS;
  if (impact < 0) impact = 0;

  const exploitability = 8.22 * AV * AC * PR * UI;
  let score;
  if (impact === 0) score = 0;
  else if (S > 1) score = Math.min(1.08 * (impact + exploitability), 10);
  else score = Math.min(impact + exploitability, 10);
  score = Math.ceil(score * 10) / 10;

  const rating = score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : score > 0 ? "Low" : "None";
  const vector = `CVSS:3.1/AV:N/AC:${AC > 0.5 ? "L" : "H"}/PR:${PR > 0.7 ? "N" : "L"}/UI:${UI > 0.7 ? "N" : "R"}/S:${S > 1 ? "C" : "U"}/C:${C > 0.3 ? "H" : C > 0 ? "L" : "N"}/I:${I > 0.3 ? "H" : I > 0 ? "L" : "N"}/A:${A > 0.3 ? "H" : A > 0 ? "L" : "N"}`;

  return { score, vector, rating };
}

// ══════════════════════════════════════════════════════════════════
// SCREENSHOT CAPTURE
// ══════════════════════════════════════════════════════════════════
async function captureScreenshot(hash) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;
    const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 60 });
    G.screenshots[hash] = dataUrl;
    scheduleFlush();
  } catch (e) { dbgWarn("captureScreenshot:", e.message); }
}

// ══════════════════════════════════════════════════════════════════
// SLACK / DISCORD WEBHOOK
// ══════════════════════════════════════════════════════════════════
async function sendWebhook(finding, url, domain, cvss) {
  if (typeof _v === 'function' && !_v()) return;
  if (!G.webhookUrl) return;
  try {
    const isDiscord = G.webhookUrl.includes("discord");
    const text = `🔴 **[${finding.severity.toUpperCase()}]** ${finding.type}${finding.subtype ? " (" + finding.subtype + ")" : ""}\n` +
      `**Domain:** ${domain}\n**URL:** ${url}\n**CVSS:** ${cvss.score} (${cvss.rating})\n` +
      `**Detail:** ${(finding.detail || "").slice(0, 200)}`;

    const body = isDiscord
      ? { content: text }
      : { text, blocks: [{ type: "section", text: { type: "mrkdwn", text } }] };

    const wr = await fetch(G.webhookUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!wr.ok) throw new Error(`HTTP ${wr.status}`);
  } catch (e) { G.webhookLastError = { message: e.message, time: Date.now() }; dbgWarn("[Webhook] Error:", e.message); }
}

// ══════════════════════════════════════════════════════════════════
// NUCLEI-STYLE TEMPLATE MATCHING
// ══════════════════════════════════════════════════════════════════
function runTemplates(html, url, headers) {
  const findings = [];
  // DoS guard: cap the input so scanner regexes can't be driven into
  // catastrophic/quadratic backtracking by a hostile page's huge HTML.
  // 100 KB covers real secret/error disclosure; the ceiling keeps worst-case
  // regex time to tens of ms even on pathological input.
  html = String(html || "").slice(0, 100000);
  const defaultTemplates = [
    { id: "exposed-env", name: "Exposed .env file", match: /(?:^|[\n;])\s*(?:DB_PASSWORD|APP_KEY|MAIL_PASSWORD|AWS_SECRET(?:_ACCESS_KEY)?|SECRET_KEY)\s*=\s*[^\s#]/i, severity: "critical", category: "info-disclosure" }, // P6: require KEY=VALUE (actual file content), not a mention
    { id: "firebase-config", name: "Firebase Config Exposed", match: /apiKey.*AIza[A-Za-z0-9_-]{35}.*authDomain/s, severity: "high", category: "info-disclosure" },
    { id: "graphql-introspection", name: "GraphQL Introspection Enabled", match: /__schema\s*\{|introspectionQuery/i, severity: "medium", category: "recon" },
    { id: "debug-mode", name: "Debug Mode Enabled", match: /Whoops!|laravel.*debug|DJANGO_DEBUG.*True|Traceback \(most recent|Ruby on Rails.*error/i, severity: "high", category: "info-disclosure" },
    { id: "directory-listing", name: "Directory Listing", match: /Index of \/|Directory listing for/i, severity: "medium", category: "info-disclosure" },
    { id: "phpmyadmin", name: "phpMyAdmin Panel Exposed", match: /name=["']pma_(?:username|password)|<title>\s*phpMyAdmin|phpMyAdmin\s+\d+\.\d+\.\d+|pmahomme/i, severity: "high", category: "info-disclosure" }, // P6: actual panel signature, not the word
    { id: "swagger-ui", name: "Swagger/OpenAPI UI referenced", match: /swagger-ui|"swagger"\s*:\s*"2|"openapi"\s*:\s*"3/i, severity: "info", category: "recon" }, // P6: "referenced" (often intentional public docs), not "exposed"
    { id: "wp-debug", name: "WordPress Debug Log", match: /\[error\].*wp-content|PHP (Warning|Notice|Fatal)/i, severity: "high", category: "info-disclosure" },
    { id: "spring-actuator", name: "Spring Actuator Exposed", match: /"_links"\s*:\s*\{[\s\S]{0,300}?"(?:health|env|beans|mappings|configprops)"\s*:/i, severity: "high", category: "info-disclosure" }, // P6: actual actuator JSON, not a mention
    { id: "git-exposed", name: ".git/HEAD Exposed", match: /ref:\s*refs\/heads\/[\w.\/\-]+/i, severity: "critical", category: "info-disclosure" }, // P6: actual .git/HEAD content ("ref: refs/heads/…"), not a reference
    { id: "error-sqli", name: "SQL Error in Response", match: /SQL syntax|mysql_fetch|pg_query|ORA-\d{5}|SQLSTATE/i, severity: "critical", category: "sqli" },
    { id: "internal-ip", name: "Internal IP Disclosure", match: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g, severity: "low", category: "info-disclosure" },
    { id: "email-disclosure", name: "Email Addresses in Source", match: /[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}/g, severity: "info", category: "info-disclosure" },
  ];

  // Run default + custom templates
  const allTemplates = [...defaultTemplates, ...G.templates];
  for (const t of allTemplates) {
    const pattern = t.match instanceof RegExp ? t.match : new RegExp(t.match || t.pattern, "i");
    if (pattern.test(html)) {
      findings.push({
        type: `Template — ${t.name}`,
        severity: t.severity || "medium",
        detail: `Nuclei-style template "${t.id || t.name}" matched`,
        category: t.category || "recon",
        subtype: "template-match",
        templateId: t.id
      });
    }
  }

  // Also run custom user rules
  for (const rule of G.customRules) {
    if (!rule.enabled) continue;
    try {
      const re = new RegExp(rule.pattern, "i");
      if (re.test(html)) {
        findings.push({
          type: `Custom Rule — ${rule.name}`,
          severity: rule.severity || "medium",
          detail: `Custom rule "${rule.name}" matched (/${rule.pattern}/)`,
          category: rule.category || "custom",
          subtype: "custom-rule",
          ruleId: rule.id
        });
      }
    } catch (e) { dbgWarn("Custom rule error:", e.message); }
  }

  return findings;
}

// ══════════════════════════════════════════════════════════════════
// CWE + OWASP MAPPING (Professional Report — from bug bounty books)
// ══════════════════════════════════════════════════════════════════
const CWE_MAP = {
  "xss": { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation", owasp: "A03:2021 Injection" },
  "sqli": { id: "CWE-89", name: "SQL Injection", owasp: "A03:2021 Injection" },
  "command-injection": { id: "CWE-78", name: "OS Command Injection", owasp: "A03:2021 Injection" },
  "ssrf": { id: "CWE-918", name: "Server-Side Request Forgery", owasp: "A10:2021 SSRF" },
  "csrf": { id: "CWE-352", name: "Cross-Site Request Forgery", owasp: "A01:2021 Broken Access Control" },
  "auth-bypass": { id: "CWE-284", name: "Improper Access Control", owasp: "A01:2021 Broken Access Control" },
  "open-redirect": { id: "CWE-601", name: "URL Redirection to Untrusted Site", owasp: "A01:2021 Broken Access Control" },
  "info-disclosure": { id: "CWE-200", name: "Exposure of Sensitive Information", owasp: "A02:2021 Cryptographic Failures" },
  "cookie-security": { id: "CWE-614", name: "Sensitive Cookie Without Secure Flag", owasp: "A05:2021 Security Misconfiguration" },
  "security-headers": { id: "CWE-693", name: "Protection Mechanism Failure", owasp: "A05:2021 Security Misconfiguration" },
  "cors": { id: "CWE-942", name: "Permissive CORS Policy", owasp: "A05:2021 Security Misconfiguration" },
  "xxe": { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference", owasp: "A05:2021 Security Misconfiguration" },
  "deserialization": { id: "CWE-502", name: "Deserialization of Untrusted Data", owasp: "A08:2021 Software and Data Integrity Failures" },
  "nosqli": { id: "CWE-943", name: "Improper Neutralization of NoSQL Queries", owasp: "A03:2021 Injection" },
  "ldap-injection": { id: "CWE-90", name: "LDAP Injection", owasp: "A03:2021 Injection" },
  "crlf-injection": { id: "CWE-93", name: "CRLF Injection", owasp: "A03:2021 Injection" },
  "host-header": { id: "CWE-644", name: "Improper Neutralization of HTTP Headers", owasp: "A05:2021 Security Misconfiguration" },
  "prototype-pollution": { id: "CWE-1321", name: "Improperly Controlled Modification of Object Prototype Attributes", owasp: "A03:2021 Injection" },
  "upload-bypass": { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type", owasp: "A04:2021 Insecure Design" },
  "template-injection": { id: "CWE-1336", name: "Improper Neutralization of Template Syntax", owasp: "A03:2021 Injection" },
  "request-smuggling": { id: "CWE-444", name: "HTTP Request/Response Smuggling", owasp: "A05:2021 Security Misconfiguration" },
  "race-condition": { id: "CWE-362", name: "Concurrent Execution Using Shared Resource with Improper Synchronization", owasp: "A04:2021 Insecure Design" },
  "filter-bypass": { id: "CWE-20", name: "Improper Input Validation", owasp: "A03:2021 Injection" },
  "websocket": { id: "CWE-1385", name: "Missing Origin Validation in WebSockets", owasp: "A07:2021 Identification and Authentication Failures" },
  "path-traversal": { id: "CWE-22", name: "Improper Limitation of a Pathname to a Restricted Directory", owasp: "A01:2021 Broken Access Control" },
  "business-logic": { id: "CWE-840", name: "Business Logic Errors", owasp: "A04:2021 Insecure Design" },
  "rate-limiting": { id: "CWE-307", name: "Improper Restriction of Excessive Authentication Attempts", owasp: "A07:2021 Identification and Authentication Failures" },
  "session": { id: "CWE-384", name: "Session Fixation", owasp: "A07:2021 Identification and Authentication Failures" },
  "oauth-csrf": { id: "CWE-352", name: "Cross-Site Request Forgery (OAuth)", owasp: "A01:2021 Broken Access Control" },
};

// ══════════════════════════════════════════════════════════════════
// AUTO-DOCUMENTATION FOR ALL FINDING TYPES (Professional Format)
// ══════════════════════════════════════════════════════════════════
function buildFindingDoc(entry, domain) {
  const f = entry.finding;
  const ts = new Date().toISOString();
  const otherFindings = (G.findings[domain] || []).filter(e => e.hash !== entry.hash).slice(0, 30);
  const headerFindings = otherFindings.filter(e => e.source === "header-audit");
  const scanFindings = otherFindings.filter(e => e.source !== "header-audit");
  const pmHandlers = (G.pmLog[domain] || []);
  const wsEvents = (G.wsTraffic[domain] || []).slice(0, 10);
  const reqs = (G.requests[domain] || []).slice(-20);

  const cwe = CWE_MAP[f.category] || CWE_MAP[f.subtype] || { id: "N/A", name: "—", owasp: "—" };
  const chains = typeof analyzeChains === "function" ? analyzeChains(domain) : [];
  const relChains = chains.filter(c => c.categories?.includes(f.category));

  return `# Bug Bounty Report: ${f.type}

**Platform:** HackerOne / Bugcrowd
**Generated:** ${ts}
**Tool:** YANSII v2.2.0
**Reporter:** YANSII (Automated)

---

## Summary

| Field | Value |
|-------|-------|
| **Vulnerability** | ${f.type} |
| **Severity** | ${f.severity?.toUpperCase()} |
| **CVSS** | ${entry.cvss?.score || "?"}/10 (${entry.cvss?.rating || "?"}) |
| **CVSS Vector** | ${entry.cvss?.vector || "N/A"} |
| **CWE** | [${cwe.id}](https://cwe.mitre.org/data/definitions/${(cwe.id || "").replace("CWE-","")}.html) — ${cwe.name} |
| **OWASP** | ${cwe.owasp} |
| **URL** | \`${entry.url}\` |
| **Domain** | \`${domain}\` |
| **Category** | ${f.category} |
| **Sub-type** | ${f.subtype || "—"} |
| **Detected** | ${new Date(entry.timestamp).toISOString()} |
| **Source** | ${entry.source} |

## Description

${f.detail || "—"}

## Impact

${f.severity === "critical" ? "An attacker can fully compromise the application or its data. This may lead to remote code execution, complete data breach, or full account takeover." : f.severity === "high" ? "An attacker can access sensitive data or perform unauthorized actions. This may lead to data theft, account takeover, or privilege escalation." : f.severity === "medium" ? "An attacker may be able to perform limited unauthorized actions or access some restricted information under specific conditions." : "Low risk — informational finding or requires significant preconditions to exploit."}

## Steps to Reproduce

1. Navigate to: \`${entry.url}\`
2. Observe the finding: ${f.detail || "see detail above"}
3. ${f.suggestion ? "Apply the suggested payload/approach below" : "Further manual testing required"}

## Proof of Concept

${f.suggestion || "No automated PoC available — manual verification required."}

${entry.screenshotUrl ? `## Screenshot\n![Screenshot](${entry.screenshotUrl})\n` : ""}
## Remediation

${f.category === "xss" ? "• Encode all user input on output (context-aware: HTML entity, JS, URL, CSS encoding)\n• Implement Content Security Policy (CSP)\n• Use a templating engine with auto-escaping" : f.category === "sqli" ? "• Use parameterized queries / prepared statements\n• Apply input validation (allowlist, not blocklist)\n• Implement least-privilege database accounts" : f.category === "command-injection" ? "• Avoid passing user input to shell commands\n• Use language-native APIs instead of system()/exec()\n• If unavoidable, apply strict allowlist validation" : f.category === "ssrf" ? "• Validate and allowlist destination URLs/IPs\n• Block internal/private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n• Disable unnecessary URL schemes (file://, gopher://, dict://)" : f.category === "auth-bypass" ? "• Implement server-side access control checks\n• Never rely on client-side authorization\n• Use role-based access control (RBAC)" : f.category === "csrf" ? "• Implement CSRF tokens on all state-changing requests\n• Validate Origin/Referer headers\n• Use SameSite=Strict or SameSite=Lax cookies" : "• Refer to OWASP guidance: " + cwe.owasp + "\n• Review CWE mitigation: " + cwe.id}

## Related Findings on ${domain} (${scanFindings.length})

${scanFindings.slice(0, 10).map(e => `- [${e.finding.severity}] ${e.finding.type}: ${e.finding.detail}`).join("\n") || "None."}

${relChains.length > 0 ? `## Exploit Chains Detected\n\n${relChains.map(c => `- **${c.name}** (${c.impact}): ${c.detail}`).join("\n")}` : ""}
## Security Headers on ${domain}

${headerFindings.length ? headerFindings.map(e => `- [${e.finding.severity}] ${e.finding.type}: ${e.finding.detail}`).join("\n") : "No header issues."}

## Raw Data

\`\`\`json
${JSON.stringify({ finding: f, cvss: entry.cvss, url: entry.url, domain, hash: entry.hash, cwe: cwe.id, owasp: cwe.owasp }, null, 2)}
\`\`\`
`;
}

// ══════════════════════════════════════════════════════════════════
// HTTP REQUEST INTERCEPTION + HEADER AUDIT + TEMPLATE MATCHING
// ══════════════════════════════════════════════════════════════════
chrome.webRequest.onCompleted.addListener(
  details => {
    if (!enabled) return;
    if (!["main_frame", "xmlhttprequest", "sub_frame"].includes(details.type)) return;
    if (!isWebOrigin(details.url)) return; // skip chrome-extension:// / chrome:// page loads
    const domain = domainOf(details.url);
    if (!isInScope(domain)) return;
    if (isNoiseDomain(domain)) return;
    const headers = {};
    (details.responseHeaders || []).forEach(h => { headers[h.name.toLowerCase()] = h.value; });
    const audit = auditHeaders(headers, details.url);
    const rl = (G.requests[domain] = G.requests[domain] || []);
    rl.push({ url: details.url, method: details.method, status: details.statusCode, type: details.type, headers, audit: audit.length, timestamp: Date.now() });
    if (typeof detectWAF === "function") detectWAF(domain, details.statusCode, headers); // Phase 7A: WAF detection + auto-throttle
    // P6: only create header/cookie observations from DOCUMENT responses (the page the user
    // actually visited), never from xhr/fetch sub-requests — that was the header-audit bleed
    // (a missing header stamped once per API call). Each visited page keeps its own finding.
    if (details.type === "main_frame" || details.type === "sub_frame") { for (const f of audit) addGlobalFinding(f, details.url, "header-audit"); }
    if (audit.length && details.type === "main_frame") ylog("info", "network", "Header audit: " + audit.length + " issue" + (audit.length === 1 ? "" : "s") + " on response", domain);
    if (details.type === "main_frame") { auditCookiesForDomain(details.url); setTimeout(() => auditCookiesForDomain(details.url), 2500); } // re-audit to catch cookies set by page JS after load (findings dedup by hash)
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

chrome.webRequest.onBeforeRedirect.addListener(
  details => {
    if (!enabled) return;
    if (!isInScope(domainOf(details.url))) return;
    // Audit headers on redirect responses too (catches Set-Cookie on 3xx)
    if (details.responseHeaders) {
      const headers = {};
      details.responseHeaders.forEach(h => { headers[h.name.toLowerCase()] = h.value; });
      const audit = auditHeaders(headers, details.url);
      for (const f of audit) addGlobalFinding(f, details.url, "header-audit-redirect");
    }
    try {
      const parsed = new URL(details.url);
      const redirP = ["redirect","redirect_uri","redirect_url","return","return_url","returnTo","return_to","next","next_url","url","uri","to","target","dest","destination","rurl","go","goto","out","continue","forward"];
      for (const [key, value] of parsed.searchParams) {
        if (!redirP.includes(key.toLowerCase())) continue;
        const redirectUrl = details.redirectUrl || "";
        const isOAuth = /oauth|authorize|callback|code=|state=/i.test(details.url);
        addGlobalFinding({
          type: isOAuth ? "Open Redirect — OAuth (Account Takeover)" : "Open Redirect — Server-Side Redirect",
          severity: isOAuth ? "critical" : "high",
          detail: `Server-side redirect via "${key}"="${value.slice(0,80)}" → ${redirectUrl.slice(0,120)}`,
          location: details.url,
          category: "open-redirect",
          subtype: isOAuth ? "oauth" : "server-side"
        }, details.url, "redirect-intercept");
        break;
      }
    } catch (e) {}
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

function auditHeaders(h, url) {
  // Header/cookie state is DIRECTLY OBSERVABLE from the response → tier 3 (confirmed).
  // But missing security headers are almost always LOW/INFO for bug bounty, so severity is
  // calibrated down and a note is attached.
  const findings = [], g = n => h[n] || "";
  const bbNote = "Missing/weak security headers are often marked informational by bug bounty programs.";
  if (!g("strict-transport-security")) findings.push({ type: "Header — No HSTS", severity: "low", tier: 3, detail: "Response has no Strict-Transport-Security header. " + bbNote, category: "security-headers", location: url });
  const csp = g("content-security-policy");
  if (!csp) findings.push({ type: "Header — No CSP", severity: "low", tier: 3, detail: "Response has no Content-Security-Policy header. " + bbNote, category: "security-headers", location: url });
  else {
    // FIX 2: only 'unsafe-inline'/'unsafe-eval' in the SCRIPT context is an XSS weakness — i.e.
    // in script-src, or in default-src when there is no script-src. 'unsafe-inline' in style-src
    // alone is common and low-risk; flagging it mis-marked an otherwise-hardened CSP (e.g.
    // /secure) as weak. Parse the directives and check only the script context.
    const dirs = {};
    csp.split(";").forEach(d => { const p = d.trim().split(/\s+/); if (p[0]) dirs[p[0].toLowerCase()] = " " + p.slice(1).join(" ").toLowerCase() + " "; });
    const scriptCtx = (dirs["script-src"] !== undefined ? dirs["script-src"] : (dirs["default-src"] || ""));
    if (/unsafe-inline/.test(scriptCtx)) findings.push({ type: "Header — CSP unsafe-inline", severity: "low", tier: 3, detail: "CSP script-src allows 'unsafe-inline' — weakens XSS mitigation (only impactful if an XSS also exists)", category: "security-headers", location: url, subtype: "csp-weakness" });
    if (/unsafe-eval/.test(scriptCtx)) findings.push({ type: "Header — CSP unsafe-eval", severity: "low", tier: 3, detail: "CSP script-src allows 'unsafe-eval' — weakens XSS mitigation (only impactful if an XSS also exists)", category: "security-headers", location: url, subtype: "csp-weakness" });
  }
  const acao = g("access-control-allow-origin");
  if (acao === "*") findings.push({ type: "Header — CORS *", severity: "low", tier: 3, detail: "Access-Control-Allow-Origin: * — any origin can read responses (not exploitable for credentialed data since '*' cannot be combined with credentials)", category: "cors", location: url });
  if (acao && acao !== "*" && g("access-control-allow-credentials") === "true") findings.push({ type: "Header — CORS + Creds", severity: "medium", tier: 3, detail: `ACAO: ${acao} with Allow-Credentials: true — verify whether the origin is reflected/attacker-controllable before treating as exploitable`, category: "cors", location: url });
  if (!g("x-frame-options") && (!csp || !csp.includes("frame-ancestors"))) findings.push({ type: "Header — No Clickjacking Protection", severity: "low", tier: 3, detail: "No X-Frame-Options and no CSP frame-ancestors — page can be framed. " + bbNote, category: "security-headers", location: url });
  // Set-Cookie header audit (this path also covers the free build, which lacks the cookies API).
  const sc = g("set-cookie");
  if (sc) {
    // P3: read the cookie NAME (not the whole header, whose value could contain "token"),
    // filter tracking cookies, and fire on any flagless cookie with calibrated severity.
    const cname = ((sc.match(/^\s*([^=;\s]+)/) || [])[1]) || "";
    if (cname && !isTrackingCookie(cname)) {
      const isAuthC = /token|jwt|auth|access[_-]?token|bearer|secret/i.test(cname);
      const isSessC = /session|sid|phpsessid|jsessionid|connect\.sid|csrf|xsrf/i.test(cname);
      const sensitiveC = isAuthC || isSessC;
      // P3 (tuned): only flag missing HttpOnly on SESSION/AUTH cookies (medium/high) — those are
      // what programs actually reward. Non-sensitive cookies lacking HttpOnly are out-of-scope on
      // most programs, so they are no longer reported.
      if (!/;\s*httponly/i.test(sc) && sensitiveC) findings.push({ type: "Cookie — No HttpOnly", severity: "medium", tier: 3, detail: `Cookie "${cname}" set without HttpOnly — ${isAuthC ? "authentication" : "session"} cookie readable by JavaScript (stealable via XSS)`, category: "cookie-security", location: url, evidenceObj: { proof: `Set-Cookie for "${cname}" lacks HttpOnly`, technique: "response-header-observation", request: null, response: "Set-Cookie: …(HttpOnly absent)", timestamp: Date.now() } });
      if (!/;\s*secure/i.test(sc) && sensitiveC && /^https:/i.test(url)) findings.push({ type: "Cookie — No Secure Flag", severity: "low", tier: 3, detail: `Cookie "${cname}" set without Secure — can be sent over plaintext HTTP`, category: "cookie-security", location: url });
      if (!/;\s*samesite/i.test(sc) && sensitiveC) findings.push({ type: "Cookie — No SameSite", severity: "low", tier: 3, detail: `Cookie "${cname}" set without SameSite — may allow CSRF`, category: "cookie-security", location: url });
    }
  }
  const srv = g("server"); if (srv && /apache|nginx|iis|express|tomcat/i.test(srv)) findings.push({ type: "Header — Server", severity: "info", tier: 3, detail: `Server: ${srv}`, category: "info-disclosure", location: url });
  const xpb = g("x-powered-by"); if (xpb) findings.push({ type: "Header — X-Powered-By", severity: "info", tier: 3, detail: `X-Powered-By: ${xpb} — reveals server technology`, category: "info-disclosure", location: url });
  const xav = g("x-aspnet-version"); if (xav) findings.push({ type: "Header — X-AspNet-Version", severity: "low", tier: 3, detail: `X-AspNet-Version: ${xav} — exact framework version exposed`, category: "info-disclosure", location: url });
  if (g("x-debug") || g("x-debug-token")) findings.push({ type: "Header — Debug", severity: "medium", tier: 3, detail: "Debug headers present on response", category: "info-disclosure", location: url });
  return findings;
}

// Cookie audit — checks security attributes (HttpOnly, Secure, SameSite)
// Reads cookie metadata only; values used locally for role comparison, never sent externally
function auditCookiesForDomain(url) {
  // The free build ships without the "cookies" permission (minimal footprint); it observes
  // cookie flags from the Set-Cookie response header instead. Skip the chrome.cookies API path
  // cleanly when the permission isn't present rather than throwing on every page.
  if (!chrome.cookies) return;
  try {
    const domain = domainOf(url);
    if (isNoiseDomain(domain)) return;
    chrome.cookies.getAll({ url }, cookies => {
      if (chrome.runtime.lastError || !cookies?.length) return;
      ylog("info", "network", "Cookie audit: " + cookies.length + " cookie" + (cookies.length === 1 ? "" : "s") + " analyzed", domain);
      const isHttps = /^https:/i.test(url);
      for (const c of cookies) {
        if (isTrackingCookie(c.name)) continue; // analytics/ads cookies are noise — filtered
        // P3 (tuned): cookie attributes are DIRECTLY OBSERVABLE → tier 3. Only flag missing
        // HttpOnly on SESSION/AUTH cookies (auth/token = HIGH, session = MEDIUM) — those are
        // what programs reward. Non-sensitive cookies lacking HttpOnly are out-of-scope on most
        // programs and are no longer reported (they were flooding the low-severity tier).
        const isAuth = /token|auth|jwt|api[_-]?key|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token|secret/i.test(c.name);
        const isSession = /session|sid|phpsessid|jsessionid|connect\.sid|asp\.?net[_-]?sessionid|csrf|xsrf/i.test(c.name);
        const sensitive = isAuth || isSession;
        const kind = isAuth ? "authentication" : "session";
        if (!c.httpOnly && sensitive) {
          const sev = "medium"; // HttpOnly-missing is exploitable only via XSS (a chain component) → medium, keeps 0 tier-3 high
          addGlobalFinding({ type: "Cookie — No HttpOnly", severity: sev, tier: 3, detail: `Cookie "${c.name}" is readable by JavaScript (httpOnly=false) — ${kind} cookie, stealable via XSS`, category: "cookie-security", location: url, evidence: `httpOnly=false on ${kind} cookie "${c.name}"`, evidenceObj: { proof: `Cookie "${c.name}" has HttpOnly=false (directly observed)`, technique: "cookie-attribute-observation", request: null, response: `Set-Cookie: ${c.name}=…; HttpOnly=false`, timestamp: Date.now() } }, url, "cookie-api-audit");
        }
        // Secure only matters on HTTPS (on http:// no cookie can be Secure); keep to sensitive
        // cookies to avoid flooding info-level noise on sites with many cookies.
        if (!c.secure && isHttps && sensitive) {
          addGlobalFinding({ type: "Cookie — No Secure Flag", severity: isAuth ? "medium" : "low", tier: 3, detail: `Cookie "${c.name}" can be sent over plaintext HTTP (secure=false)`, category: "cookie-security", location: url, evidenceObj: { proof: `Cookie "${c.name}" has Secure=false (directly observed)`, technique: "cookie-attribute-observation", request: null, response: null, timestamp: Date.now() } }, url, "cookie-api-audit");
        }
        // SameSite None/unspecified only matters for sensitive cookies (CSRF surface).
        if ((c.sameSite === "no_restriction" || c.sameSite === "unspecified") && sensitive) {
          addGlobalFinding({ type: "Cookie — No SameSite", severity: "low", tier: 3, detail: `Cookie "${c.name}" has sameSite=${c.sameSite} — may allow cross-site request forgery`, category: "cookie-security", location: url, evidenceObj: { proof: `Cookie "${c.name}" sameSite=${c.sameSite} (directly observed)`, technique: "cookie-attribute-observation", request: null, response: null, timestamp: Date.now() } }, url, "cookie-api-audit");
        }
      }
    });
  } catch (e) { dbgWarn("Cookie audit error:", e.message); }
}

// ══════════════════════════════════════════════════════════════════
// BUG CHAINING ENGINE (#20 — from Zseano's Methodology)
// ══════════════════════════════════════════════════════════════════
// BUG CHAINING ENGINE
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
// CONTEXT MENU + INSTALL
// ══════════════════════════════════════════════════════════════════
chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setOptions({ enabled: true });
  chrome.alarms.create("keepalive", { periodInMinutes: 0.4 });
});

// SW keepalive (Bug 7 fix)
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "keepalive") { /* no-op — keeps service worker alive */ }
});
chrome.runtime.onConnect.addListener(port => { if (port.name?.startsWith("verify:")) { const v = port.name.split("verify:")[1]; verifyPorts[v] = port; port.onDisconnect.addListener(() => delete verifyPorts[v]); } });


// ══════════════════════════════════════════════════════════════════
// MESSAGE ROUTER
// ══════════════════════════════════════════════════════════════════
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;

  // Toggle
  if (msg.type === "TOGGLE_EXTENSION" || msg.type === "setEnabled") { enabled = msg.enabled !== undefined ? !!msg.enabled : !!msg.value; chrome.storage.local.set({ enabled }); chrome.storage.sync.set({ enabled }); updateBadge(); chrome.tabs.query({}, tabs => { for (const t of tabs) chrome.tabs.sendMessage(t.id, { type: "SET_ENABLED", enabled }).catch(() => {}); }); sendResponse?.({ enabled }); return true; }
  if (msg.type === "getEnabled") { sendResponse({ enabled }); return true; }
  if (msg.type === "SET_SCAN_PAUSED") { scanPausedState = !!msg.paused; chrome.storage.sync.set({ scanPaused: scanPausedState }); updateBadge(); sendResponse?.({ ok: true, paused: scanPausedState }); return true; }
  if (msg.type === "GET_SCAN_PAUSED") { sendResponse({ paused: scanPausedState }); return true; }
  if (msg.type === "SET_LIGHTWEIGHT") { G.lightweightMode = !!msg.enabled; chrome.storage.sync.set({ lightweightMode: G.lightweightMode }); scheduleFlush(); ylog("info", "system", "Lightweight mode " + (G.lightweightMode ? "enabled" : "disabled")); sendResponse?.({ ok: true }); return true; }
  if (msg.type === "SET_MAX_RPS") { G.maxRequestsPerSec = Math.max(1, Math.min(50, parseInt(msg.value, 10) || 5)); chrome.storage.sync.set({ maxRequestsPerSec: G.maxRequestsPerSec }); scheduleFlush(); ylog("info", "system", "Max requests/sec set to " + G.maxRequestsPerSec); sendResponse?.({ ok: true, value: G.maxRequestsPerSec }); return true; }
  if (msg.type === "GET_MAX_RPS") { sendResponse({ value: G.maxRequestsPerSec || 5 }); return true; }
  // ── Diagnostics / error collector ──
  if (msg.type === "PING") { sendResponse({ ok: true, pong: Date.now() }); return true; }
  if (msg.type === "REPORT_ERROR") { const e = msg.error || {}; RUNTIME_ERRORS.push({ source: msg.source || "unknown", message: String(e.message || "").slice(0, 500), stack: (e.stack || "").slice(0, 800), url: (e.url || "").slice(0, 200), ts: Date.now() }); if (RUNTIME_ERRORS.length > 100) RUNTIME_ERRORS.splice(0, RUNTIME_ERRORS.length - 100); return; }
  if (msg.type === "YLOG") { ylog(msg.level, msg.category, msg.message, msg.domain || (sender.tab ? domainOf(sender.tab.url || "") : null), msg.detail); return; }
  if (msg.type === "GET_ACTIVITY_LOG") { sendResponse({ log: G.activityLog || [] }); return true; }
  if (msg.type === "CLEAR_ACTIVITY_LOG") { G.activityLog = []; scheduleFlush(); ylog("info", "system", "Activity log cleared"); sendResponse({ success: true }); return true; }
  if (msg.type === "GET_ERRORS") { sendResponse({ errors: RUNTIME_ERRORS.slice().reverse() }); return true; }
  if (msg.type === "CLEAR_ERRORS") { RUNTIME_ERRORS.length = 0; sendResponse({ ok: true }); return true; }
  if (msg.type === "GET_DIAGNOSTICS") {
    let totalFindings = 0; const domains = Object.keys(G.findings || {});
    for (const d of domains) totalFindings += (G.findings[d] || []).length;
    let pmCount = 0; for (const d in (G.pmLog || {})) pmCount += G.pmLog[d].length;
    sendResponse({
      enabled, scanPaused: scanPausedState,
      scope: G.targetScope || [], safeMode: !!G.safeMode,
      domains: domains.length, totalFindings, pmHandlers: pmCount,
      confirmedBugs: (G.confirmedBugs || []).length,
      falsePositivePatterns: (G.falsePositivePatterns || []).length,
      bridge: { url: (G.bridge && G.bridge.url) || "", connected: !!(G.bridge && G.bridge.connected) },
      license: { tier: (G.license && G.license.valid) ? "pro" : ((G.trial && G.trial.active) ? "trial" : "free"), trialDays: (G.trial && G.trial.active) ? G.trial.daysRemaining : null },
      aiConfigured: false, // filled client-side from storage
      errorCount: RUNTIME_ERRORS.length,
      recentErrors: RUNTIME_ERRORS.slice(-10).reverse()
    });
    return true;
  }

  // Auto-scan results (every page)
  if (msg.type === "AUTO_SCAN_RESULTS" && sender.tab) {
    dbg("AUTO_SCAN_RESULTS from tab", sender.tab.id, "URL:", msg.payload?.url, "findings:", msg.payload?.findings?.length);
    if (!enabled) { dbgWarn("Disabled, dropping"); return; }
    if (!msg.payload?.findings?.length) { dbg("No findings, skipping"); return; }
    if (!isInScope(msg.payload.url)) { dbg("Out of scope, dropping:", msg.payload.url); ylog("warning", "scan", "Scan skipped: page out of scope", domainOf(msg.payload.url)); return; }
    // Run templates on the page too
    try {
      chrome.scripting.executeScript({ target: { tabId: sender.tab.id }, func: () => document.documentElement.outerHTML }, results => {
        if (results?.[0]?.result) {
          const tplFindings = runTemplates(results[0].result, msg.payload.url, {});
          dbg("Template matches:", tplFindings.length);
          for (const f of tplFindings) addGlobalFinding(f, msg.payload.url, "template-match");
        }
      });
    } catch(e) { dbgWarn("Template exec error:", e.message); }
    const _scanDomain = domainOf(msg.payload.url);
    let added = 0;
    for (const f of msg.payload.findings) { if (addGlobalFinding(f, msg.payload.url, "auto-scan")) added++; }
    dbgOk(`Stored ${added} new findings (${msg.payload.findings.length - added} dupes skipped)`);
    ylog("info", "scan", `Auto-scan complete: ${added} new finding${added === 1 ? "" : "s"}`, _scanDomain, msg.payload.findings.length + " total, " + (msg.payload.findings.length - added) + " filtered");
    // Persist latest scan so a freshly-opened side panel can restore & render it
    try { chrome.storage.session.set({ latestScan: msg.payload }); } catch {}
    // Broadcast to sidepanel so it shows findings
    chrome.runtime.sendMessage({ type: "SCAN_RESULTS", payload: msg.payload }).catch(() => {});
    // Badge: show stored finding count for this tab's domain
    updateBadge(sender.tab.id);
    if (added > 0) {
    }
    return;
  }

  // Manual scan
  if (msg.type === "SCAN_RESULTS") { chrome.storage.session.set({ latestScan: msg.payload }); chrome.runtime.sendMessage(msg).catch(() => {}); if (msg.payload?.findings?.length) for (const f of msg.payload.findings) addGlobalFinding(f, msg.payload.url, "manual-scan"); return; }
  if (msg.type === "REQUEST_SCAN") { chrome.tabs.query({ active: true, currentWindow: true }, tabs => { if (tabs[0]) { ylog("info", "scan", "Manual scan triggered", domainOf(tabs[0].url || "")); triggerScan(tabs[0]); } }); return; }

  // postMessage
  if (msg.type === "listener" && sender.tab) { if (!enabled) return; const tabId = sender.tab.id, r = msg.record, k = keyOf(r); const list = (pmByTab[tabId] = pmByTab[tabId] || []); if (!list.some(x => keyOf(x) === k)) list.push(r); const domain = domainOf(sender.url || (sender.tab && sender.tab.url) || r.frameUrl); if (!isInScope(domain)) return; const gl = (G.pmLog[domain] = G.pmLog[domain] || []); if (!gl.some(x => keyOf(x.record) === k)) { gl.push({ record: r, url: r.frameUrl, timestamp: Date.now() }); ylog("info", "network", "postMessage handler captured", domain); scheduleFlush(); } return; }
  if (msg.type === "traffic" && sender.tab) { if (!enabled) return; const e = msg.entry, d = domainOf(sender.url || (sender.tab && sender.tab.url) || e.frameUrl); if (!isInScope(d)) return; const tl = (G.pmTraffic[d] = G.pmTraffic[d] || []); if (tl.length < 500) { tl.push(e); scheduleFlush(); } return; }
  if (msg.type === "getPmFindings") { sendResponse({ findings: pmByTab[msg.tabId] || [], analysisCache: pmAnalysisByTab[msg.tabId] || {} }); return true; }
  if (msg.type === "recollect") { chrome.tabs.sendMessage(msg.tabId, { type: "collect" }, {}, () => void chrome.runtime.lastError); sendResponse({ ok: true }); return true; }

  // WebSocket events
  if (msg.type === "ws_event" && sender.tab) { if (!enabled) return; const e = msg.entry, d = domainOf(sender.url || (sender.tab && sender.tab.url) || e.frameUrl); if (!isInScope(d)) return; const tl = (G.wsTraffic[d] = G.wsTraffic[d] || []); if (tl.length === 0) ylog("info", "network", "WebSocket connection detected", d); if (tl.length < 300) { tl.push(e); scheduleFlush(); } return; }

  // Worker events
  if (msg.type === "worker_event" && sender.tab) { if (!enabled) return; const e = msg.entry, d = domainOf(sender.url || (sender.tab && sender.tab.url) || e.frameUrl); if (!isInScope(d)) return; const wl = (G.workerEvents[d] = G.workerEvents[d] || []); if (wl.length < 200) { wl.push(e); scheduleFlush(); } return; }

  // API Traffic (fetch/XHR with response bodies)
  if (msg.type === "api_traffic" && sender.tab) { if (!enabled) return; const e = msg.entry, d = domainOf(e.url || e.frameUrl); if (!isInScope(d)) return; const al = (G.apiTraffic[d] = G.apiTraffic[d] || []); if (al.length < 200) { al.push(e); let _p = ""; try { _p = new URL(e.url).pathname; } catch { _p = e.url || ""; } ylog("info", "network", "API request captured: " + (e.method || "GET") + " " + _p.slice(0, 60), d); scheduleFlush(); } return; }


  // PM analysis
  if (msg.type === "analyzePm") { analyzePmWithAI(msg.record).then(r => { const c = (pmAnalysisByTab[msg.tabId] = pmAnalysisByTab[msg.tabId] || {}); c[keyOf(msg.record)] = r; G.pmAnalysis[domainOf(msg.record.frameUrl) + "::" + (msg.record.source || "").slice(0, 400)] = r; scheduleFlush(); sendResponse({ ok: true, result: r }); }).catch(e => sendResponse({ ok: false, error: String(e?.message || e) })); return true; }

  // Verify XSS
  if (msg.type === "startVerify") { const vid = uid(); const payloads = generatePayloads(msg.record, msg.analysis, vid); pendingJobs[vid] = { verifyId: vid, targetUrl: msg.record.frameUrl, payloads, record: msg.record, analysis: msg.analysis, status: "pending" }; chrome.tabs.create({ url: chrome.runtime.getURL("src/verify.html") + "?id=" + vid }); sendResponse({ ok: true, verifyId: vid }); return true; }
  if (msg.type === "getVerifyJob") { const j = pendingJobs[msg.verifyId]; if (j) { j.status = "running"; sendResponse({ ok: true, job: j }); } else sendResponse({ ok: false }); return true; }
  if (msg.type === "xss_confirmed") { const vid = msg.verifyId, job = pendingJobs[vid]; if (job && job.status !== "confirmed") { job.status = "confirmed"; job.confirmedAt = Date.now(); const port = verifyPorts[vid]; if (port) try { port.postMessage({ type: "confirmed", payloadIndex: job._currentIndex || 0 }); } catch {} const doc = buildPmDocumentation(job.record, job.analysis, "confirmed", null); const d = domainOf(job.record.frameUrl); G.confirmedBugs.push({ type: "postMessage DOM XSS", url: job.record.frameUrl, domain: d, doc, timestamp: Date.now() }); scheduleFlush(); } return; }
  if (msg.type === "verifyProgress") { const j = pendingJobs[msg.verifyId]; if (j) j._currentIndex = msg.index; return; }
  if (msg.type === "getVerifyStatus") { sendResponse({ status: pendingJobs[msg.verifyId]?.status || "unknown" }); return true; }

  // Global data
  if (msg.type === "getGlobalLog") { sendResponse({ globalLog: G.pmLog, globalAnalysis: G.pmAnalysis, globalTraffic: G.pmTraffic }); return true; }
  if (msg.type === "getGlobalFindings") { sendResponse({ G }); return true; }
  if (msg.type === "clearAllData") {
    const _keepLog = G.activityLog, _keepLogVer = G.logVersion, _keepLight = G.lightweightMode;
    G = { findings: {}, pmLog: {}, pmAnalysis: {}, pmTraffic: {}, requests: {}, apiTraffic: {}, wsTraffic: {}, workerEvents: {}, confirmedBugs: [], customRules: G.customRules, templates: G.templates, webhookUrl: G.webhookUrl, screenshots: {}, verifyLog: [], safeMode: G.safeMode, targetScope: G.targetScope, customHeaders: G.customHeaders, customHeadersEnabled: G.customHeadersEnabled, falsePositivePatterns: G.falsePositivePatterns || [], crawlHistory: null, activityLog: _keepLog || [], logVersion: _keepLogVer || "", lightweightMode: _keepLight || false };
    ylog("warning", "system", "Data cleared (findings, traffic, postMessage)");
    chrome.storage.local.set({ G }); sendResponse({ ok: true }); return true; }
  if (msg.type === "getTraffic") { sendResponse({ traffic: G.pmTraffic[msg.domain] || [] }); return true; }
  if (msg.type === "generateDoc") { sendResponse({ ok: true, markdown: buildPmDocumentation(msg.record, msg.analysis, msg.verifyResult, msg.pocHtml) }); return true; }
  if (msg.type === "generateFindingDoc") { const domain = domainOf(msg.url); const entries = G.findings[domain] || []; const entry = entries.find(e => e.hash === msg.hash); if (entry) sendResponse({ ok: true, markdown: buildFindingDoc(entry, domain) }); else sendResponse({ ok: false }); return true; }
  if (msg.type === "getConfirmedBugs") { sendResponse({ bugs: G.confirmedBugs }); return true; }

  // Scope enforcement
  if (msg.type === "SET_SCOPE") { G.targetScope = msg.scope || []; scheduleFlush(); chrome.storage.sync.set({ targetScope: G.targetScope }); if (typeof updateResearcherHeaderRule === "function") updateResearcherHeaderRule(); sendResponse({ ok: true }); return true; }
  if (msg.type === "GET_SCOPE") { sendResponse({ scope: G.targetScope || [], safeMode: G.safeMode || false }); return true; }
  if (msg.type === "SET_SAFE_MODE") { G.safeMode = !!msg.enabled; scheduleFlush(); sendResponse({ ok: true }); return true; }

  // Custom rules + templates
  if (msg.type === "saveCustomRules") { G.customRules = msg.rules; scheduleFlush(); sendResponse({ ok: true }); return true; }
  if (msg.type === "getCustomRules") { sendResponse({ rules: G.customRules }); return true; }
  if (msg.type === "saveTemplates") { G.templates = msg.templates; scheduleFlush(); sendResponse({ ok: true }); return true; }

  // Verification engine
  if (msg.type === "VERIFY_FINDING") {
    if (!isInScope(msg.domain)) { sendResponse({ status: "error", reason: "Domain out of scope: " + msg.domain }); return true; }
    if (G.safeMode && !/localhost|127\.0\.0\.1|\[::1\]/.test(msg.domain)) { sendResponse({ status: "error", reason: "Safe mode: active verification blocked on external target" }); return true; }
    verifyFinding(msg.domain, msg.hash).then(sendResponse).catch(e => sendResponse({ status: "error", reason: e.message })); return true;
  }
  if (msg.type === "VERIFY_BATCH") { verifyBatch(msg.maxCount || 20).then(sendResponse).catch(e => sendResponse({ status: "error", reason: e.message })); return true; }
  if (msg.type === "SET_VERIFY_STATUS") { const entry = vfFind(msg.domain, msg.hash); if (entry) { entry.verificationStatus = msg.status; entry.verifiedAt = Date.now(); if (msg.status === "false_positive") { learnFalsePositive(entry.finding, entry.url); } scheduleFlush(); sendResponse({ ok: true }); } else sendResponse({ ok: false }); return true; }
  if (msg.type === "GET_FP_PATTERNS") { sendResponse({ patterns: G.falsePositivePatterns || [] }); return true; }
  if (msg.type === "CLEAR_FP_PATTERNS") { G.falsePositivePatterns = []; scheduleFlush(); sendResponse({ ok: true }); return true; }
  if (msg.type === "UPDATE_FINDING_FIELD") { const entry = vfFind(msg.domain, msg.hash); if (entry && msg.field) { entry[msg.field] = msg.value; scheduleFlush(); sendResponse({ ok: true }); } else sendResponse({ ok: false }); return true; }
  if (msg.type === "getVerifyLog") { sendResponse({ log: G.verifyLog }); return true; }
  if (msg.type === "setSafeMode") { G.safeMode = !!msg.value; scheduleFlush(); sendResponse({ ok: true, safeMode: G.safeMode }); return true; }
  if (msg.type === "getSafeMode") { sendResponse({ safeMode: G.safeMode }); return true; }
  if (msg.type === "SET_DEBUG") { DEBUG = !!msg.enabled; sendResponse({ ok: true, debug: DEBUG }); return true; }
  if (msg.type === "GET_DEBUG") { sendResponse({ debug: DEBUG }); return true; }
  if (msg.type === "setTargetScope") { G.targetScope = Array.isArray(msg.scope) ? msg.scope : (msg.scope || "").split(/[,\n]/).map(s=>s.trim()).filter(Boolean); scheduleFlush(); chrome.storage.sync.set({ targetScope: G.targetScope }); if (typeof updateResearcherHeaderRule === "function") updateResearcherHeaderRule(); sendResponse({ ok: true }); return true; }
  if (msg.type === "getTargetScope") { sendResponse({ scope: G.targetScope }); return true; }







  // Bug chaining + professional report
  if (msg.type === "GET_CHAINS") { const domain = msg.domain || ""; sendResponse({ chains: chainFindings(domain) }); return true; }




  // Wordlist building (#33)
  if (msg.type === "GET_WORDLISTS") {
    const wl = { params: new Set(), paths: new Set(), domains: new Set(), emails: new Set(), techs: new Set() };
    for (const d in G.findings) {
      wl.domains.add(d);
      for (const e of G.findings[d]) {
        try {
          const u = new URL(e.url);
          u.pathname.split("/").filter(Boolean).forEach(s => wl.paths.add(s));
          for (const k of u.searchParams.keys()) wl.params.add(k);
        } catch {}
        const det = e.finding?.detail || "";
        const emailMatch = det.match(/[\w.+-]+@[\w-]+\.[\w.]+/g);
        if (emailMatch) emailMatch.forEach(em => wl.emails.add(em));
        if (e.finding?.category === "recon" && /Technology|Fingerprint/i.test(e.finding?.type || "")) wl.techs.add(det.slice(0, 80));
      }
    }
    for (const d in G.requests) {
      for (const r of (G.requests[d] || [])) {
        try { new URL(r.url).pathname.split("/").filter(Boolean).forEach(s => wl.paths.add(s)); } catch {}
      }
    }
    sendResponse({
      params: [...wl.params].sort(),
      paths: [...wl.paths].sort(),
      domains: [...wl.domains].sort(),
      emails: [...wl.emails].sort(),
      techs: [...wl.techs].sort()
    });
    return true;
  }


  // Auth diff
  if (msg.type === "getAuthDiff") { sendResponse(computeAuthDiff()); return true; }


  // General AI
  if (msg.type === "AI_ANALYZE") { handleAIRequest(msg.payload).then(sendResponse).catch(e => sendResponse({ error: e.message })); return true; }

  // Custom headers
  if (msg.type === "SET_CUSTOM_HEADERS") {
    G.customHeaders = msg.headers || [];
    G.customHeadersEnabled = !!msg.enabled;
    scheduleFlush();
    updateCustomHeaderRules();
    sendResponse({ ok: true, count: G.customHeaders.length, enabled: G.customHeadersEnabled });
    return true;
  }
  if (msg.type === "GET_CUSTOM_HEADERS") {
    sendResponse({ headers: G.customHeaders || [], enabled: G.customHeadersEnabled || false });
    return true;
  }


  // Crawler status polling (Bug 5 fix)
  if (msg.type === "GET_CRAWL_STATUS") {
    sendResponse({
      running: crawlerState.running,
      paused: crawlerState.paused,
      pagesVisited: crawlerState.stats.pages,
      findingsCount: crawlerState.stats.findings,
      queueLength: crawlerState.queue.length,
      currentUrl: crawlerState.currentUrl || null,
      stats: crawlerState.stats
    });
    return true;
  }
  if (msg.type === "CRAWL_WAIT") {
    if (!crawlerState.running) {
      sendResponse({ done: true, stats: crawlerState.stats });
    } else {
      const waitInterval = setInterval(() => {
        if (!crawlerState.running) {
          clearInterval(waitInterval);
          sendResponse({ done: true, stats: crawlerState.stats });
        }
      }, 1000);
      setTimeout(() => {
        clearInterval(waitInterval);
        sendResponse({ done: false, timeout: true, stats: crawlerState.stats });
      }, 300000);
    }
    return true;
  }

  // Crawler
  if (msg.type === "CRAWL_START") { dbg("Received CRAWL_START:", msg.config?.startUrl); startCrawler(msg.config); }
  if (msg.type === "GET_CRAWL_HISTORY") { sendResponse({ history: G.crawlHistory || null }); return true; }
  if (msg.type === "CRAWL_PAUSE") crawlerState.paused = true;
  if (msg.type === "CRAWL_RESUME") { crawlerState.paused = false; pCQ(); }
  if (msg.type === "CRAWL_STOP") { crawlerState.running = false; }

  // Memory usage (Bug 9 fix)
  if (msg.type === "GET_MEMORY_USAGE") {
    let totalFindings = 0, domainsCount = 0;
    for (const d in G.findings) { totalFindings += G.findings[d].length; domainsCount++; }
    sendResponse({ findingsCount: totalFindings, domainsCount, aiQueuePending: aiAnalysisQueue.length });
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, info) => { if (info.status === "loading") { delete pmByTab[tabId]; delete pmAnalysisByTab[tabId]; } });
chrome.tabs.onRemoved.addListener(tabId => { delete pmByTab[tabId]; delete pmAnalysisByTab[tabId]; });
function triggerScan(tab) { chrome.tabs.sendMessage(tab.id, { type: "RUN_SCAN" }).catch(() => { chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["src/content.js"] }, () => setTimeout(() => chrome.tabs.sendMessage(tab.id, { type: "RUN_SCAN" }), 300)); }); }

// ══════════════════════════════════════════════════════════════════
// AUTH vs NOAUTH DIFF
// ══════════════════════════════════════════════════════════════════
function computeAuthDiff() {
  const diff = { authOnly: [], noauthOnly: [], both: [], domains: new Set() };
  for (const d in G.findings) {
    const entries = G.findings[d];
    const authFindings = entries.filter(e => e.finding.authMode === "auth");
    const noauthFindings = entries.filter(e => e.finding.authMode === "noauth");
    const authHashes = new Set(authFindings.map(e => e.finding.type + "|" + (e.finding.detail || "").slice(0, 50)));
    const noauthHashes = new Set(noauthFindings.map(e => e.finding.type + "|" + (e.finding.detail || "").slice(0, 50)));

    for (const e of authFindings) { const k = e.finding.type + "|" + (e.finding.detail || "").slice(0, 50); if (!noauthHashes.has(k)) diff.authOnly.push({ ...e, domain: d }); else diff.both.push({ ...e, domain: d }); }
    for (const e of noauthFindings) { const k = e.finding.type + "|" + (e.finding.detail || "").slice(0, 50); if (!authHashes.has(k)) diff.noauthOnly.push({ ...e, domain: d }); }
    if (authFindings.length || noauthFindings.length) diff.domains.add(d);
  }
  diff.domains = [...diff.domains];
  return diff;
}

// ══════════════════════════════════════════════════════════════════
// AI PROVIDERS — BYOK (Bring Your Own Key)
// User provides their own API key; calls go ONLY to the provider they chose.
// No data is sent to YANSII servers. No AI safety measures are circumvented.
// ══════════════════════════════════════════════════════════════════

// Payload generation
function detectSinkType(r,a){const s=a?.data_flow?.sink||"",sk=r?.analysis?.sinks||[];if(/el\.src|iframe/i.test(s)||sk.includes("el.src"))return"iframe-src";if(/location|href/i.test(s)||sk.includes("location"))return"location";if(/eval|Function/i.test(s)||sk.includes("eval"))return"eval";return"html"}
function generatePayloads(record,analysis,vid){const canary=`window.dispatchEvent(new CustomEvent('__pmm_xss_ok',{detail:'${vid}'}))`;const st=detectSinkType(record,analysis);const hV=[{t:"img",p:`<img src=x onerror="${canary}">`},{t:"svg",p:`<svg onload="${canary}">`}];const lV=[{t:"js-http",p:`javascript:void(document.title='__pmm_verify_${vid}')//http:`},{t:"js-bare",p:`javascript:void(document.title='__pmm_verify_${vid}')`}];const iV=[{t:"ifr",p:`javascript:void(parent.document.title='__pmm_verify_${vid}')`}];const eV=[{t:"eval",p:canary},{t:"break",p:`';${canary};//`}];const vs=st==="location"?lV:st==="iframe-src"?iV:st==="eval"?eV:hV;const pl=[];if(st!=="location"&&analysis?.test_payloads?.length)for(const tp of analysis.test_payloads){if(!/\{\{XSS\}\}/.test(typeof tp.data==="string"?tp.data:JSON.stringify(tp.data)))continue;for(const v of vs)pl.push({data:iP(tp.data,v.p),targetOrigin:tp.targetOrigin||"*",description:(tp.note||"shaped")+" ("+v.t+")",vector:v.t})}if(st==="location")for(const v of lV)pl.push({data:v.p,targetOrigin:"*",description:"js: ("+v.t+")",vector:v.t});if(!pl.length){const shapes=[x=>x,x=>({html:x}),x=>({content:x}),x=>({data:x}),x=>({type:"update",html:x})];for(const s of shapes)for(const v of vs.slice(0,2))pl.push({data:s(v.p),targetOrigin:"*",description:"generic("+v.t+")",vector:v.t})}return pl}
function iP(o,v){if(o==null)return o;if(typeof o==="string")return o.replace(/\{\{XSS\}\}/g,v);if(Array.isArray(o))return o.map(x=>iP(x,v));if(typeof o==="object"){const r={};for(const k of Object.keys(o))r[k]=iP(o[k],v);return r}return o}
function buildPmDocumentation(r,a,vr,poc){const d=domainOf(r?.frameUrl);return`# ${vr==="confirmed"?"CONFIRMED":"Potential"} DOM XSS via postMessage\n\n**Domain:** ${d}\n**URL:** ${r?.frameUrl}\n**Verdict:** ${a?.verdict} (${a?.confidence}%)\n**Origin:** ${a?.origin_check?.present?"Checked":"❌ NONE"}\n**Sink:** ${a?.data_flow?.sink||"?"}\n\n## Source\n\`\`\`js\n${r?.source||""}\n\`\`\`\n\n## AI Notes\n${a?.notes||""}\n\n## Test\n\`\`\`js\n${a?.test_payload||""}\n\`\`\`\n${poc?"\n## PoC\n```html\n"+poc+"\n```\n":""}`}

// Crawler
const crawlerState={running:false,paused:false,queue:[],visited:new Set(),results:[],config:null,stats:{pages:0,findings:0,critical:0,high:0,medium:0},baselineHash:null,spaDetected:{}};

const SPA_MARKERS = /<app-root|<div\s+id=["'](?:root|app|__next|__nuxt)["']|__NEXT_DATA__|window\.__INITIAL_STATE__|window\.__NUXT__|ng-app=|data-reactroot/i;
const DISCOVERY_PATHS = /\/\.env|\/\.git\/|\/\.svn\/|\/\.hg\/|\/package\.json|\/composer\.json|\/web\.config|\/wp-config|\/\.aws\/|\/\.docker/i;

function simpleHash(str) {
  let h = 0;
  const s = (str || "").slice(0, 5000);
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return h;
}

function isSPACatchAll(html, url, baselineHash) {
  if (!html || !baselineHash) return false;
  if (!DISCOVERY_PATHS.test(url)) return false;
  const pageHash = simpleHash(html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "").replace(/\s+/g, " "));
  if (pageHash === baselineHash) return true;
  const stripped = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "").replace(/\s+/g, " ");
  if (SPA_MARKERS.test(html) && stripped.length < 2000) return true;
  return false;
}
// pCQ = processCrawlQueue, fP = fetchPage (opens tab to get HTML), aPH = analyzePageHtml
// eL = extractLinks, iIS = isInScope (crawler), nU = normalizeURL, bc = broadcastCrawlEvent
function saveCrawlHistory(){ try { G.crawlHistory = { results: crawlerState.results || [], stats: crawlerState.stats || {}, startUrl: crawlerState.config?.startUrl || "", timestamp: Date.now() }; ylog("success", "crawl", "Crawler complete: " + (crawlerState.stats?.pages || 0) + " pages, " + (crawlerState.stats?.findings || 0) + " findings", domainOf(crawlerState.config?.startUrl || "")); scheduleFlush(); } catch {} }
function startCrawler(c){dbg("🕷️ CRAWLER START:",c.startUrl,"scope:",c.scope,"maxPages:",c.maxPages);ylog("info","crawl","Crawler started: depth "+c.maxDepth+", max "+c.maxPages+" pages",domainOf(c.startUrl));Object.assign(crawlerState,{running:true,paused:false,queue:[{url:c.startUrl,depth:0}],visited:new Set(),results:[],config:c,stats:{pages:0,findings:0,critical:0,high:0,medium:0},baselineHash:null,spaDetected:{}});bc("CRAWL_STATUS",{status:"running",stats:crawlerState.stats,queue:1});fP(c.startUrl,"noauth").then(html=>{if(html){crawlerState.baselineHash=simpleHash(html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi,"").replace(/\s+/g," "))}pCQ()}).catch(()=>pCQ())}
async function pCQ(){const{config:c}=crawlerState;if(!c){dbg("🕷️ No config, aborting");return}dbg("🕷️ processCrawlQueue started, queue:",crawlerState.queue.length);while(crawlerState.running&&!crawlerState.paused&&crawlerState.queue.length>0){if(crawlerState.stats.pages>=parseInt(c.maxPages)){crawlerState.running=false;(saveCrawlHistory(),bc("CRAWL_STATUS",{status:"done",stats:crawlerState.stats,queue:0,totalResults:crawlerState.results}));dbg("🕷️ Max pages reached");return}const{url,depth}=crawlerState.queue.shift();const n=nU(url);if(crawlerState.visited.has(n)){dbg("🕷️ Skip visited:",url);continue}if(depth>parseInt(c.maxDepth)){dbg("🕷️ Skip depth:",url,depth);continue}if(!iIS(url,c)){dbg("🕷️ Skip out-of-scope:",url);continue}crawlerState.visited.add(n);const modes=c.authMode==="both"?["auth","noauth"]:[c.authMode];for(const mode of modes){try{dbg("🕷️ Crawling:",url,"depth:",depth,"mode:",mode);bc("CRAWL_PAGE_START",{url,depth,mode});const html=await fP(url,mode);if(!html){dbg("🕷️ Fetch failed/empty:",url);continue}dbg("🕷️ Got HTML:",html.length,"chars");const pf=aPH(html,url,mode,crawlerState.baselineHash);const nu=eL(html,url);dbg("🕷️ Findings:",pf.length,"Links:",nu.length);crawlerState.stats.pages++;crawlerState.stats.findings+=pf.length;crawlerState.stats.critical+=pf.filter(f=>f.severity==="critical").length;crawlerState.stats.high+=pf.filter(f=>f.severity==="high").length;crawlerState.stats.medium+=pf.filter(f=>f.severity==="medium").length;const pr={url,depth,mode,timestamp:new Date().toISOString(),findings:pf,linksFound:nu.length};crawlerState.results.push(pr);for(const f of pf)addGlobalFinding(f,url,"crawl-"+mode);for(const u of nu)if(!crawlerState.visited.has(nU(u))&&iIS(u,c))crawlerState.queue.push({url:u,depth:depth+1});bc("CRAWL_PAGE_DONE",{page:pr,stats:{...crawlerState.stats},queue:crawlerState.queue.length})}catch(e){dbg("🕷️ ERROR crawling:",url,e.message);ylog("warning","crawl","Crawl page failed: "+url,domainOf(url),e.message);bc("CRAWL_PAGE_ERROR",{url,error:e.message,mode})}}await new Promise(r=>setTimeout(r,parseInt(c.speed)||1500))}if(!crawlerState.paused){crawlerState.running=false;dbg("🕷️ CRAWLER DONE — pages:",crawlerState.stats.pages,"findings:",crawlerState.stats.findings);(saveCrawlHistory(),bc("CRAWL_STATUS",{status:"done",stats:crawlerState.stats,queue:0,totalResults:crawlerState.results}))}else bc("CRAWL_STATUS",{status:"paused",stats:crawlerState.stats,queue:crawlerState.queue.length})}
async function fP(u,m){await waitForRateLimit();let tabId=null;try{const tab=await chrome.tabs.create({url:u,active:false});tabId=tab.id;await new Promise((resolve)=>{let done=false;const finish=()=>{if(!done){done=true;resolve()}};const listener=(tid,info)=>{if(tid===tabId&&info.status==="complete"){chrome.tabs.onUpdated.removeListener(listener);finish()}};chrome.tabs.onUpdated.addListener(listener);chrome.tabs.get(tabId).then(t=>{if(t.status==="complete"){chrome.tabs.onUpdated.removeListener(listener);finish()}}).catch(finish);setTimeout(()=>{chrome.tabs.onUpdated.removeListener(listener);finish()},12000)});await new Promise(r=>setTimeout(r,500));let html=null;try{const results=await chrome.scripting.executeScript({target:{tabId},func:()=>document.documentElement.outerHTML});html=results?.[0]?.result||null}catch(se){dbg("🕷️ Script inject failed (403/error page):",u,se.message)}try{await chrome.tabs.remove(tabId)}catch(e){}return html}catch(e){if(tabId)try{await chrome.tabs.remove(tabId)}catch(e2){}dbg("🕷️ Tab fetch error:",u,e.message);return null}}
function aPH(h,u,m,baseHash){const f=[];if(baseHash&&isSPACatchAll(h,u,baseHash)){dbg("🕷️ SPA catch-all suppressed:",u);return f}try{const p=new URL(u),pm=[...p.searchParams.entries()];const sq=["id","uid","search","q","query","filter","order","sort","page","limit","name","email","type","status","role","ref"];for(const[k,v]of pm)if(sq.includes(k.toLowerCase()))f.push({type:"SQLi",severity:/^\d+$/.test(v)?"high":"medium",detail:`${k}=${v.slice(0,40)}`,location:u,category:"sqli",authMode:m});for(const[k,v]of pm)if(v.length>2&&v.length<200&&h.includes(v))f.push({type:"XSS—Reflected",severity:"high",detail:`"${k}" reflected`,location:u,category:"xss",subtype:"reflected",authMode:m});if(/SQL syntax.*?MySQL|PostgreSQL.*?ERROR|ORA-\d{5}|SQLSTATE/i.test(h))f.push({type:"SQLi—DB Error",severity:"critical",detail:"DB error",location:u,category:"sqli",authMode:m});if(/AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|sk-[A-Za-z0-9]{48}|-----BEGIN.*PRIVATE KEY-----|(?:password|passwd)\s*[:=]\s*['"][^'"]{4,}['"]/i.test(h))f.push({type:"Secrets",severity:"critical",detail:"Secret in page",location:u,category:"info-disclosure",authMode:m});const cmdiP=["cmd","exec","command","host","ping","ip","domain","shell","run","timeout","address","hostname"];for(const[k,v]of pm)if(cmdiP.includes(k.toLowerCase()))f.push({type:"CMDi—Parameter",severity:"high",detail:`${k}=${v.slice(0,40)}`,location:u,category:"command-injection",subtype:"parameter",authMode:m});if(/uid=\d+\(\w+\)\s+gid=|root:x:0:0:|PING\s+\S+\s+\(\d+\.\d+\.\d+\.\d+\)|sh:\s+\d+:.*not found/i.test(h))f.push({type:"CMDi—Output Detected",severity:"critical",detail:"Command output in page",location:u,category:"command-injection",subtype:"output-detected",authMode:m});const csrfForms=h.match(/<form[^>]*method\s*=\s*["']?post[^>]*>/gi)||[];if(csrfForms.length>0&&!/csrf|_token|authenticity_token/i.test(h))f.push({type:"CSRF—No Token",severity:"medium",detail:`${csrfForms.length} POST form(s) without CSRF token`,location:u,category:"csrf",authMode:m});const tpl=runTemplates(h,u,{});f.push(...tpl)}catch(e){dbg("🕷️ aPH error:",u,e.message)}return f}
function eL(h,b){const l=new Set(),sk=/\.(css|js|png|jpg|gif|svg|ico|woff2?|ttf|mp[34]|pdf|zip)(\?.*)?$/i;try{const ms=h.match(/(?:href|action)\s*=\s*["']([^"'#]+)["']/gi)||[];for(const m of ms){const v=m.match(/["']([^"'#]+)["']/)?.[1];if(!v||/^(javascript|mailto|data):/.test(v))continue;try{const r=new URL(v,b).href.split("#")[0];if(r.startsWith("http")&&!sk.test(new URL(r).pathname))l.add(r)}catch{}}}catch{}return[...l]}
function iIS(u,c){try{const p=new URL(u),s=new URL(c.startUrl);if(c.scope==="subdomain")return p.hostname===s.hostname;if(c.scope==="domain"){const rd=h=>h.split(".").slice(-2).join(".");return rd(p.hostname)===rd(s.hostname)}if(c.scope==="custom"&&c.scopeRegex)return new RegExp(c.scopeRegex).test(u)}catch{}return false}
function nU(u){try{const x=new URL(u);x.searchParams.sort();return`${x.origin}${x.pathname.replace(/\/+$/,"")||"/"}?${x.searchParams}`}catch{return u}}
function bc(t,d){chrome.runtime.sendMessage({type:t,payload:d}).catch(()=>{})}

// ══════════════════════════════════════════════════════════════════
// ACTIVE VERIFICATION ENGINE v2
// Fixes: URL-based param extraction, attribute-context XSS, dedup,
//        DOM XSS via tab, batch verify, cross-category deconfliction
// ══════════════════════════════════════════════════════════════════
let lastVerifyTime = 0;
const VERIFY_RATE_MS = 2000;

function vfFind(domain, hash) {
  return (G.findings[domain] || []).find(e => e.hash === hash);
}

function vfInScope(url) {
  if (!G.targetScope || !G.targetScope.length) return true;
  try {
    const hostname = new URL(url).hostname;
    const patterns = Array.isArray(G.targetScope) ? G.targetScope : G.targetScope.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    if (!patterns.length) return true;
    return patterns.some(p => {
      p = p.trim().toLowerCase();
      if (p.startsWith("*.")) { const d = p.slice(2); return hostname === d || hostname.endsWith("." + d); }
      return hostname === p || hostname.endsWith("." + p);
    });
  } catch { return false; }
}

function vfIsLocalhost(url) {
  try { const h = new URL(url).hostname; return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "0.0.0.0"; } catch { return false; }
}

// Fix 1: Extract param from URL directly, fall back to detail string
function vfExtractParam(entry, hintNames) {
  const url = new URL(entry.url);
  const params = [...url.searchParams.keys()];
  if (hintNames) {
    for (const k of params) { if (hintNames.some(h => h.test ? h.test(k) : k.toLowerCase() === h)) return k; }
  }
  // Try detail string as fallback
  const detail = entry.finding.detail || "";
  const dm = detail.match(/"([^"]+)"/);
  if (dm && params.includes(dm[1])) return dm[1];
  const em = detail.match(/^(\w+)=/);
  if (em && params.includes(em[1])) return em[1];
  // Last resort: first param
  return params[0] || null;
}

// Fix 3: Dedup key for verification — same URL origin+path + same param = same injection point
function vfDedupKey(entry) {
  try {
    const u = new URL(entry.url);
    const cat = entry.finding.category || "";
    const param = vfExtractParam(entry) || "_none_";
    return `${u.origin}${u.pathname}|${cat}|${param}`;
  } catch { return entry.hash; }
}

// Fix 6: Check if a param is already confirmed as a higher-priority category
function vfParamAlreadyConfirmed(entry, asCategory) {
  const domain = domainOf(entry.url);
  const entries = G.findings[domain] || [];
  const param = vfExtractParam(entry);
  if (!param) return false;
  const priority = { "command-injection": 0, "sqli": 1, "xss": 2, "ssrf": 3 };
  const thisPri = priority[asCategory] ?? 99;
  for (const e of entries) {
    if (e.verificationStatus !== "verified") continue;
    const eCat = (e.finding.category || "").toLowerCase();
    const ePri = priority[eCat] ?? 99;
    if (ePri < thisPri) {
      const eParam = vfExtractParam(e);
      if (eParam === param) {
        try { const a = new URL(e.url), b = new URL(entry.url); if (a.origin === b.origin && a.pathname === b.pathname) return eCat; } catch {}
      }
    }
  }
  return false;
}

async function vfRateLimit() {
  const now = Date.now();
  const wait = VERIFY_RATE_MS - (now - lastVerifyTime);
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  lastVerifyTime = Date.now();
}

// Active validation (tier 2/3 promotion) is a Pro feature. In the free build the Pro
// licensing state is stripped from G, so its absence means "free build → passive only".
function activeValidationAllowed() {
  if (!G.license && !G.trial) return false; // free build
  return (typeof _v === "function") ? _v() : true;
}

async function verifyFinding(domain, hash) {
  if (!activeValidationAllowed()) return { status: "detected", reason: "Active validation is a Pro feature — upgrade to auto-confirm findings with evidence." };
  if (G.safeMode) return { status: "blocked", reason: "Safe mode — passive only" };
  const entry = vfFind(domain, hash);
  if (!entry) return { status: "error", reason: "Finding not found" };
  if (!vfInScope(entry.url)) return { status: "blocked", reason: "Out of target scope (set scope in the popup — validation only runs in-scope)" };

  // Fix 3: Check dedup — if another finding with same injection point was already verified, propagate
  const dk = vfDedupKey(entry);
  const d2 = domainOf(entry.url);
  for (const e of (G.findings[d2] || [])) {
    if (e.hash !== hash && (e.tier === 3 || e.verificationStatus === "confirmed" || e.verificationStatus === "verified") && vfDedupKey(e) === dk) {
      entry.tier = 3; entry.tierLabel = "confirmed"; entry.verificationStatus = "confirmed"; entry.confidence = 95;
      entry.evidence = e.evidence || null;
      entry.verifyResult = { ...e.verifyResult, reason: `Same injection point as ${e.finding.type}: ${e.verifyResult?.reason || ""}` };
      entry.verifiedAt = Date.now();
      scheduleFlush();
      return entry.verifyResult;
    }
  }

  await vfRateLimit();
  G.verifyLog.push({ hash, domain, url: entry.url, type: entry.finding.type, category: entry.finding.category, timestamp: Date.now() });
  scheduleFlush();

  const cat = (entry.finding.category || "").toLowerCase();
  const sub = (entry.finding.subtype || "").toLowerCase();
  const typ = (entry.finding.type || "").toLowerCase();
  let result;
  try {
    if (cat === "xss" && /reflected/.test(sub)) result = await vfXSSReflected(entry);
    else if (cat === "xss" && /dom/.test(sub)) result = await vfXSSDom(entry);
    else if (cat === "sqli") result = await vfSQLi(entry);
    else if (cat === "command-injection") result = await vfCMDi(entry);
    else if (cat === "ssrf") { const skip = vfParamAlreadyConfirmed(entry, "ssrf"); if (skip) result = { status: "filtered", reason: `Param already confirmed as ${skip} — not SSRF` }; else result = await vfSSRF(entry); }
    else if (cat === "csrf") result = await vfCSRF(entry);
    else if (/security-headers|cookie/.test(cat)) result = await vfHeaders(entry);
    else if (cat === "info-disclosure" && /secret/i.test(typ)) result = await vfSecrets(entry);
    else if (cat === "open-redirect") result = await vfOpenRedirect(entry);
    else if (cat === "crlf") result = await vfCRLF(entry);
    else if (cat === "path-traversal") result = await vfPathTraversal(entry);
    else if (cat === "nosqli") result = await vfNoSQLi(entry);
    else if (cat === "exploit-chain" || cat === "chain" || cat === "bug-chain") result = { status: "info", reason: "Exploit chains are composite findings — verify each individual finding in the chain separately" };
    else if (cat === "cors" || cat === "idor" || cat === "host-header") result = { status: "detected", reason: "Manual verification recommended for " + cat + " — automated verifier not available for this category" };
    else result = { status: "detected", reason: "No automated verifier for: " + cat + " — try AI Verify or manual testing" };
  } catch (e) { result = { status: "error", reason: e.message }; }

  // Map the verifier result onto the three-tier system with evidence capture.
  if (result.status === "verified") {
    entry.tier = 3; entry.tierLabel = "confirmed"; entry.verificationStatus = "confirmed"; entry.confidence = 95;
    entry.evidence = {
      request: result.request || result.payload || null,
      response: String(result.evidence || result.reason || "").slice(0, 500),
      proof: result.reason || "Active verification confirmed the issue",
      technique: result.technique || ((entry.finding.category || "") + " active test"),
      timestamp: Date.now()
    };
  } else if (result.status === "likely") {
    entry.tier = 2; entry.tierLabel = "validated"; entry.verificationStatus = "validated"; entry.confidence = 65;
  } else if (result.status === "false_positive" || result.status === "filtered") {
    entry.verificationStatus = "false_positive"; entry.tier = 1; entry.tierLabel = "detected";
    try { learnFalsePositive(entry.finding, entry.url); } catch {}
  } else {
    // unchanged — stays whatever tier it was (usually tier 1 detected)
    entry.verificationStatus = entry.verificationStatus || "detected";
  }
  entry.verifyResult = result;
  entry.verifiedAt = Date.now();
  scheduleFlush();
  dbg("🔬 VERIFY", entry.finding.type, "→", result.status, result.reason);


  return result;
}

// Fix 5: Batch verify — verify top N by severity, deduped by injection point
const VERIFIABLE_CATS = new Set(["xss", "sqli", "command-injection", "ssrf", "csrf", "security-headers", "cookie-security", "open-redirect", "info-disclosure", "crlf", "path-traversal", "nosqli"]);
async function verifyBatch(maxCount) {
  if (G.safeMode) return { status: "blocked", reason: "Safe mode", results: [] };
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const all = [];
  for (const d in G.findings) for (const e of G.findings[d]) all.push({ ...e, _domain: d });
  all.sort((a, b) => (sevOrder[a.finding?.severity] || 5) - (sevOrder[b.finding?.severity] || 5));
  const seen = new Set();
  const queue = [];
  for (const e of all) {
    if (e.verificationStatus !== "detected") continue;
    const cat = (e.finding?.category || "").toLowerCase();
    if (!VERIFIABLE_CATS.has(cat)) continue;
    const dk = vfDedupKey(e);
    if (seen.has(dk)) continue;
    seen.add(dk);
    if (!vfInScope(e.url)) continue;
    queue.push(e);
    if (queue.length >= (maxCount || 20)) break;
  }
  const results = [];
  for (const e of queue) {
    const r = await verifyFinding(e._domain, e.hash);
    results.push({ type: e.finding.type, hash: e.hash, domain: e._domain, ...r });
  }
  return { status: "done", total: queue.length, results };
}

// Fix 2: XSS Reflected — tries HTML context, attribute context, and JS context payloads
async function vfXSSReflected(entry) {
  const param = vfExtractParam(entry, [/^q$/i, /^search$/i, /^name$/i, /^query$/i, /^input$/i, /^val/i, /^text/i, /^msg/i, /^data/i]);
  if (!param) return { status: "error", reason: "No param found in URL" };
  const canary = "bhp" + Math.random().toString(36).slice(2, 8);

  // Phase 1: Probe which chars survive
  const probeStr = canary + '<">\'`;';
  const url1 = new URL(entry.url); url1.searchParams.set(param, probeStr);
  const resp1 = await fetchWithHeaders(url1.toString(), { redirect: "follow" });
  const body1 = await resp1.text();
  if (!body1.includes(canary)) return { status: "false_positive", reason: `Canary not reflected via "${param}"` };

  // Check each char independently — they may not be contiguous after encoding
  const ci1 = body1.indexOf(canary);
  const afterCanary = body1.slice(ci1 + canary.length, ci1 + canary.length + 60);
  const ltOk = afterCanary.includes("<");
  const dqOk = afterCanary.includes('"');
  const sqOk = afterCanary.includes("'");
  const survived = (ltOk ? "<" : "") + (dqOk ? '"' : "") + (sqOk ? "'" : "");

  // Detect reflection context
  const ci = body1.indexOf(canary);
  const before60 = body1.slice(Math.max(0, ci - 80), ci);
  const inAttr = /=\s*["']?[^"']*$/.test(before60);
  const inScript = /<script[^>]*>[^<]*$/.test(before60);

  // Phase 2: Try payloads by context
  const payloads = [];

  if (ltOk) {
    payloads.push({ p: `${canary}<img src=x onerror=alert(1)>`, d: "HTML img tag" });
    payloads.push({ p: `${canary}<svg/onload=alert(1)>`, d: "HTML svg tag" });
  }
  if (dqOk && inAttr) {
    payloads.push({ p: `${canary}" onfocus=alert(1) autofocus="`, d: "Attribute breakout (dquote)" });
    payloads.push({ p: `${canary}" onmouseover=alert(1) x="`, d: "Attribute event (dquote)" });
  }
  if (sqOk && inAttr) {
    payloads.push({ p: `${canary}' onfocus=alert(1) autofocus='`, d: "Attribute breakout (squote)" });
  }
  if (inScript) {
    payloads.push({ p: `${canary}';alert(1)//`, d: "JS breakout (squote)" });
    payloads.push({ p: `${canary}";alert(1)//`, d: "JS breakout (dquote)" });
    payloads.push({ p: `${canary}</script><img src=x onerror=alert(1)>`, d: "Script tag escape" });
  }
  if (!ltOk && dqOk) {
    payloads.push({ p: `${canary}" onfocus=alert(1) autofocus="`, d: "Attr injection (no angle brackets needed)" });
  }
  if (!ltOk && sqOk) {
    payloads.push({ p: `${canary}' onfocus=alert(1) autofocus='`, d: "Attr injection squote" });
  }

  for (const { p, d } of payloads) {
    const url2 = new URL(entry.url); url2.searchParams.set(param, p);
    const resp2 = await fetchWithHeaders(url2.toString(), { redirect: "follow" });
    const body2 = await resp2.text();
    if (body2.includes(p)) {
      return { status: "verified", reason: `XSS via ${d} on "${param}"`, payload: p,
        evidence: body2.slice(Math.max(0, body2.indexOf(canary) - 30), body2.indexOf(canary) + 80) };
    }
  }

  if (ltOk) return { status: "likely", reason: `< reflected unencoded via "${param}" — XSS likely with payload tuning`, evidence: `Survived: ${survived}` };
  if (dqOk || sqOk) return { status: "likely", reason: `Quote chars reflected via "${param}" in ${inAttr ? "attribute" : "body"} context`, evidence: `Survived: ${survived}, context: ${inAttr ? "attribute" : inScript ? "script" : "body"}` };
  return { status: "filtered", reason: `Canary reflected but dangerous chars encoded (survived: "${survived || "none"}")` };
}

// Fix 4: DOM XSS verification via tab execution
async function vfXSSDom(entry) {
  const canary = "__bhp_domxss_" + Math.random().toString(36).slice(2, 8);
  const url = new URL(entry.url);
  // Try hash-based injection
  url.hash = canary;
  try {
    const tab = await chrome.tabs.create({ url: url.toString(), active: false });
    await new Promise(resolve => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      const listener = (tabId, info) => { if (tabId === tab.id && info.status === "complete") { chrome.tabs.onUpdated.removeListener(listener); finish(); } };
      chrome.tabs.onUpdated.addListener(listener);
      setTimeout(() => { chrome.tabs.onUpdated.removeListener(listener); finish(); }, 8000);
    });
    await new Promise(r => setTimeout(r, 1000));
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (c) => {
        const html = document.documentElement.innerHTML;
        const inDom = html.includes(c);
        const scripts = [...document.querySelectorAll("script:not([src])")].map(s => s.textContent).join("\n");
        const sources = [/location\.hash/, /location\.search/, /location\.href/, /document\.URL/];
        const sinks = [/\.innerHTML\s*=/, /document\.write/, /eval\s*\(/, /\.insertAdjacentHTML/];
        const hasSource = sources.some(p => p.test(scripts));
        const hasSink = sinks.some(p => p.test(scripts));
        return { inDom, hasSource, hasSink, scriptLen: scripts.length };
      },
      args: [canary]
    });
    try { await chrome.tabs.remove(tab.id); } catch {}
    const r = results?.[0]?.result;
    if (r?.inDom && r?.hasSource && r?.hasSink) {
      return { status: "verified", reason: "DOM XSS — hash canary injected into DOM via source→sink flow",
        evidence: `Source+sink in ${r.scriptLen} chars of inline JS, canary reached DOM` };
    }
    if (r?.hasSource && r?.hasSink) {
      return { status: "likely", reason: "DOM source→sink flow exists, canary not directly injected but flow is present",
        evidence: `Source+sink found in inline scripts` };
    }
    if (r?.inDom) {
      return { status: "likely", reason: "Hash canary appeared in DOM — potential DOM XSS",
        evidence: "Canary reached innerHTML/DOM" };
    }
  } catch (e) { return { status: "error", reason: "Tab-based DOM check failed: " + e.message }; }
  return { status: "filtered", reason: "No DOM source→sink flow detected" };
}

async function vfSQLi(entry) {
  const param = vfExtractParam(entry, [/^id$/i, /^uid$/i, /^user_?id/i, /^search/i, /^q$/i, /^query/i, /^filter/i, /^order/i, /^sort/i]);
  if (!param) return { status: "error", reason: "No injectable param found in URL" };
  const orig = new URL(entry.url).searchParams.get(param) || "1";
  const tu = new URL(entry.url); tu.searchParams.set(param, orig + " AND 1=1");
  const fu = new URL(entry.url); fu.searchParams.set(param, orig + " AND 1=2");
  const [tr, fr] = await Promise.all([fetchWithHeaders(tu.toString()).then(r => r.text()), fetchWithHeaders(fu.toString()).then(r => r.text())]);
  const diff = Math.abs(tr.length - fr.length);
  const eu = new URL(entry.url); eu.searchParams.set(param, orig + "'");
  const er = await fetchWithHeaders(eu.toString()).then(r => r.text());
  const sqlErr = /SQL syntax|mysql_fetch|pg_query|ORA-\d{5}|SQLSTATE|sqlite3?\.OperationalError|unterminated|near ".*"/i;
  if (sqlErr.test(er)) return { status: "verified", reason: `SQL error via single quote on "${param}"`, payload: orig + "'", evidence: (er.match(sqlErr) || [""])[0] };
  if (diff > 50) return { status: "verified", reason: `Boolean blind SQLi — AND 1=1 vs 1=2 diff: ${diff} chars`, payload: `${param}=${orig} AND 1=1`, evidence: `True: ${tr.length}, False: ${fr.length}` };
  if (diff > 10) return { status: "likely", reason: `Possible blind SQLi — ${diff} char diff`, evidence: `True: ${tr.length}, False: ${fr.length}` };
  return { status: "filtered", reason: "No SQL error or boolean difference" };
}

async function vfCMDi(entry) {
  const param = vfExtractParam(entry, [/^cmd$/i, /^exec/i, /^host$/i, /^ping$/i, /^ip$/i, /^command/i, /^shell/i, /^run$/i, /^domain$/i, /^timeout/i, /^address/i]);
  if (!param) return { status: "error", reason: "No injectable param found in URL" };
  const orig = new URL(entry.url).searchParams.get(param) || "";
  const canary = "bhpv" + Math.random().toString(36).slice(2, 8);
  const payloads = [
    { p: `${orig};echo ${canary}`, d: "semicolon" },
    { p: `${orig}|echo ${canary}`, d: "pipe" },
    { p: `${orig}\`echo ${canary}\``, d: "backtick" },
    { p: `${orig}$(echo ${canary})`, d: "subshell" },
  ];
  for (const { p, d } of payloads) {
    const tu = new URL(entry.url); tu.searchParams.set(param, p);
    const r = await fetchWithHeaders(tu.toString()).then(r => r.text());
    if (r.includes(canary)) return { status: "verified", reason: `CMDi confirmed via ${d} on "${param}"`, payload: p, evidence: `Canary "${canary}" in response` };
  }
  const t0 = Date.now();
  const su = new URL(entry.url); su.searchParams.set(param, `${orig};sleep 3`);
  await fetchWithHeaders(su.toString());
  const elapsed = Date.now() - t0;
  if (elapsed > 2500) return { status: "likely", reason: `Time-based CMDi — sleep 3 → ${elapsed}ms`, payload: `${orig};sleep 3`, evidence: `${elapsed}ms response` };
  return { status: "filtered", reason: "No command output or timing diff" };
}

// Fix 6: SSRF skips params already confirmed as CMDi
async function vfSSRF(entry) {
  const param = vfExtractParam(entry, [/^url$/i, /^uri$/i, /^src$/i, /^source$/i, /^dest/i, /^redirect/i, /^target$/i, /^link$/i, /^fetch$/i, /^load$/i, /^endpoint/i]);
  if (!param) return { status: "error", reason: "No SSRF param found in URL" };
  const origResp = await fetchWithHeaders(entry.url).then(r => r.text());
  const tu = new URL(entry.url); tu.searchParams.set(param, "http://127.0.0.1:80");
  const ssrfResp = await fetchWithHeaders(tu.toString()).then(r => r.text());
  if (ssrfResp !== origResp && ssrfResp.length > 100) return { status: "likely", reason: `SSRF — response differs for 127.0.0.1 via "${param}"`, evidence: `Orig: ${origResp.length}, SSRF: ${ssrfResp.length}` };
  return { status: "filtered", reason: "No observable SSRF" };
}

async function vfCSRF(entry) {
  const r = await fetchWithHeaders(entry.url).then(r => r.text());
  const hasToken = /csrf|_token|authenticity_token|__RequestVerificationToken|csrfmiddlewaretoken/i.test(r);
  const hasSameSite = /samesite\s*=\s*(strict|lax)/i.test(r);
  const hasForm = /<form[^>]*method\s*=\s*["']?post/i.test(r);
  if (hasForm && !hasToken && !hasSameSite) return { status: "verified", reason: "POST form without CSRF token or SameSite cookie", evidence: "No csrf input, no SameSite" };
  if (hasForm && !hasToken && hasSameSite) return { status: "likely", reason: "No CSRF token but SameSite cookie may mitigate", evidence: "SameSite present" };
  if (hasForm && hasToken) return { status: "false_positive", reason: "CSRF token present" };
  return { status: "filtered", reason: "No POST form found" };
}

async function vfHeaders(entry) {
  const r = await fetchWithHeaders(entry.url, { method: "HEAD" });
  const h = {}; r.headers.forEach((v, k) => { h[k] = v; });
  const issues = [];
  if (!h["strict-transport-security"]) issues.push("No HSTS");
  if (!h["content-security-policy"]) issues.push("No CSP");
  if (!h["x-frame-options"] && !(h["content-security-policy"] || "").includes("frame-ancestors")) issues.push("No clickjacking protection");
  const sc = h["set-cookie"] || "";
  if (sc && !/httponly/i.test(sc) && /session|token|auth/i.test(sc)) issues.push("Cookie without HttpOnly");
  if (issues.length > 0) return { status: "verified", reason: issues.join(", "), evidence: JSON.stringify(h, null, 2).slice(0, 300) };
  return { status: "false_positive", reason: "Headers OK on re-check" };
}

async function vfSecrets(entry) {
  const r = await fetchWithHeaders(entry.url).then(r => r.text());
  const pats = [
    { p: /AKIA[0-9A-Z]{16}/, n: "AWS Key" },
    { p: /ghp_[A-Za-z0-9_]{36}/, n: "GitHub Token" },
    { p: /sk-[A-Za-z0-9]{48}/, n: "API Key" },
    { p: /-----BEGIN.*PRIVATE KEY-----/, n: "Private Key" },
    { p: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i, n: "Hardcoded Password" },
  ];
  for (const { p, n } of pats) { const m = r.match(p); if (m) return { status: "verified", reason: `${n} found`, evidence: m[0].slice(0, 20) + "..." }; }
  return { status: "false_positive", reason: "Secret no longer found" };
}

async function vfOpenRedirect(entry) {
  const param = vfExtractParam(entry, [/^redirect/i, /^return/i, /^next$/i, /^url$/i, /^to$/i, /^target$/i, /^dest/i, /^goto$/i]);
  if (!param) return { status: "error", reason: "Cannot identify redirect param" };
  const tu = new URL(entry.url); tu.searchParams.set(param, "https://evil.com");
  const r = await fetchWithHeaders(tu.toString(), { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  if (loc.includes("evil.com")) return { status: "verified", reason: `Redirect to evil.com via "${param}"`, payload: tu.toString(), evidence: `Location: ${loc}` };
  return { status: "filtered", reason: "Redirect blocked" };
}

// New verifiers for previously unsupported categories
async function vfCRLF(entry) {
  const param = vfExtractParam(entry);
  if (!param) return { status: "error", reason: "No param found" };
  const tu = new URL(entry.url); tu.searchParams.set(param, "test%0d%0aInjected-Header:true");
  const r = await fetchWithHeaders(tu.toString(), { redirect: "manual" });
  const injH = r.headers.get("injected-header");
  if (injH) return { status: "verified", reason: `CRLF injection — custom header injected via "${param}"`, payload: "test%0d%0aInjected-Header:true", evidence: `Injected-Header: ${injH}` };
  const body = await r.text();
  if (body.includes("Injected-Header:true")) return { status: "likely", reason: "CRLF payload reflected in body", evidence: "Header text in response body" };
  return { status: "filtered", reason: "CRLF injection not confirmed" };
}

async function vfPathTraversal(entry) {
  const param = vfExtractParam(entry, [/^file/i, /^path/i, /^page/i, /^doc/i, /^template/i, /^include/i, /^dir/i]);
  if (!param) return { status: "error", reason: "No param found" };
  const tu = new URL(entry.url); tu.searchParams.set(param, "....//....//....//etc/passwd");
  const r = await fetchWithHeaders(tu.toString()).then(r => r.text());
  if (/root:x:0:0:/.test(r)) return { status: "verified", reason: `Path traversal — /etc/passwd read via "${param}"`, payload: "....//....//....//etc/passwd", evidence: "root:x:0:0: in response" };
  const tu2 = new URL(entry.url); tu2.searchParams.set(param, "..\\..\\..\\..\\windows\\win.ini");
  const r2 = await fetchWithHeaders(tu2.toString()).then(r => r.text());
  if (/\[fonts\]|\[extensions\]/i.test(r2)) return { status: "verified", reason: "Path traversal — win.ini read", evidence: "[fonts] in response" };
  return { status: "filtered", reason: "No path traversal confirmed" };
}

async function vfNoSQLi(entry) {
  const param = vfExtractParam(entry, [/^id$/i, /^user/i, /^search/i, /^q$/i, /^query/i, /^filter/i, /^name/i]);
  if (!param) return { status: "error", reason: "No param found" };
  const orig = new URL(entry.url).searchParams.get(param) || "test";
  // Operator injection: try [$ne]=
  const tu = new URL(entry.url);
  tu.searchParams.delete(param);
  tu.searchParams.set(param + "[$ne]", "impossible_value_xyz");
  const r1 = await fetchWithHeaders(tu.toString()).then(r => r.text());
  const origResp = await fetchWithHeaders(entry.url).then(r => r.text());
  const diff = Math.abs(r1.length - origResp.length);
  if (diff > 30) return { status: "likely", reason: `NoSQLi — [$ne] operator changed response by ${diff} chars`, evidence: `Orig: ${origResp.length}, [$ne]: ${r1.length}` };
  return { status: "filtered", reason: "No NoSQLi behavior detected" };
}

// ══════════════════════════════════════════════════════════════════
// BUG CHAINING ENGINE (#20) — Automatic chain detection
// ══════════════════════════════════════════════════════════════════

const CHAIN_RULES = [
  { needs: ["xss", "security-headers"], check: (xss, hdr) => hdr.some(h => h.finding.type.includes("No HttpOnly") || h.finding.type.includes("Cookie")),
    title: "XSS → Session Hijacking", severity: "critical",
    detail: "XSS + missing HttpOnly = steal session cookies via document.cookie",
    steps: "1. Trigger XSS payload\n2. Exfiltrate document.cookie to attacker server\n3. Replay session cookie for account takeover" },
  { needs: ["xss", "cors"], check: () => true,
    title: "XSS + CORS → Cross-Origin Data Theft", severity: "critical",
    detail: "XSS on trusted origin + permissive CORS = read data from other origins",
    steps: "1. Trigger XSS on the allowed origin\n2. fetch() cross-origin API with credentials\n3. Exfiltrate response data" },
  { needs: ["open-redirect", "auth-bypass"], check: () => true,
    title: "Open Redirect → OAuth Token Theft", severity: "critical",
    detail: "Redirect + OAuth flow = steal authorization code or token",
    steps: "1. Set redirect_uri to your server via open redirect\n2. Victim clicks OAuth link\n3. Auth code/token lands on your server\n4. Exchange code for access token" },
  { needs: ["ssrf", "security-headers"], check: (ssrf) => ssrf.some(s => /cloud|metadata|AWS|GCP|Azure/i.test(s.finding.suggestion || "")),
    title: "SSRF → Cloud Metadata → RCE", severity: "critical",
    detail: "SSRF to cloud metadata endpoint can yield IAM credentials",
    steps: "1. SSRF to http://169.254.169.254/latest/meta-data/iam/security-credentials/\n2. Extract temporary AWS credentials\n3. Use credentials for S3 access, Lambda execution, or EC2 control" },
  { needs: ["sqli"], check: (sqli) => sqli.some(s => /Login|auth bypass/i.test(s.finding.type)),
    title: "SQLi Login Bypass → Admin Access", severity: "critical",
    detail: "SQL injection on login form bypasses authentication entirely",
    steps: "1. Use ' OR 1=1-- in username field\n2. Gain admin access\n3. Explore admin panel for further vulns (file upload, command exec)" },
  { needs: ["xss", "business-logic"], check: (xss, biz) => biz.some(b => /CSRF|2FA|email/i.test(b.finding.type)),
    title: "XSS + Self-XSS → CSRF Chain", severity: "high",
    detail: "Self-XSS or reflected XSS can be chained with CSRF to force victim to trigger payload",
    steps: "1. Craft CSRF form that submits XSS payload to stored field\n2. Victim visits attacker page → form auto-submits\n3. XSS triggers on victim's next page load" },
  { needs: ["upload-bypass"], check: () => true,
    title: "File Upload → RCE", severity: "critical",
    detail: "Unrestricted file upload can lead to web shell execution",
    steps: "1. Upload .php/.jsp/.aspx web shell with bypass technique\n2. Access uploaded file via URL\n3. Execute OS commands via web shell" },
  { needs: ["open-redirect", "ssrf"], check: () => true,
    title: "Open Redirect → SSRF Bypass", severity: "high",
    detail: "Use open redirect as SSRF hop to bypass allowlists",
    steps: "1. SSRF param → open redirect URL on same domain\n2. Open redirect → http://169.254.169.254/...\n3. Bypasses domain allowlist that trusts same domain" },
];

function chainFindings(domain) {
  const entries = G.findings[domain] || [];
  if (entries.length < 2) return [];
  const byCat = {};
  for (const e of entries) {
    const cat = e.finding?.category || "other";
    (byCat[cat] = byCat[cat] || []).push(e);
  }
  const chains = [];
  for (const rule of CHAIN_RULES) {
    const groups = rule.needs.map(cat => byCat[cat] || []);
    if (groups.every(g => g.length > 0)) {
      if (!rule.check || rule.check(...groups)) {
        chains.push({
          title: rule.title,
          severity: rule.severity,
          detail: rule.detail,
          steps: rule.steps,
          components: rule.needs.map(cat => ({
            category: cat,
            count: (byCat[cat] || []).length,
            sample: (byCat[cat] || [])[0]?.finding?.type || cat
          }))
        });
      }
    }
  }
  return chains;
}




// Schedule pattern cleanup every 24 hours
let patternCleanupTimer = null;
function schedulePatternCleanup() {
  if (patternCleanupTimer) clearTimeout(patternCleanupTimer);
  patternCleanupTimer = setTimeout(() => { patternCleanup(); schedulePatternCleanup(); }, 24 * 60 * 60 * 1000);
}







// ── Keyboard shortcuts ──
chrome.commands.onCommand.addListener((command) => {
  if (command === "quick-scan") {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) chrome.tabs.sendMessage(tabs[0].id, { type: "REQUEST_SCAN" }).catch(() => {});
    });
  } else if (command === "open-dashboard") {
    chrome.tabs.create({ url: chrome.runtime.getURL("src/dashboard.html") });
  }
});

// Note: updateBadge() is defined once, earlier in this file (per-tab, current-domain
// count colored by worst severity, with a paused indicator). A second definition used
// to live here and silently overrode it via hoisting — removed.

// ═══ FREE BUILD STUBS ═══
// Free tier: Pro is locked. isProFeature must return FALSE so Pro gates return a
// clean upgrade prompt (proFeatureBlocked) instead of appearing unlocked then erroring.
function isProFeature(){ return false; }
function proFeatureBlocked(){ return {action:'PRO_FEATURE_BLOCKED',msg:'Upgrade to YANSII Pro'}; }
function validateLicense(){ return Promise.resolve({valid:false}); }
function getLicenseStatus(){ return Promise.resolve({tier:'free',valid:false}); }
function handleAIRequest(){ return Promise.resolve({error:'Pro feature'}); }
function analyzePmWithAI(){ return Promise.resolve(null); }
function buildProfessionalReport(){ return Promise.resolve(''); }
function computeAuthDiff(){ return {}; }
function autoAIAnalyze(){}
function aiVerifyFinding(){ return Promise.resolve({error:'Pro feature'}); }
function buildInvestigationPackage(){ return Promise.resolve({}); }
function buildAllUnconfirmedPackage(){ return Promise.resolve({}); }
function captureJSFiles(){}
function testGraphQLEndpoint(){ return Promise.resolve(null); }
function buildCurlCommand(){ return ''; }
function processAiAnalysisQueue(){}
function exportCSV(){ return ''; }
function exportSARIF(){ return '{}'; }
function exportCurlAll(){ return ''; }
function exportPocHtml(){ return ''; }
function replayRequest(){ return Promise.resolve(null); }
function replayModified(){ return Promise.resolve(null); }
function diffResponses(){ return {}; }
function extractPattern(){ return null; }
function patternFeedback(){}
function runRoleComparison(){ return Promise.resolve({}); }
function runParamDiscovery(){ return Promise.resolve({}); }
function buildAttackSurface(){ return Promise.resolve({}); }
function handleCopilotContext(){}
function handleCopilotAsk(){ return Promise.resolve({error:'Pro feature'}); }
function analyzeJSWithAI(){ return Promise.resolve(null); }
function analyzeRequestsWithAI(){ return Promise.resolve(null); }
function aiVerificationAssist(){ return Promise.resolve(null); }
function testGraphQLAuth(){ return Promise.resolve(null); }
function analyzeGraphQLSchema(){ return Promise.resolve(null); }
function buildPmPrompt(){ return ''; }
function activateLicense(){ return Promise.resolve({success:false}); }
function deactivateLicense(){ return Promise.resolve({success:false}); }
function getFingerprint(){ return Promise.resolve('free'); }
const BUILTIN_PERSONAS = [];
function getActivePersonaPrompt(){ return ''; }
function findFindingByHash(){ return null; }
function initPatternMemory(){}
function schedulePatternCleanup(){}
function matchPatterns(){ return []; }
const MINED_PATTERN_LIBRARY = [];
const ANTI_PATTERNS = [];
