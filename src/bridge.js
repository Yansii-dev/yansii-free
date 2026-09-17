// bridge.js — relays events between injected.js (MAIN world) and background

(function () {
  "use strict";

  // --- on/off toggle ---
  var enabled = true;
  try {
    chrome.storage.local.get("enabled", function(r) { enabled = r.enabled !== false; });
    chrome.storage.onChanged.addListener(function(changes) {
      if (changes.enabled) enabled = changes.enabled.newValue !== false;
    });
  } catch(e) {}

  // Relay captured listeners
  window.addEventListener("__pmm_listener", function (ev) {
    if (!enabled) return;
    var record;
    try { record = JSON.parse(ev.detail); } catch (e) { return; }
    try { chrome.runtime.sendMessage({ type: "listener", record: record }); } catch (e) {}
  });

  // Relay live postMessage traffic
  window.addEventListener("__pmm_traffic", function (ev) {
    if (!enabled) return;
    var entry;
    try { entry = JSON.parse(ev.detail); } catch (e) { return; }
    try { chrome.runtime.sendMessage({ type: "traffic", entry: entry }); } catch (e) {}
  });

  // XSS verification canary (event-based) — works for innerHTML/eval sinks
  window.addEventListener("__pmm_xss_ok", function (ev) {
    var detail = ev.detail || "";
    try { chrome.runtime.sendMessage({ type: "xss_confirmed", verifyId: String(detail) }); } catch (e) {}
  });

  // XSS verification (title-based) — works for location.href sinks.
  // When javascript:void(document.title='__pmm_verify_XXX')//http: executes
  // via location.href, we can't catch it via events (unforgeable property,
  // content scripts may detach during navigation). Instead, we poll
  // document.title — which IS readable from the ISOLATED world.
  var lastTitle = "";
  setInterval(function () {
    if (!enabled) return;
    try {
      var title = document.title || "";
      if (title !== lastTitle) {
        lastTitle = title;
        var m = title.match(/__pmm_verify_([a-z0-9]+)/i);
        if (m) {
          try {
            chrome.runtime.sendMessage({ type: "xss_confirmed", verifyId: m[1] });
          } catch (e) {}
          // reset title to avoid re-triggering
          try { document.title = title.replace(/__pmm_verify_[a-z0-9]+/i, ""); } catch (e) {}
        }
      }
    } catch (e) {}
  }, 250);

  // Commands from popup / dashboard
  chrome.runtime.onMessage.addListener(function (msg) {
    if (msg && msg.type === "collect") {
      try { window.dispatchEvent(new CustomEvent("__pmm_collect")); } catch (e) {}
    }
    if (msg && msg.type === "collectTraffic") {
      try { window.dispatchEvent(new CustomEvent("__pmm_collect_traffic")); } catch (e) {}
    }
  });

  // Relay Fetch/XHR API traffic
  window.addEventListener("__pmm_fetch", function(ev) {
    if (!enabled) return;
    try { chrome.runtime.sendMessage({ type: "api_traffic", entry: JSON.parse(ev.detail) }); } catch(e) {}
  });
  window.addEventListener("__pmm_xhr", function(ev) {
    if (!enabled) return;
    try { chrome.runtime.sendMessage({ type: "api_traffic", entry: JSON.parse(ev.detail) }); } catch(e) {}
  });

  // Relay WebSocket events
  window.addEventListener("__pmm_ws", function(ev) {
    if (!enabled) return;
    try { chrome.runtime.sendMessage({ type: "ws_event", entry: JSON.parse(ev.detail) }); } catch(e) {}
  });

  // Relay Worker events
  window.addEventListener("__pmm_worker", function(ev) {
    if (!enabled) return;
    try { chrome.runtime.sendMessage({ type: "worker_event", entry: JSON.parse(ev.detail) }); } catch(e) {}
  });
})();
