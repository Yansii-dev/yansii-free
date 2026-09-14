// injected.js — MAIN world hooks for postMessage and traffic interception

(function () {
  "use strict";
  // Double-injection guard. Kept non-enumerable so it doesn't show up in a page's
  // Object.keys(window)/for-in fingerprint sweep. (Fully hiding a MAIN-world hooking
  // extension from a determined fingerprinter isn't achievable in JS — the wrapped
  // natives are inherently detectable; this only removes the trivial named signal.)
  if (window.__pmmHooked) return;
  try { Object.defineProperty(window, "__pmmHooked", { value: true, enumerable: false, configurable: true, writable: false }); }
  catch (e) { window.__pmmHooked = true; }

  const registry = [];
  const REGISTRY_CAP = 500;
  const trafficLog = [];
  const TRAFFIC_CAP = 200;

  // --- resolve parent page URL (for iframe context) ---
  var parentUrl = null;
  try {
    if (window.top !== window.self) {
      try { parentUrl = window.top.location.href; }
      catch (e) { parentUrl = document.referrer || "[cross-origin parent]"; }
    }
  } catch (e) {}

  // --- static pre-filter ---
  var SINKS = [
    ["innerHTML", /\.innerHTML\s*=/],
    ["outerHTML", /\.outerHTML\s*=/],
    ["insertAdjacentHTML", /insertAdjacentHTML\s*\(/],
    ["document.write", /document\s*\.\s*write(ln)?\s*\(/],
    ["eval", /\beval\s*\(/],
    ["Function", /\bFunction\s*\(/],
    ["setTimeout(string)", /set(Timeout|Interval)\s*\(\s*['"`]/],
    ["location", /\blocation\s*(\.\s*(href|assign|replace)\s*)?=/],
    ["el.src", /\.src\s*=/],
    ["jQuery.html", /\.html\s*\(/],
    ["postMessage", /\.postMessage\s*\(/],
    ["localStorage", /(local|session)Storage\s*\.\s*setItem/],
    ["document.cookie", /document\s*\.\s*cookie\s*=/],
    ["appendChild", /appendChild\s*\(/]
  ];

  function analyze(src) {
    var originRef = /\borigin\b/.test(src);
    var sourceRef = /\bsource\b/.test(src);
    var originCompared =
      /origin\s*(===|!==|==|!=)/.test(src) ||
      /origin\s*\)?\.(indexOf|includes|startsWith|endsWith|match|test)/.test(src) ||
      /\.(test|match)\s*\([^)]*origin/.test(src);
    var sinks = SINKS.filter(function(s) { return s[1].test(src); }).map(function(s) { return s[0]; });
    return { originRef: originRef, sourceRef: sourceRef, originCompared: originCompared, sinks: sinks };
  }

  function emit(source, kind) {
    var src = "";
    try { src = typeof source === "function" ? source.toString() : String(source); }
    catch (e) { src = "[unstringifiable handler]"; }

    var stack = "";
    try { stack = new Error().stack || ""; } catch (e) {}

    var record = {
      id: registry.length + 1,
      frameUrl: location.href,
      parentUrl: parentUrl,
      isTop: window.top === window.self,
      kind: kind,
      source: src.slice(0, 6000),
      stack: stack.split("\n").slice(1, 6).join("\n"),
      analysis: analyze(src),
      capturedAt: Date.now()
    };
    if (registry.length >= REGISTRY_CAP) registry.splice(0, 100);
    registry.push(record);

    try {
      window.dispatchEvent(new CustomEvent("__pmm_listener", { detail: JSON.stringify(record) }));
    } catch (e) {}
  }

  // --- live postMessage traffic capture ---
  function logTraffic(direction, data, origin, targetOrigin) {
    if (trafficLog.length >= TRAFFIC_CAP) return;
    var preview = "";
    try { preview = JSON.stringify(data).slice(0, 500); }
    catch (e) { try { preview = String(data).slice(0, 500); } catch(e2) { preview = "[unserializable]"; } }

    var entry = {
      direction: direction,
      preview: preview,
      origin: origin || null,
      targetOrigin: targetOrigin || null,
      frameUrl: location.href,
      parentUrl: parentUrl,
      timestamp: Date.now()
    };
    trafficLog.push(entry);
    try {
      window.dispatchEvent(new CustomEvent("__pmm_traffic", { detail: JSON.stringify(entry) }));
    } catch (e) {}
  }

  // Hook window.postMessage → capture OUTGOING messages
  try {
    var origPost = window.postMessage.bind(window);
    window.postMessage = function (data, targetOrigin) {
      try { logTraffic("out", data, location.origin, targetOrigin); } catch (e) {}
      // Forward the exact original arguments so we never mangle either the classic
      // (message, targetOrigin, transfer) or the modern (message, options) signature.
      return origPost.apply(window, arguments);
    };
  } catch (e) {}

  // Capture INCOMING messages (passive, capture-phase → runs first)
  try {
    window.addEventListener("message", function (e) {
      try { logTraffic("in", e.data, e.origin, null); } catch (e2) {}
    }, true);
  } catch (e) {}

  // Re-emit listeners on demand
  window.addEventListener("__pmm_collect", function () {
    for (var i = 0; i < registry.length; i++) {
      try { window.dispatchEvent(new CustomEvent("__pmm_listener", { detail: JSON.stringify(registry[i]) })); }
      catch (e) {}
    }
  });

  // Re-emit traffic on demand
  window.addEventListener("__pmm_collect_traffic", function () {
    for (var i = 0; i < trafficLog.length; i++) {
      try { window.dispatchEvent(new CustomEvent("__pmm_traffic", { detail: JSON.stringify(trafficLog[i]) })); }
      catch (e) {}
    }
  });

  // --- hook addEventListener ---
  var proto = EventTarget.prototype;
  var origProtoAdd = proto.addEventListener;

  proto.addEventListener = function (type, listener, opts) {
    try {
      if (type === "message" && (this === window || this === self)) emit(listener, "addEventListener");
    } catch (e) {}
    return origProtoAdd.call(this, type, listener, opts);
  };

  // --- hook window.onmessage setter ---
  try {
    var desc = Object.getOwnPropertyDescriptor(window, "onmessage") ||
               Object.getOwnPropertyDescriptor(Window.prototype, "onmessage");
    Object.defineProperty(window, "onmessage", {
      configurable: true,
      enumerable: true,
      get: function() { return desc && desc.get ? desc.get.call(window) : this.__pmm_onmessage; },
      set: function(fn) {
        try { if (fn) emit(fn, "onmessage"); } catch (e) {}
        if (desc && desc.set) desc.set.call(window, fn); else this.__pmm_onmessage = fn;
      }
    });
  } catch (e) {}

  // --- hook location sinks (href, assign, replace) ---
  // When our verification payload reaches location.href, the page navigates
  // and bridge.js may be detached before the canary event fires.
  // By hooking the setter, we detect our payload BEFORE navigation starts.
  function checkLocationSink(v) {
    if (typeof v !== "string") return;
    // Check for our canary verify ID embedded in the URL
    var m = v.match(/detail:'([^']+)'/);
    if (m) {
      try {
        window.dispatchEvent(new CustomEvent("__pmm_xss_ok", { detail: m[1] }));
      } catch (e) {}
    }
    // Also detect any javascript: URI reaching a location sink (generic)
    if (/^javascript:/i.test(v)) {
      // extract verify ID from anywhere in the string
      var vm = v.match(/__pmm_verify_([a-z0-9]+)/);
      if (vm) {
        try {
          window.dispatchEvent(new CustomEvent("__pmm_xss_ok", { detail: vm[1] }));
        } catch (e) {}
      }
    }
  }

  // Hook location.href setter
  try {
    var hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, "href");
    if (hrefDesc && hrefDesc.set) {
      Object.defineProperty(Location.prototype, "href", {
        get: hrefDesc.get,
        set: function (v) {
          try { checkLocationSink(v); } catch (e) {}
          return hrefDesc.set.call(this, v);
        },
        configurable: true,
        enumerable: true
      });
    }
  } catch (e) {}

  // Hook location.assign and location.replace
  ["assign", "replace"].forEach(function (method) {
    try {
      var orig = Location.prototype[method];
      Location.prototype[method] = function (v) {
        try { checkLocationSink(v); } catch (e) {}
        return orig.call(this, v);
      };
    } catch (e) {}
  });
})();

// ══════════════════════════════════════════════════════════════════
// Fetch / XHR Interceptor — Response Body Capture
// ══════════════════════════════════════════════════════════════════
(function() {
  "use strict";
  var MAX_BODY = 10240;
  var BINARY_TYPES = /^(image|audio|video|font|application\/octet|application\/wasm|application\/pdf)/i;
  // Static assets are not "API traffic" — skip them so cross-origin JSON/API calls stand out.
  var NONAPI_TYPES = /text\/css|javascript/i;
  var SKIP_HOSTS = /google-analytics|googletagmanager|googleapis\.com\/analytics|facebook\.net|doubleclick\.net|hotjar\.com|clarity\.ms|sentry\.io|datadog|newrelic|cloudflare.*challenges|\/\/cdn\.(cloudflare|jsdelivr|unpkg)\./i;
  var pageOrigin = location.origin;

  function isSameOrigin(url) {
    try { return new URL(url, location.href).origin === pageOrigin; }
    catch(e) { return false; }
  }

  function headersToObj(h) {
    var o = {};
    try { if (h && h.forEach) h.forEach(function(v, k) { o[k] = v; }); }
    catch(e) {}
    return o;
  }

  function emitTraffic(eventName, data) {
    try {
      window.dispatchEvent(new CustomEvent(eventName, { detail: JSON.stringify(data) }));
    } catch(e) {}
  }

  // ── fetch() hook ──
  try {
    var origFetch = window.fetch;
    window.fetch = function(input, init) {
      var url, method, reqHeaders, reqBody;
      try {
        if (input instanceof Request) {
          url = input.url;
          method = input.method || "GET";
          reqHeaders = headersToObj(input.headers);
          reqBody = init && init.body ? String(init.body).slice(0, MAX_BODY) : null;
        } else {
          url = String(input);
          method = (init && init.method) || "GET";
          reqHeaders = init && init.headers ? (init.headers instanceof Headers ? headersToObj(init.headers) : Object.assign({}, init.headers)) : {};
          reqBody = init && init.body ? String(init.body).slice(0, MAX_BODY) : null;
        }
      } catch(e) { url = String(input); method = "GET"; reqHeaders = {}; reqBody = null; }

      // Capture cross-origin API calls too (real sites hit api.* hosts) — passive
      // observation, not active testing; only analytics/noise hosts are skipped.
      if (SKIP_HOSTS.test(url)) {
        return origFetch.apply(this, arguments);
      }

      return origFetch.apply(this, arguments).then(function(response) {
        try {
          var ct = response.headers.get("content-type") || "";
          if (BINARY_TYPES.test(ct) || NONAPI_TYPES.test(ct)) return response;
          var clone = response.clone();
          clone.text().then(function(body) {
            emitTraffic("__pmm_fetch", {
              url: url,
              method: method,
              requestHeaders: reqHeaders,
              requestBody: reqBody,
              status: response.status,
              responseHeaders: headersToObj(response.headers),
              responseBody: body.slice(0, MAX_BODY),
              timestamp: Date.now(),
              frameUrl: location.href
            });
          }).catch(function() {});
        } catch(e) {}
        return response;
      });
    };
  } catch(e) {}

  // ── XMLHttpRequest hook ──
  try {
    var OrigXHR = window.XMLHttpRequest;
    var origOpen = OrigXHR.prototype.open;
    var origSend = OrigXHR.prototype.send;
    var origSetHeader = OrigXHR.prototype.setRequestHeader;

    OrigXHR.prototype.open = function(method, url) {
      this.__pmm_method = method;
      this.__pmm_url = String(url);
      this.__pmm_headers = {};
      return origOpen.apply(this, arguments);
    };

    OrigXHR.prototype.setRequestHeader = function(name, value) {
      if (this.__pmm_headers) this.__pmm_headers[name] = value;
      return origSetHeader.apply(this, arguments);
    };

    OrigXHR.prototype.send = function(body) {
      var xhr = this;
      var xhrUrl = xhr.__pmm_url || "";
      if (!SKIP_HOSTS.test(xhrUrl)) {
        var reqBody = body ? String(body).slice(0, MAX_BODY) : null;
        xhr.addEventListener("load", function() {
          try {
            var ct = (xhr.getResponseHeader("content-type") || "");
            if (BINARY_TYPES.test(ct) || NONAPI_TYPES.test(ct)) return;
            var respHeaders = {};
            try {
              var raw = xhr.getAllResponseHeaders() || "";
              raw.split("\r\n").forEach(function(line) {
                var idx = line.indexOf(":");
                if (idx > 0) respHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
              });
            } catch(e) {}
            emitTraffic("__pmm_xhr", {
              url: xhrUrl,
              method: xhr.__pmm_method || "GET",
              requestHeaders: xhr.__pmm_headers || {},
              requestBody: reqBody,
              status: xhr.status,
              responseHeaders: respHeaders,
              responseBody: (xhr.responseText || "").slice(0, MAX_BODY),
              timestamp: Date.now(),
              frameUrl: location.href
            });
          } catch(e) {}
        });
      }
      return origSend.apply(this, arguments);
    };
  } catch(e) {}
})();

// ══════════════════════════════════════════════════════════════════
// WebSocket Traffic Capture
// ══════════════════════════════════════════════════════════════════
(function() {
  try {
    var OrigWS = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      var ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
      var wsUrl = url;

      // Log connection
      try {
        window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
          event: "connect", url: wsUrl, timestamp: Date.now(), frameUrl: location.href
        })}));
      } catch(e) {}

      // Hook onmessage
      var origOnMsg = null;
      var currentWrapped = null;
      Object.defineProperty(ws, "onmessage", {
        get: function() { return origOnMsg; },
        set: function(fn) {
          origOnMsg = fn;
          if (currentWrapped) ws.removeEventListener("message", currentWrapped);
          if (!fn) { currentWrapped = null; return; }
          currentWrapped = function(ev) {
            try {
              var preview = typeof ev.data === "string" ? ev.data.slice(0, 500) : "[binary]";
              window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
                event: "message", direction: "in", url: wsUrl, data: preview, timestamp: Date.now(), frameUrl: location.href
              })}));
            } catch(e) {}
            return fn.call(this, ev);
          };
          ws.addEventListener("message", currentWrapped);
        }
      });

      // Hook send
      var origSend = ws.send.bind(ws);
      ws.send = function(data) {
        try {
          var preview = typeof data === "string" ? data.slice(0, 500) : "[binary " + (data.byteLength||data.size||"?") + " bytes]";
          window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
            event: "message", direction: "out", url: wsUrl, data: preview, timestamp: Date.now(), frameUrl: location.href
          })}));
        } catch(e) {}
        return origSend(data);
      };

      // Hook close
      ws.addEventListener("close", function(ev) {
        try {
          window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
            event: "close", url: wsUrl, code: ev.code, reason: ev.reason, timestamp: Date.now(), frameUrl: location.href
          })}));
        } catch(e) {}
      });

      return ws;
    };
    window.WebSocket.prototype = OrigWS.prototype;
    window.WebSocket.CONNECTING = OrigWS.CONNECTING;
    window.WebSocket.OPEN = OrigWS.OPEN;
    window.WebSocket.CLOSING = OrigWS.CLOSING;
    window.WebSocket.CLOSED = OrigWS.CLOSED;

    // Also hook addEventListener("message") for WebSockets created before our hook
    var origAddEL = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, opts) {
      if (type === "message" && this instanceof OrigWS) {
        var wsRef = this;
        var wrapped = function(ev) {
          try {
            var preview = typeof ev.data === "string" ? ev.data.slice(0, 500) : "[binary]";
            window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
              event: "message", direction: "in", url: wsRef.url || "", data: preview, timestamp: Date.now(), frameUrl: location.href
            })}));
          } catch(e) {}
          return fn.call(this, ev);
        };
        return origAddEL.call(this, type, wrapped, opts);
      }
      return origAddEL.call(this, type, fn, opts);
    };
  } catch(e) {}
})();

// ══════════════════════════════════════════════════════════════════
// Socket.io Interception (Bug 8 fix)
// ══════════════════════════════════════════════════════════════════
(function() {
  try {
    var checkInterval = setInterval(function() {
      if (window.io && typeof window.io === "function" && !window.io.__bh_hooked) {
        window.io.__bh_hooked = true;
        var origIo = window.io;
        window.io = function() {
          var socket = origIo.apply(this, arguments);
          try {
            var socketUrl = arguments[0] || location.origin;
            window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
              event: "connect", url: "socket.io:" + socketUrl, timestamp: Date.now(), frameUrl: location.href
            })}));
            if (socket && socket.on) {
              var origOn = socket.on.bind(socket);
              socket.on = function(ev, fn) {
                var wrapped = function() {
                  try {
                    var data = arguments[0];
                    var preview = typeof data === "string" ? data.slice(0, 500) : JSON.stringify(data).slice(0, 500);
                    window.dispatchEvent(new CustomEvent("__pmm_ws", { detail: JSON.stringify({
                      event: "message", direction: "in", url: "socket.io:" + socketUrl, data: ev + ":" + preview,
                      timestamp: Date.now(), frameUrl: location.href
                    })}));
                  } catch(e) {}
                  return fn.apply(this, arguments);
                };
                return origOn(ev, wrapped);
              };
            }
          } catch(e) {}
          return socket;
        };
        Object.assign(window.io, origIo);
        clearInterval(checkInterval);
      }
    }, 500);
    setTimeout(function() { clearInterval(checkInterval); }, 10000);
  } catch(e) {}
})();

// ══════════════════════════════════════════════════════════════════
// Web Worker / Service Worker Message Interception
// ══════════════════════════════════════════════════════════════════
(function() {
  // Hook Worker constructor
  try {
    var OrigWorker = window.Worker;
    window.Worker = function(url, opts) {
      var w = new OrigWorker(url, opts);
      var workerUrl = typeof url === "string" ? url : url.toString();
      try {
        window.dispatchEvent(new CustomEvent("__pmm_worker", { detail: JSON.stringify({
          event: "created", type: "Worker", url: workerUrl, frameUrl: location.href, timestamp: Date.now()
        })}));
      } catch(e) {}

      // Hook postMessage to worker
      var origPost = w.postMessage.bind(w);
      w.postMessage = function(data, transfer) {
        try {
          window.dispatchEvent(new CustomEvent("__pmm_worker", { detail: JSON.stringify({
            event: "message", direction: "out", type: "Worker", url: workerUrl, data: JSON.stringify(data).slice(0, 500), frameUrl: location.href, timestamp: Date.now()
          })}));
        } catch(e) {}
        return transfer ? origPost(data, transfer) : origPost(data);
      };

      // Hook messages FROM worker
      w.addEventListener("message", function(ev) {
        try {
          window.dispatchEvent(new CustomEvent("__pmm_worker", { detail: JSON.stringify({
            event: "message", direction: "in", type: "Worker", url: workerUrl, data: JSON.stringify(ev.data).slice(0, 500), frameUrl: location.href, timestamp: Date.now()
          })}));
        } catch(e) {}
      });

      return w;
    };
    window.Worker.prototype = OrigWorker.prototype;
  } catch(e) {}

  // Hook SharedWorker
  try {
    var OrigShared = window.SharedWorker;
    if (OrigShared) {
      window.SharedWorker = function(url, opts) {
        var w = opts ? new OrigShared(url, opts) : new OrigShared(url);
        try {
          window.dispatchEvent(new CustomEvent("__pmm_worker", { detail: JSON.stringify({
            event: "created", type: "SharedWorker", url: typeof url === "string" ? url : url.toString(), frameUrl: location.href, timestamp: Date.now()
          })}));
        } catch(e) {}
        return w;
      };
      window.SharedWorker.prototype = OrigShared.prototype;
    }
  } catch(e) {}

  // Hook navigator.serviceWorker.register
  try {
    if (navigator.serviceWorker) {
      var origReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = function(url, opts) {
        try {
          window.dispatchEvent(new CustomEvent("__pmm_worker", { detail: JSON.stringify({
            event: "created", type: "ServiceWorker", url: typeof url === "string" ? url : url.toString(), frameUrl: location.href, timestamp: Date.now()
          })}));
        } catch(e) {}
        return origReg(url, opts);
      };
    }
  } catch(e) {}
})();
