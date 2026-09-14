// popup.js — settings, scope config, provider setup
const $=id=>document.getElementById(id);
// Attribute-safe HTML escaper for any dynamic value placed in innerHTML/attributes.
const esc=s=>String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
try {
  window.addEventListener("error", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "popup", error: { message: e.message, stack: e.error && e.error.stack, url: location.href } }); } catch {} });
  window.addEventListener("unhandledrejection", e => { try { chrome.runtime.sendMessage({ type: "REPORT_ERROR", source: "popup", error: { message: "Unhandled rejection: " + (e.reason && (e.reason.message || e.reason)), stack: e.reason && e.reason.stack, url: location.href } }); } catch {} });
} catch {}

// Onboarding — show welcome screen on first run
chrome.storage.local.get(["onboardingComplete"],r=>{
  if(!r.onboardingComplete){
    $("onboarding").style.display="block";
    $("mainUI").style.display="none";
  }
});
$("onboardingDone").addEventListener("click",()=>{
  chrome.storage.local.set({onboardingComplete:true});
  $("onboarding").style.display="none";
  $("mainUI").style.display="block";
});

chrome.storage.sync.get(["enabled"],d=>{
  const on=d.enabled!==false;$("masterToggle").checked=on;toggleUI(on);
});
// Build stamp — lets you confirm which build is loaded (kills "am I on the old build?")
fetch(chrome.runtime.getURL("build-info.json")).then(r=>r.json()).then(info=>{
  if($("buildStamp"))$("buildStamp").textContent=`${info.build}·${info.buildId}`;
  if($("buildIdShow"))$("buildIdShow").textContent=`${info.build} · ${info.buildId}`;
}).catch(()=>{ if($("buildStamp"))$("buildStamp").textContent="dev"; });
// Official-source verification: show the REAL runtime extension ID (a clone gets a different ID).
try { if($("extIdShow")) $("extIdShow").textContent = chrome.runtime.id || "unknown"; } catch(e){}
$("diagBtn")?.addEventListener("click",()=>{
  chrome.tabs.create({url:chrome.runtime.getURL("src/diagnostics.html")});
});
chrome.storage.sync.get(["scanPaused"],d=>{
  const paused=d.scanPaused===true;
  if($("scanPausedToggle")){$("scanPausedToggle").checked=paused;$("scanPausedText").textContent=paused?"On":"Off";}
});
$("scanPausedToggle")?.addEventListener("change",()=>{
  const paused=$("scanPausedToggle").checked;
  chrome.storage.sync.set({scanPaused:paused});
  $("scanPausedText").textContent=paused?"On":"Off";
  chrome.runtime.sendMessage({type:"SET_SCAN_PAUSED",paused});
});
chrome.storage.sync.get(["lightweightMode"],d=>{
  const on=d.lightweightMode===true;
  if($("lightweightToggle")){$("lightweightToggle").checked=on;$("lightweightText").textContent=on?"On":"Off";}
});
$("lightweightToggle")?.addEventListener("change",()=>{
  const on=$("lightweightToggle").checked;
  chrome.storage.sync.set({lightweightMode:on});
  chrome.runtime.sendMessage({type:"SET_LIGHTWEIGHT",enabled:on});
  $("lightweightText").textContent=on?"On":"Off";
});
chrome.storage.sync.get(["maxRequestsPerSec"],d=>{
  if($("maxRpsInput")&&d.maxRequestsPerSec)$("maxRpsInput").value=d.maxRequestsPerSec;
});
$("maxRpsInput")?.addEventListener("change",()=>{
  let v=parseInt($("maxRpsInput").value,10); if(isNaN(v))v=5; v=Math.max(1,Math.min(50,v)); $("maxRpsInput").value=v;
  chrome.storage.sync.set({maxRequestsPerSec:v});
  chrome.runtime.sendMessage({type:"SET_MAX_RPS",value:v});
});
// Performance stats
async function updatePerfStats(){
  if(!$("perfStats"))return;
  try{
    const bytes=await new Promise(r=>chrome.storage.local.getBytesInUse(null,r));
    const mb=(bytes/1048576).toFixed(1);
    chrome.runtime.sendMessage({type:"GET_DIAGNOSTICS"},d=>{
      if(chrome.runtime.lastError||!d)return;
      $("perfStats").textContent=`Performance: ${mb} MB used · ${d.domains} domains · ${d.totalFindings} findings`;
    });
  }catch{}
}
updatePerfStats();

// Status indicator — extension health at a glance
const SCANNER_COUNT = 46;
function updateStatusIndicator(){
  const el=$("statusIndicator"); if(!el)return;
  chrome.runtime.sendMessage({type:"GET_DIAGNOSTICS"}, d=>{
    if(chrome.runtime.lastError){el.textContent="";return;}
    chrome.storage.local.get(["apiKey","provider"], s=>{
      if(!d){el.textContent="";return;}
      const scope=(d.scope&&d.scope.length)?d.scope.join(", "):null;
      const aiOk=!!(s.apiKey&&s.provider);
      let html, color;
      if(!d.enabled){ html="⏸️ Extension disabled"; color="var(--dim,#6e7681)"; }
      else if(!scope){ html="⚠️ No scope set · scanning all domains"; color="var(--yellow,#d29922)"; }
      else { html=`✅ Active · ${SCANNER_COUNT} scanners · Scope: ${scope}`; color="var(--green,#3fb950)"; }
      el.innerHTML="Status: "+html;
      el.style.color=color;
    });
  });
}
updateStatusIndicator();

// Keep the footer pattern count accurate (pattern memory is Pro; free returns 0)
chrome.runtime.sendMessage({type:"GET_PATTERN_STATS"},r=>{
  if(chrome.runtime.lastError)return;
  if($("patternCount")) $("patternCount").textContent=((r&&r.count)||0)+" patterns";
});

// Load stats
chrome.tabs.query({active:true,currentWindow:true},tabs=>{
  if(!tabs[0])return;
  const tabId=tabs[0].id;
  // P7: these callbacks tolerate no response (a cold/busy service worker may not reply before
  // the port closes). Reading chrome.runtime.lastError marks it handled, so there is no
  // "Unchecked runtime.lastError: message port closed" console error.
  chrome.runtime.sendMessage({type:"getPmFindings",tabId},r=>{
    if(chrome.runtime.lastError||!r)return;
    $("sPm").textContent=r.findings?r.findings.length:0;
  });
  chrome.runtime.sendMessage({type:"getGlobalLog"},r=>{
    if(chrome.runtime.lastError||!r)return;
    let total=0;
    for(const d in r.globalTraffic)total+=(r.globalTraffic[d]||[]).length;
    $("sTraffic").textContent=total>999?"999+":total;
  });
  chrome.runtime.sendMessage({type:"getGlobalFindings"},r=>{
    if(chrome.runtime.lastError||!r)return;
    const findings=r.G?r.G.findings:r.globalFindings||r.findings||{};
    let total=0;
    for(const d in findings)total+=(findings[d]||[]).length;
    $("sVuln").textContent=total>999?"999+":total;
  });
});

$("masterToggle").addEventListener("change",()=>{
  const on=$("masterToggle").checked;
  chrome.storage.sync.set({enabled:on});
  chrome.runtime.sendMessage({type:"TOGGLE_EXTENSION",enabled:on});
  toggleUI(on);
});

function toggleUI(on){
  $("statusText").textContent=on?"Active":"Disabled";
  $("statusText").className="status-text "+(on?"on":"off");
  document.querySelectorAll(".section,.actions,.stats").forEach(el=>{el.style.opacity=on?"1":"0.35";el.style.pointerEvents=on?"auto":"none"});
}


// Scope management
chrome.runtime.sendMessage({type:"GET_SCOPE"},r=>{
  if(chrome.runtime.lastError)return;
  if(r&&r.scope&&r.scope.length){
    $("scopeInput").value=r.scope.join("\n");
    $("scopeStatus").textContent=`Scope: ${r.scope.length} pattern(s) active`;
    $("scopeStatus").style.color="#3fb950";
  }
  if(r&&r.safeMode){
    $("safeModeToggle").checked=true;
    $("safeModeText").textContent="On";
    $("safeModeText").style.color="#3fb950";
  }
});

$("scopeSetBtn").addEventListener("click",()=>{
  const raw=$("scopeInput").value.trim();
  if(!raw){$("scopeStatus").textContent="Enter at least one domain pattern";$("scopeStatus").style.color="#e8403a";return}
  const patterns=raw.split(/\n/).map(s=>s.trim()).filter(Boolean);
  chrome.runtime.sendMessage({type:"SET_SCOPE",scope:patterns},r=>{
    if(r&&r.ok){
      $("scopeStatus").textContent=`Scope set: ${patterns.length} pattern(s) — only in-scope domains scanned`;
      $("scopeStatus").style.color="#3fb950";
    }
  });
});

$("scopeClearBtn").addEventListener("click",()=>{
  $("scopeInput").value="";
  chrome.runtime.sendMessage({type:"SET_SCOPE",scope:[]},()=>{
    $("scopeStatus").textContent="Scope cleared — all domains allowed";
    $("scopeStatus").style.color="var(--fg2)";
  });
});

$("safeModeToggle").addEventListener("change",()=>{
  const on=$("safeModeToggle").checked;
  chrome.runtime.sendMessage({type:"SET_SAFE_MODE",enabled:on});
  $("safeModeText").textContent=on?"On":"Off";
  $("safeModeText").style.color=on?"#3fb950":"var(--fg2)";
});

// Custom headers
chrome.runtime.sendMessage({type:"GET_CUSTOM_HEADERS"},r=>{
  if(r&&r.headers&&r.headers.length){
    $("customHeaders").value=r.headers.map(h=>h.name+": "+h.value).join("\n");
    updateHeaderBadge(r.headers.length,r.enabled);
  }
  if(r&&r.enabled){
    $("headerToggle").checked=true;
    $("headerStatusText").textContent="On";
    $("headerStatusText").style.color="#3fb950";
  }
});

function parseHeaders(text){
  return text.split("\n").map(l=>l.trim()).filter(Boolean).map(l=>{
    const i=l.indexOf(":");
    if(i<1)return null;
    return{name:l.slice(0,i).trim(),value:l.slice(i+1).trim()};
  }).filter(Boolean);
}

function saveCustomHeaders(){
  const headers=parseHeaders($("customHeaders").value);
  const enabled=$("headerToggle").checked;
  chrome.runtime.sendMessage({type:"SET_CUSTOM_HEADERS",headers,enabled},r=>{
    updateHeaderBadge(headers.length,enabled);
  });
}

function updateHeaderBadge(count,enabled){
  const badge=$("headerBadge");
  if(count>0&&enabled){
    badge.textContent=count+" header"+(count>1?"s":"")+" set";
    badge.style.color="#3fb950";
  }else if(count>0){
    badge.textContent=count+" header"+(count>1?"s":"")+" (disabled)";
    badge.style.color="var(--fg2)";
  }else{
    badge.textContent="";
  }
}

// Preset buttons
$("presetAuth").addEventListener("click",()=>{
  const ta=$("customHeaders");
  ta.value=(ta.value?ta.value+"\n":"")+"Authorization: Bearer YOUR_TOKEN_HERE";
  saveCustomHeaders();
});
$("presetCookie").addEventListener("click",()=>{
  const ta=$("customHeaders");
  ta.value=(ta.value?ta.value+"\n":"")+"Cookie: session=YOUR_SESSION_ID";
  saveCustomHeaders();
});
$("presetXFF").addEventListener("click",()=>{
  const ta=$("customHeaders");
  ta.value=(ta.value?ta.value+"\n":"")+"X-Forwarded-For: 127.0.0.1";
  saveCustomHeaders();
});

// Import/Export JSON
$("exportHeaders").addEventListener("click",()=>{
  const headers=parseHeaders($("customHeaders").value);
  const blob=new Blob([JSON.stringify(headers,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;a.download="custom-headers.json";a.click();
  URL.revokeObjectURL(url);
});
$("importHeaders").addEventListener("click",()=>$("headerFileInput").click());
$("headerFileInput").addEventListener("change",(e)=>{
  const file=e.target.files[0];if(!file)return;
  const reader=new FileReader();
  reader.onload=(ev)=>{
    try{
      const headers=JSON.parse(ev.target.result);
      if(Array.isArray(headers)){
        $("customHeaders").value=headers.map(h=>h.name+": "+h.value).join("\n");
        saveCustomHeaders();
        showStatus("Imported "+headers.length+" headers","ok");
      }
    }catch(err){showStatus("Invalid JSON file","err")}
  };
  reader.readAsText(file);
});

$("customHeaders").addEventListener("change",saveCustomHeaders);
$("headerToggle").addEventListener("change",()=>{
  const on=$("headerToggle").checked;
  $("headerStatusText").textContent=on?"On":"Off";
  $("headerStatusText").style.color=on?"#3fb950":"var(--fg2)";
  saveCustomHeaders();
});



let scanListener = null;
$("scanBtn").addEventListener("click",()=>{
  showStatus("Scanning…","ok");
  if (scanListener) chrome.runtime.onMessage.removeListener(scanListener);
  chrome.runtime.sendMessage({type:"REQUEST_SCAN"});
  scanListener = function(msg){
    if(msg.type==="SCAN_RESULTS"){
      chrome.runtime.onMessage.removeListener(scanListener);
      scanListener = null;
      const s=msg.payload.summary;
      $("sVuln").textContent=s.total;
      showStatus(`${s.critical} crit · ${s.high} high · ${s.medium} med · ${s.total} total`,s.critical+s.high>0?"err":"ok");
    }
  };
  chrome.runtime.onMessage.addListener(scanListener);
});

$("xssProbeBtn").addEventListener("click",()=>{
  chrome.tabs.query({active:true,currentWindow:true},tabs=>{
    if(!tabs[0])return;
    chrome.tabs.sendMessage(tabs[0].id,{type:"XSS_PROBE"});
    showStatus("XSS probe injected into all inputs","ok");
  });
});

$("crawlBtn").addEventListener("click",()=>{
  chrome.tabs.query({active:true,currentWindow:true},tabs=>{
    if(tabs[0]){chrome.sidePanel.open({tabId:tabs[0].id});chrome.storage.session.set({openTab:"crawl"})}
  });
});

$("panelBtn").addEventListener("click",()=>{
  chrome.tabs.query({active:true,currentWindow:true},tabs=>{if(tabs[0])chrome.sidePanel.open({tabId:tabs[0].id})});
});

$("dashBtn").addEventListener("click",()=>{
  chrome.tabs.create({url:chrome.runtime.getURL("src/dashboard.html")});
});

function showStatus(t,c){const el=$("status");el.textContent=t;el.className="status "+c}


