/* -----------------------------------------------------------------
   Bulwark Check engine (extracted from check.html)
   ----------------------------------------------------------------- */
window.BULWARK_INTEL = "https://intel.example.com";
window.BULWARK_SNAPSHOT = "data/blocklist.json";
window.BULWARK_SNAPSHOT_JS = "data/blocklist.js";

(function () {
  "use strict";
  var LANG = { en: 1, sw: 0 };
  var STR = {
    checkGo:    { en: "Check", sw: "Angalia" },
    note:       { en: "Paste an IP, a domain (with or without http://), or a full link — Bulwark extracts the host for you.", sw: "Bandika IP, mwenyeji (domain) na hata bila http://), au kiungo kizima — Bulwark itachukua mwenyeji pekee." },
    checking:   { en: "Checking…", sw: "Inaangalia…" },
    blocked:    { en: "BLOCK", sw: "HATARI" },
    caution:    { en: "CAUTION", sw: "TAHADHARI" },
    clean:      { en: "CLEAN", sw: "SALAMA" },
    onLists:    { en: "found on the live lists Bulwark keeps warm", sw: "imepatikana kwenye orodha za moja kwa moja za Bulwark" },
    noLists:    { en: "not currently on any Bulwark blocklist", sw: "haipo kwenye orodha yoyote ya Bulwark kwa sasa" },
    consensus:  { en: "strictly fleet consensus — three or more protected machines agree", sw: "makubaliano ya fleet — mashine tatu au zaidi zilindwa zinakubaliana" },
    checked:    { en: "checked", sw: "imeangaliwa" },
    tri:        { en: "Try:", sw: "Jaribu:" },
    invalid:    { en: "That doesn\u2019t look like an IP address or a domain.", sw: "Hilo halionekani kama IP au mwenyeji (domain)." },
    offline:    { en: "Checker is offline right now — the intel service is not reachable. Please try again shortly.", sw: "Cheki haipo mtandaoni sasa — huduma haifikiki. Jaribu tena baadaye kidogo." },
    rate:       { en: "Slow down — this free tier allows a limited number of checks per minute. Try again in a moment.", sw: "Polepole — upi wa bure unaruhusu idadi fulani ya angalizi kwa dakika. Jaribu tena baadaye." },
    snapshot:   { en: "bundled snapshot", sw: "snapshot iliyopakiwa" },
    sourcesHead:{ en: "Sources", sw: "Vyanzo" }
  };
  var intelBase = window.BULWARK_INTEL || "http://127.0.0.1:5599";
  var $ = function (id) { return document.getElementById(id); };
  var input = $("addrInput"), btn = $("runCheck"), verdict = $("verdict"),
      vTag = $("vTag"), vValue = $("vValue"), vSources = $("vSources"),
      vMeta = $("vMeta"), err = $("errMsg");

  function t(o) { return o[LANG.en ? "en" : "sw"]; }
  function setLang() {
    $("langEn").classList.toggle("on", LANG.en === 1);
    $("langSw").classList.toggle("on", LANG.en === 0);
    btn.textContent = t(STR.checkGo);
    $("exLabel").textContent = t(STR.tri);
    [].forEach.call(document.querySelectorAll("[data-note]"), function (el) { el.textContent = t(STR.note); });
  }
  $("langEn").addEventListener("click", function () { LANG.en = 1; setLang(); });
  $("langSw").addEventListener("click", function () { LANG.en = 0; setLang(); });

  function normalize(raw) {
    var s = (raw || "").trim();
    if (!s) return "";
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    s = s.split(/[/?#]/)[0];
    s = s.replace(/^www\./i, "");
    return s.toLowerCase();
  }
  function looksValid(s) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      var ok = s.split(".").every(function (o) { var n = +o; return n >= 0 && n <= 255; });
      return ok ? "ip" : false;
    }
    if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s)) return "domain";
    return false;
  }

  var EXAMPLES = ["8.8.8.8", "185.100.11.22", "evil.example.com", "https://docs.google.com"];
  function buildExamples() {
    var box = $("examples");
    EXAMPLES.forEach(function (v) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = v;
      b.addEventListener("click", function () { input.value = v; run(); });
      box.appendChild(b);
    });
  }

  function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

  function showVerdict(kind, value, sources, verdict, whenUtc, snapshot) {
    verdict.classList.add("show");
    vValue.textContent = value;
    var cls = verdict === "BLOCK" ? "block" : verdict === "CAUTION" ? "caution" : "clean";
    var label = verdict === "BLOCK" ? t(STR.blocked) : verdict === "CAUTION" ? t(STR.caution) : t(STR.clean);
    vTag.className = "vtag " + cls;
    vTag.textContent = label;
    vSources.innerHTML = "";
    (sources || []).forEach(function (src) {
      var span = document.createElement("span");
      span.className = "srctag" + (src === "fleet-consensus" ? " fleet" : "");
      span.textContent = src;
      vSources.appendChild(span);
    });
    var gist = verdict === "BLOCK" || verdict === "CAUTION" ? t(STR.onLists) : t(STR.noLists);
    var when = whenUtc ? new Date(whenUtc).toLocaleString() : "—";
    vMeta.textContent = gist + " · " + t(STR.checked) + " " + when + (snapshot ? " · " + t(STR.snapshot) : "");
  }

  /* --- offline fallback: match against the bundled snapshot --- */
  var SHARED = ["github.com","gitlab.com","bitbucket.org","sourceforge.net","drive.google.com",
    "docs.google.com","dropbox.com","onedrive.live.com","mega.nz","mediafire.com","sendspace.com",
    "anonfiles.com","discord.com","discordapp.net","telegram.me","t.me"];

  function ipToInt(ip) {
    var p = ip.split("."); if (p.length !== 4) return null;
    var n = 0;
    for (var i = 0; i < 4; i++) { var o = +p[i]; if (!(o >= 0 && o <= 255)) return null; n = n * 256 + o; }
    return n >>> 0;
  }
  function cidrToRange(cidr) {
    var parts = cidr.split("/"); if (parts.length !== 2) return null;
    var base = ipToInt(parts[0]), p = +parts[1];
    if (base === null || !(p >= 0 && p <= 32)) return null;
    var mask = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0;
    var start = (base & mask) >>> 0;
    return [start, (start | (~mask >>> 0)) >>> 0];
  }

  /* Load snapshot: prefer the JS file (works on file://), fall back to JSON fetch */
  var snapCache = null;
  function loadSnapshot() {
    if (snapCache) return Promise.resolve(snapCache);

    var jsUrl = window.BULWARK_SNAPSHOT_JS || "data/blocklist.js";
    var jsonUrl = window.BULWARK_SNAPSHOT || "data/blocklist.json";

    // 1) Try the JS file first (works on file:// via script injection)
    var jsPromise = new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = jsUrl;
      s.onload = function () {
        var d = window.BULWARK_BLOCKLIST;
        if (d) { cleanup(); resolve(d); }
        else { cleanup(); reject(new Error("js-empty")); }
      };
      s.onerror = function () { cleanup(); reject(new Error("js-fail")); };
      function cleanup() { s.onload = s.onerror = null; s.parentNode && s.parentNode.removeChild(s); }
      document.head.appendChild(s);
      // timeout for local files that just hang
      setTimeout(function () { cleanup(); reject(new Error("js-timeout")); }, 3000);
    });

    // 2) Fallback to JSON fetch (works on http(s))
    var jsonPromise = fetch(jsonUrl, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("json-fail"); return r.json(); });

    return Promise.race([jsPromise, jsonPromise])
      .then(function (d) {
        var nets = [], doms = [];
        Object.keys(d.nets || {}).forEach(function (src) {
          (d.nets[src] || []).forEach(function (c) { var rg = cidrToRange(c); if (rg) nets.push({ s: rg[0], e: rg[1], src: src }); });
        });
        Object.keys(d.domains || {}).forEach(function (src) {
          (d.domains[src] || []).forEach(function (h) { doms.push({ d: h, src: src }); });
        });
        var snap = { generatedUtc: d.generatedUtc, nets: nets, doms: doms };
        snapCache = snap;
        return snap;
      });
  }

  function localCheck(kind, value) {
    return loadSnapshot().then(function (snap) {
      var srcs = [];
      if (kind === "ip") {
        var n = ipToInt(value);
        snap.nets.forEach(function (r) { if (n >= r.s && n <= r.e) srcs.push(r.src); });
      } else {
        var parts = value.split(".");
        for (var i = 0; i < parts.length - 1; i++) {
          var cand = parts.slice(i).join(".");
          snap.doms.forEach(function (r) { if (r.d === cand) srcs.push(r.src); });
        }
      }
      srcs = srcs.filter(function (v, i, a) { return a.indexOf(v) === i; });
      var listed = srcs.length > 0;
      var shared = kind === "domain" && SHARED.indexOf(value) >= 0;
      return { sources: srcs, verdict: !listed ? "CLEAN" : shared ? "CAUTION" : "BLOCK", generatedUtc: snapCache.generatedUtc };
    });
  }

  function showErr(msg) { err.textContent = msg; err.style.display = "block"; }

  function run() {
    err.style.display = "none";
    var raw = normalize(input.value);
    if (!raw) { return; }
    var kind = looksValid(raw);
    if (!kind) { showErr(t(STR.invalid)); return; }
    btn.textContent = t(STR.checking);
    btn.disabled = true;
    verdict.classList.remove("show");
    var done = function () { btn.textContent = t(STR.checkGo); btn.disabled = false; };

    var live = fetch(intelBase + "/intel/check/" + encodeURIComponent(raw), {
      method: "GET",
      headers: { "Accept": "application/json" }
    }).then(function (r) {
      if (r.status === 429) throw new Error("rate");
      if (r.status === 400) throw new Error("bad");
      if (!r.ok) throw new Error("off");
      return r.json();
    });
    // don't hang the UI if the tunnel/server is asleep — fall back fast
    var raced = new Promise(function (resolve, reject) {
      var to = setTimeout(function () { reject(new Error("off")); }, 5000);
      live.then(function (d) { clearTimeout(to); resolve(d); },
                function (e) { clearTimeout(to); reject(e); });
    });

    raced.then(function (d) {
      showVerdict(kind, d.value || raw, d.sources || [], d.verdict || "CLEAN", d.checkedUtc, false);
    }).catch(function (e) {
      var msg = e && e.message;
      // engine unreachable → answer from the bundled snapshot instead
      localCheck(kind, raw).then(function (r) {
        showVerdict(kind, raw, r.sources, r.verdict, r.generatedUtc, true);
      }).catch(function () {
        if (msg === "rate") showErr(t(STR.rate));
        else if (msg === "bad") showErr(t(STR.invalid));
        else showErr(t(STR.offline));
      });
    }).then(done, done);
  }

  btn.addEventListener("click", run);
  input.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  buildExamples();
  setLang();
})();
