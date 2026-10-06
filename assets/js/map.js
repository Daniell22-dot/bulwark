/* -----------------------------------------------------------------
   Bulwark Live map engine (extracted from map.html)
   ----------------------------------------------------------------- */
window.BULWARK_LIVE = "https://live.example.com";
window.BULWARK_SNAPSHOT_LIVE = "data/live.json";
window.BULWARK_SNAPSHOT_LIVE_JS = "data/live.js";

(function () {
  "use strict";
  var LANG = { en: 1, sw: 0 };
  var STR = {
    offline:  { en: "offline", sw: "haipo mtandaoni" },
    online:   { en: "live", sw: "moja kwa moja" },
    events:   { en: "events", sw: "matukio" },
    refresh:  { en: "refreshes every 30s", sw: "inaburudishwa kila sek 30" },
    empty:    { en: "No detections yet. The fleet console is listening — as soon as an agent reports a threat, it lands here.", sw: "Hakuna matukio bado. Fleet console inasikiliza — mara tu agent inaporipoti tishio, litaonekana hapa." },
    justnow:  { en: "just now", sw: "sasa hivi" },
    minsAgo:  { en: "min ago", sw: "dakika iliyopita" },
    bannerOn: { en: "Map is offline — the fleet console is not reachable on this network. Start Sentinel.Console and expose /api/live (see your deployment notes), then this page lights up on its own.", sw: "Ramani haipo mtandaoni — fleet console haifikiki. Anzisha Sentinel.Console na ufunue /api/live (tazama maelezo yako ya usambazaji), kisha ukurasa huu utawaka peke yake." },
    bannerCached: { en: "Fleet console offline — showing the last bundled snapshot from", sw: "Fleet console haipo mtandaoni — inaonyesha snapshot ya mwisho iliyopakiwa ya" },
    bannerEmpty: { en: "Fleet console offline and no snapshot is bundled yet. Once an agent reports, export data/live.json (scripts/export-live.ps1) and commit it.", sw: "Fleet console haipo mtandaoni na hakuna snapshot bado. Mara agent inaporipoti, hamisha data/live.json (scripts/export-live.ps1) na uiweke." }
  };
  var liveBase = window.BULWARK_LIVE || "http://127.0.0.1:5000";
  var svg = document.getElementById("kenyaSvg");
  var NS = "http://www.w3.org/2000/svg";
  var feed = document.getElementById("liveFeed");
  var offBanner = document.getElementById("offBanner");

  function t(o) { return o[LANG.en ? "en" : "sw"]; }
  function setLang() {
    document.getElementById("langEn").classList.toggle("on", LANG.en === 1);
    document.getElementById("langSw").classList.toggle("on", LANG.en === 0);
    document.querySelectorAll("[data-st]").forEach(function (el) {
      var k = el.getAttribute("data-st");
      if (k === "offline") el.textContent = t(STR[ document.getElementById("stStatus").getAttribute("data-on") ? "online" : "offline" ]);
      if (k === "ev") el.textContent = t(STR.events);
      if (k === "upd") el.textContent = t(STR.refresh);
    });
    document.getElementById("feedEmpty").textContent = t(STR.empty);
  }

  /* --- projection + base geography (stylised, approximate) --- */
  var LON_MIN = 33.7, LON_MAX = 41.9, LAT_MAX = 5.0, LAT_MIN = -4.9;
  var LON_STEP = (LON_MAX - LON_MIN) / 400;
  var LAT_STEP = (LAT_MAX - LAT_MIN) / 470;
  function px(lon) { return (lon - LON_MIN) / (LON_MAX - LON_MIN) * 400; }
  function py(lat) { return (LAT_MAX - lat) / (LAT_MAX - LAT_MIN) * 470; }
  function lon(px) { return LON_MIN + px / 400 * (LON_MAX - LON_MIN); }
  function lat(py) { return LAT_MAX - py / 470 * (LAT_MAX - LAT_MIN); }
  function poly(points) {
    return points.map(function (p) { return px(p[0]).toFixed(1) + "," + py(p[1]).toFixed(1); }).join(" ");
  }
  var KENYA = [
    [34.60,4.95],[35.85,4.85],[36.9,4.7],[38.0,4.55],[39.0,4.4],[40.0,4.1],
    [40.95,3.95],[41.02,3.5],[41.2,2.7],[41.25,1.6],[41.1,0.6],[40.9,-0.2],
    [40.75,-0.9],[40.45,-1.55],[39.9,-1.9],[39.55,-1.75],[39.6,-2.4],[39.3,-2.75],
    [39.1,-3.5],[38.9,-4.05],[38.55,-4.55],[37.9,-4.7],[37.1,-4.3],[36.7,-3.6],
    [36.4,-2.9],[36.25,-2.3],[36.6,-1.8],[36.5,-1.35],[35.6,-1.3],[34.9,-1.35],
    [34.45,-1.6],[34.15,-1.5],[33.92,-1.2],[33.95,-0.6],[34.1,-0.2],[34.0,0.3],
    [34.15,0.8],[34.5,1.15],[34.75,1.6],[34.55,2.1],[34.6,2.8],[34.55,3.3],
    [34.9,3.7],[35.15,4.2],[34.8,4.6],[34.6,4.95]
  ];
  var LAKE = [
    [34.75,-0.45],[34.15,-0.4],[33.9,-0.5],[33.92,-0.9],[34.05,-1.25],
    [34.35,-1.6],[34.6,-1.7],[34.75,-1.35],[34.7,-0.95],[34.75,-0.45]
  ];
  var CITIES = [
    ["Nairobi", -1.286, 36.817], ["Mombasa", -4.04, 39.66], ["Kisumu", -0.09, 34.75],
    ["Eldoret", 0.51, 35.27], ["Nyeri", -0.42, 36.95], ["Garissa", -0.46, 39.65],
    ["Nakuru", -0.30, 36.08], ["Malindi", -3.22, 40.12], ["Kakamega", 0.28, 34.75],
    ["Meru", 0.05, 37.65], ["Thika", -1.03, 37.08], ["Machakos", -1.52, 37.27],
    ["Kitui", -1.37, 38.02], ["Isiolo", 0.35, 38.58], ["Wajir", 1.75, 40.06],
    ["Mandera", 3.94, 41.87], ["Lamu", -2.27, 40.90], ["Lodwar", 3.12, 35.60],
    ["Busia", 0.46, 34.11], ["Bungoma", 0.57, 34.56]
  ];
  var COUNTIES = [
    ["Nairobi", -1.29, 36.82], ["Mombasa", -4.04, 39.67], ["Kisumu", -0.09, 34.77],
    ["Nakuru", -0.30, 36.08], ["Eldoret", 0.51, 35.27], ["Nyeri", -0.42, 36.95],
    ["Garissa", -0.46, 39.64], ["Thika", -1.03, 37.08], ["Malindi", -3.22, 40.12],
    ["Lamu", -2.27, 40.90], ["Kakamega", 0.28, 34.75], ["Meru", 0.05, 37.65],
    ["Embu", -0.53, 37.45], ["Machakos", -1.52, 37.27], ["Kitui", -1.37, 38.02],
    ["Isiolo", 0.35, 38.58], ["Wajir", 1.75, 40.06], ["Mandera", 3.94, 41.87],
    ["Marsabit", 2.31, 37.99], ["Moyale", 3.52, 39.05], ["Lokichoggio", 4.34, 34.35],
    ["Busia", 0.46, 34.11], ["Bungoma", 0.57, 34.56], ["Kitale", 1.02, 35.00],
    ["Kapenguria", 1.24, 35.11], ["Turkana", 3.50, 35.85]
  ];

  function el(name, attrs, parent) {
    var n = document.createElementNS(NS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    (parent || svg).appendChild(n);
    return n;
  }

  /* layer visibility state */
  var layers = { grid: true, osint: false, live: true };
  function setLayer(name, on) {
    layers[name] = on;
    var grp = svg.querySelector("[data-layer='" + name + "']");
    if (grp) grp.style.display = on ? "" : "none";
    if (name === "osint") {
      document.getElementById("osintLegend").style.display = on ? "" : "none";
    }
    document.querySelectorAll(".layer-btn[data-layer='" + name + "']").forEach(function (b) {
      b.classList.toggle("on", on);
    });
  }

  function drawGrid() {
    var g = el("g", { "data-layer": "grid" }, svg);
    if (!layers.grid) g.style.display = "none";
    for (var lon = 34; lon <= 42; lon++) {
      var x = px(lon);
      el("line", { x1: x, y1: 0, x2: x, y2: 470, "class": "grid-line" }, g);
      if (lon % 2 === 0) {
        var lbl = el("text", { x: x + 2, y: 10, "class": "grid-label" }, g);
        lbl.textContent = lon + "°E";
      }
    }
    for (var lat = -5; lat <= 5; lat++) {
      var y = py(lat);
      el("line", { x1: 0, y1: y, x2: 400, y2: y, "class": "grid-line" }, g);
      if (lat % 2 === 0) {
        var lbl = el("text", { x: 2, y: y - 2, "class": "grid-label" }, g);
        lbl.textContent = Math.abs(lat) + "°" + (lat < 0 ? "S" : "N");
      }
    }
  }

  function drawCounties() {
    var g = el("g", { "data-layer": "grid" }, svg);
    if (!layers.grid) g.style.display = "none";
    COUNTIES.forEach(function (c) {
      el("text", {
        x: px(c[2]).toFixed(1),
        y: py(c[1]).toFixed(1),
        "class": "county-label",
        "text-anchor": "middle"
      }).textContent = c[0];
    });
  }

  function osintColor(d) {
    if (d >= 0.75) return "#ff5a5f";
    if (d >= 0.50) return "#ffb347";
    if (d >= 0.25) return "#ffd94d";
    return "rgba(5,229,99,.18)";
  }
  function osintOpacity(d) {
    return 0.12 + d * 0.55;
  }

  function drawOSINT(data) {
    var g = el("g", { "data-layer": "osint" }, svg);
    if (!layers.osint) g.style.display = "none";
    (data || []).forEach(function (cell) {
      var x = px(cell.lon);
      var y = py(cell.lat);
      var w = px(cell.lon + 1) - x;
      var h = y - py(cell.lat + 1);
      var r = Math.max(0.01, cell.density);
      el("rect", {
        x: x.toFixed(1), y: y.toFixed(1), width: w.toFixed(1), height: h.toFixed(1),
        fill: osintColor(r), "fill-opacity": osintOpacity(r), "class": "osint-cell"
      }, g);
    });
  }

  function drawBase() {
    el("polygon", { points: poly(KENYA), "class": "land" });
    el("polygon", { points: poly(LAKE), "class": "lake" });
    CITIES.forEach(function (c) {
      el("circle", { cx: px(c[2]).toFixed(1), cy: py(c[1]).toFixed(1), r: 2, "class": "city" });
      var lb = c[0];
      if (c[0] === "Mombasa" || c[0] === "Kisumu" || c[0] === "Eldoret") lb = c[0].slice(0, 3) + ".";
      el("text", { x: (px(c[2]) + 5).toFixed(1), y: (py(c[1]) + 3).toFixed(1), "class": "citylabel" }).textContent = lb;
    });
  }

  /* load OSINT data from file or fall back to embedded snapshot */
  var osintCache = null;
  function loadOSINT() {
    if (osintCache) return Promise.resolve(osintCache);
    return fetch("data/osint_grid.json", { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("osint-fail"); return r.json(); })
      .then(function (d) { osintCache = d; return d; })
      .catch(function () {
        return {
          grid: [
            {"lon":34,"lat":-1,"density":0.15},{"lon":34,"lat":0,"density":0.35},{"lon":34,"lat":1,"density":0.20},{"lon":34,"lat":2,"density":0.10},{"lon":34,"lat":3,"density":0.08},{"lon":34,"lat":4,"density":0.05},
            {"lon":35,"lat":-4,"density":0.10},{"lon":35,"lat":-3,"density":0.12},{"lon":35,"lat":-2,"density":0.18},{"lon":35,"lat":-1,"density":0.55},{"lon":35,"lat":0,"density":0.60},{"lon":35,"lat":1,"density":0.45},{"lon":35,"lat":2,"density":0.30},{"lon":35,"lat":3,"density":0.15},{"lon":35,"lat":4,"density":0.10},
            {"lon":36,"lat":-4,"density":0.08},{"lon":36,"lat":-3,"density":0.12},{"lon":36,"lat":-2,"density":0.20},{"lon":36,"lat":-1,"density":0.65},{"lon":36,"lat":0,"density":0.85},{"lon":36,"lat":1,"density":0.70},{"lon":36,"lat":2,"density":0.40},{"lon":36,"lat":3,"density":0.25},{"lon":36,"lat":4,"density":0.12},
            {"lon":37,"lat":-4,"density":0.05},{"lon":37,"lat":-3,"density":0.10},{"lon":37,"lat":-2,"density":0.18},{"lon":37,"lat":-1,"density":0.50},{"lon":37,"lat":0,"density":0.95},{"lon":37,"lat":1,"density":0.60},{"lon":37,"lat":2,"density":0.35},{"lon":37,"lat":3,"density":0.20},{"lon":37,"lat":4,"density":0.10},
            {"lon":38,"lat":-4,"density":0.05},{"lon":38,"lat":-3,"density":0.08},{"lon":38,"lat":-2,"density":0.15},{"lon":38,"lat":-1,"density":0.45},{"lon":38,"lat":0,"density":0.80},{"lon":38,"lat":1,"density":0.55},{"lon":38,"lat":2,"density":0.30},{"lon":38,"lat":3,"density":0.18},{"lon":38,"lat":4,"density":0.10},
            {"lon":39,"lat":-4,"density":0.85},{"lon":39,"lat":-3,"density":0.20},{"lon":39,"lat":-2,"density":0.25},{"lon":39,"lat":-1,"density":0.40},{"lon":39,"lat":0,"density":0.70},{"lon":39,"lat":1,"density":0.45},{"lon":39,"lat":2,"density":0.25},{"lon":39,"lat":3,"density":0.15},{"lon":39,"lat":4,"density":0.08},
            {"lon":40,"lat":-4,"density":0.15},{"lon":40,"lat":-3,"density":0.12},{"lon":40,"lat":-2,"density":0.20},{"lon":40,"lat":-1,"density":0.35},{"lon":40,"lat":0,"density":0.50},{"lon":40,"lat":1,"density":0.30},{"lon":40,"lat":2,"density":0.18},{"lon":40,"lat":3,"density":0.12},{"lon":40,"lat":4,"density":0.06},
            {"lon":41,"lat":-3,"density":0.10},{"lon":41,"lat":-2,"density":0.12},{"lon":41,"lat":-1,"density":0.20},{"lon":41,"lat":0,"density":0.25},{"lon":41,"lat":1,"density":0.15},{"lon":41,"lat":2,"density":0.10},{"lon":41,"lat":3,"density":0.08},{"lon":41,"lat":4,"density":0.05}
          ],
          counties: [
            {"name":"Nairobi","lat":-1.29,"lon":36.82,"density":0.95},{"name":"Mombasa","lat":-4.04,"lon":39.67,"density":0.85},
            {"name":"Kisumu","lat":-0.09,"lon":34.77,"density":0.65},{"name":"Nakuru","lat":-0.30,"lon":36.08,"density":0.60},
            {"name":"Eldoret","lat":0.51,"lon":35.27,"density":0.55},{"name":"Nyeri","lat":-0.42,"lon":36.95,"density":0.50},
            {"name":"Garissa","lat":-0.46,"lon":39.64,"density":0.45},{"name":"Thika","lat":-1.03,"lon":37.08,"density":0.50},
            {"name":"Malindi","lat":-3.22,"lon":40.12,"density":0.30},{"name":"Lamu","lat":-2.27,"lon":40.90,"density":0.20},
            {"name":"Kakamega","lat":0.28,"lon":34.75,"density":0.40},{"name":"Meru","lat":0.05,"lon":37.65,"density":0.40},
            {"name":"Embu","lat":-0.53,"lon":37.45,"density":0.35},{"name":"Machakos","lat":-1.52,"lon":37.27,"density":0.35},
            {"name":"Kitui","lat":-1.37,"lon":38.02,"density":0.25},{"name":"Isiolo","lat":0.35,"lon":38.58,"density":0.20},
            {"name":"Wajir","lat":1.75,"lon":40.06,"density":0.15},{"name":"Mandera","lat":3.94,"lon":41.87,"density":0.12},
            {"name":"Marsabit","lat":2.31,"lon":37.99,"density":0.15},{"name":"Moyale","lat":3.52,"lon":39.05,"density":0.10},
            {"name":"Lokichoggio","lat":4.34,"lon":34.35,"density":0.08},{"name":"Busia","lat":0.46,"lon":34.11,"density":0.30},
            {"name":"Bungoma","lat":0.57,"lon":34.56,"density":0.30},{"name":"Kitale","lat":1.02,"lon":35.00,"density":0.25},
            {"name":"Kapenguria","lat":1.24,"lon":35.11,"density":0.15},{"name":"Lodwar","lat":3.12,"lon":35.60,"density":0.10},
            {"name":"Turkana","lat":3.50,"lon":35.85,"density":0.05}
          ]
        };
      });
  }

  var pings = { };

  function addMarker(e) {
    if (e.lat == null || e.lon == null) return;
    var x = px(e.lon), y = py(e.lat);
    var sev = e.severity || 0;
    var cls = sev >= 3 ? "smark" : sev === 2 ? "smark med" : "smark low";
    var label = (e.type || "") + " · " + (e.sourceIp || "") + (e.place ? " · " + e.place : "");
    var g = el("g", { transform: "translate(" + x.toFixed(1) + "," + y.toFixed(1) + ")", "data-marker": "1" });
    var pulse = el("g", { "class": "pulse" }, g);
    el("circle", { r: 3, "class": cls }, g);
    el("circle", { r: 3, "class": cls }, pulse);
    el("circle", { r: 7, cx: 0, cy: 0, fill: "#05e563", opacity: .25 }, pulse);
    var ring = el("circle", { r: 7, fill: "none", stroke: "#05e563", "stroke-width": 1 }, pulse);
    ring.style.animationDelay = "0.4s";
    var tip = el("title", {});
    tip.textContent = label;
  }

  function sevPill(s) {
    var v = Math.max(1, Math.min(4, s));
    return '<span class="sev-pill s' + v + '">S' + v + '</span>';
  }
  function timeAgo(iso) {
    var ms = Date.now() - new Date(iso).getTime();
    if (ms < 60 * 1000) return t(STR.justnow);
    var m = Math.round(ms / 60000);
    return m + " " + t(STR.minsAgo);
  }
  function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

  function render(events, updatedUtc) {
    svg.querySelectorAll("g[data-marker]").forEach(function (n) { n.parentNode.removeChild(n); });
    feed.innerHTML = "";
    var located = 0;
    (events || []).forEach(function (e) {
      if (e.lat != null && e.lon != null) { located++; addMarker(e); }
      var row = document.createElement("div");
      row.className = "feed-row";
      row.innerHTML = sevPill(e.severity || 0) +
        '<span class="src">' + esc(e.sourceIp || "—") + '</span>' +
        '<span class="type">' + esc(e.type || "") + (e.place ? " · " + esc(e.place) : "") + '</span>' +
        '<span class="when">' + timeAgo(e.utc) + '</span>';
      feed.appendChild(row);
    });
    var el = document.getElementById("feedEmpty");
    if ((events || []).length === 0) { feed.appendChild(el); }
    document.getElementById("stEvents").innerHTML = "<b>" + (events || []).length + "</b> <span data-st='ev'>" + t(STR.events) + "</span>";
    // normalise data-st after innerHTML rebuild
    document.querySelectorAll("#stEvents [data-st]").forEach(function (n) { n.textContent = t(STR.events); });
    document.getElementById("stCount").textContent = " " + (located + "/" + (events || []).length + " on map");
  }

  function setStatus(on) {
    var st = document.getElementById("stStatus");
    if (on) st.setAttribute("data-on", "1"); else st.removeAttribute("data-on");
    st.innerHTML = "<b data-st='offline'>" + t(on ? STR.online : STR.offline) + "</b>";
  }

  var liveCache = null;
  function loadLiveSnapshot() {
    if (liveCache) return Promise.resolve(liveCache);

    var jsUrl = window.BULWARK_SNAPSHOT_LIVE_JS || "data/live.js";
    var jsonUrl = window.BULWARK_SNAPSHOT_LIVE || "data/live.json";

    var jsPromise = new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = jsUrl;
      s.onload = function () {
        var d = window.BULWARK_LIVE_SNAPSHOT;
        if (d) { cleanup(); resolve(d); }
        else { cleanup(); reject(new Error("js-empty")); }
      };
      s.onerror = function () { cleanup(); reject(new Error("js-fail")); };
      function cleanup() { s.onload = s.onerror = null; s.parentNode && s.parentNode.removeChild(s); }
      document.head.appendChild(s);
      setTimeout(function () { cleanup(); reject(new Error("js-timeout")); }, 3000);
    });

    var jsonPromise = fetch(jsonUrl, { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("json-fail"); return r.json(); });

    return Promise.race([jsPromise, jsonPromise])
      .then(function (d) { liveCache = d; return d; });
  }

  function showOffline() {
    setStatus(false);
    return loadLiveSnapshot()
      .then(function (d) {
        var n = (d.events || []).length;
        render(d.events || [], d.updatedUtc);
        offBanner.textContent = n
          ? t(STR.bannerCached) + " " + new Date(d.updatedUtc || d.generatedUtc).toLocaleString()
          : t(STR.bannerEmpty);
        offBanner.classList.add("show");
      })
      .catch(function () {
        offBanner.textContent = t(STR.bannerOn);
        offBanner.classList.add("show");
      });
  }

  function poll() {
    fetch(liveBase + "/api/live", { headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        setStatus(true);
        offBanner.classList.remove("show");
        render(d.events || [], d.updatedUtc);
      })
      .catch(showOffline);
  }

  drawBase();
  drawGrid();
  drawCounties();
  loadOSINT().then(function (d) { drawOSINT(d.grid); });
  setLayer("grid", true);
  setLayer("osint", false);
  setLayer("live", true);

  document.querySelectorAll(".layer-btn").forEach(function (b) {
    b.addEventListener("click", function () { setLayer(b.getAttribute("data-layer"), !layers[b.getAttribute("data-layer")]); });
  });

  setLang();
  poll();
  setInterval(poll, 30000);
})();
