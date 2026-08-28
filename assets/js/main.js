/* Bulwark site interactions — vanilla JS, no dependencies */
(function () {
  "use strict";

  /* ------------------------------------------------------------------
     Inline SVG icon library (real icons, not emoji/stickers).
     Usage: <span class="g" data-icon="whatsapp"></span>  -> gets <svg>
  ------------------------------------------------------------------ */
  var ICONS = {
    whatsapp:
      '<path d="M17.47 14.38c-.3-.15-1.77-.87-2.04-.97-.28-.1-.48-.15-.68.15-.2.3-.78.97-.95 1.17-.17.2-.35.22-.65.07-.3-.15-1.26-.46-2.4-1.48-.89-.79-1.49-1.77-1.66-2.07-.17-.3-.02-.46.13-.61.13-.13.3-.35.45-.52.15-.17.2-.3.3-.5.1-.2.05-.37-.02-.52-.08-.15-.68-1.63-.93-2.23-.24-.58-.49-.5-.68-.51h-.58c-.2 0-.52.07-.8.37-.27.3-1.04 1.02-1.04 2.5 0 1.47 1.07 2.9 1.22 3.1.15.2 2.1 3.2 5.1 4.49.71.31 1.27.49 1.7.63.72.23 1.37.2 1.88.12.58-.09 1.77-.72 2.02-1.42.25-.7.25-1.3.17-1.42-.07-.12-.27-.2-.57-.35zM12.04 21.5h-.01a9.4 9.4 0 01-4.8-1.32l-.34-.2-3.55.93.95-3.46-.22-.35a9.44 9.44 0 01-1.45-5.06c0-5.22 4.26-9.47 9.5-9.47a9.42 9.42 0 019.48 9.5c0 5.23-4.26 9.47-9.5 9.47zm8.1-17.61a11.35 11.35 0 00-16.13.9c-3.18 3.85-3.86 9.02-1.77 13.32L0 24l8.13-2.13a11.5 11.5 0 005.9 1.51h.01c6.32 0 11.46-5.14 11.46-11.46 0-3.06-1.2-5.94-3.36-8.1z"/>',
    phone:
      '<path d="M6.62 10.79a15.05 15.05 0 006.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.25.94.31 1.95.48 3 .48.55 0 1 .45 1 1V20c0 .55-.45 1-1 1C10.4 21 3 13.6 3 4.57c0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.05.16 2.06.48 3 .11.35.03.75-.25 1.02l-2.11 2.2z"/>',
    message:
      '<path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-2 12H6v-2h12v2zm0-3H6V9h12v2zm0-3H6V6h12v2z"/>',
    map:
      '<path d="M20.5 3l-.16.03L15 5.1 9 3 3.36 4.9c-.21.07-.36.25-.36.48V20.5c0 .28.22.5.5.5l.16-.03L9 18.9l6 2.1 5.64-1.9c.21-.07.36-.25.36-.48V3.5c0-.28-.22-.5-.5-.5zM15 19l-6-2.1V5l6 2.1V19z"/>',
    list:
      '<path d="M4 6h2v2H4V6zm0 5h2v2H4v-2zm0 5h2v2H4v-2zM20 6H8v2h12V6zm-12 7h12v-2H8v2zm0 3h12v-2H8v2z"/>',
    shield:
      '<path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>',
    radar:
      '<path d="M20 20l-2.9-2.9A8 8 0 1118 10h-2a6 6 0 10.88 3.12L20 18v2zM12 8a2 2 0 100 4 2 2 0 000-4z"/>',
    web:
      '<path d="M12 2a10 10 0 100 20 10 10 0 000-20zm1 2.07A8 8 0 0119.93 11H13V4.07zM4.07 11A8 8 0 0111 4.07V11H4.07zM11 19.93A8 8 0 014.07 13H11v6.93zm2 0V13h6.93A8 8 0 0113 19.93z"/>',
    bolt:
      '<path d="M11 21h-1l1-7H7.5c-.58 0-.57-.32-.38-.66.19-.34.05-.08.07-.12C8.48 10.94 10.42 7.54 13 3h1l-1 7h3.5c.49 0 .56.33.47.51l-.07.15C12.96 17.55 11 21 11 21z"/>',
    lock:
      '<path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>',
    eye:
      '<path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17a5 5 0 110-10 5 5 0 010 10zm0-8a3 3 0 103 3 3 3 0 00-3-3z"/>',
    clock:
      '<path d="M11.99 2A10 10 0 1022 12 10 10 0 0011.99 2zM12 20a8 8 0 118-8 8 8 0 01-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/>',
    chart:
      '<path d="M5 9.2h3V19H5V9.2zM10.6 5h2.8v14h-2.8V5zm5.6 8H19v6h-2.8v-6z"/>',
    check:
      '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>'
  };

  function injectIcons(root) {
    (root || document).querySelectorAll("[data-icon]").forEach(function (el) {
      if (el.querySelector("svg")) return;
      var name = el.getAttribute("data-icon");
      var d = ICONS[name];
      if (!d) return;
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("class", "g " + (el.className || ""));
      svg.innerHTML = d;
      el.innerHTML = "";
      el.appendChild(svg);
    });
  }
  injectIcons(document);

  /* mobile nav */
  var toggle = document.getElementById("navToggle");
  var links = document.getElementById("navLinks");
  if (toggle && links) {
    toggle.addEventListener("click", function () { links.classList.toggle("open"); });
  }

  /* FAQ accordion */
  document.querySelectorAll(".faq .q").forEach(function (q) {
    q.addEventListener("click", function () {
      q.parentElement.classList.toggle("open");
      var arrow = q.querySelector(".a");
      if (arrow) arrow.textContent = q.parentElement.classList.contains("open") ? "−" : "+";
    });
  });

  /* ------------------------------------------------------------------
     Letter-by-letter logo animation (like "UNITED24").
     Each char masks in sequentially, then the brand colour peeks through.
  ------------------------------------------------------------------ */
  function animateBrand() {
    var word = document.querySelector(".brand .word");
    if (!word) return;
    var text = word.getAttribute("data-text") || word.textContent;
    // base outline
    word.textContent = "";
    var base = document.createElement("div");
    base.className = "mask";
    base.style.position = "static";
    base.style.overflow = "visible";
    base = null;
    word.innerHTML = "";
    var baseSpan = document.createElement("span");
    (text.split("")).forEach(function (ch) {
      var s = document.createElement("span");
      s.textContent = ch;
      baseSpan.appendChild(s);
    });
    baseSpan.style.opacity = "1";
    word.appendChild(baseSpan);
    // animated overlay (moves each char up with stagger)
    var mask = document.createElement("span");
    mask.className = "mask";
    text.split("").forEach(function (ch, i) {
      var s = document.createElement("span");
      s.textContent = ch;
      s.style.animationDelay = (0.05 * i) + "s";
      mask.appendChild(s);
    });
    var overlay = document.createElement("div");
    overlay.style.cssText = "position:absolute;inset:0;display:flex;";
    overlay.appendChild(mask);
    word.appendChild(overlay);
    // neon peek-through
    var green = document.createElement("span");
    green.className = "mask green";
    text.split("").forEach(function (ch, i) {
      var s = document.createElement("span");
      s.textContent = ch;
      s.style.animationDelay = (1.9 + 0.04 * i) + "s";
      green.appendChild(s);
    });
    var gover = document.createElement("div");
    gover.style.cssText = "position:absolute;inset:0;display:flex;";
    gover.appendChild(green);
    word.appendChild(gover);
  }
  animateBrand();

  /* ------------------------------------------------------------------
     BULWARK preloader (UNITED24-style): show each letter building up on a
     black screen, glow line, then fade the overlay to reveal the page.
  ------------------------------------------------------------------ */
  var preloader = document.getElementById("preloader");
  if (preloader) {
    var plWord = preloader.querySelector(".pl-word");
    var plText = "BULWARK";
    var chars = [];
    plText.split("").forEach(function (ch) {
      var s = document.createElement("span");
      s.className = "pld";
      s.textContent = ch;
      plWord.appendChild(s);
      chars.push(s);
    });
    // reveal each letter top-to-bottom, spread over ~20 seconds total
    var idx = 0;
    var PACE = 2400;          // ms per letter => ~7 * 2.4s = ~17s of build
    var HOLD = 3000;          // hold full word before fading
    function nextLetter() {
      if (idx >= chars.length) { setTimeout(finish, HOLD); return; }
      chars[idx].classList.add("filled");
      idx++;
      setTimeout(nextLetter, PACE);
    }
    function finish() {
      preloader.classList.add("done");
      setTimeout(function () { preloader.style.display = "none"; }, 1200);
    }
    setTimeout(nextLetter, 200);
  }

  /* live map: network of triangulated nodes (blinking) + SVG links */
  var threatMap = document.getElementById("threatMap");
  if (threatMap) {
    var ns = "http://www.w3.org/2000/svg";
    // svg overlay for triangulation links
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("id", "netLines");
    svg.setAttribute("viewBox", "0 0 100 100");
    svg.setAttribute("preserveAspectRatio", "none");
    threatMap.appendChild(svg);

    // deterministic pseudo-random seed so layout is stable
    var seed = 7;
    function rnd() { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; }
    var kinds = ["green","blue","green","red","blue","green","green","blue"];

    // position nodes (percent coords)
    var pts = [];
    for (var i = 0; i < 30; i++) {
      pts.push({ x: 6 + rnd() * 88, y: 10 + rnd() * 80, cls: kinds[i % kinds.length] });
    }
    // draw links: connect each node to its 2-3 nearest neighbours (triangulation mesh)
    function dist(a, b) { return Math.hypot(a.x - b.x, a.y - b.y); }
    var edges = {};
    for (var i = 0; i < pts.length; i++) {
      var nei = pts.map(function (p, j) { return { j: j, d: dist(pts[i], p) }; })
                   .filter(function (q) { return q.j !== i; })
                   .sort(function (a, b) { return a.d - b.d; })
                   .slice(0, 3);
      nei.forEach(function (q) {
        var key = i < q.j ? i + "-" + q.j : q.j + "-" + i;
        if (!edges[key]) edges[key] = true;
      });
    }
    Object.keys(edges).forEach(function (key) {
      var ij = key.split("-").map(Number);
      var a = pts[ij[0]], b = pts[ij[1]];
      var line = document.createElementNS(ns, "line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
      line.setAttribute("class", "net-link");
      svg.appendChild(line);
    });
    // thin white pulse traveling along each link
    Object.keys(edges).forEach(function (key, idx) {
      var ij = key.split("-").map(Number);
      var a = pts[ij[0]], b = pts[ij[1]];
      var p = document.createElementNS(ns, "line");
      p.setAttribute("x1", a.x); p.setAttribute("y1", a.y);
      p.setAttribute("x2", b.x); p.setAttribute("y2", b.y);
      p.setAttribute("class", "net-pulse");
      p.style.animationDelay = (idx * 0.18) % 6 + "s";
      svg.appendChild(p);
    });
    // blinking node dots
    for (var i = 0; i < pts.length; i++) {
      var n = document.createElement("div");
      n.className = "mapnode " + pts[i].cls;
      n.style.left = pts[i].x + "%";
      n.style.top = pts[i].y + "%";
      n.style.animationDelay = (rnd() * 2) + "s";
      threatMap.appendChild(n);
    }
  }

  /* list panel toggle (Map/List). Removed the visible tab; panel remains for future use.
     Kept map/list icons for the footer/hero links. */
  var listPanel = document.getElementById("listPanel");

  /* crossfading ticker (u24 header stat strip) */
  var tickerItems = document.querySelectorAll(".ticker-item");
  if (tickerItems.length > 1) {
    var ti = 0;
    tickerItems[0].classList.add("active");
    setInterval(function () {
      tickerItems[ti].classList.remove("active");
      ti = (ti + 1) % tickerItems.length;
      tickerItems[ti].classList.add("active");
    }, 3200);
  }

  /* progress bars animate when scrolled into view */
  var progressBars = document.querySelectorAll(".pbar .fill");
  if (progressBars.length && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          var w = e.target.getAttribute("data-width");
          e.target.style.width = w + (w.indexOf("%") === -1 ? "%" : "");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.4 });
    progressBars.forEach(function (b) { io.observe(b); });
  }

  /* LEAD form: opens WhatsApp with the enquiry, same number every time */
  var PHONE = "+254796874539", WA = "254796874539";
  var form = document.getElementById("leadForm");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var data = new FormData(form);
      function g(n) { return (data.get(n) || "").toString().trim(); }
      var text =
        "Bulwark enquiry\n----------------\n" +
        "Name: " + (g("name") || "-") + "\n" +
        "Email: " + (g("email") || "-") + "\n" +
        "Company: " + (g("company") || "-") + "\n" +
        "Interest: " + (g("interest") || "-") + "\n" +
        "Devices: " + (g("seats") || "-") + "\n\nMessage: " + (g("message") || "-");
      window.open("https://wa.me/" + WA + "?text=" + encodeURIComponent(text), "_blank");
      var ok = document.getElementById("formOk");
      if (ok) {
        ok.style.display = "block";
        ok.textContent = "Opening WhatsApp to +254 796 874 539 with your enquiry. Prefer voice? Call or SMS the same number any time.";
      }
      form.reset();
    });
  }

  /* zoom buttons on the map (visual only) */
  var zoomIn = document.getElementById("zmIn"), zoomOut = document.getElementById("zmOut");
  var mapScale = 1;
  function applyZoom() {
    if (threatMap) { threatMap.style.transform = "scale(" + mapScale + ")"; threatMap.style.transformOrigin = "center center"; }
  }
  if (zoomIn) zoomIn.addEventListener("click", function () { mapScale = Math.min(2, mapScale + 0.25); applyZoom(); });
  if (zoomOut) zoomOut.addEventListener("click", function () { mapScale = Math.max(0.6, mapScale - 0.25); applyZoom(); });
})();
