/* Script commun du site : cadenas 3D du héro (WebGL, sans bibliothèque),
   accroche qui se déchiffre quand il s'ouvre, animations des sections à leur
   arrivée à l'écran, points de navigation. Aucun appel réseau. */
(function () {
  "use strict";

  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ===== Cadenas 3D =========================================================
  // Rendu par lancer de rayons sur une scène décrite par des fonctions de
  // distance (WebGL 1, aucune bibliothèque) : corps en aluminium anodisé
  // graphite aux arêtes très arrondies, barillet chromé et serrure éclairée de
  // l'intérieur, anse en acier poli qui se soulève puis pivote autour de sa
  // branche longue. Éclairage de studio simulé (boîte à lumière au-dessus,
  // bande blanche à gauche, contre-jour bleuté à droite) : les reflets
  // glissent sur les arêtes quand le cadenas tourne. Sans WebGL, un cadenas
  // dessiné (SVG) prend sa place.
  var VERT = "attribute vec2 p; void main() { gl_Position = vec4(p, 0.0, 1.0); }";
  var FRAG = [
    "precision highp float;",
    "uniform vec2 uRes;",
    "uniform float uLift, uSwing, uGlow, uYaw, uPitch, uBob;",
    "uniform vec3 uAccent;",
    "const float R = 0.40;",            // demi-écart des branches de l'anse
    "const float TR = 0.095;",          // rayon du tube de l'anse
    "const vec3 BODY = vec3(0.70, 0.56, 0.30);",
    "const vec3 BODY_C = vec3(0.0, -0.40, 0.0);",
    "const vec3 CENTER = vec3(0.0, 0.22, 0.0);",
    "mat2 rot(float a) { float c = cos(a), s = sin(a); return mat2(c, s, -s, c); }",
    "float sdRoundBox(vec3 p, vec3 b, float r) { vec3 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, max(q.y, q.z)), 0.0) - r; }",
    "float sdRoundRect(vec2 p, vec2 b, float r) { vec2 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r; }",
    "float sdCapsule(vec3 p, vec3 a, vec3 b, float r) { vec3 pa = p - a, ba = b - a; float h = clamp(dot(pa, ba) / dot(ba, ba), 0.0, 1.0); return length(pa - ba * h) - r; }",
    "float sdRoundCyl(vec3 p, float ra, float rb, float h) { vec2 d = vec2(length(p.xy) - ra + rb, abs(p.z) - h + rb); return min(max(d.x, d.y), 0.0) + length(max(d, 0.0)) - rb; }",
    "float shackle(vec3 p) {",
    "  p.y -= 0.64 + 0.32 * uLift;",
    "  p.x += R; p.xz = rot(uSwing) * p.xz; p.x -= R;",
    "  float arc = p.y > 0.0 ? length(vec2(length(p.xy) - R, p.z)) - TR : 1e5;",
    "  float legL = sdCapsule(p, vec3(-R, 0.0, 0.0), vec3(-R, -1.12, 0.0), TR);",
    "  float legR = sdCapsule(p, vec3(R, 0.0, 0.0), vec3(R, -0.60, 0.0), TR);",
    "  return min(arc, min(legL, legR));",
    "}",
    // Distance et matière : 1 corps, 2 chrome (anse, barillet), 3 serrure.
    "vec2 map(vec3 p) {",
    "  p.y -= uBob;",
    "  p -= CENTER; p.xz = rot(uYaw) * p.xz; p.yz = rot(uPitch) * p.yz; p += CENTER;",
    "  vec3 q = p - BODY_C;",
    "  float body = sdRoundBox(q, BODY, 0.22);",
    "  body = max(body, -max(length(vec2(abs(q.x) - R, q.z)) - (TR + 0.012), abs(q.y - BODY.y) - 0.08));",
    "  vec3 k = q - vec3(0.0, -0.05, BODY.z);",
    "  float bezel = sdRoundCyl(k, 0.17, 0.025, 0.04);",
    "  float wall = -max(min(length(k.xy - vec2(0.0, 0.03)) - 0.05, sdRoundRect(k.xy - vec2(0.0, -0.045), vec2(0.021, 0.065), 0.01)), abs(k.z) - 0.16);",
    "  vec2 res = vec2(max(body, wall), 1.0);",
    "  float cyl = max(bezel, wall);",
    "  if (cyl < res.x) res = vec2(cyl, 2.0);",
    "  if (res.x == wall) res.y = 3.0;",
    "  float s = shackle(p);",
    "  if (s < res.x) res = vec2(s, 2.0);",
    "  return res;",
    "}",
    "vec3 calcNormal(vec3 p) {",
    "  const vec2 e = vec2(1.0, -1.0) * 0.0007;",
    "  return normalize(e.xyy * map(p + e.xyy).x + e.yyx * map(p + e.yyx).x + e.yxy * map(p + e.yxy).x + e.xxx * map(p + e.xxx).x);",
    "}",
    "float calcAO(vec3 p, vec3 n) {",
    "  float occ = 0.0, sca = 1.0;",
    "  for (int i = 0; i < 5; i++) { float h = 0.01 + 0.07 * float(i); occ += (h - map(p + h * n).x) * sca; sca *= 0.8; }",
    "  return clamp(1.0 - 2.2 * occ, 0.0, 1.0);",
    "}",
    // Studio ; `w` élargit les transitions pour une matière plus mate.
    "vec3 env(vec3 r, float w) {",
    "  vec3 c = mix(vec3(0.008, 0.009, 0.012), vec3(0.05, 0.055, 0.07), smoothstep(-0.4, 0.8, r.y));",
    "  c += vec3(1.0) * 2.2 * smoothstep(0.62 - w, 0.86 + 0.5 * w, dot(r, normalize(vec3(-0.3, 1.0, 0.5))));",
    "  float az = atan(r.x, r.z);",
    "  c += vec3(1.0, 0.98, 0.95) * 1.7 * (1.0 - smoothstep(0.03, 0.12 + w, abs(az + 1.2))) * smoothstep(-0.35 - w, 0.25, r.y) * (1.0 - smoothstep(0.45 - w, 0.9, r.y));",
    "  c += uAccent * 1.5 * (1.0 - smoothstep(0.05, 0.2 + w, abs(az - 1.95))) * smoothstep(-0.5, 0.2, r.y);",
    "  c += vec3(0.75, 0.8, 0.9) * 0.3 * pow(max(dot(r, normalize(vec3(0.15, 0.2, 1.0))), 0.0), 3.0);",
    "  return c;",
    "}",
    "void main() {",
    "  vec2 uv = (2.0 * gl_FragCoord.xy - uRes) / uRes.y;",
    "  vec3 ro = vec3(0.0, 0.45, 4.2);",
    "  vec3 ww = normalize(CENTER - ro);",
    "  vec3 uu = normalize(cross(ww, vec3(0.0, 1.0, 0.0)));",
    "  vec3 vv = cross(uu, ww);",
    "  const float FL = 2.55;",
    "  vec3 rd = normalize(uv.x * uu + uv.y * vv + FL * ww);",
    "  vec3 oc = ro - CENTER;",
    "  float bq = dot(oc, rd);",
    "  float disc = bq * bq - (dot(oc, oc) - 1.55 * 1.55);",
    "  if (disc < 0.0) { gl_FragColor = vec4(0.0); return; }",
    "  disc = sqrt(disc);",
    "  float t = max(-bq - disc, 0.0), tEnd = -bq + disc;",
    "  float px = 2.0 / (uRes.y * FL);",
    "  float minD = 1e9, tMin = t, tHit = -1.0, mat = 1.0;",
    "  for (int i = 0; i < 110; i++) {",
    "    vec2 m = map(ro + rd * t);",
    "    if (m.x < minD) { minD = m.x; tMin = t; }",
    "    if (m.x < 0.0003 * t) { tHit = t; mat = m.y; break; }",
    "    t += m.x * 0.85;",
    "    if (t > tEnd) break;",
    "  }",
    "  float alpha = tHit > 0.0 ? 1.0 : 1.0 - smoothstep(0.0, 1.5 * px * tMin, minD);",
    "  if (alpha <= 0.0) { gl_FragColor = vec4(0.0); return; }",
    "  vec3 pos = ro + rd * (tHit > 0.0 ? tHit : tMin);",
    "  if (tHit < 0.0) mat = map(pos).y;",
    "  vec3 n = calcNormal(pos);",
    "  float ao = calcAO(pos, n);",
    "  vec3 col;",
    "  if (mat > 2.5) {",
    "    col = vec3(0.004) + uAccent * uGlow * (0.25 + 0.75 * ao);",
    "  } else {",
    "    bool chrome = mat > 1.5;",
    "    vec3 tint = chrome ? vec3(0.95, 0.95, 0.97) : vec3(0.30, 0.32, 0.37);",
    "    float rough = chrome ? 0.04 : 0.28;",
    "    vec3 rf = reflect(rd, n);",
    "    float ndv = max(dot(n, -rd), 0.0);",
    "    vec3 F = tint + (1.0 - tint) * pow(1.0 - ndv, 5.0);",
    "    col = env(normalize(mix(rf, n, 0.5 * rough)), rough) * F;",
    "    vec3 L = normalize(vec3(-0.5, 0.9, 0.7));",
    "    vec3 H = normalize(L - rd);",
    "    col += F * pow(max(dot(n, H), 0.0), chrome ? 400.0 : 60.0) * (chrome ? 2.0 : 0.6);",
    "    col += tint * 0.03 * max(dot(n, L), 0.0);",
    "    col *= mix(0.35, 1.0, ao);",
    "  }",
    "  col = clamp((col * (2.51 * col + 0.03)) / (col * (2.43 * col + 0.59) + 0.14), 0.0, 1.0);",
    "  col = pow(col, vec3(0.4545));",
    "  gl_FragColor = vec4(col * alpha, alpha);",
    "}"
  ].join("\n");

  // Pages sans cadenas (« sécurité en détail ») : seulement les animations
  // de sections.
  var stage = document.getElementById("lock-stage");
  var canvas = document.getElementById("lock-canvas");
  var statusEl = document.getElementById("lock-status");
  var statusTextEl = document.getElementById("lock-status-text");
  var hasLock = !!(stage && canvas && statusEl && statusTextEl);
  var renderer = hasLock ? createRenderer() : null;
  if (hasLock && !renderer) stage.classList.add("no-webgl");

  function createRenderer() {
    var gl;
    try {
      gl = canvas.getContext("webgl", { alpha: true, premultipliedAlpha: true, antialias: false, powerPreference: "high-performance" });
    } catch (e) {
      gl = null;
    }
    if (!gl) return null;
    function shader(type, source) {
      var s = gl.createShader(type);
      gl.shaderSource(s, source);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        console.error("cadenas 3D :", gl.getShaderInfoLog(s));
        return null;
      }
      return s;
    }
    var vs = shader(gl.VERTEX_SHADER, VERT);
    var fs = shader(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return null;
    var program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.error("cadenas 3D :", gl.getProgramInfoLog(program));
      return null;
    }
    gl.useProgram(program);
    var buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(program, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    var u = {};
    ["uRes", "uLift", "uSwing", "uGlow", "uYaw", "uPitch", "uBob", "uAccent"].forEach(function (name) { u[name] = gl.getUniformLocation(program, name); });
    gl.uniform3f(u.uAccent, 0.486, 0.576, 1.0);
    gl.clearColor(0, 0, 0, 0);

    // Résolution adaptative : moins de pixels si l'image prend trop de temps.
    var scale = Math.min(window.devicePixelRatio || 1, 1.5);
    function resize() {
      var r = canvas.getBoundingClientRect();
      var w = Math.max(1, Math.round(r.width * scale));
      var h = Math.max(1, Math.round(r.height * scale));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
      }
    }
    resize();
    return {
      resize: resize,
      draw: function (s) {
        gl.uniform2f(u.uRes, canvas.width, canvas.height);
        gl.uniform1f(u.uLift, s.lift);
        gl.uniform1f(u.uSwing, s.swing);
        gl.uniform1f(u.uGlow, s.glow);
        gl.uniform1f(u.uYaw, s.yaw);
        gl.uniform1f(u.uPitch, s.pitch);
        gl.uniform1f(u.uBob, s.bob || 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      },
      slower: function () {
        if (scale <= 0.6) return;
        scale = Math.max(0.6, scale * 0.8);
        resize();
      }
    };
  }

  // ===== Cycle verrouillé → ouvert → verrouillé (20 s) ======================
  // Le texte de l'accroche suit le cadenas : chiffré quand il est fermé, il
  // se déchiffre quand l'anse se soulève et se rechiffre quand elle retombe.
  var CYCLE = 20;
  var SWING_OPEN = -2.3;
  // Étapes, en secondes dans le cycle.
  var T_UNLOCK = 1.0, T_SWING = 1.55, T_SWING_BACK = 14.6, T_DROP = 15.45, T_SHUT = 15.75;
  function clamp01(x) { return x < 0 ? 0 : x > 1 ? 1 : x; }
  function smooth(x) { x = clamp01(x); return x * x * (3 - 2 * x); }
  function easeIn(x) { x = clamp01(x); return x * x * x; }
  function easeInOut(x) { x = clamp01(x); return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2; }
  // Arrivée avec un léger dépassement (ressort), `k` : son ampleur.
  function easeOutBack(x, k) { x = clamp01(x); return 1 + (k + 1) * Math.pow(x - 1, 3) + k * Math.pow(x - 1, 2); }

  function lockState(c) {
    var lift = 0, swing = 0, jolt = 0;
    if (c >= T_UNLOCK && c < T_DROP) lift = easeOutBack((c - T_UNLOCK) / 0.5, 1.6);
    else if (c >= T_DROP && c < T_SHUT) lift = 1 - easeIn((c - T_DROP) / (T_SHUT - T_DROP));
    if (c >= T_SWING && c < T_SWING_BACK) swing = SWING_OPEN * easeOutBack((c - T_SWING) / 1.0, 0.9);
    else if (c >= T_SWING_BACK && c < T_DROP) swing = SWING_OPEN * (1 - easeInOut((c - T_SWING_BACK) / (T_DROP - T_SWING_BACK - 0.05)));
    // « Clac » de la fermeture : rebond amorti de tout le cadenas.
    if (c >= T_SHUT && c < T_SHUT + 1) jolt = Math.exp(-(c - T_SHUT) * 6) * Math.sin((c - T_SHUT) * 34);
    var open = c >= T_UNLOCK && c < T_SHUT;
    var glow = open ? 0.25 + 0.75 * smooth((c - T_UNLOCK) / 0.5) : 0.25 + 0.75 * (c >= T_SHUT ? Math.max(0, 1 - (c - T_SHUT) / 0.6) : 0);
    return { lift: lift, swing: swing, jolt: jolt, open: open, glow: glow };
  }

  // Avancement du déchiffrement (0 = tout chiffré, 1 = tout clair).
  function textProgress(c) {
    if (c < T_UNLOCK) return 0;
    if (c < T_UNLOCK + 1.8) return (c - T_UNLOCK) / 1.8;
    if (c < T_SWING_BACK) return 1;
    if (c < T_SHUT) return 1 - (c - T_SWING_BACK) / (T_SHUT - T_SWING_BACK);
    return 0;
  }

  var textEl = document.getElementById("hero-decrypt-text");
  var plain = textEl ? textEl.textContent : "";
  var CIPHER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function randomChar() { return CIPHER_CHARS.charAt(Math.floor(Math.random() * CIPHER_CHARS.length)); }
  function newCipher() {
    var out = "";
    for (var i = 0; i < plain.length; i++) out += plain.charAt(i) === " " ? " " : randomChar();
    return out;
  }
  var cipher = newCipher();
  var lastText = null;
  function renderText(k) {
    var text;
    if (k >= 1) {
      text = plain;
    } else {
      // Front de déchiffrement de gauche à droite, quelques caractères qui
      // s'agitent juste devant lui. Chasse fixe et espaces gardés : le
      // paragraphe ne change jamais de forme.
      var n = plain.length;
      var parts = [];
      for (var i = 0; i < n; i++) {
        var ch = plain.charAt(i);
        var at = (i / n) * 1.05;
        if (ch === " ") parts.push(" ");
        else if (k >= at + 0.05) parts.push(ch);
        else if (k >= at - 0.01 && k > 0) parts.push(randomChar());
        else parts.push(cipher.charAt(i));
      }
      text = parts.join("");
    }
    if (text !== lastText) {
      textEl.textContent = text;
      lastText = text;
    }
  }

  var lastOpen = null;
  function renderStatus(open) {
    if (open === lastOpen) return;
    lastOpen = open;
    statusEl.classList.toggle("open", open);
    // Textes de la page (data-open / data-locked) : français ou anglais.
    statusTextEl.textContent = open ? statusEl.getAttribute("data-open") : statusEl.getAttribute("data-locked");
  }

  // Orientation : le cadenas se tourne vers le curseur (jusqu'à ~50° de côté,
  // ~25° en hauteur) ; sans pointeur sur la page, lent balancement. Position
  // du curseur relative au centre du cadenas, en demi-fenêtres.
  var FOLLOW_YAW = 0.85, FOLLOW_PITCH = 0.45;
  var pointer = { x: 0, y: 0, active: false }, tilt = { x: 0, y: 0 }, follow = 0;
  if (hasLock) window.addEventListener("pointermove", function (e) {
    var r = stage.getBoundingClientRect();
    pointer.x = Math.max(-1, Math.min(1, (e.clientX - (r.left + r.width / 2)) / (window.innerWidth / 2)));
    pointer.y = Math.max(-1, Math.min(1, (e.clientY - (r.top + r.height / 2)) / (window.innerHeight / 2)));
    pointer.active = true;
  }, { passive: true });
  var pointerGone = function () { pointer.active = false; pointer.x = 0; pointer.y = 0; };
  document.documentElement.addEventListener("pointerleave", pointerGone);
  window.addEventListener("blur", pointerGone);

  if (!hasLock) {
    // Rien à animer en haut de page.
  } else if (reducedMotion) {
    // Image fixe : cadenas fermé de trois quarts, texte en clair.
    renderText(1);
    renderStatus(false);
    var still = function () {
      if (!renderer) return;
      renderer.resize();
      renderer.draw({ lift: 0, swing: 0, glow: 0.3, yaw: -0.12, pitch: -0.15, bob: 0 });
    };
    still();
    window.addEventListener("resize", still);
  } else {
    renderText(0);
    var visible = true;
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) { visible = entries[0].isIntersecting; }).observe(stage);
    }
    if (renderer && "ResizeObserver" in window) new ResizeObserver(renderer.resize).observe(canvas);
    var start = performance.now();
    var previous = start, slowFrames = 0, prevCycle = 0;
    var loop = function (now) {
      requestAnimationFrame(loop);
      var dt = now - previous;
      previous = now;
      var time = (now - start) / 1000;
      var c = time % CYCLE;
      if (c < prevCycle) cipher = newCipher(); // nouveau message chiffré à chaque tour
      prevCycle = c;
      var s = lockState(c);
      renderText(textProgress(c));
      renderStatus(s.open);
      if (!renderer || !visible || document.hidden) return;
      // Suivi lissé (réponse vive mais sans à-coups) ; le balancement
      // s'efface pendant le suivi et revient quand le curseur quitte la page.
      tilt.x += (pointer.x - tilt.x) * 0.12;
      tilt.y += (pointer.y - tilt.y) * 0.12;
      follow += ((pointer.active ? 1 : 0) - follow) * 0.05;
      var sway = 1 - 0.75 * follow;
      s.yaw = -0.12 + sway * 0.16 * Math.sin(time * 0.3) + tilt.x * FOLLOW_YAW;
      s.pitch = -0.15 + sway * 0.04 * Math.sin(time * 0.45) + tilt.y * FOLLOW_PITCH + s.jolt * 0.03;
      s.bob = 0.025 * Math.sin(time * 0.9) - s.jolt * 0.015;
      renderer.draw(s);
      // Images trop lentes (plus de 28 ms) plusieurs fois de suite : résolution réduite.
      if (dt > 28 && dt < 200) slowFrames++; else slowFrames = Math.max(0, slowFrames - 1);
      if (slowFrames > 20) { renderer.slower(); slowFrames = 0; }
    };
    requestAnimationFrame(loop);
  }

  // ===== Sections : animation jouée à l'arrivée à l'écran ===================
  var sections = Array.prototype.slice.call(document.querySelectorAll(".feature, .section, .status"));
  var dots = Array.prototype.slice.call(document.querySelectorAll(".dots .dot"));
  if (reducedMotion || !("IntersectionObserver" in window)) {
    sections.forEach(function (s) { s.classList.add("play"); });
  } else {
    var playObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        // Rejouée à chaque visite : réarmée une fois la section sortie de l'écran.
        if (entry.intersectionRatio >= 0.3) entry.target.classList.add("play");
        else if (!entry.isIntersecting) entry.target.classList.remove("play");
      });
    }, { threshold: [0, 0.3] });
    sections.forEach(function (s) { playObserver.observe(s); });
  }

  // Point de navigation actif : la section qui occupe le plus l'écran.
  var ratios = new Map();
  if ("IntersectionObserver" in window) {
    var dotObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) { ratios.set(entry.target.id, entry.intersectionRatio); });
      var best = null, bestRatio = 0;
      ratios.forEach(function (ratio, id) { if (ratio > bestRatio) { bestRatio = ratio; best = id; } });
      dots.forEach(function (dot) { dot.classList.toggle("active", bestRatio > 0 && dot.getAttribute("href") === "#" + best); });
    }, { threshold: [0, 0.2, 0.4, 0.6, 0.8, 1] });
    sections.forEach(function (s) { dotObserver.observe(s); });
  }
  // ===== Thème clair / sombre =============================================
  // Choix gardé dans le navigateur (le thème est posé avant l'affichage par
  // un petit script en tête de page) ; libellé du bouton selon la langue.
  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    var syncToggle = function () {
      var light = document.documentElement.getAttribute("data-theme") === "light";
      var label = toggle.getAttribute(light ? "data-to-dark" : "data-to-light");
      toggle.setAttribute("aria-label", label);
      toggle.setAttribute("title", label);
    };
    syncToggle();
    toggle.addEventListener("click", function () {
      var light = document.documentElement.getAttribute("data-theme") !== "light";
      if (light) document.documentElement.setAttribute("data-theme", "light");
      else document.documentElement.removeAttribute("data-theme");
      try { localStorage.setItem("openpgp-site-theme", light ? "light" : "dark"); } catch (e) {}
      syncToggle();
    });
  }
  // ===== Liens vers une section : bien cadrée ================================
  // Le contenu de la section (sans ses grandes marges) est centré dans la zone
  // sous le menu s'il y tient ; sinon son haut s'aligne juste sous le menu. Avant :
  // le haut de la section, marges comprises, arrivait sous le menu, avec du vide
  // en haut et le bas coupé.
  var GAP = 28;
  function navHeight() {
    var nav = document.querySelector(".nav");
    return nav ? nav.getBoundingClientRect().height : 0;
  }
  function contentOf(section) {
    return section.querySelector(":scope > .section-inner, :scope > .feature-inner, :scope > .status-inner, :scope > .deep-inner, :scope > .strip-inner") || section;
  }
  function frameTop(section) {
    if (section.id === "top" || section.classList.contains("hero")) return 0;
    var box = contentOf(section).getBoundingClientRect();
    var nav = navHeight();
    var room = window.innerHeight - nav;
    var top = box.top + window.scrollY;
    var y = box.height + 2 * GAP <= room ? top - nav - (room - box.height) / 2 : top - nav - GAP;
    return Math.max(0, Math.min(y, document.documentElement.scrollHeight - window.innerHeight));
  }
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var link = e.target.closest ? e.target.closest('a[href^="#"]') : null;
    if (!link) return;
    var id = link.getAttribute("href").slice(1);
    var target = id ? document.getElementById(id) : null;
    if (!target) return;
    e.preventDefault();
    window.scrollTo({ top: frameTop(target), behavior: reducedMotion ? "auto" : "smooth" });
    if (window.history && history.replaceState) history.replaceState(null, "", "#" + id);
  });
  // Arrivée avec une ancre (lien depuis une autre page) : même cadrage.
  if (location.hash.length > 1) {
    var initial = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (initial) {
      window.addEventListener("load", function () {
        setTimeout(function () { window.scrollTo({ top: frameTop(initial), behavior: "auto" }); }, 80);
      });
    }
  }
})();
