// Datenquelle:
//  - Site + Daten auf demselben Branch (z.B. GitHub Pages von 'result'):
//      const DATA_BASE = "./";
//  - Site auf 'gh-pages', Daten auf 'result' (raw.githubusercontent, CORS *):
//      const DATA_BASE = "https://raw.githubusercontent.com/OWNER/REPO/result/";
const DATA_BASE = "https://raw.githubusercontent.com/TiloHeidasch/harvest-moon/result/";

const SIZE = 4096;          // Gesamtbild: 4096 x 4096 Pixel
const CLASSA_PX = 256;      // eine Class A = 256 x 256 Pixel (256*256 /24)

const canvas = document.getElementById("map");
canvas.width = SIZE;
canvas.height = SIZE;
const ctx = canvas.getContext("2d");
const img = ctx.createImageData(SIZE, SIZE);

const wrap = document.getElementById("canvasWrap");
const overlay = document.getElementById("grid");

// Geladene Class-A-Binärdateien (classa -> Uint8Array) für Live-Lookup beim Hover.
const binCache = new Map();
// Last-Modified-Datum pro Class A (aus dem HTTP-Header).
const binDates = new Map();
// generated-Timestamp aus manifest.json (Fallback wenn kein Last-Modified).
let generated = null;
// Commit-Datum des result-Branches via GitHub-API (primäre Datenstands-Quelle).
let dataDate = null;

// Platzhalter: Class-A-Nummer -> zugewiesener Zweck / Inhaber (für den Tooltip-Titel).
// Nach und nach mit echten Zuweisungen füllen (z.B. aus IANA-Registrierungen).
const CLASSA_NAMES = {
  0:   "IANA - Local Identification",
  1:   "APNIC (Asia-Pacific)",
  2:   "RIPE NCC (Europe/Middle East)",
  3:   "Amazon (ex-General Electric)",
  4:   "Level 3 / Lumen",
  5:   "RIPE NCC (Europe/Middle East)",
  6:   "US Dept. of Defense (Army ISC)",
  7:   "US Dept. of Defense (DNIC)",
  8:   "Level 3 / Lumen",
  9:   "IBM",
  10:  "IANA - Private Use",
  11:  "US Dept. of Defense (Intel)",
  12:  "AT&T",
  13:  "ARIN (North America)",
  14:  "APNIC (Asia-Pacific)",
  15:  "Hewlett-Packard",
  16:  "Hewlett-Packard / DEC",
  17:  "Apple",
  18:  "MIT (partly Amazon)",
  19:  "Ford Motor Company",
  20:  "ARIN (North America)",
  21:  "US Dept. of Defense (DDN-RVN)",
  22:  "US Dept. of Defense (DISA)",
  23:  "ARIN (North America)",
  24:  "ARIN (North America)",
  25:  "UK Ministry of Defence",
  26:  "US Dept. of Defense (DISA)",
  27:  "APNIC (Asia-Pacific)",
  28:  "US Dept. of Defense (DSI-North)",
  29:  "US Dept. of Defense (DISA)",
  30:  "US Dept. of Defense (DISA)",
  31:  "RIPE NCC (Europe/Middle East)",
  32:  "ARIN (North America)",
  33:  "US Dept. of Defense (DLA)",
  34:  "ARIN (North America)",
  35:  "ARIN (North America)",
  36:  "APNIC (Asia-Pacific)",
  37:  "RIPE NCC (Europe/Middle East)",
  38:  "Cogent Communications (ex-PSINet)",
  39:  "APNIC (Asia-Pacific)",
  40:  "ARIN (North America)",
  41:  "AFRINIC (Africa)",
  42:  "APNIC (Asia-Pacific)",
  43:  "APNIC (Asia-Pacific)",
  44:  "Amazon (ex-AMPRNet, amateur radio)",
  45:  "ARIN (North America)",
  46:  "RIPE NCC (Europe/Middle East)",
  47:  "ARIN (North America)",
  48:  "Prudential Securities",
  49:  "APNIC (Asia-Pacific)",
  50:  "ARIN (North America)",
  51:  "RIPE NCC (Europe/Middle East)",
  52:  "ARIN (North America)",
  53:  "Mercedes-Benz Group",
  54:  "ARIN (North America)",
  55:  "US Dept. of Defense (DNIC)",
  56:  "US Postal Service",
  57:  "RIPE NCC (Europe/Middle East)",
  58:  "APNIC (Asia-Pacific)",
  59:  "APNIC (Asia-Pacific)",
  60:  "APNIC (Asia-Pacific)",
  61:  "APNIC (Asia-Pacific)",
  62:  "RIPE NCC (Europe/Middle East)",
  63:  "ARIN (North America)",
  64:  "ARIN (North America)",
  65:  "ARIN (North America)",
  66:  "ARIN (North America)",
  67:  "ARIN (North America)",
  68:  "ARIN (North America)",
  69:  "ARIN (North America)",
  70:  "ARIN (North America)",
  71:  "ARIN (North America)",
  72:  "ARIN (North America)",
  73:  "Comcast",
  74:  "ARIN (North America)",
  75:  "ARIN (North America)",
  76:  "ARIN (North America)",
  77:  "RIPE NCC (Europe/Middle East)",
  78:  "RIPE NCC (Europe/Middle East)",
  79:  "RIPE NCC (Europe/Middle East)",
  80:  "RIPE NCC (Europe/Middle East)",
  81:  "RIPE NCC (Europe/Middle East)",
  82:  "RIPE NCC (Europe/Middle East)",
  83:  "RIPE NCC (Europe/Middle East)",
  84:  "RIPE NCC (Europe/Middle East)",
  85:  "RIPE NCC (Europe/Middle East)",
  86:  "RIPE NCC (Europe/Middle East)",
  87:  "RIPE NCC (Europe/Middle East)",
  88:  "RIPE NCC (Europe/Middle East)",
  89:  "RIPE NCC (Europe/Middle East)",
  90:  "RIPE NCC (Europe/Middle East)",
  91:  "RIPE NCC (Europe/Middle East)",
  92:  "RIPE NCC (Europe/Middle East)",
  93:  "RIPE NCC (Europe/Middle East)",
  94:  "RIPE NCC (Europe/Middle East)",
  95:  "RIPE NCC (Europe/Middle East)",
  96:  "ARIN (North America)",
  97:  "ARIN (North America)",
  98:  "ARIN (North America)",
  99:  "ARIN (North America)",
  100: "ARIN (North America)",
  101: "APNIC (Asia-Pacific)",
  102: "AFRINIC (Africa)",
  103: "APNIC (Asia-Pacific)",
  104: "ARIN (North America)",
  105: "AFRINIC (Africa)",
  106: "APNIC (Asia-Pacific)",
  107: "ARIN (North America)",
  108: "ARIN (North America)",
  109: "RIPE NCC (Europe/Middle East)",
  110: "APNIC (Asia-Pacific)",
  111: "APNIC (Asia-Pacific)",
  112: "APNIC (Asia-Pacific)",
  113: "APNIC (Asia-Pacific)",
  114: "APNIC (Asia-Pacific)",
  115: "APNIC (Asia-Pacific)",
  116: "APNIC (Asia-Pacific)",
  117: "APNIC (Asia-Pacific)",
  118: "APNIC (Asia-Pacific)",
  119: "APNIC (Asia-Pacific)",
  120: "APNIC (Asia-Pacific)",
  121: "APNIC (Asia-Pacific)",
  122: "APNIC (Asia-Pacific)",
  123: "APNIC (Asia-Pacific)",
  124: "APNIC (Asia-Pacific)",
  125: "APNIC (Asia-Pacific)",
  126: "SoftBank (APNIC, Asia-Pacific)",
  127: "IANA - Loopback",
  128: "ARIN (North America)",
  129: "ARIN (North America)",
  130: "ARIN (North America)",
  131: "ARIN (North America)",
  132: "ARIN (North America)",
  133: "APNIC (Asia-Pacific)",
  134: "ARIN (North America)",
  135: "ARIN (North America)",
  136: "ARIN (North America)",
  137: "ARIN (North America)",
  138: "ARIN (North America)",
  139: "ARIN (North America)",
  140: "ARIN (North America)",
  141: "RIPE NCC (Europe/Middle East)",
  142: "ARIN (North America)",
  143: "ARIN (North America)",
  144: "ARIN (North America)",
  145: "RIPE NCC (Europe/Middle East)",
  146: "ARIN (North America)",
  147: "ARIN (North America)",
  148: "ARIN (North America)",
  149: "ARIN (North America)",
  150: "APNIC (Asia-Pacific)",
  151: "RIPE NCC (Europe/Middle East)",
  152: "ARIN (North America)",
  153: "APNIC (Asia-Pacific)",
  154: "AFRINIC (Africa)",
  155: "ARIN (North America)",
  156: "ARIN (North America)",
  157: "ARIN (North America)",
  158: "ARIN (North America)",
  159: "ARIN (North America)",
  160: "ARIN (North America)",
  161: "ARIN (North America)",
  162: "ARIN (North America)",
  163: "APNIC (Asia-Pacific)",
  164: "ARIN (North America)",
  165: "ARIN (North America)",
  166: "ARIN (North America)",
  167: "ARIN (North America)",
  168: "ARIN (North America)",
  169: "ARIN (North America)",
  170: "ARIN (North America)",
  171: "APNIC (Asia-Pacific)",
  172: "ARIN (North America)",
  173: "ARIN (North America)",
  174: "ARIN (North America)",
  175: "APNIC (Asia-Pacific)",
  176: "RIPE NCC (Europe/Middle East)",
  177: "LACNIC (Latin America & Caribbean)",
  178: "RIPE NCC (Europe/Middle East)",
  179: "LACNIC (Latin America & Caribbean)",
  180: "APNIC (Asia-Pacific)",
  181: "LACNIC (Latin America & Caribbean)",
  182: "APNIC (Asia-Pacific)",
  183: "APNIC (Asia-Pacific)",
  184: "ARIN (North America)",
  185: "RIPE NCC (Europe/Middle East)",
  186: "LACNIC (Latin America & Caribbean)",
  187: "LACNIC (Latin America & Caribbean)",
  188: "RIPE NCC (Europe/Middle East)",
  189: "LACNIC (Latin America & Caribbean)",
  190: "LACNIC (Latin America & Caribbean)",
  191: "LACNIC (Latin America & Caribbean)",
  192: "ARIN (North America)",
  193: "RIPE NCC (Europe/Middle East)",
  194: "RIPE NCC (Europe/Middle East)",
  195: "RIPE NCC (Europe/Middle East)",
  196: "AFRINIC (Africa)",
  197: "AFRINIC (Africa)",
  198: "ARIN (North America)",
  199: "ARIN (North America)",
  200: "LACNIC (Latin America & Caribbean)",
  201: "LACNIC (Latin America & Caribbean)",
  202: "APNIC (Asia-Pacific)",
  203: "APNIC (Asia-Pacific)",
  204: "ARIN (North America)",
  205: "ARIN (North America)",
  206: "ARIN (North America)",
  207: "ARIN (North America)",
  208: "ARIN (North America)",
  209: "ARIN (North America)",
  210: "APNIC (Asia-Pacific)",
  211: "APNIC (Asia-Pacific)",
  212: "RIPE NCC (Europe/Middle East)",
  213: "RIPE NCC (Europe/Middle East)",
  214: "US Dept. of Defense",
  215: "US Dept. of Defense",
  216: "ARIN (North America)",
  217: "RIPE NCC (Europe/Middle East)",
  218: "APNIC (Asia-Pacific)",
  219: "APNIC (Asia-Pacific)",
  220: "APNIC (Asia-Pacific)",
  221: "APNIC (Asia-Pacific)",
  222: "APNIC (Asia-Pacific)",
  223: "APNIC (Asia-Pacific)",
  224: "Multicast",
  225: "Multicast",
  226: "Multicast",
  227: "Multicast",
  228: "Multicast",
  229: "Multicast",
  230: "Multicast",
  231: "Multicast",
  232: "Multicast",
  233: "Multicast",
  234: "Multicast",
  235: "Multicast",
  236: "Multicast",
  237: "Multicast",
  238: "Multicast",
  239: "Multicast",
  240: "Future use",
  241: "Future use",
  242: "Future use",
  243: "Future use",
  244: "Future use",
  245: "Future use",
  246: "Future use",
  247: "Future use",
  248: "Future use",
  249: "Future use",
  250: "Future use",
  251: "Future use",
  252: "Future use",
  253: "Future use",
  254: "Future use",
  255: "Future use",
};

// Bekannte /24-Netze (Key = "A.B.C") -> Name. Überschreibt im Tooltip den Class-A-Titel,
// damit z.B. 8.8.8.0 als „Google Public DNS“ statt „Level 3 / Lumen“ erscheint.
const KNOWN_NETS = {
  "8.8.8":       "Google Public DNS",
  "8.8.4":       "Google Public DNS",
  "1.1.1":       "Cloudflare DNS",
  "1.0.0":       "Cloudflare DNS",
  "9.9.9":       "Quad9 DNS",
  "208.67.222":  "Cisco OpenDNS",
  "208.67.220":  "Cisco OpenDNS",
  "4.2.2":       "Level 3 / Lumen DNS",
};

// Heatmap (linear): 0 -> Hintergrund, dann blau -> grün -> gelb -> rot
const STOPS = [
  [0.00, [0, 0, 90]],
  [0.25, [0, 120, 255]],
  [0.50, [0, 230, 120]],
  [0.75, [255, 230, 0]],
  [1.00, [255, 50, 0]],
];
const BG = [8, 8, 18];

function heat(t) {
  if (t <= 0) return BG;
  t = Math.min(1, t);
  for (let i = 1; i < STOPS.length; i++) {
    if (t <= STOPS[i][0]) {
      const [t0, c0] = STOPS[i - 1];
      const [t1, c1] = STOPS[i];
      const f = (t - t0) / (t1 - t0);
      return [
        c0[0] + (c1[0] - c0[0]) * f,
        c0[1] + (c1[1] - c0[1]) * f,
        c0[2] + (c1[2] - c0[2]) * f,
      ];
    }
  }
  return STOPS[STOPS.length - 1][1];
}

// Quadranten-Layout: 4 Quadranten à 8x8 Class A.
// q = Quadrant (0..3), w = Class A innerhalb des Quadranten (0..63)
function classAOffset(classa) {
  const q = classa >> 6;
  const w = classa & 63;
  const ax = (w & 7) + ((q & 1) ? 8 : 0);
  const ay = (w >> 3) + ((q & 2) ? 8 : 0);
  return [ax, ay];
}

// Umkehrung: globale Pixel (ix, iy) -> Class A / Block / /24.
function resolve(ix, iy) {
  const ax = Math.floor(ix / CLASSA_PX);
  const ay = Math.floor(iy / CLASSA_PX);
  const q = (ax >= 8 ? 1 : 0) | (ay >= 8 ? 2 : 0);
  const w = ((ay & 7) << 3) | (ax & 7);
  const classa = (q << 6) | w;

  const xin = ix - ax * CLASSA_PX;
  const yin = iy - ay * CLASSA_PX;
  const b = ((yin >> 4) << 4) | (xin >> 4);
  const c = ((yin & 15) << 4) | (xin & 15);
  const off = b * 256 + c;
  const bx = b & 15;
  const by = b >> 4;
  return { classa, b, c, off, bx, by };
}

function setPixel(x, y, rgb) {
  const idx = (y * SIZE + x) * 4;
  img.data[idx] = rgb[0];
  img.data[idx + 1] = rgb[1];
  img.data[idx + 2] = rgb[2];
  img.data[idx + 3] = 255;
}

// Faint grid overlay: major lines + Class-A labels (0–255), drawn in %-Koordinaten,
// damit es bei jeder Canvas-Skalierung scharf bleibt.
function buildGrid() {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("preserveAspectRatio", "none");

  const step = 100 / 16; // 6.25% pro Class A
  for (let i = 0; i <= 16; i++) {
    const p = (i * step).toFixed(4);
    const v = document.createElementNS(NS, "line");
    v.setAttribute("x1", p); v.setAttribute("y1", "0");
    v.setAttribute("x2", p); v.setAttribute("y2", "100");
    if (i % 8 === 0) v.setAttribute("class", "quad");
    svg.appendChild(v);

    const h = document.createElementNS(NS, "line");
    h.setAttribute("x1", "0"); h.setAttribute("y1", p);
    h.setAttribute("x2", "100"); h.setAttribute("y2", p);
    if (i % 8 === 0) h.setAttribute("class", "quad");
    svg.appendChild(h);
  }

  for (let classa = 0; classa < 256; classa++) {
    const [ax, ay] = classAOffset(classa);
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", ((ax + 0.5) * step).toFixed(4));
    t.setAttribute("y", ((ay + 0.5) * step).toFixed(4));
    t.textContent = classa;
    svg.appendChild(t);
  }

  overlay.appendChild(svg);
}

// Overlay (Grid + Highlights) an die tatsächliche Canvas-Größe koppeln,
// damit es beim Zoom mitscrollt.
function syncOverlay() {
  overlay.style.width = canvas.clientWidth + "px";
  overlay.style.height = canvas.clientHeight + "px";
}

// --- Infopanel ---------------------------------------------------------------

const infoEmpty = document.getElementById("infoEmpty");
const infoDl = document.getElementById("infoDl");
const infoNet = document.getElementById("infoNet");
const infoName = document.getElementById("infoName");
const infoHosts = document.getElementById("infoHosts");
const infoClassA = document.getElementById("infoClassA");

function showInfo(classa, b, c, count) {
  const title =
    KNOWN_NETS[`${classa}.${b}.${c}`] ||
    CLASSA_NAMES[classa] ||
    `Class A ${classa}`;
  const countLabel = count === undefined ? "— (keine Daten)" : count;

  infoEmpty.hidden = true;
  infoDl.hidden = false;
  infoNet.textContent = `${classa}.${b}.${c}.0`;
  infoName.textContent = title;
  infoHosts.textContent = countLabel;
  infoClassA.textContent = `${classa} (${CLASSA_NAMES[classa] || "unbekannt"})`;

  // Floating-Tooltip ebenfalls aktualisieren.
  const tooltip = document.getElementById("tooltip");
  tooltip.hidden = false;
  tooltip.innerHTML =
    `<div class="tip-title">${title}</div>` +
    `${classa}.${b}.${c}.0<br>${countLabel} Hosts`;
}

// --- Highlights --------------------------------------------------------------

const cellHighlight = document.getElementById("cellHighlight");
const blockHighlight = document.getElementById("blockHighlight");

function setHighlights(classa, bx, by) {
  const step = 100 / 16;
  const [ax, ay] = classAOffset(classa);

  cellHighlight.hidden = false;
  cellHighlight.style.left = (ax * step) + "%";
  cellHighlight.style.top = (ay * step) + "%";
  cellHighlight.style.width = step + "%";
  cellHighlight.style.height = step + "%";

  const bstep = step / 16;
  blockHighlight.hidden = false;
  blockHighlight.style.left = (ax * step + bx * bstep) + "%";
  blockHighlight.style.top = (ay * step + by * bstep) + "%";
  blockHighlight.style.width = bstep + "%";
  blockHighlight.style.height = bstep + "%";
}

function clearBlockHighlight() {
  blockHighlight.hidden = true;
}

// --- Zoom / Navigation -------------------------------------------------------

let zoomedClassA = null;

function zoomToClassA(classa) {
  const [ax, ay] = classAOffset(classa);
  // Canvas so vergrößern, dass eine Class A exakt die sichtbare Breite füllt.
  const target = wrap.clientWidth * 16;
  canvas.style.width = target + "px";
  canvas.style.height = "auto";
  syncOverlay();
  // Echte Anzeige-Breite einer Class A in Inhalt-Pixeln (canvas, nicht der
  // durch Scrollbars verkleinerte Viewport) — das ist der Maßstab für Scroll.
  const classAViewW = canvas.clientWidth / 16;
  // Class A oben links im Viewport platzieren (linke obere Ecke = Class-A-Ecke).
  wrap.scrollLeft = ax * classAViewW;
  wrap.scrollTop = ay * classAViewW;
  zoomedClassA = classa;
  document.getElementById("resetBtn").hidden = false;
}

function resetZoom() {
  canvas.style.width = "";
  canvas.style.height = "";
  syncOverlay();
  wrap.scrollLeft = 0;
  wrap.scrollTop = 0;
  zoomedClassA = null;
  document.getElementById("resetBtn").hidden = true;
  cellHighlight.hidden = true;
  clearBlockHighlight();
}

// Springt zu einem Class A (und ggf. einem /24) und hebt es hervor.
// centerNet: bei true das konkrete /24 zentrieren (Suche nach IP),
// bei false die Class A oben links im Viewport ausrichten (Klick).
function gotoClassA(classa, b, c, centerNet) {
  if (zoomedClassA !== classa) zoomToClassA(classa);

  const buf = binCache.get(classa);
  const off = (b << 8) | c;
  const count = buf ? buf[off] : undefined;
  const bx = b & 15;
  const by = b >> 4;

  setHighlights(classa, bx, by);
  showInfo(classa, b, c, count);

  if (centerNet) {
    const [ax, ay] = classAOffset(classa);
    const classAViewW = canvas.clientWidth / 16;
    // Position des /24 innerhalb der Class A (in Anzeige-Pixeln).
    const xin = (bx & 15) * 16 + (c & 15);
    const yin = (by >> 4) * 16 + (c >> 4);
    wrap.scrollLeft = ax * classAViewW + (xin / 256) * classAViewW - classAViewW / 2;
    wrap.scrollTop = ay * classAViewW + (yin / 256) * classAViewW - classAViewW / 2;
  }
}

// --- Hover -------------------------------------------------------------------

function setupHover() {
  const tooltip = document.getElementById("tooltip");

  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const fx = (e.clientX - rect.left) / rect.width;
    const fy = (e.clientY - rect.top) / rect.height;
    if (fx < 0 || fx >= 1 || fy < 0 || fy >= 1) return;

    const ix = Math.min(SIZE - 1, Math.floor(fx * SIZE));
    const iy = Math.min(SIZE - 1, Math.floor(fy * SIZE));
    const { classa, b, c, off, bx, by } = resolve(ix, iy);
    const buf = binCache.get(classa);
    const count = buf ? buf[off] : undefined;

    setHighlights(classa, bx, by);
    showInfo(classa, b, c, count);

    tooltip.style.left = (e.clientX + 14) + "px";
    tooltip.style.top = (e.clientY + 14) + "px";
  });

  canvas.addEventListener("mouseleave", () => {
    tooltip.hidden = true;
    clearBlockHighlight();
  });

  // Klick zoomt in die Class A unter dem Cursor.
  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const fx = (e.clientX - rect.left) / rect.width;
    const fy = (e.clientY - rect.top) / rect.height;
    if (fx < 0 || fx >= 1 || fy < 0 || fy >= 1) return;
    const ix = Math.min(SIZE - 1, Math.floor(fx * SIZE));
    const iy = Math.min(SIZE - 1, Math.floor(fy * SIZE));
    const { classa, b, c } = resolve(ix, iy);
    gotoClassA(classa, b, c, false);
  });
}

// --- Suche -------------------------------------------------------------------

function setupSearch() {
  const input = document.getElementById("searchInput");
  const btn = document.getElementById("searchBtn");
  const msg = document.getElementById("searchMsg");

  function run() {
    const raw = input.value.trim();
    if (!raw) { msg.textContent = ""; return; }
    // Class A als bloße Zahl?
    if (/^\d{1,3}$/.test(raw)) {
      const n = parseInt(raw, 10);
      if (n > 255) { msg.textContent = "Class A muss zwischen 0 und 255 liegen."; return; }
      msg.textContent = "";
      gotoClassA(n, 0, 0, false);
      return;
    }
    // IPv4 (A.B.C[.0])?
    const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\.(\d{1,3}))?$/);
    if (m) {
      const a = +m[1], b = +m[2], c = +m[3];
      if (a > 255 || b > 255 || c > 255) {
        msg.textContent = "Ungültige IP: jeder Teil muss ≤ 255 sein."; return;
      }
      msg.textContent = "";
      gotoClassA(a, b, c, true);
      return;
    }
    msg.textContent = "Bitte eine Zahl (0–255) oder eine IP wie 8.8.8.0 eingeben.";
  }

  btn.addEventListener("click", run);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
}

// --- Laden -------------------------------------------------------------------

async function load() {

  let manifest;
  generated = null;
  try {
    const manifestResp = await fetch(DATA_BASE + "manifest.json");
    if (!manifestResp.ok) {
      console.error(`Keine Daten: manifest.json HTTP ${manifestResp.status}`);
      return;
    }
    const text = await manifestResp.text();
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        manifest = parsed;
      } else {
        manifest = parsed.classas || [];
        generated = parsed.generated || null;
      }
    } catch (e) {
      console.error(`manifest.json ungültig: ${e.message}`, text);
      return;
    }
  } catch (e) {
    console.error("Netzwerkfehler manifest.json:", e);
    return;
  }

  if (!Array.isArray(manifest) || manifest.length === 0) {
    console.error("manifest.json enthält keine Class-A-Bereiche.");
    return;
  }

  // Datum des letzten Commits auf dem result-Branch via GitHub-API.
  try {
    const branchResp = await fetch("https://api.github.com/repos/TiloHeidasch/harvest-moon/branches/result");
    if (branchResp.ok) {
      const branchData = await branchResp.json();
      const commitDate = branchData?.commit?.commit?.committer?.date;
      if (commitDate) dataDate = new Date(commitDate);
    }
  } catch (e) {
    console.warn("GitHub-API nicht erreichbar:", e);
  }

  buildGrid();
  syncOverlay();
  setupHover();
  setupSearch();
  document.getElementById("resetBtn")
    .addEventListener("click", resetZoom);
  window.addEventListener("resize", syncOverlay);

  let done = 0;
  let totalNetworks = 0;
  let totalHosts = 0;
  let newestBin = null;
  await Promise.all(manifest.map(async (classa) => {
    const resp = await fetch(DATA_BASE + classa + ".bin");
    if (!resp.ok) {
      console.warn(`übersprungen (HTTP ${resp.status}): ${classa}.bin`);
      done++;
      return;
    }
    const buf = new Uint8Array(await resp.arrayBuffer());
    binCache.set(classa, buf);

    const lm = resp.headers.get("last-modified");
    if (lm) {
      const d = new Date(lm);
      binDates.set(classa, d);
      if (!newestBin || d > newestBin) newestBin = d;
    }
    const [gx, gy] = classAOffset(classa);

    for (let off = 0; off < buf.length; off++) {
      const v = buf[off];
      if (!v) continue;
      totalNetworks++;
      totalHosts += v;
      const b = off >> 8;       // classb
      const c = off & 255;      // classc
      const xin = (b & 15) * 16 + (c & 15);
      const yin = (b >> 4) * 16 + (c >> 4);
      const x = gx * CLASSA_PX + xin;
      const y = gy * CLASSA_PX + yin;
      setPixel(x, y, heat(v / 255));
    }

    done++;
  }));

  ctx.putImageData(img, 0, 0);
  syncOverlay();

  // Statistik anzeigen.
  const stats = document.getElementById("stats");
  stats.hidden = false;
  document.getElementById("statClassA").textContent =
    `${manifest.length} von 256 Class-A-Bereichen`;
  document.getElementById("statNetworks").textContent =
    `${totalNetworks.toLocaleString("de-DE")} /24 mit Hosts`;
  document.getElementById("statHosts").textContent =
    `${totalHosts.toLocaleString("de-DE")} live Hosts gesamt`;
  const updated = dataDate || newestBin || (generated ? new Date(generated) : null);
  document.getElementById("statUpdated").textContent =
    `Zuletzt aktualisiert: ${updated ? updated.toLocaleString("de-DE") : "unbekannt"}`;
}

load().catch((e) => {
  console.error("Fehler beim Laden:", e);
});
