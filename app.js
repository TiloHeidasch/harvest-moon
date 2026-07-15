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

// Geladene Class-A-Binärdateien (classa -> Uint8Array) für Live-Lookup beim Hover.
const binCache = new Map();

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

// Quadranten-Layout aus AGENTS.md: 4 Quadranten à 8x8 Class A.
// q = Quadrant (0..3), w = Class A innerhalb des Quadranten (0..63)
function classAOffset(classa) {
  const q = classa >> 6;
  const w = classa & 63;
  const ax = (w & 7) + ((q & 1) ? 8 : 0);
  const ay = (w >> 3) + ((q & 2) ? 8 : 0);
  return [ax, ay];
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
  const overlay = document.getElementById("grid");
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

// Hover: Pixel -> Class A / Block / /24 auflösen und Tooltip + Zellen-Highlight zeigen.
function setupHover() {
  const tooltip = document.getElementById("tooltip");
  const highlight = document.getElementById("cellHighlight");

  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const fx = (e.clientX - rect.left) / rect.width;
    const fy = (e.clientY - rect.top) / rect.height;
    if (fx < 0 || fx >= 1 || fy < 0 || fy >= 1) return;

    const ix = Math.min(SIZE - 1, Math.floor(fx * SIZE));
    const iy = Math.min(SIZE - 1, Math.floor(fy * SIZE));

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

    const buf = binCache.get(classa);
    const count = buf ? buf[off] : undefined;

    const title =
      KNOWN_NETS[`${classa}.${b}.${c}`] ||
      CLASSA_NAMES[classa] ||
      `Class A ${classa}`;
    const countLabel = count === undefined ? "—" : count;

    tooltip.hidden = false;
    tooltip.innerHTML =
      `<div class="tip-title">${title}</div>` +
      `${classa}.${b}.${c}.0<br>${countLabel} Hosts`;
    tooltip.style.left = (e.clientX + 14) + "px";
    tooltip.style.top = (e.clientY + 14) + "px";

    const step = 100 / 16;
    highlight.hidden = false;
    highlight.style.left = (ax * step) + "%";
    highlight.style.top = (ay * step) + "%";
    highlight.style.width = step + "%";
    highlight.style.height = step + "%";
  });

  canvas.addEventListener("mouseleave", () => {
    tooltip.hidden = true;
    highlight.hidden = true;
  });
}

async function load() {
  const status = document.getElementById("status");
  status.textContent = "lade manifest…";

  let manifest;
  try {
    const manifestResp = await fetch(DATA_BASE + "manifest.json");
    if (!manifestResp.ok) {
      status.textContent =
        `Keine Daten auf dem 'result'-Branch (manifest.json HTTP ${manifestResp.status}). ` +
        `Erzeuge mit tools/csv2bin.py die Dateien <classa>.bin + manifest.json und pushe sie dorthin.`;
      return;
    }
    const text = await manifestResp.text();
    try {
      manifest = JSON.parse(text);
    } catch (e) {
      status.textContent = `manifest.json ist kein gültiges JSON: ${e.message}`;
      console.error("manifest body:", text);
      return;
    }
  } catch (e) {
    status.textContent = "Netzwerkfehler beim Laden von manifest.json: " + e;
    return;
  }

  if (!Array.isArray(manifest)) {
    status.textContent = "manifest.json muss ein JSON-Array von Class-A-Nummern sein.";
    return;
  }

  status.textContent = `lade ${manifest.length} Class-A-Binärdateien…`;

  buildGrid();
  setupHover();

  let done = 0;
  await Promise.all(manifest.map(async (classa) => {
    const resp = await fetch(DATA_BASE + classa + ".bin");
    if (!resp.ok) {
      console.warn(`übersprungen (HTTP ${resp.status}): ${classa}.bin`);
      done++;
      return;
    }
    const buf = new Uint8Array(await resp.arrayBuffer());
    binCache.set(classa, buf);
    const [gx, gy] = classAOffset(classa);

    for (let off = 0; off < buf.length; off++) {
      const v = buf[off];
      if (!v) continue;
      const b = off >> 8;       // classb
      const c = off & 255;      // classc
      const xin = (b & 15) * 16 + (c & 15);
      const yin = (b >> 4) * 16 + (c >> 4);
      const x = gx * CLASSA_PX + xin;
      const y = gy * CLASSA_PX + yin;
      setPixel(x, y, heat(v / 255));
    }

    done++;
    status.textContent = `lade ${done}/${manifest.length} Class A…`;
  }));

  ctx.putImageData(img, 0, 0);
  status.textContent =
    `fertig — ${manifest.length} Class A, IPv4-Gesamtübersicht (${SIZE}×${SIZE})`;
}

load().catch((e) => {
  const status = document.getElementById("status");
  status.textContent = "Fehler: " + e;
  console.error(e);
});
