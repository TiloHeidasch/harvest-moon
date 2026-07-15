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
  0:   "Reserved — „This network“ (0.0.0.0/8)",
  10:  "Private-Use (RFC 1918, 10.0.0.0/8)",
  100: "Shared Address Space / CGN (100.64.0.0/10)",
  127: "Loopback (127.0.0.0/8)",
  224: "Multicast (224.0.0.0/4)",
  240: "Reserved (240.0.0.0/4)",
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

    const title = CLASSA_NAMES[classa] || `Class A ${classa}`;
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
