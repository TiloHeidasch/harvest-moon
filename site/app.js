// Datenquelle:
//  - Site + Daten auf demselben Branch (z.B. GitHub Pages von 'results'):
//      const DATA_BASE = "./";
//  - Site auf 'gh-pages', Daten auf 'results' (raw.githubusercontent, CORS *):
//      const DATA_BASE = "https://raw.githubusercontent.com/OWNER/REPO/results/";
const DATA_BASE = "https://raw.githubusercontent.com/TiloHeidasch/harvest-moon/results/";

const SIZE = 4096;          // Gesamtbild: 4096 x 4096 Pixel
const CLASSA_PX = 256;      // eine Class A = 256 x 256 Pixel (256*256 /24)

const canvas = document.getElementById("map");
canvas.width = SIZE;
canvas.height = SIZE;
const ctx = canvas.getContext("2d");
const img = ctx.createImageData(SIZE, SIZE);

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

async function load() {
  const status = document.getElementById("status");
  status.textContent = "lade manifest…";

  const manifestResp = await fetch(DATA_BASE + "manifest.json");
  const manifest = await manifestResp.json();
  status.textContent = `lade ${manifest.length} Class-A-Binärdateien…`;

  let done = 0;
  await Promise.all(manifest.map(async (classa) => {
    const resp = await fetch(DATA_BASE + classa + ".bin");
    const buf = new Uint8Array(await resp.arrayBuffer());
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
