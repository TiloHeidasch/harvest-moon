const SHA = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SOURCE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const API = "https://api.github.com/repos/TiloHeidasch/harvest-moon/branches/result";
const RAW = "https://raw.githubusercontent.com/TiloHeidasch/harvest-moon/";

function invalid(message) { throw new Error(`Datenvertrag verletzt: ${message}`); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function exactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) invalid(`${label} enthält unbekannte oder fehlende Felder`);
}
function safeClassa(value) { return Number.isInteger(value) && value >= 0 && value <= 255; }
function safePath(value, classa) { return value === `${classa}.bin` && !value.includes("/") && !value.includes("\\"); }
function safeCoveragePath(value, classa) {
  return typeof value === "string" && value === `coverage/${classa}.json` && !value.includes("\\");
}
function safeDigest(value) { return typeof value === "string" && HEX64.test(value); }
function safeSourceDigest(value) { return typeof value === "string" && SOURCE_DIGEST.test(value); }

export function validateManifest(manifest) {
  if (!object(manifest)) invalid("Manifest ist kein Objekt");
  exactKeys(manifest, ["schema", "schema_version", "classas", "assets"], "Manifest");
  if (manifest.schema !== "harvest-moon.manifest" || manifest.schema_version !== 2) invalid("Schema-Version");
  if (!Array.isArray(manifest.classas) || !manifest.classas.length) invalid("classas muss nichtleer sein");
  if (manifest.classas.some((value, i) => !safeClassa(value) || (i && value <= manifest.classas[i - 1]))) invalid("classas muss eindeutig und sortiert sein");
  if (!Array.isArray(manifest.assets) || manifest.assets.length !== manifest.classas.length) invalid("assets/classas stimmen nicht überein");
  const seen = new Set();
  manifest.assets.forEach((asset, i) => {
    if (!object(asset)) invalid(`asset ${i} ist kein Objekt`);
    exactKeys(asset, ["classa", "path", "byte_length", "sha256", "source_digest", "coverage_status", "coverage_path", "coverage_digest", "coverage_summary", "coverage"], `Asset ${i}`);
    const classa = asset.classa;
    if (!safeClassa(classa) || classa !== manifest.classas[i] || seen.has(classa)) invalid(`Asset ${i} gehört nicht zu Class A`);
    seen.add(classa);
    if (!safePath(asset.path, classa) || asset.byte_length !== 65536 || !safeDigest(asset.sha256) || !safeSourceDigest(asset.source_digest)) invalid(`Asset ${classa} ist inkonsistent`);
    if (!["V", "U"].includes(asset.coverage_status)) invalid(`Coverage-Status von ${classa}`);
    if (!object(asset.coverage) || asset.coverage.status !== asset.coverage_status || asset.coverage.path !== asset.coverage_path || asset.coverage.digest !== asset.coverage_digest || JSON.stringify(asset.coverage.summary) !== JSON.stringify(asset.coverage_summary)) invalid(`Coverage-Metadaten von ${classa}`);
    exactKeys(asset.coverage, ["status", "path", "digest", "summary"], `Coverage ${classa}`);
    if (!object(asset.coverage_summary)) invalid(`Coverage-Summary von ${classa}`);
    exactKeys(asset.coverage_summary, ["S", "Z", "E", "F", "U"], `Coverage-Summary ${classa}`);
    if (Object.values(asset.coverage_summary).some(value => !Number.isInteger(value) || value < 0) || Object.values(asset.coverage_summary).reduce((a, b) => a + b, 0) !== 65536) invalid(`Coverage-Summary von ${classa} ist ungültig`);
    if (asset.coverage_status === "U") {
      const legacyUnverified = asset.coverage_path === null && asset.coverage_digest === null;
      const partialUnverified = safeCoveragePath(asset.coverage_path, classa) && safeDigest(asset.coverage_digest);
      if (legacyUnverified) {
        if (asset.coverage_summary.U !== 65536 || Object.entries(asset.coverage_summary).some(([key, value]) => key !== "U" && value !== 0)) invalid(`U-Coverage von ${classa}`);
      } else if (partialUnverified) {
        if (asset.coverage_summary.U <= 0 || asset.coverage_summary.F !== 0) invalid(`U-Coverage von ${classa}`);
      } else {
        invalid(`U-Coverage von ${classa}`);
      }
    } else {
      if (!safeCoveragePath(asset.coverage_path, classa) || !safeDigest(asset.coverage_digest) || asset.coverage_summary.U !== 0 || asset.coverage_summary.F !== 0) invalid(`V-Coverage von ${classa}`);
    }
  });
  return manifest;
}

async function responseBody(response, label) {
  if (!response || !response.ok) invalid(`${label} HTTP ${response?.status ?? "unbekannt"}`);
  return response;
}

export async function loadResult({ fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto, now = Date.now, onProgress } = {}) {
  if (typeof fetchImpl !== "function") throw new Error("Kein Netzwerkzugriff verfügbar");
  const apiResponse = await responseBody(await fetchImpl(`${API}?cachebust=${now()}`, { cache: "no-store" }), "Branch-Auflösung");
  const branch = await apiResponse.json();
  const sha = branch?.commit?.sha;
  const dateText = branch?.commit?.commit?.committer?.date;
  if (!SHA.test(sha || "") || typeof dateText !== "string" || !Number.isFinite(Date.parse(dateText))) invalid("Branch liefert keinen unveränderlichen Commit mit Datum");
  const commitDate = new Date(dateText);
  const manifestResponse = await responseBody(await fetchImpl(`${RAW}${sha}/manifest.json`), "manifest.json");
  let manifest;
  try { manifest = JSON.parse(await manifestResponse.text()); } catch { invalid("manifest.json ist kein gültiges JSON"); }
  validateManifest(manifest);
  let verified = 0;
  const entries = await Promise.all(manifest.assets.map(async asset => {
    const response = await responseBody(await fetchImpl(`${RAW}${sha}/${asset.path}`), `${asset.path}`);
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength !== asset.byte_length || buffer.byteLength !== 65536) invalid(`${asset.path} hat die falsche Länge`);
    if (!cryptoImpl?.subtle?.digest) throw new Error("Web Crypto SHA-256 ist nicht verfügbar");
    const digest = [...new Uint8Array(await cryptoImpl.subtle.digest("SHA-256", buffer))].map(byte => byte.toString(16).padStart(2, "0")).join("");
    if (digest !== asset.sha256) invalid(`SHA-256-Prüfung für ${asset.path} fehlgeschlagen`);
    verified += 1;
    onProgress?.(verified, manifest.assets.length);
    return [asset.classa, new Uint8Array(buffer), asset.coverage_status];
  }));
  return { manifest, assets: new Map(entries.map(([classa, bytes]) => [classa, bytes])), commitSha: sha, commitDate, hasUnverified: entries.some(([, , status]) => status === "U") };
}

export const loaderUrls = { API, RAW };
