import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { loadResult, validateManifest } from "../site/result-loader.mjs";

const sha = "0123456789abcdef0123456789abcdef01234567";
const bytes = new Uint8Array(65536);
const digest = [...new Uint8Array(await webcrypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
const sourceDigest = `sha256:${"a".repeat(64)}`;
const summary = { S: 0, Z: 0, E: 0, F: 0, U: 65536 };
function converterContractAsset(extra = {}) {
  return { classa: 8, path: "8.bin", byte_length: 65536, sha256: digest, source_digest: sourceDigest, coverage_status: "U", coverage_path: null, coverage_digest: null, coverage_summary: summary, coverage: { status: "U", path: null, digest: null, summary }, ...extra };
}
function manifest(extra = {}, assetExtra = {}) {
  const asset = converterContractAsset(assetExtra);
  return { schema: "harvest-moon.manifest", schema_version: 2, classas: [8], assets: [asset], ...extra };
}
function response(body, ok = true, status = 200) {
  return { ok, status, async json() { return body; }, async text() { return JSON.stringify(body); }, async arrayBuffer() { return body.buffer; } };
}
function fetchMock(manifestValue = manifest(), binary = bytes, status = 200) {
  const urls = [];
  const fetchImpl = async url => {
    urls.push(url);
    if (url.includes("branches/result")) return response({ commit: { sha, commit: { committer: { date: "2026-07-31T12:00:00Z" } } } });
    if (url.endsWith("manifest.json")) return response(manifestValue);
    return response(binary, status === 200, status);
  };
  return { fetchImpl, urls };
}

test("resolves one SHA, fetches only SHA-pinned assets, uses commit timestamp, and signals U", async () => {
  const mock = fetchMock();
  const result = await loadResult({ fetchImpl: mock.fetchImpl, cryptoImpl: webcrypto, now: () => 42 });
  assert.equal(mock.urls.filter(url => url.includes("branches/result")).length, 1);
  assert.ok(mock.urls.slice(1).every(url => url.includes(`/${sha}/`)));
  assert.equal(result.commitDate.toISOString(), "2026-07-31T12:00:00.000Z");
  assert.equal(result.hasUnverified, true);
  assert.equal(result.assets.get(8).byteLength, 65536);
});

test("accepts partial canonical U coverage and signals unverified data", async () => {
  const partialSummary = { S: 256, Z: 64000, E: 128, F: 0, U: 1152 };
  const partial = manifest({}, {
    coverage_path: "coverage/8.json",
    coverage_digest: "b".repeat(64),
    coverage_summary: partialSummary,
    coverage: { status: "U", path: "coverage/8.json", digest: "b".repeat(64), summary: partialSummary },
  });
  const result = await loadResult({ fetchImpl: fetchMock(partial).fetchImpl, cryptoImpl: webcrypto });
  assert.equal(result.hasUnverified, true);
});

test("accepts path-backed canonical all-U coverage", async () => {
  const allU = manifest({}, {
    coverage_path: "coverage/8.json",
    coverage_digest: "c".repeat(64),
    coverage: { status: "U", path: "coverage/8.json", digest: "c".repeat(64), summary },
  });
  const result = await loadResult({ fetchImpl: fetchMock(allU).fetchImpl, cryptoImpl: webcrypto });
  assert.equal(result.hasUnverified, true);
});

test("loads a converter-contract asset with a qualified source digest", async () => {
  const asset = converterContractAsset();
  assert.match(asset.source_digest, /^sha256:[0-9a-f]{64}$/);
  const result = await loadResult({ fetchImpl: fetchMock(manifest({}, asset)).fetchImpl, cryptoImpl: webcrypto });
  assert.equal(result.assets.get(asset.classa).byteLength, 65536);
});

test("requires a lowercase sha256-qualified source digest", () => {
  for (const source_digest of [
    "a".repeat(64),
    `sha256:${"A".repeat(64)}`,
    `sha512:${"a".repeat(64)}`,
    `sha256:${"g".repeat(64)}`,
  ]) {
    assert.throws(() => validateManifest(manifest({}, { source_digest })));
  }
});

test("rejects invalid U coverage metadata", () => {
  const partialSummary = { S: 256, Z: 64000, E: 128, F: 0, U: 1152 };
  const partial = {
    coverage_path: "coverage/8.json",
    coverage_digest: "b".repeat(64),
    coverage_summary: partialSummary,
    coverage: { status: "U", path: "coverage/8.json", digest: "b".repeat(64), summary: partialSummary },
  };
  const invalid = [
    { ...partial, coverage_digest: null, coverage: { ...partial.coverage, digest: null } },
    { ...partial, coverage_path: "../coverage/8.json", coverage: { ...partial.coverage, path: "../coverage/8.json" } },
    { ...partial, coverage_digest: "g".repeat(64), coverage: { ...partial.coverage, digest: "g".repeat(64) } },
    { ...partial, coverage_summary: { S: 256, Z: 65280, E: 0, F: 0, U: 0 }, coverage: { ...partial.coverage, summary: { S: 256, Z: 65280, E: 0, F: 0, U: 0 } } },
    { ...partial, coverage_summary: { S: 0, Z: 0, E: 0, F: 1, U: 65535 }, coverage: { ...partial.coverage, summary: { S: 0, Z: 0, E: 0, F: 1, U: 65535 } } },
  ];
  for (const metadata of invalid) assert.throws(() => validateManifest(manifest({}, metadata)));
});

test("rejects unknown schema fields and never returns partial assets", async () => {
  const mock = fetchMock(manifest({ extra: true }));
  await assert.rejects(loadResult({ fetchImpl: mock.fetchImpl, cryptoImpl: webcrypto }));
  assert.equal(mock.urls.filter(url => url.endsWith(".bin")).length, 0);
});

test("rejects HTTP failure, wrong length, and hash mismatch", async () => {
  await assert.rejects(loadResult({ fetchImpl: fetchMock(manifest(), bytes, 503).fetchImpl, cryptoImpl: webcrypto }));
  const short = new Uint8Array(10);
  await assert.rejects(loadResult({ fetchImpl: fetchMock(manifest(), short).fetchImpl, cryptoImpl: webcrypto }));
  const bad = manifest(); bad.assets[0].sha256 = "b".repeat(64);
  await assert.rejects(loadResult({ fetchImpl: fetchMock(bad).fetchImpl, cryptoImpl: webcrypto }));
});

test("does not accept mutable fallback URLs", () => {
  assert.throws(() => validateManifest(manifest({ classas: [8, 9] })));
});
