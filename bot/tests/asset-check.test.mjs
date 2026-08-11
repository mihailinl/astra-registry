#!/usr/bin/env node
// `bot/asset-check.mjs`, driven against a real HTTP server on loopback.
//
// The acceptance criterion for task 6.6 is a NUMBER — "the nightly job costs
// kilobytes when nothing changed" — so this test measures it rather than
// asserting a shape. It serves two artifacts of a realistic size, runs the
// check twice, and compares the bytes moved against what the unconditional
// version of the same job would have moved.
//
// The server is `node:http` on 127.0.0.1 with an ephemeral port. No fixtures on
// disk, no network, and the numbers it prints are the numbers the job produces.

import assert from "node:assert/strict";
import http from "node:http";
import { createHash } from "node:crypto";

import { runAssetCheck } from "../asset-check.mjs";

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}

/** Two artifacts: one the size of `doom`, one the size of a small plugin. */
function makeAssets() {
  const assets = new Map();
  for (const [name, size] of [
    ["big.astraplugin", 15 * 1024 * 1024],
    ["small.astraplugin", 900 * 1024],
  ]) {
    const body = Buffer.alloc(size, name);
    assets.set(`/${name}`, {
      body,
      sha256: createHash("sha256").update(body).digest("hex"),
      etag: `"${createHash("sha256").update(body).digest("hex").slice(0, 16)}"`,
    });
  }
  return assets;
}

function serve(assets, counters) {
  const server = http.createServer((req, res) => {
    const asset = assets.get(req.url);
    if (!asset) {
      res.writeHead(404).end();
      return;
    }
    counters.requests++;
    const inm = req.headers["if-none-match"];
    if (inm && inm === asset.etag) {
      counters.by_method[`${req.method} 304`] = (counters.by_method[`${req.method} 304`] ?? 0) + 1;
      res.writeHead(304, { ETag: asset.etag }).end();
      return;
    }
    counters.by_method[`${req.method} 200`] = (counters.by_method[`${req.method} 200`] ?? 0) + 1;
    res.writeHead(200, { "Content-Length": String(asset.body.length), ETag: asset.etag, "Content-Type": "application/octet-stream" });
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    counters.body_bytes_served += asset.body.length;
    res.end(asset.body);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function catalogue(base, assets) {
  return {
    signatures: [{ key_id: "k", sig: "x" }],
    signed: {
      schema: "astra.registry.index/1",
      serial: 12,
      plugins: [...assets].map(([p, a], i) => ({
        id: `plugin-${i}`,
        name: `plugin ${i}`,
        version: "1.0.0",
        releases: [
          {
            version: "1.0.0",
            published_at: "2026-08-01T00:00:00Z",
            release: { kind: "github_release", repo: "owner/repo", tag: "v1.0.0" },
            artifacts: { "linux-x64": { url: base + p, filename: p.slice(1), sha256: a.sha256, size: a.body.length } },
          },
        ],
      })),
    },
  };
}

console.log("bot/tests/asset-check.test.mjs");

const assets = makeAssets();
const counters = { requests: 0, body_bytes_served: 0, by_method: {} };
const server = await serve(assets, counters);
const base = `http://127.0.0.1:${server.address().port}`;
const index = catalogue(base, assets);
const totalSize = [...assets.values()].reduce((n, a) => n + a.body.length, 0);

await test("a cold run checks every artifact and downloads none of them", async () => {
  const cache = {};
  const report = await runAssetCheck({ indexDoc: index, cache });
  assert.equal(report.results.length, 2);
  assert.deepEqual(report.counts, { unchanged: 2 });
  assert.equal(report.transferred.body_bytes, 0, "a cold run downloaded a body");
  // The cold run has no ETag memory at all. It is still conclusive, because the
  // content-length is compared against the size the SIGNED INDEX records — the
  // index is the memory, and the cache is only an optimisation on top of it.
  assert.ok(report.transferred.header_bytes < 2048, `header bytes were ${report.transferred.header_bytes}`);
  console.log(
    `        cold: ${report.transferred.requests} request(s), ` +
      `${report.transferred.header_bytes} B of headers, ${report.transferred.body_bytes} B of body ` +
      `(the artifacts are ${(totalSize / 1024 / 1024).toFixed(1)} MB)`,
  );
});

await test("a warm run costs the same, and 304s where the origin supports it", async () => {
  const cache = {};
  await runAssetCheck({ indexDoc: index, cache });
  const before = { ...counters.by_method };
  const report = await runAssetCheck({ indexDoc: index, cache });
  assert.deepEqual(report.counts, { unchanged: 2 });
  assert.equal(report.transferred.body_bytes, 0);
  const warm304 = (counters.by_method["HEAD 304"] ?? 0) - (before["HEAD 304"] ?? 0);
  assert.equal(warm304, 2, "the second run did not send If-None-Match");
  console.log(
    `        warm: ${report.transferred.requests} request(s), ` +
      `${report.transferred.header_bytes} B of headers, ${report.transferred.body_bytes} B of body`,
  );
});

await test("--full is what the unconditional nightly job would have cost", async () => {
  const report = await runAssetCheck({ indexDoc: index, cache: {}, full: true });
  assert.deepEqual(report.counts, { verified: 2 });
  assert.equal(report.transferred.body_bytes, totalSize);
  console.log(
    `        full: ${report.transferred.requests} request(s), ` +
      `${(report.transferred.body_bytes / 1024 / 1024).toFixed(1)} MB of body — ` +
      `${((report.transferred.body_bytes * 7) / 1024 / 1024).toFixed(0)} MB a week for two artifacts`,
  );
});

await test("a length change escalates to a download, and a good file passes", async () => {
  const cache = {};
  await runAssetCheck({ indexDoc: index, cache });
  // The author replaced the asset with a longer one that is otherwise fine —
  // which is what a legitimate re-upload looks like, and what the signed index
  // no longer describes.
  const grown = Buffer.alloc(16 * 1024 * 1024, "g");
  const asset = assets.get("/big.astraplugin");
  const original = { ...asset };
  asset.body = grown;
  asset.etag = '"grown"';
  try {
    const report = await runAssetCheck({ indexDoc: index, cache });
    const hit = report.results.find((r) => r.id === "plugin-0");
    assert.equal(hit.verdict, "mismatch", `verdict was ${hit.verdict}: ${hit.why}`);
    assert.ok(/content-length/.test(hit.why), hit.why);
    assert.equal(report.transferred.body_bytes, grown.length, "the escalation did not download the body");
  } finally {
    Object.assign(asset, original);
  }
});

await test("a same-length replacement is caught by the etag, not the length", async () => {
  const cache = {};
  await runAssetCheck({ indexDoc: index, cache });
  const asset = assets.get("/small.astraplugin");
  const original = { body: asset.body, etag: asset.etag };
  // Same number of bytes, different bytes. `content-length` sees nothing.
  asset.body = Buffer.alloc(original.body.length, "z");
  asset.etag = '"swapped"';
  try {
    const report = await runAssetCheck({ indexDoc: index, cache });
    const hit = report.results.find((r) => r.id === "plugin-1");
    assert.equal(hit.verdict, "mismatch", `verdict was ${hit.verdict}: ${hit.why}`);
    assert.ok(/etag/.test(hit.why), hit.why);
  } finally {
    Object.assign(asset, original);
  }
});

await test("an entry with no digest is skipped rather than fetched", async () => {
  const staging = JSON.parse(JSON.stringify(index));
  delete staging.signed.plugins[0].releases[0].artifacts["linux-x64"].sha256;
  const report = await runAssetCheck({ indexDoc: staging, cache: {} });
  assert.equal(report.results.length, 1);
  assert.equal(report.unpinned.length, 1);
});

server.close();

if (failures) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall asset-check tests passed");
