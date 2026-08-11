#!/usr/bin/env node
// Does every artifact this catalogue lists still hash to what it says?
//
//   node bot/asset-check.mjs --index registry/v1/index.json --cache /tmp/assets.json
//   node bot/asset-check.mjs --index … --cache … --out report.json
//   node bot/asset-check.mjs --index … --full        download and hash everything
//
// ── WHY THIS IS CONDITIONAL, AND WHAT THE UNCONDITIONAL VERSION COSTS ───────
//
// The obvious nightly job downloads every listed artifact and hashes it. For
// this catalogue that is roughly 60 MB a night — the `doom` bundle alone is
// about 15 MB — so about 420 MB a week, growing linearly with the catalogue and
// paid every night to learn a fact that changes approximately never. A hundred
// plugins at an average of 5 MB across two targets is ~1 GB a night, ~7 GB a
// week, for no information.
//
// It is also the wrong shape. A GitHub release asset is immutable in ordinary
// use; the event worth catching is an author (or somebody holding their
// credentials) DELETING an asset and uploading a different file under the same
// name. That event changes the object, and an object that changed announces
// itself in two headers before a single byte of body is transferred:
//
//   * `Content-Length` — compared against the `size` the signed index records.
//     This needs NO memory of a previous run at all: the index is the memory.
//   * `ETag` — compared against the value the last run saw. Catches the case
//     `Content-Length` cannot: a replacement of exactly the same length.
//
// So the nightly job issues one conditional request per artifact and stops
// there. It downloads a body only when a header disagrees — at which point the
// download is not a cost, it is the investigation.
//
// The ETag cache is deliberately NOT committed to this repository. It is
// per-run state with no security value: the worst a lost or poisoned cache does
// is cost one extra HEAD, because the `Content-Length`-against-`size` check
// does not consult it. `.github/workflows/asset-check.yml` keeps it in the
// Actions cache, which means no commit, no serial, and nothing for a reviewer
// to have to ignore in a diff.
//
// ── WHAT A MISMATCH MEANS ───────────────────────────────────────────────────
//
// It does not mean users are at risk right now: Astra pins the digest from the
// signed index and refuses bytes that do not match it, so a swapped asset makes
// the plugin UNINSTALLABLE rather than dangerous. What it means is that the
// release the catalogue points at is no longer the release that was reviewed,
// and somebody has to find out why. That is a maintainer's decision — one of
// the four moderation actions — not something a cron job should take.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

/** Requests in flight. Small on purpose: this is a background job. */
const CONCURRENCY = 4;

/**
 * Every artifact the catalogue pins, flattened.
 *
 * Artifacts with no `sha256` are skipped and counted: a staging entry names a
 * release that does not exist, so a request for it is a guaranteed 404 and a
 * nightly job that logs eleven 404s is a nightly job people stop reading.
 */
export function pinnedArtifacts(indexDoc) {
  const out = [];
  const skipped = [];
  for (const p of indexDoc?.signed?.plugins ?? []) {
    for (const rel of p.releases ?? []) {
      for (const [target, art] of Object.entries(rel.artifacts ?? {})) {
        const row = { id: p.id, version: rel.version, target, url: art.url, sha256: art.sha256, size: art.size };
        if (typeof art.sha256 === "string" && typeof art.size === "number" && typeof art.url === "string") out.push(row);
        else skipped.push(row);
      }
    }
  }
  return { artifacts: out, skipped };
}

/** Header bytes, as an upper bound. HTTP/2 compresses these; nothing here can see that. */
function headerBytes(headers) {
  let n = 16; // status line, roughly
  for (const [k, v] of headers) n += k.length + v.length + 4;
  return n;
}

/**
 * One conditional check.
 *
 * @returns {{verdict: string, ...}} verdict is `unchanged`, `changed`,
 *          `mismatch`, `verified` or `error`.
 */
export async function checkOne(art, cache, { fetchImpl = fetch, full = false } = {}) {
  const known = cache[art.url] ?? {};
  const stats = { requests: 0, header_bytes: 0, body_bytes: 0 };

  const download = async (why) => {
    const res = await fetchImpl(art.url, { redirect: "follow", headers: { "User-Agent": "astra-registry-asset-check" } });
    stats.requests++;
    stats.header_bytes += headerBytes(res.headers);
    if (!res.ok) return { verdict: "error", why: `HTTP ${res.status} on the body fetch`, stats };
    const buf = Buffer.from(await res.arrayBuffer());
    stats.body_bytes += buf.length;
    const digest = createHash("sha256").update(buf).digest("hex");
    if (digest !== art.sha256) {
      return { verdict: "mismatch", why, got: digest, expected: art.sha256, stats };
    }
    return {
      verdict: "verified",
      why,
      stats,
      etag: res.headers.get("etag") ?? null,
      content_length: buf.length,
    };
  };

  if (full) return download("--full was passed");

  let res;
  try {
    const headers = { "User-Agent": "astra-registry-asset-check" };
    // `If-None-Match` on a HEAD is not what saves the bytes — a HEAD has no
    // body to save. It is what makes a 304 an unambiguous "the object is the
    // one you saw", from the origin's own bookkeeping rather than from ours.
    if (known.etag) headers["If-None-Match"] = known.etag;
    res = await fetchImpl(art.url, { method: "HEAD", redirect: "follow", headers });
    stats.requests++;
    stats.header_bytes += headerBytes(res.headers);
  } catch (e) {
    return { verdict: "error", why: e.message, stats };
  }

  if (res.status === 304) return { verdict: "unchanged", why: "304 Not Modified", stats, etag: known.etag };

  if (!res.ok) {
    // A 405 means this origin does not answer HEAD. Fall back rather than
    // reporting a problem with the artifact — a store that changed its server
    // is not an author who changed their bytes.
    if (res.status === 405 || res.status === 501) return download(`HEAD refused with ${res.status}`);
    return { verdict: "error", why: `HTTP ${res.status}`, stats };
  }

  const etag = res.headers.get("etag");
  const lenHeader = res.headers.get("content-length");
  const len = lenHeader === null ? null : Number(lenHeader);

  // The index is the memory. This comparison works on the very first run, with
  // an empty cache, on a fresh runner — which is what keeps the cache from
  // being load-bearing.
  if (len !== null && len !== art.size) {
    return { verdict: "changed", why: `content-length ${len}, and the signed index says ${art.size}`, stats, etag, content_length: len };
  }
  if (known.etag && etag && etag !== known.etag) {
    return { verdict: "changed", why: `etag ${etag}, and the last run saw ${known.etag}`, stats, etag, content_length: len };
  }
  if (len === null && !etag) {
    return { verdict: "error", why: "the origin returned neither content-length nor etag, so nothing was checked", stats };
  }
  return { verdict: "unchanged", why: len === null ? "etag unchanged" : `content-length ${len} matches`, stats, etag, content_length: len };
}

/**
 * The whole run.
 *
 * A `changed` verdict escalates to a body fetch and a hash, once, here — the
 * point of the cheap check is to decide whether to pay for the expensive one,
 * not to report a suspicion nobody resolves.
 */
export async function runAssetCheck({ indexDoc, cache = {}, fetchImpl = fetch, full = false, now = new Date() } = {}) {
  const { artifacts, skipped } = pinnedArtifacts(indexDoc);
  const results = [];
  const totals = { requests: 0, header_bytes: 0, body_bytes: 0 };

  const queue = [...artifacts];
  const worker = async () => {
    for (;;) {
      const art = queue.shift();
      if (!art) return;
      let r = await checkOne(art, cache, { fetchImpl, full });
      if (r.verdict === "changed") {
        const deep = await checkOne(art, cache, { fetchImpl, full: true });
        for (const k of ["requests", "header_bytes", "body_bytes"]) deep.stats[k] += r.stats[k];
        deep.why = `${r.why}; ${deep.verdict === "verified" ? "and the bytes still hash correctly" : "and the bytes do not match"}`;
        r = deep;
      }
      for (const k of ["requests", "header_bytes", "body_bytes"]) totals[k] += r.stats[k];
      if (r.etag !== undefined || r.content_length !== undefined) {
        cache[art.url] = {
          ...(r.etag ? { etag: r.etag } : {}),
          ...(typeof r.content_length === "number" ? { content_length: r.content_length } : {}),
          last_checked: now.toISOString(),
        };
      }
      results.push({ ...art, verdict: r.verdict, why: r.why, ...(r.got ? { got: r.got } : {}) });
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));

  results.sort((a, b) => `${a.id}${a.version}${a.target}`.localeCompare(`${b.id}${b.version}${b.target}`));
  const counts = {};
  for (const r of results) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;

  return {
    schema: "astra.registry.asset-check/1",
    checked_at: now.toISOString(),
    catalogue_serial: indexDoc?.signed?.serial,
    counts,
    transferred: totals,
    unpinned: skipped.map(({ id, version, target }) => ({ id, version, target })),
    results,
    cache,
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function arg(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

async function main(argv) {
  const indexFile = arg(argv, "--index") ?? "registry/v1/index.json";
  const cacheFile = arg(argv, "--cache");
  const outFile = arg(argv, "--out");
  const full = argv.includes("--full");

  const indexDoc = JSON.parse(fs.readFileSync(indexFile, "utf8"));
  let cache = {};
  if (cacheFile && fs.existsSync(cacheFile)) {
    try {
      cache = JSON.parse(fs.readFileSync(cacheFile, "utf8")).assets ?? {};
    } catch {
      // A corrupt cache costs one extra HEAD per artifact and nothing else.
      console.warn(`note: ${cacheFile} is not readable JSON; continuing with an empty cache`);
    }
  }

  const report = await runAssetCheck({ indexDoc, cache, full });

  const kb = (n) => `${(n / 1024).toFixed(1)} KB`;
  console.log(
    `asset check: ${report.results.length} pinned artifact(s), serial ${report.catalogue_serial}` +
      (report.unpinned.length ? `, ${report.unpinned.length} unpinned entr${report.unpinned.length === 1 ? "y" : "ies"} skipped` : ""),
  );
  for (const r of report.results) {
    const mark = r.verdict === "mismatch" ? "FAIL" : r.verdict === "error" ? "ERR " : "ok  ";
    console.log(`  ${mark}  ${r.id} ${r.version} ${r.target} — ${r.verdict}: ${r.why}`);
  }
  console.log(
    `transferred ${report.transferred.requests} request(s), ` +
      `${kb(report.transferred.header_bytes)} of headers (upper bound; HTTP/2 compresses them) and ` +
      `${kb(report.transferred.body_bytes)} of body`,
  );

  if (cacheFile) {
    fs.mkdirSync(path.dirname(path.resolve(cacheFile)), { recursive: true });
    fs.writeFileSync(cacheFile, `${JSON.stringify({ schema: "astra.registry.asset-cache/1", updated_at: report.checked_at, assets: report.cache }, null, 2)}\n`);
  }
  if (outFile) {
    const { cache: _drop, ...published } = report;
    fs.writeFileSync(outFile, `${JSON.stringify(published, null, 2)}\n`);
  }

  const mismatched = report.results.filter((r) => r.verdict === "mismatch");
  if (mismatched.length) {
    console.error(
      `\n${mismatched.length} artifact(s) no longer hash to what the signed index says. Astra will ` +
        "refuse to install them, so nobody is at risk right now — but the release this catalogue " +
        "points at is not the release that was reviewed. docs/POLICY.md says what happens next.",
    );
    return 1;
  }
  // An error is not a failure: a repository that went private overnight is a
  // maintainer's problem tomorrow, and a job that pages somebody for it at 4am
  // is a job that gets turned off.
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((c) => process.exit(c))
    .catch((e) => {
      console.error(`asset-check: ${e.message}`);
      process.exit(2);
    });
}
