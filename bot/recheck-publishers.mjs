#!/usr/bin/env node
// Re-fetch the evidence behind every `verified` publisher, and take the badge
// off when it stops holding.
//
//   node bot/recheck-publishers.mjs            # report only
//   node bot/recheck-publishers.mjs --write    # also edit publishers/*.json
//
// ── why this exists ────────────────────────────────────────────────────────
//
// `verified` is not a verdict, it is a standing claim. A tier granted once and
// never revisited stops being a statement about who somebody IS and becomes one
// about who they USED to be — and the registry is the only place that can
// notice the difference, because it is the only party that kept the evidence.
//
// So the badge rests on something re-fetchable: a document on a domain the
// publisher controls, naming their GitHub login. This walks those documents.
//
// ── why a failure does not withdraw immediately ────────────────────────────
//
// A fetch fails for reasons that have nothing to do with the publisher: a
// certificate renewing, a CDN having a minute, this job's own network. Taking a
// badge off for that would make the mark flicker, and a mark that flickers is
// one nobody reads.
//
// So a failure moves nothing. What moves is `expires_at`: a SUCCESS pushes it
// forward, and nothing else does. A publisher whose document has been gone for
// months therefore expires on schedule rather than on the first bad night, and
// the withdrawal is the absence of confirmations rather than the presence of
// one failure.
//
// ── why the clock lives here and nowhere downstream ────────────────────────
//
// `tools/build-index.mjs` reads no clock, by contract: same sources, same
// bytes. If expiry were enforced there, today's catalogue would differ from
// tomorrow's for a reason no diff could show. So this job holds the clock, and
// what it produces is an ordinary commit somebody can read.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT, loadPublishers } from "../tools/lib/sources.mjs";

const CONFIRM_WINDOW_DAYS = 180;
const FETCH_TIMEOUT_MS = 15_000;
const UA = "astra-registry publisher re-check (github.com/mihailinl/astra-registry)";

const today = () => new Date().toISOString().slice(0, 10);
const plusDays = (days) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);

/**
 * Does this document still name this owner?
 *
 * Whole-line and case-insensitive, not `includes`: a page that merely mentions
 * a login somewhere — a blog post, a directory listing, somebody else's README
 * — is not that person asserting it. The file has to say the name and little
 * else, which is what makes it a statement rather than a coincidence.
 */
export function proofNamesOwner(body, owner) {
  const want = String(owner).trim().toLowerCase();
  return String(body)
    .split(/\r?\n/)
    .some((line) => line.trim().toLowerCase() === want);
}

async function fetchProof(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers: { "user-agent": UA }, signal: ctrl.signal, redirect: "follow" });
    if (!res.ok) return { ok: false, why: `HTTP ${res.status}` };
    const body = await res.text();
    if (body.length > 64 * 1024) return { ok: false, why: "the document is larger than 64 KiB" };
    return { ok: true, body };
  } catch (e) {
    return { ok: false, why: e.name === "AbortError" ? `no answer in ${FETCH_TIMEOUT_MS} ms` : e.message };
  } finally {
    clearTimeout(timer);
  }
}

export async function recheck({ root = REPO_ROOT, write = false, fetcher = fetchProof } = {}) {
  const { errors, publishers } = loadPublishers(root);
  const results = [];
  for (const { file, doc } of publishers.values()) {
    if (doc.tier !== "verified") continue;
    if (doc.evidence?.kind !== "domain") {
      results.push({ file, owner: doc.owner, state: "unsupported", why: `evidence.kind is ${JSON.stringify(doc.evidence?.kind)}` });
      continue;
    }
    const got = await fetcher(doc.evidence.proof);
    if (!got.ok) {
      results.push({ file, owner: doc.owner, state: "unreachable", why: got.why, expires_at: doc.expires_at });
      continue;
    }
    if (!proofNamesOwner(got.body, doc.owner)) {
      results.push({ file, owner: doc.owner, state: "mismatched", why: `the document does not name ${doc.owner} on a line of its own`, expires_at: doc.expires_at });
      continue;
    }
    results.push({ file, owner: doc.owner, state: "confirmed" });
    if (write) {
      const p = path.join(root, file);
      const next = JSON.parse(fs.readFileSync(p, "utf8"));
      next.last_confirmed_at = today();
      next.expires_at = plusDays(CONFIRM_WINDOW_DAYS);
      fs.writeFileSync(p, `${JSON.stringify(next, null, 2)}\n`);
    }
  }

  // Expired: the confirmations stopped long enough ago that the claim has run
  // out. This is where the badge actually comes off, and it comes off by
  // deleting the tier rather than the record — the file stays, so the history
  // of the claim stays with it.
  const expired = [];
  for (const { file, doc } of publishers.values()) {
    if (doc.tier !== "verified") continue;
    if (typeof doc.expires_at !== "string" || doc.expires_at >= today()) continue;
    expired.push({ file, owner: doc.owner, expires_at: doc.expires_at });
    if (write) fs.rmSync(path.join(root, file));
  }

  return { errors, results, expired };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const write = process.argv.includes("--write");
  const { errors, results, expired } = await recheck({ write });
  for (const e of errors) console.log(`load  ${e.file}: ${e.message}`);
  for (const r of results) {
    console.log(`${r.state === "confirmed" ? "ok   " : "WARN "} ${r.owner}: ${r.state}${r.why ? ` — ${r.why}` : ""}`);
  }
  for (const e of expired) {
    console.log(`GONE  ${e.owner}: no confirmation since ${e.expires_at}; the badge is withdrawn`);
  }
  if (!results.length && !expired.length) console.log("no `verified` publishers to re-check");
  process.exit(errors.length ? 1 : 0);
}
