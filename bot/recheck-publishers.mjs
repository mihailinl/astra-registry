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
// ── why this file has no expiry rule of its own ─────────────────────────────
//
// It had one, and it was the only copy anything ran. `tools/lib/sources.mjs`
// `expiredPublishers` is the rule the build asks of the committed tree; this
// job, which is the thing that actually takes a badge off, walked
// `publishers.values()` instead — a map keyed by LOGIN, which yields a record
// with `covers` once per login it speaks for. On the first expired
// multi-login `verified` record it would have fetched the proof twice,
// deleted the file, and thrown ENOENT on the second delete: the step red, the
// commit never made, the badge never withdrawn, that day or any day after.
// Dormant only because no `verified` record existed yet. So the records are
// `publisherRecords` and the selection is `expiredPublishers`, imported, and
// `tools/selftest/publishers.mjs` proves the job follows the library by
// changing the library under it.
//
// ── why a withdrawal edits the declarations file ───────────────────────────
//
// A record that expects no listing says so in `NO_LISTING_FILE`, and the suite
// refuses a declaration that names no record (gap 6). This job deletes records
// and runs no suite before it pushes, so withdrawing a DECLARED record used to
// leave its declaration behind — and the next run of the suite anywhere, the
// publish path's fifth gate included, was red on "declares a record that is not
// here" for a withdrawal nobody had done wrong. Composed, not observed: the one
// declared record today is `astra_team` and carries no `expires_at`, so it
// cannot expire. So the declaration goes in the same write as the record, and
// the workflow commits both.
//
// **It edits the file as JSON and writes it back in the file's own format**
// (two-space indent, one trailing newline), which the committed file
// round-trips byte-for-byte — the test asserts that, so a reformatting of the
// file is loud rather than silently undone by the next withdrawal. A file this
// job cannot parse is REPORTED and the withdrawal still happens: the suite is
// already red on such a file, and a badge that outlives its evidence because a
// neighbouring file is broken is the failure entry 80 recorded.
//
// **Why the file is under `state/`.** It lived under `tools/selftest/`, a
// directory entry of contract TRUST-31's hashed set, so after R3 a withdrawal
// that dropped a declaration would have been a hashed-path commit made by an
// unattended job (registry plan: ROLL-64): the bot back in shadow, and an
// alarm, for a badge withdrawal nobody did wrong. Leaving the declaration
// behind instead would have been quieter and worse: `main` red on every
// publication until a person noticed. The file is a record a run writes, not a
// rule a run judges by — it vouches only for `publishers/**`, which the set
// keeps outside, and a writer who could edit a declaration could as easily
// delete the record it excuses — so it lives with the other records a run
// writes as it works. Not under `publishers/`: `loadPublishers` reads every
// `*.json` there as a publisher record. `tools/selftest/publishers.mjs` holds
// every path the workflow's commit step stages outside the set, so the day
// this file moves back inside it, the suite is red.
//
// ── why the clock lives here and nowhere downstream ────────────────────────
//
// `tools/build-index.mjs` reads no clock, by contract: same sources, same
// bytes. If expiry were enforced there, today's catalogue would differ from
// tomorrow's for a reason no diff could show. So this job holds the clock, and
// what it produces is an ordinary commit somebody can read.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT, expiredPublishers, loadPublishers, publisherRecords } from "../tools/lib/sources.mjs";

/**
 * Where a publisher record that expects no listing says so. The suite
 * (`tools/selftest/publishers.mjs`) owns the file's shape and is its judge, and
 * imports this name rather than spelling the path a second time; this job
 * reads it for one purpose, to drop the declaration of a record it withdraws.
 */
export const NO_LISTING_FILE = "state/publishers-without-listing.json";

/**
 * `text` — the declarations file — without every declaration naming one of
 * `files`, and the records whose declarations were dropped. When nothing is
 * dropped the text comes back as it came in, byte for byte, so a run that
 * withdraws an undeclared record never touches the file.
 */
export function withoutDeclarations(text, files) {
  const doc = JSON.parse(text);
  if (doc === null || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray(doc.declarations)) {
    throw new Error("carries no `declarations` array");
  }
  const gone = new Set(files);
  const kept = doc.declarations.filter((d) => !gone.has(d?.record));
  const dropped = doc.declarations.filter((d) => gone.has(d?.record)).map((d) => d.record);
  if (!dropped.length) return { text, dropped };
  return { text: `${JSON.stringify({ ...doc, declarations: kept }, null, 2)}\n`, dropped };
}

const CONFIRM_WINDOW_DAYS = 180;
const FETCH_TIMEOUT_MS = 15_000;
const UA = "astra-registry publisher re-check (github.com/mihailinl/astra-registry)";

const today = (now) => now.toISOString().slice(0, 10);
const plusDays = (now, days) => new Date(now.getTime() + days * 86_400_000).toISOString().slice(0, 10);

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

export async function recheck({ root = REPO_ROOT, write = false, fetcher = fetchProof, now = new Date() } = {}) {
  const { errors, publishers } = loadPublishers(root);
  const results = [];
  // Each RECORD once. `publishers` is keyed by login, so its values repeat a
  // record once per login in `covers`, and each repeat was a second fetch.
  for (const { file, doc } of publisherRecords(publishers)) {
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
      next.last_confirmed_at = today(now);
      next.expires_at = plusDays(now, CONFIRM_WINDOW_DAYS);
      fs.writeFileSync(p, `${JSON.stringify(next, null, 2)}\n`);
    }
  }

  // Expired: the confirmations stopped long enough ago that the claim has run
  // out. This is where the badge actually comes off, and it comes off by
  // DELETING THE RECORD, once — docs/POLICY.md §7 ("the window runs out, the
  // record is deleted in a commit anyone can read"), schema/publisher-v1.json's
  // `expires_at` ("a record past this date is dropped"), and the workflow's own
  // header all say so. The history of the claim is the commit that removed it,
  // and the way back is a reviewed re-add after the document is restored.
  //
  // The selection is the library's, judged on the tree this run STARTED from,
  // and for every tier: a record that carries an `expires_at` is held to it,
  // which is also what the build's own check of the committed tree does. A
  // record whose proof answered on this same run is still removed if its window
  // had already closed — its renewal above is written to a file this deletes.
  const expired = expiredPublishers(publishers, now);

  // Their declarations, computed before anything is deleted and written after,
  // in the same run, so the workflow's one commit carries both.
  let undeclared = [];
  let declarationProblem = null;
  let rewrite = null;
  const declarationsFile = path.join(root, NO_LISTING_FILE);
  if (expired.length && fs.existsSync(declarationsFile)) {
    try {
      const edit = withoutDeclarations(fs.readFileSync(declarationsFile, "utf8"), expired.map((e) => e.file));
      undeclared = edit.dropped;
      if (edit.dropped.length) rewrite = edit.text;
    } catch (e) {
      declarationProblem = `${NO_LISTING_FILE} could not be read (${e.message}), so a declaration of a withdrawn ` +
        "record, if there is one, was not dropped with it";
    }
  }
  if (write) {
    for (const { file } of expired) fs.rmSync(path.join(root, file));
    if (rewrite !== null) fs.writeFileSync(declarationsFile, rewrite);
  }

  return { errors, results, expired, undeclared, declarationProblem };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const write = process.argv.includes("--write");
  const { errors, results, expired, undeclared, declarationProblem } = await recheck({ write });
  for (const e of errors) console.log(`load  ${e.file}: ${e.message}`);
  for (const r of results) {
    console.log(`${r.state === "confirmed" ? "ok   " : "WARN "} ${r.owner}: ${r.state}${r.why ? ` — ${r.why}` : ""}`);
  }
  for (const e of expired) {
    console.log(`GONE  ${e.owner}: no confirmation since ${e.expires_at}; the badge is withdrawn`);
  }
  for (const record of undeclared) {
    console.log(`UNDECLARED  ${record}: its entry in ${NO_LISTING_FILE} goes with it`);
  }
  if (declarationProblem) console.log(`WARN  ${declarationProblem}`);
  if (!results.length && !expired.length) console.log("no `verified` publishers to re-check");
  process.exit(errors.length ? 1 : 0);
}
