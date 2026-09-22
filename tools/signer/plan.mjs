// What the signer is going to do this run, decided before anything is signed.
//
// One run, two documents, and D4's rule that **each document stands alone**:
// every run regenerates both from main's head, each passes or fails its own
// gates, and a document that fails is carried forward byte for byte from
// `signed`'s head while the other one still commits. A signer that refused the
// whole run on one bad listing would hold a withdrawal back behind a catalogue
// problem, which is the one direction the estate cannot afford.
//
// Everything here is a decision, not an act. Nothing in this file signs, holds
// a key, pushes, or writes a file; it reads git and the working tree and
// returns what the workflow should do. That is deliberate: the plan is the part
// with rules in it, and a rule inside a workflow step is a rule with no test.
//
// ── the serials are D3's, at the Source-Commit ──────────────────────────────
//
//   catalogue: git rev-list --count <sha> -- CATALOGUE_PATHSPEC
//   list:      git rev-list --count <sha> -- SERIAL_PATHSPEC     + 1
//
// `SERIAL_PATHSPEC` is `tools/lib/revocations.mjs`'s, and SERVE-85's clock reads
// the same export; the reason it is one export, and why it is the whole
// `tools/revocations` directory, is written there.
//
// The signer is the only thing that assigns them. The two regenerations count
// at HEAD, and they do NOT treat a pending change alike (gap 69; the
// measurement is in `resolveSerial`'s comment). `tools/build-index.mjs` adds
// one when `git status` shows anything under `plugins/`, because it runs
// inside the workflow that is about to commit. `tools/lib/revocations.mjs`'s
// `resolveSerial` adds one ALWAYS — the same reserved-zero offset as the `+ 1`
// above — and never looks at the working tree, so with an advisory staged it
// writes HEAD's serial, one short of what this file assigns at the commit that
// lands it. The signer counts at a commit that already exists, so it adds
// nothing for a pending change. `serialsAt` is where the signer's half lives,
// once.
//
// ── what a "change" is ──────────────────────────────────────────────────────
//
// A document is unchanged when its CONTENT matches the head's — everything in
// `signed` except `issued_at` and `expires_at`, which are properties of the
// publication rather than of the catalogue. An unchanged document is re-signed
// only once the head's is 20 hours old (D4's cadence, inside the list's 7-day
// TTL with room for a missed run); a changed one publishes at once.

import fs from "node:fs";
import path from "node:path";

import { CATALOGUE_PATHSPEC, buildIndex } from "../build-index.mjs";
import { SERIAL_PATHSPEC, buildRevocations } from "../lib/revocations.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { runValidation } from "../validate.mjs";
import { blobAt, gitMaybe, revCount } from "./git.mjs";

export const SIGNED_BRANCH = "signed";

/** D2: each `signed` commit holds exactly these four files. */
export const SIGNED_FILES = {
  index: "registry/v1/index.json",
  revocations: "registry/v1/revocations.json",
  trust: "registry/v1/trust.json",
  root: "registry/v1/root.json",
};

/** D4's cadence: an unchanged document is re-signed once the head's is this old. */
export const RESIGN_AFTER_HOURS = 20;

const HOUR_MS = 3600 * 1000;

const hoursBetween = (from, to) => (Date.parse(to) - Date.parse(from)) / HOUR_MS;

/**
 * The part of a document a fresh generation reproduces: `signed`, minus the two
 * members signing stamps.
 *
 * A DENYLIST and not an allowlist, and the difference decides what happens when
 * a member is added to either document. An allowlist — `{schema, serial,
 * revocations}` — silently stops comparing anything new, so a member added to
 * the generator would make every run report "unchanged" and the new member
 * would never reach `signed` at all, with nothing red. Naming the two members
 * that are NOT content fails the other way: a third publication-time member
 * added without a thought here shows up as a document that changes every run,
 * which is loud.
 *
 * `tools/build-index.mjs`'s `indexContent` is the same projection for the
 * catalogue and the suite asserts the two agree, so this is not a second
 * opinion about the catalogue — it is the same opinion, extended to the list.
 */
export function contentOf(doc) {
  const signed = doc?.signed ?? doc ?? {};
  const { issued_at, expires_at, ...content } = signed;
  return content;
}

/** TRUST-28's comparand: the listings, with the publisher block taken off each. */
export function pluginsWithoutPublisher(doc) {
  const signed = doc?.signed ?? doc ?? {};
  return (signed.plugins ?? []).map(({ publisher, ...rest }) => rest);
}

/**
 * SERVE-49's cap, from policy/limits.json. Never a literal in a gate.
 *
 * Read from THIS repository, not from the tree being signed, which is
 * `tools/validate.mjs`'s rule for the same reason it gives there: a tree
 * supplies the sources to be judged and does not get to supply the rules it is
 * judged by. A catalogue that could raise its own ceiling by editing a file
 * inside itself has no ceiling.
 */
export function maxIndexBytes(root = REPO_ROOT) {
  const limits = JSON.parse(fs.readFileSync(path.join(root, "policy", "limits.json"), "utf8"));
  const n = limits.max_index_bytes;
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new Error(`policy/limits.json max_index_bytes is ${JSON.stringify(n)}, not a positive integer`);
  }
  return n;
}

/** SERVE-49, as a decision over a number so it can be tested at the boundary. */
export function indexSizeVerdict(byteLength, limit) {
  if (byteLength <= limit) return { ok: true, message: null };
  return {
    ok: false,
    message:
      `the generated catalogue is ${byteLength} bytes and policy/limits.json caps it at ${limit} ` +
      `(SERVE-49). The catalogue at \`signed\`'s head is carried; raising the cap is a written ` +
      `decision in policy/limits.json, and the note there says what grew.`,
  };
}

/**
 * `signed`'s head: the four documents, their exact bytes, and the commit.
 *
 * `{present: false}` before the first signer run has created the branch, which
 * is not an error — it is R1's opening state, and every carry below is
 * conditioned on it.
 *
 * The fetch lands in a ref of the signer's own — not `refs/remotes/<remote>/…`
 * — for two reasons: `remote` may be a URL or a path, which cannot be spliced
 * into a ref name at all, and a job that writes to the remote-tracking ref of
 * the branch it is about to push is a job whose next `git push` has an opinion
 * it did not form itself.
 *
 * @param {{root: string, remote?: string, branch?: string, fetch?: boolean, ref?: string}} opts
 */
export function fetchSignedHead({
  root,
  remote = "origin",
  branch = SIGNED_BRANCH,
  fetch = true,
  ref = `refs/astra-signer/${branch}`,
}) {
  if (fetch) {
    const fetched = gitMaybe(
      ["fetch", "--quiet", "--no-tags", remote, `+refs/heads/${branch}:${ref}`],
      { root },
    );
    if (!fetched.ok) {
      return { present: false, reason: `no ${remote}/${branch}: ${fetched.error}`, sha: null, bytes: {}, documents: {} };
    }
  }
  const resolved = gitMaybe(["rev-parse", "--verify", `${ref}^{commit}`], { root });
  if (!resolved.ok) {
    return { present: false, reason: `no ${ref}: ${resolved.error}`, sha: null, bytes: {}, documents: {} };
  }
  const sha = resolved.out.trim();
  const bytes = {};
  const documents = {};
  const parseErrors = [];
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const text = blobAt({ root, ref: sha, path: rel });
    bytes[name] = text;
    if (text === null) {
      parseErrors.push(`${rel} is missing from ${branch}@${sha.slice(0, 12)}`);
      documents[name] = null;
      continue;
    }
    try {
      documents[name] = JSON.parse(text);
    } catch (e) {
      documents[name] = null;
      parseErrors.push(`${rel} at ${branch}@${sha.slice(0, 12)} is not readable JSON (${e.message})`);
    }
  }
  return { present: true, reason: null, sha, ref, bytes, documents, parseErrors };
}

/**
 * D3's two formulas, at an explicit commit.
 *
 * @param {{root: string, sha: string}} opts
 */
export function serialsAt({ root, sha }) {
  return {
    index: revCount({ root, sha, pathspec: CATALOGUE_PATHSPEC }),
    revocations: revCount({ root, sha, pathspec: SERIAL_PATHSPEC }) + 1,
  };
}

/**
 * Run the validator the way the signer must: `--allow-staging`, no
 * `ASTRA_PLUGINS_DIR`, nothing downloaded.
 *
 * The environment variable is process-global, so this sets and restores it
 * around the call — which is safe here only because the one suite that calls it
 * runs its modules one at a time and says so in `tools/selftest.mjs`'s header.
 */
export async function validateForSigning({ root }) {
  const prev = process.env.ASTRA_PLUGINS_DIR;
  delete process.env.ASTRA_PLUGINS_DIR;
  try {
    return await runValidation({
      root,
      allowStaging: true,
      allowDirect: false,
      online: false,
      artifactsDir: null,
      index: false,
    });
  } finally {
    if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
    else process.env.ASTRA_PLUGINS_DIR = prev;
  }
}

/**
 * Seam 4, as one function so that it has one place to be wrong in.
 *
 * **A `NOT verified` note never decides anything here.** `tools/validate.mjs`
 * emits one per cross-repository check it could not run — the icon formats, the
 * mirrored limits, the locale vocabulary, the listing caps, the shared locale
 * corpus — and the `publish` job has no AstraPlugins checkout on purpose, so
 * every run emits all of them. `build-index.yml` turns a `NOT verified` line
 * into exit 1, and it is right to: it HAS the checkout, so a note there means a
 * check that should have run did not. The signer does not have one and must
 * never grow one, because signing that waits on another repository is signing
 * that stops when that repository is unavailable — which is the state a
 * withdrawal is most likely to be needed in.
 *
 * So the notes are recorded, printed and carried into the run's record, and the
 * verdict reads `report.errors` and nothing else.
 */
export function gateVerdict(report) {
  return {
    ok: report.errors.length === 0,
    failures: report.errors.map((e) => `${e.where}: ${e.message}`),
    notes: report.notes.map((n) => `${n.where}: ${n.message}`),
  };
}

/**
 * The catalogue's gates (D4), all of them, collected rather than short-circuited.
 *
 * @param {{root: string, serial: number, head: object, limit: number}} opts
 */
export async function catalogueGate({ root, serial, head, limit }) {
  const failures = [];
  const notes = [];

  const { report } = await validateForSigning({ root });
  const verdict = gateVerdict(report);
  notes.push(...verdict.notes);
  failures.push(...verdict.failures);

  let candidate = null;
  let bytes = null;
  try {
    candidate = buildIndex({ root, serial });
    bytes = stableStringify(candidate);
    // Generate twice and diff. Not a formality: the generator walks a
    // directory, reads icons and READMEs off disk and sorts what it finds, and
    // the day one of those orderings stops being total is the day two runs an
    // hour apart publish two different catalogues at one serial, each verifying
    // perfectly.
    const again = stableStringify(buildIndex({ root, serial }));
    if (again !== bytes) {
      failures.push("two generations of the catalogue at one serial produced different bytes");
    }
  } catch (e) {
    failures.push(`the catalogue does not generate: ${e.message}`);
    return { ok: false, failures, notes, candidate: null, bytes: null, serial };
  }

  const size = indexSizeVerdict(Buffer.byteLength(bytes, "utf8"), limit);
  if (!size.ok) failures.push(size.message);

  const headDoc = head?.present ? head.documents.index : null;
  if (headDoc) {
    const headSerial = headDoc?.signed?.serial;
    if (Number.isSafeInteger(headSerial)) {
      if (serial < headSerial) {
        // SERVE-36. D3 says the counts only rise, because ROLL-5 forbids
        // rewriting `main` — so a lower one is not a smaller catalogue, it is
        // evidence that something the serial rests on is no longer true.
        failures.push(
          `the catalogue's serial at the Source-Commit is ${serial} and \`signed\`'s head is ` +
          `${headSerial} (SERVE-36). A serial only falls if main's history was rewritten or the ` +
          `count was taken somewhere other than the Source-Commit.`,
        );
      } else if (serial === headSerial) {
        // TRUST-28. Equal serial must mean equal `plugins/**`, and the
        // publisher block is excluded because `publishers/**` is outside the
        // path the serial counts and may legitimately change under it.
        const now = stableStringify(pluginsWithoutPublisher(candidate));
        const then = stableStringify(pluginsWithoutPublisher(headDoc));
        if (now !== then) {
          failures.push(
            `the catalogue differs from \`signed\`'s head at the same serial ${serial} (TRUST-28). ` +
            `An equal serial has to mean equal listings; the served catalogue is carried until a ` +
            `commit under plugins/ raises the serial.`,
          );
        }
      }
    }
  }

  return { ok: failures.length === 0, failures, notes, candidate, bytes, serial };
}

/**
 * The list's gates (D4).
 *
 * Built from `tools/revocations/**` alone. Nothing here reads
 * `registry/v1/revocations.json` on `main`: that file is an unsigned
 * regeneration compared by content at its own serial (ROLL-12), and a stale one
 * — which is what it is between an advisory commit and the next `build-index`
 * run — must not be able to hold a withdrawal back.
 *
 * @param {{root: string, serial: number, head: object}} opts
 */
export function listGate({ root, serial, head }) {
  const failures = [];
  const notes = [];

  let candidate = null;
  let bytes = null;
  try {
    // Advisory validation, ROLL-50's host refusal included, happens inside
    // buildRevocations: it refuses to build from invalid sources.
    candidate = buildRevocations({ root, serial });
    bytes = stableStringify(candidate);
    const again = stableStringify(buildRevocations({ root, serial }));
    if (again !== bytes) {
      failures.push("two generations of the withdrawal list at one serial produced different bytes");
    }
  } catch (e) {
    failures.push(`the withdrawal list does not generate: ${e.message}`);
    return { ok: false, failures, notes, candidate: null, bytes: null, serial };
  }

  const headDoc = head?.present ? head.documents.revocations : null;
  const headSerial = headDoc?.signed?.serial;
  if (Number.isSafeInteger(headSerial) && serial < headSerial) {
    failures.push(
      `the list's serial at the Source-Commit is ${serial} and \`signed\`'s head is ${headSerial} ` +
      `(SERVE-36). The daemon replaces its set on a strictly greater serial and may only add on an ` +
      `equal one, so a list that goes backwards is a list every armed client refuses.`,
    );
  }

  return { ok: failures.length === 0, failures, notes, candidate, bytes, serial };
}

/**
 * One document's decision, given its gates and the head.
 *
 * `changed` and `resign` are signed this run at `now`; `unchanged` and `carry`
 * re-commit the head's exact bytes and differ only in whether that is news.
 * `blocked` is the one state the run cannot commit through: the gates failed
 * and there is nothing to carry — either because `signed` has no head yet, or
 * because D10 forbids carrying this one.
 *
 * @param {{name: string, file: string, gate: object, head: object, now: string,
 *          resignAfterHours?: number, carryAllowed?: boolean}} opts
 */
export function decideDocument({
  name,
  file,
  gate,
  head,
  now,
  resignAfterHours = RESIGN_AFTER_HOURS,
  carryAllowed = true,
}) {
  const headDoc = head?.present ? head.documents[name] : null;
  const headBytes = head?.present ? head.bytes[name] : null;
  const canCarry = carryAllowed && headDoc !== null && typeof headBytes === "string";

  const carry = (reasons) => ({
    document: name,
    file,
    decision: "carry",
    reasons,
    serial: headDoc?.signed?.serial ?? null,
    bytes: headBytes,
    issued_at: headDoc?.signed?.issued_at ?? null,
    expires_at: headDoc?.signed?.expires_at ?? null,
  });
  const blocked = (reasons, why) => ({
    document: name,
    file,
    decision: "blocked",
    reasons,
    blocked_because: why,
    serial: gate.serial,
    bytes: null,
  });

  if (!gate.ok) {
    if (!canCarry) {
      return blocked(
        gate.failures,
        carryAllowed
          ? "`signed` has no usable copy of this document to carry forward"
          : "D10's compromise mode forbids carrying a document signed by the dropped key",
      );
    }
    return carry(gate.failures);
  }

  const candidateContent = stableStringify(contentOf(gate.candidate));
  const headContent = headDoc ? stableStringify(contentOf(headDoc)) : null;

  if (headContent !== candidateContent) {
    // SERVE-89: a CHANGED document must carry an `issued_at` later than the
    // one it replaces. Not a style rule — two documents at two serials with the
    // same instant, or with time going backwards, is how a reader that orders
    // by `issued_at` can be walked to the older one.
    const headIssued = headDoc?.signed?.issued_at;
    if (headIssued && !(Date.parse(now) > Date.parse(headIssued))) {
      const reason =
        `the catalogue changed but this run's clock (${now}) is not later than \`signed\`'s head ` +
        `(${headIssued}) (SERVE-89)`;
      return canCarry ? carry([reason]) : blocked([reason], "SERVE-89 and nothing to carry");
    }
    return {
      document: name,
      file,
      decision: "changed",
      reasons: [],
      serial: gate.serial,
      candidate: gate.candidate,
      issued_at: now,
    };
  }

  const age = hoursBetween(headDoc.signed.issued_at, now);
  if (age >= resignAfterHours) {
    return {
      document: name,
      file,
      decision: "resign",
      reasons: [`\`signed\`'s copy was issued ${headDoc.signed.issued_at}, ${age.toFixed(2)} h ago`],
      serial: gate.serial,
      candidate: gate.candidate,
      issued_at: now,
    };
  }
  return {
    document: name,
    file,
    decision: "unchanged",
    reasons: [`unchanged and issued ${age.toFixed(2)} h ago; re-signed at ${resignAfterHours} h`],
    serial: headDoc.signed.serial,
    bytes: headBytes,
    issued_at: headDoc.signed.issued_at,
    expires_at: headDoc.signed.expires_at,
  };
}

/** D4: every carry alerts, and the alert says what is being served meanwhile. */
export function carryAlert(result) {
  const served = result.issued_at
    ? `\`signed\`'s copy, issued ${result.issued_at} and expiring ${result.expires_at}, stays served`
    : "nothing is served for it";
  const outage =
    result.document === "revocations"
      ? " A carried withdrawal list is an outage, not a delay: SERVE-85 fires 30 minutes from the main commit."
      : "";
  return `CARRY ${result.file}: ${result.reasons.join("; ")}. ${served}.${outage}`;
}

/**
 * The whole run's plan.
 *
 * Holds no key and signs nothing — `carryCatalogueAllowed` is how D10's
 * compromise mode reaches here, as a boolean from
 * `tools/signer/key-window.mjs`, so that this file never has to know what a
 * key is.
 *
 * @param {object} opts
 * @param {string} opts.root
 * @param {string} opts.sourceCommit  main's head at run start
 * @param {object} opts.head          from fetchSignedHead
 * @param {string} opts.now           RFC 3339
 * @param {number} [opts.limit]       SERVE-49's cap; defaults to policy/limits.json
 * @param {number} [opts.resignAfterHours]
 * @param {boolean} [opts.carryCatalogueAllowed]
 */
export async function planRun({
  root,
  sourceCommit,
  head,
  now,
  limit,
  resignAfterHours = RESIGN_AFTER_HOURS,
  carryCatalogueAllowed = true,
}) {
  const serials = serialsAt({ root, sha: sourceCommit });
  const cap = limit ?? maxIndexBytes();

  const gates = {
    index: await catalogueGate({ root, serial: serials.index, head, limit: cap }),
    revocations: listGate({ root, serial: serials.revocations, head }),
  };

  const documents = {
    index: decideDocument({
      name: "index",
      file: SIGNED_FILES.index,
      gate: gates.index,
      head,
      now,
      resignAfterHours,
      carryAllowed: carryCatalogueAllowed,
    }),
    revocations: decideDocument({
      name: "revocations",
      file: SIGNED_FILES.revocations,
      gate: gates.revocations,
      head,
      now,
      resignAfterHours,
    }),
  };

  const alerts = [];
  const refusals = [];
  for (const result of Object.values(documents)) {
    if (result.decision === "carry") alerts.push(carryAlert(result));
    if (result.decision === "blocked") {
      refusals.push(
        `BLOCKED ${result.file}: ${result.reasons.join("; ")} — ${result.blocked_because}. ` +
        "A `signed` commit holds all four documents (D2), so the run commits nothing.",
      );
    }
  }

  const notes = [...gates.index.notes, ...gates.revocations.notes];
  const commit =
    refusals.length === 0 &&
    Object.values(documents).some((d) => d.decision === "changed" || d.decision === "resign");

  return { source_commit: sourceCommit, head_sha: head?.sha ?? null, serials, gates, documents, alerts, notes, refusals, commit };
}
