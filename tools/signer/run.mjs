#!/usr/bin/env node
// The signer's three acts: sign, commit, and assemble what Pages serves.
//
//     node tools/signer/run.mjs --step sign   --source-commit <sha> --out dist/signed --record record.json
//     node tools/signer/run.mjs --step commit --record record.json --tree dist/signed
//     node tools/signer/run.mjs --step pages  --out dist/pages --site dist/site --record pages.json
//
// `--step sign` also takes `--test-key <[published_id=]test_key_id>`, repeatable,
// which signs with the throwaway keys in tools/testkeys/ instead of the
// environment's. It is how RC-R2-5's ROLL-60 rehearsal fixtures are produced —
// see `testKeySigners` below for the three guards on it.
//
// `tools/signer/{plan,key-window,pages,git}.mjs` decide; this file is the only
// thing under `tools/signer/` that DOES anything — it holds the key for the
// length of one function, writes files, makes a commit and pushes it. The split
// is RC-R1-1's and it is kept here for the reason that module header gives: a
// rule inside a workflow step is a rule with no test, and every rule below
// decides what a stranger's daemon is served.
//
// **Why this is not three heredocs in `sign.yml`.** The same argument
// `tools/served-set/` makes for the comparisons, one step further along: the
// steps below run with `contents: write` and the index signing key, against
// `signed`, with no way to take a commit back. `--step sign` is exercised
// against a fixture tree and the committed TEST keys in
// `tools/selftest/signer-run.mjs`, including the refusal that matters most —
// SERVE-95's, below — and none of that is possible over a shell block.
//
// ── SERVE-95, and why it is here rather than in the plan ───────────────────
//
// `refusesDroppedKey` (key-window.mjs) asks whether every document about to be
// committed verifies under the trust.json committed BESIDE it. It is asked
// here, after the documents are assembled and before anything is written,
// because it is the only question in the run whose answer depends on all four
// files at once: a carried catalogue is byte-perfect, its signature is a real
// signature by a key that was trusted when it was made, and it is wrong only
// relative to the file next to it. `planRun` never sees a key and cannot ask
// it; a workflow step could ask it and could also be edited to skip it.
//
// A document that fails it does not get carried, or re-signed, or dropped: the
// run commits NOTHING. D2 puts all four documents in one commit, so there is no
// half of this commit that is safe to make, and SERVE-91 would refuse the whole
// thing at the client anyway — leaving the repair unlanded and the old bytes
// served, which is the failure D10 step 4 exists to prevent.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { cleanEnv } from "../lib/git-env.mjs";
import { pathToFileURL } from "node:url";

import { indexSignersFromEnv } from "../../bot/lib/sign.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { signIndex } from "../../bot/sign-index.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
// One spelling of the trailer grammar and of the receipt's name, shared with
// the check that reads them. `tools/served-set/provenance.mjs` is where
// SERVE-90 decides whether a `signed` commit was made by a signer run; a
// second reader here is a second answer waiting to disagree with it, and the
// half that goes wrong silently is this one — a receipt uploaded under a name
// the check does not look for makes SERVE-90 red on every commit for ever,
// which reads as noise and gets switched off.
import { receiptName, trailersOf } from "../served-set/provenance.mjs";
import { PAGES_BASE, fetchServed } from "../served-set/served-vs-signed.mjs";
import { blobAt, gitMaybe, gitText } from "./git.mjs";
import {
  DOCUMENT_DOMAINS, keyPlan, readDelegationTimes, refusesDroppedKey, trustAtCommit,
} from "./key-window.mjs";
import { SIGNED_BRANCH, SIGNED_FILES, carryAlert, fetchSignedHead, planRun } from "./plan.mjs";
import { armingState, pagesRegistryFiles, pagesTree } from "./pages.mjs";

/** D2's four trailers, in the order they are written. */
export const SIGNER_TRAILER = "sign.yml";

/** The verdict codes this run can report. Fixed, because the channel refuses a sentence. */
export const CODES = {
  carry: { index: "SIGNER_CARRIED_INDEX", revocations: "SIGNER_CARRIED_REVOCATIONS" },
  blocked: "SIGNER_BLOCKED",
  droppedKey: "SIGNER_TRUST_REFUSED_DOCUMENT",
  noKey: "SIGNER_NO_INDEX_KEY",
  pushRace: "SIGNER_PUSH_RACE",
  siteRender: "SIGNER_SITE_RENDER_FAILED",
};

const rfc3339 = (d) => new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * Sign one document with the keys its window allows, or say why not.
 *
 * Kept apart from the loop below so the "no key may sign this" branch is one
 * decision rather than two copies of it. It is not a theoretical branch: it is
 * the state of every run in the seven hours after a rotation's delegating
 * commit (SERVE-30), for the catalogue alone.
 */
function signDocument({ name, candidate, signers, now }) {
  const issuedAt = new Date(now);
  return name === "index"
    ? signIndex(candidate, { signers, issuedAt })
    : signRevocations(candidate, { signers, issuedAt });
}

/**
 * The whole of `--step sign`, as a value.
 *
 * Takes its signers as an argument rather than reading the environment, so the
 * suite can run every branch of it with the committed TEST keys and no secret
 * anywhere near the process.
 *
 * @param {object} o
 * @param {string} o.root
 * @param {string} o.sourceCommit  main's head at run start
 * @param {object} o.head          from fetchSignedHead
 * @param {string} o.now           RFC 3339
 * @param {{key_id: string}[]} o.available
 * @param {Map<string,string>} [o.delegatedAt]
 * @param {number} [o.resignAfterHours]
 * @param {number} [o.limit]
 */
export async function signRun({
  root,
  sourceCommit,
  head,
  now,
  available,
  delegatedAt = new Map(),
  resignAfterHours,
  limit,
}) {
  const candidateTrust = trustAtCommit({ root, sha: sourceCommit });
  if (candidateTrust === null) {
    throw new Error(
      `main@${sourceCommit.slice(0, 12)} has no ${SIGNED_FILES.trust}. Every document in a \`signed\` commit is ` +
      `verified against the trust.json committed beside it (SERVE-95), so there is nothing to sign against.`,
    );
  }
  const headTrust = head?.present ? head.documents.trust : null;

  const keys = keyPlan({ candidateTrust, headTrust, delegatedAt, now, available });
  const plan = await planRun({
    root,
    sourceCommit,
    head,
    now,
    limit,
    resignAfterHours,
    carryCatalogueAllowed: keys.carryCatalogueAllowed,
  });

  const alerts = [...plan.alerts];
  const refusals = [...plan.refusals];
  const codes = [];
  const notes = [...plan.notes, ...keys.notes];
  const documents = {};

  for (const name of ["index", "revocations"]) {
    const decided = plan.documents[name];
    const file = SIGNED_FILES[name];

    if (decided.decision === "blocked") {
      // Recorded, not skipped. The first spelling of this left `documents`
      // without the entry, and the run's own summary line then printed
      // `catalogue 2 (undefined)` for the one outcome a reader most needs
      // named — found by running the CLI end to end against a fixture whose
      // catalogue would not build, which is the only way it shows.
      documents[name] = { decision: "blocked", serial: decided.serial, bytes: null, doc: null };
      codes.push(CODES.blocked);
      continue;
    }

    if (decided.decision === "carry" || decided.decision === "unchanged") {
      documents[name] = {
        decision: decided.decision,
        serial: decided.serial,
        bytes: decided.bytes,
        doc: JSON.parse(decided.bytes),
      };
      if (decided.decision === "carry") codes.push(CODES.carry[name]);
      continue;
    }

    // `changed` or `resign`: this run signs it, if a key may.
    const signers = keys[name].signers;
    if (signers.length === 0) {
      const reason = keys[name].refused ?? "no index key may sign this document";
      const headBytes = head?.present ? head.bytes[name] : null;
      const carryAllowed = name === "index" ? keys.carryCatalogueAllowed : true;
      if (carryAllowed && typeof headBytes === "string") {
        const headDoc = head.documents[name];
        documents[name] = {
          decision: "carry",
          serial: headDoc?.signed?.serial ?? null,
          bytes: headBytes,
          doc: headDoc,
        };
        codes.push(CODES.carry[name], CODES.noKey);
        alerts.push(carryAlert({
          document: name,
          file,
          reasons: [reason],
          issued_at: headDoc?.signed?.issued_at ?? null,
          expires_at: headDoc?.signed?.expires_at ?? null,
        }));
      } else {
        documents[name] = { decision: "blocked", serial: decided.serial, bytes: null, doc: null };
        codes.push(CODES.blocked, CODES.noKey);
        refusals.push(
          `BLOCKED ${file}: ${reason}, and there is nothing to carry. A \`signed\` commit holds all four ` +
          `documents (D2), so the run commits nothing.`,
        );
      }
      continue;
    }

    const signed = signDocument({ name, candidate: decided.candidate, signers, now });
    documents[name] = {
      decision: decided.decision,
      serial: decided.serial,
      bytes: stableStringify(signed),
      doc: signed,
      signed_by: signers.map((s) => s.key_id),
    };
  }

  // D2: trust.json and root.json are byte copies from the Source-Commit's tree
  // (TRUST-3). Copied, never regenerated and never re-signed here — the root
  // layer is an offline ceremony and this job holds no root key.
  for (const name of ["trust", "root"]) {
    const bytes = blobAt({ root, ref: sourceCommit, path: SIGNED_FILES[name] });
    if (bytes === null) {
      documents[name] = { decision: "blocked", serial: null, bytes: null, doc: null };
      codes.push(CODES.blocked);
      refusals.push(
        `BLOCKED ${SIGNED_FILES[name]}: main@${sourceCommit.slice(0, 12)} does not have it, and a \`signed\` ` +
        `commit holds all four documents (D2).`,
      );
      continue;
    }
    documents[name] = { decision: "copied", serial: null, bytes, doc: null };
  }

  // SERVE-95, over everything about to be committed and not only over what
  // this run signed. The carried catalogue is the case: real signature, real
  // key, wrong relative to the trust.json beside it.
  const verifiable = ["index", "revocations"].filter((n) => documents[n]?.doc);
  const dropped = refusesDroppedKey({
    trust: candidateTrust,
    documents: verifiable.map((n) => ({ name: SIGNED_FILES[n], domain: DOCUMENT_DOMAINS[n], doc: documents[n].doc })),
  });
  if (dropped.length) {
    codes.push(CODES.droppedKey);
    for (const problem of dropped) {
      refusals.push(
        `BLOCKED: ${problem} (SERVE-95). SERVE-91 refuses a commit whose documents do not verify against its own ` +
        `trust.json, so committing this would withhold all four and leave the previous bytes served.`,
      );
    }
  }

  const commit =
    refusals.length === 0 &&
    ["index", "revocations"].every((n) => typeof documents[n]?.bytes === "string") &&
    ["trust", "root"].every((n) => typeof documents[n]?.bytes === "string") &&
    Object.values(documents).some((d) => d.decision === "changed" || d.decision === "resign");

  // D4: a carried catalogue keeps the `Index-Source-Commit` it was published
  // with, because the tree it was generated from is that one and not this run's.
  let indexSourceCommit = sourceCommit;
  if (documents.index?.decision === "carry" || documents.index?.decision === "unchanged") {
    if (head?.present && head.sha) {
      const message = gitMaybe(["log", "-1", "--format=%B", head.sha], { root });
      const carried = message.ok ? trailersOf(message.out)["Index-Source-Commit"] : null;
      if (/^[0-9a-f]{40}$/.test(String(carried ?? ""))) indexSourceCommit = carried;
    }
  }

  const files = {};
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    if (typeof documents[name]?.bytes === "string") files[rel] = documents[name].bytes;
  }

  return {
    schema: "astra.registry.signer-run/1",
    step: "sign",
    now,
    source_commit: sourceCommit,
    index_source_commit: indexSourceCommit,
    parent: head?.present ? head.sha : null,
    branch: SIGNED_BRANCH,
    serials: plan.serials,
    key_mode: keys.mode,
    dropped_keys: keys.dropped,
    documents: Object.fromEntries(
      Object.entries(documents).map(([n, d]) => [n, { decision: d.decision, serial: d.serial, signed_by: d.signed_by ?? null }]),
    ),
    files,
    alerts,
    refusals,
    notes,
    codes: [...new Set(codes)],
    hexes: [sourceCommit],
    status: alerts.length || refusals.length ? "red" : "green",
    commit,
  };
}

/** The commit subject and body D2 asks for, with its four trailers last. */
export function commitMessage(record, runUrl) {
  const decisions = ["index", "revocations"]
    .map((n) => `${SIGNED_FILES[n]}: ${record.documents[n]?.decision ?? "absent"} at serial ${record.documents[n]?.serial ?? "?"}`)
    .join("\n");
  const subject =
    `signed: catalogue ${record.serials.index}, withdrawal list ${record.serials.revocations}` +
    ` at ${record.source_commit.slice(0, 12)}`;
  const carries = record.alerts.length ? `\n\n${record.alerts.join("\n")}` : "";
  return (
    `${subject}\n\n${decisions}${carries}\n\n` +
    `Source-Commit: ${record.source_commit}\n` +
    `Run: ${runUrl}\n` +
    `Signer: ${SIGNER_TRAILER}\n` +
    `Index-Source-Commit: ${record.index_source_commit}\n`
  );
}

/**
 * Write the four documents into a directory, exactly as they will be committed.
 *
 * The bytes go out through `fs.writeFileSync` with no transformation at all —
 * no re-stringify, no trailing-newline fix-up. A carry is byte-for-byte or it
 * is a new document whose signature was made over other bytes (git.mjs's
 * header says the same thing about reading them back).
 */
export function writeTree({ out, files }) {
  fs.rmSync(out, { recursive: true, force: true });
  for (const [rel, bytes] of Object.entries(files)) {
    const file = path.join(out, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
  }
  return Object.keys(files).sort();
}

/**
 * Make the `signed` commit with plumbing, in an index of the signer's own.
 *
 * `commit-tree` over a temporary `GIT_INDEX_FILE` and never `git checkout
 * signed`: the working tree here is `main` at the Source-Commit, and a job that
 * switches branches to make a commit is a job whose failure leaves a checkout
 * of `signed` behind for whatever runs next. It also gives the first run — the
 * one that CREATES the branch — the same code path as every run after it, with
 * the orphan falling out of "there is no parent" rather than out of a flag.
 *
 * @param {{root: string, files: Record<string,string>, parent: string|null, message: string,
 *          identity?: {name: string, email: string}}} o
 * @returns {string} the new commit's sha
 */
export function buildSignedCommit({ root, files, parent, message, identity }) {
  const indexFile = path.join(root, ".git", "astra-signer-index");
  fs.rmSync(indexFile, { force: true });
  // The index is this function's own file; everything else in the environment
  // is `cleanEnv()`, so an inherited GIT_DIR cannot take the commit elsewhere
  // (tools/lib/git-env.mjs). `who` is the commit's identity, when one is made.
  const git = (args, { input, who } = {}) =>
    execFileSync("git", ["-C", root, ...args], {
      encoding: "utf8",
      input,
      env: {
        ...cleanEnv(),
        GIT_INDEX_FILE: indexFile,
        ...(who ? {
          GIT_AUTHOR_NAME: who.name, GIT_AUTHOR_EMAIL: who.email,
          GIT_COMMITTER_NAME: who.name, GIT_COMMITTER_EMAIL: who.email,
        } : {}),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

  try {
    for (const [rel, bytes] of Object.entries(files)) {
      const blob = git(["hash-object", "-w", "--stdin"], { input: bytes }).trim();
      git(["update-index", "--add", "--cacheinfo", `100644,${blob},${rel}`]);
    }
    const tree = git(["write-tree"]).trim();
    const who = identity ?? { name: "astra-registry signer", email: "signer@users.noreply.github.com" };
    const args = ["commit-tree", tree, ...(parent ? ["-p", parent] : [])];
    return git(args, { input: message, who }).trim();
  } finally {
    fs.rmSync(indexFile, { force: true });
  }
}

/**
 * Push it, fast-forward only, and retry ONLY while the plan still holds.
 *
 * "Still holds" is one question: is `signed`'s head the commit this run planned
 * against? If it is, the rejection was transient and pushing again is right. If
 * it is not, another publisher exists or a run overtook this one, and the
 * documents in hand were generated against a head that is gone — re-pushing
 * them would either lose that commit or stack a document on a parent it was
 * never compared with. The next run re-plans from the new head, an hour away at
 * worst and immediately on the next commit to `main`.
 *
 * @returns {{pushed: boolean, attempts: number, reason: string|null, head: string|null}}
 */
export function pushSigned({ root, sha, parent, remote = "origin", branch = SIGNED_BRANCH, attempts = 3, sleep }) {
  let reason = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const pushed = gitMaybe(["push", remote, `${sha}:refs/heads/${branch}`], { root });
    if (pushed.ok) return { pushed: true, attempts: attempt, reason: null, head: sha };
    reason = pushed.error;
    if (attempt === attempts) break;
    const fetched = gitMaybe(["fetch", "--quiet", "--no-tags", remote, `+refs/heads/${branch}:refs/astra-signer/${branch}`], { root });
    const head = fetched.ok
      ? (gitMaybe(["rev-parse", "--verify", `refs/astra-signer/${branch}^{commit}`], { root }).out ?? "").trim()
      : null;
    const stillHolds = (parent === null && !fetched.ok) || (parent !== null && head === parent);
    if (!stillHolds) {
      return {
        pushed: false,
        attempts: attempt,
        head: head || null,
        reason:
          `the push was rejected and \`${branch}\` is now ${head ? head.slice(0, 12) : "absent"}, not the ` +
          `${parent ? parent.slice(0, 12) : "empty branch"} this run planned against. The plan no longer holds, so ` +
          `nothing is retried: these documents were generated and signed against a head that is gone, and the next ` +
          `run re-plans from the new one. (${reason})`,
      };
    }
    if (sleep) sleep(attempt);
  }
  return { pushed: false, attempts, head: parent, reason };
}

// ── the three steps, as a command line ──────────────────────────────────────

function parseArgs(argv) {
  const args = {
    step: "sign", root: REPO_ROOT, out: null, record: null, tree: null, site: null,
    sourceCommit: null, now: null, testKeys: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--step") args.step = argv[++i];
    else if (flag === "--root") args.root = argv[++i];
    else if (flag === "--out") args.out = argv[++i];
    else if (flag === "--record") args.record = argv[++i];
    else if (flag === "--tree") args.tree = argv[++i];
    else if (flag === "--site") args.site = argv[++i];
    else if (flag === "--source-commit") args.sourceCommit = argv[++i];
    else if (flag === "--now") args.now = argv[++i];
    else if (flag === "--test-key") args.testKeys.push(argv[++i]);
    else throw new Error(`unknown argument: ${flag}`);
  }
  return args;
}

/**
 * `--test-key`, repeatable, for the one job no other tool in this repository can do.
 *
 * `bot/sign-index.mjs` and `tools/sign-revocations.mjs` each take a single
 * `--test-key` and sign one document with one key. **Neither can produce
 * SERVE-30's dual-signed withdrawal list**, and neither can produce D10's
 * compromise commit, because the rotation and the compromise are not properties
 * of a document — they are decisions this file's `signRun` makes about four
 * documents at once, from `signed`'s own history. A fixture for them assembled
 * out of two single-key invocations would prove something about the fixture and
 * nothing about the signer, which is the whole reason RC-R2-5 exists.
 *
 * So the same affordance those two already have arrives here, with the same
 * guards and one more. The spelling is `--test-key <test_key_id>` or
 * `--test-key <published_key_id>=<test_key_id>`: the second form publishes a
 * `key_id` the trust.json delegates while signing with a throwaway key's bytes,
 * which `tools/selftest/signer-run.mjs`'s BOOTSTRAP does for the one run that
 * cannot otherwise exist — the first, whose catalogue may only be signed
 * because `WINDOW_EXEMPT_KEY_IDS` names `astra-index-2026a` by id.
 *
 * Three guards, and the third is the one worth stating:
 *
 *   1. every key is one of `tools/testkeys/`'s, whose private halves are
 *      committed on purpose and which `tools/sign-trust.mjs` refuses to
 *      delegate in production;
 *   2. the output may not land inside `registry/` — a test signature there is a
 *      document that looks signed and is not;
 *   3. **it refuses to run at all when `ASTRA_INDEX_SIGNING_KEY` is in the
 *      environment.** The failure that guard is for is not a fixture author's;
 *      it is `--test-key` reaching `sign.yml`, where the run would hold the
 *      real key, ignore it, and publish a `signed` commit every daemon refuses
 *      — green, with a WARNING in a log nobody reads. Fail closed instead.
 */
function testKeySigners(specs, { out, env = process.env } = {}) {
  if (env.ASTRA_INDEX_SIGNING_KEY || env.ASTRA_INDEX_SIGNING_KEY_NEXT) {
    throw new Error(
      "--test-key was passed to a run that also holds ASTRA_INDEX_SIGNING_KEY. One of the two is a mistake and " +
      "this job cannot tell which, so it makes neither: a test-key run in the publishing job would commit a " +
      "`signed` commit every daemon refuses.",
    );
  }
  const signers = [];
  const seen = new Map();
  for (const spec of specs) {
    const [left, right] = String(spec).split("=");
    const keyId = right === undefined ? left : left;
    const testKeyId = right === undefined ? left : right;
    const key = loadTestRoot(testKeyId);
    if (seen.has(key.publicKeyB64)) {
      throw new Error(
        `--test-key ${spec} signs with the same Ed25519 key as ${seen.get(key.publicKeyB64)}. Two signatures by ` +
        "one key are not a rotation (bot/lib/sign.mjs says the same about ASTRA_INDEX_SIGNING_KEY_NEXT).",
      );
    }
    seen.set(key.publicKeyB64, spec);
    signers.push({ key_id: keyId, privateKey: key.privateKey, public_key: key.publicKeyB64 });
  }
  const target = path.resolve(out ?? "dist/signed");
  if (target === path.join(REPO_ROOT, "registry") || target.startsWith(`${path.join(REPO_ROOT, "registry")}${path.sep}`)) {
    throw new Error(`refusing to write TEST-key signatures into ${path.relative(REPO_ROOT, target)}`);
  }
  console.error(
    `WARNING: signing with ${signers.map((s) => s.key_id).join(", ")}, TEST keys whose private halves are ` +
    "committed to this repository. Nothing a user installs may be signed with them.",
  );
  return signers;
}

/** A step output, when there is a `$GITHUB_OUTPUT` to write to. */
function output(pairs) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  fs.appendFileSync(file, `${Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join("\n")}\n`);
}

const writeRecord = (file, record) => {
  if (file) fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
};

async function stepSign(args) {
  const root = args.root;
  const sourceCommit = args.sourceCommit ?? gitText(["rev-parse", "HEAD"], { root });
  const now = args.now ?? rfc3339(Date.now());
  const head = fetchSignedHead({ root });
  const delegatedAt = head.present ? readDelegationTimes({ root, ref: head.ref }) : new Map();
  let available;
  try {
    available = args.testKeys.length
      ? testKeySigners(args.testKeys, { out: args.out })
      : indexSignersFromEnv();
  } catch (e) {
    // A named refusal, not a stack. A guard that reports itself as an uncaught
    // throw is a guard a reader scrolls past — `tools/selftest.mjs`'s own
    // header records the same finding about its module loader.
    console.error(`FAIL  ${e.message}`);
    return 2;
  }
  if (available.length === 0) {
    console.error(
      "FAIL  no ASTRA_INDEX_SIGNING_KEY in this job. The signer is the one publisher of the catalogue and the " +
      "withdrawal list (D1); a run with no key would publish nothing and report success.",
    );
    return 1;
  }

  const record = await signRun({ root, sourceCommit, head, now, available, delegatedAt });
  writeTree({ out: args.out ?? "dist/signed", files: record.files });
  // The bytes are on disk; the record is what every step after this one reads,
  // and it never carries them — a document in a JSON field is a document
  // somebody will re-serialise.
  writeRecord(args.record, { ...record, files: Object.keys(record.files).sort() });

  for (const note of record.notes) console.log(`note  ${note}`);
  for (const alert of record.alerts) console.log(`::warning::${alert}`);
  for (const refusal of record.refusals) console.error(`::error::${refusal}`);
  console.log(
    `ok    ${record.key_mode} mode, catalogue ${record.serials.index} (${record.documents.index?.decision}), ` +
    `list ${record.serials.revocations} (${record.documents.revocations?.decision}); commit=${record.commit}`,
  );
  output({
    status: record.status,
    codes: record.codes.join(" "),
    hexes: record.hexes.join(" "),
    commit: String(record.commit),
    source_commit: record.source_commit,
  });
  // A refusal is red. A carry is not: the run still publishes, and the alert
  // job is what says so — failing here would skip the commit that carried it.
  return record.refusals.length ? 1 : 0;
}

function stepCommit(args) {
  const root = args.root;
  const record = JSON.parse(fs.readFileSync(args.record, "utf8"));
  if (!record.commit) {
    console.log("ok    nothing changed at this Source-Commit, so there is nothing to commit (D4)");
    output({ committed: "false", signed_sha: "", receipt: "" });
    return 0;
  }
  const tree = args.tree ?? "dist/signed";
  const files = {};
  for (const rel of Object.values(SIGNED_FILES)) {
    const file = path.join(tree, rel);
    if (!fs.existsSync(file)) {
      console.error(`::error::${file} is not in the signed tree; the signing step writes all four documents (D2)`);
      return 1;
    }
    files[rel] = fs.readFileSync(file, "utf8");
  }

  const runUrl = `${process.env.GITHUB_SERVER_URL ?? "https://github.com"}/${process.env.GITHUB_REPOSITORY}` +
    `/actions/runs/${process.env.GITHUB_RUN_ID}`;
  const sha = buildSignedCommit({ root, files, parent: record.parent, message: commitMessage(record, runUrl) });
  const pushed = pushSigned({ root, sha, parent: record.parent });
  if (!pushed.pushed) {
    console.error(`::error::${CODES.pushRace}: ${pushed.reason}`);
    output({ committed: "false", signed_sha: "", receipt: "", codes: CODES.pushRace, status: "red" });
    return 1;
  }
  console.log(`ok    ${SIGNED_BRANCH} ${sha} pushed in ${pushed.attempts} attempt(s)`);
  output({ committed: "true", signed_sha: sha, receipt: receiptName(sha) });
  return 0;
}

/** Every file under a directory, relative path → bytes. `{}` when it is not there. */
function readTree(dir) {
  const out = {};
  if (!dir || !fs.existsSync(dir)) return out;
  const walk = (rel) => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const next = path.join(rel, entry.name);
      if (entry.isDirectory()) walk(next);
      else out[next.split(path.sep).join("/")] = fs.readFileSync(path.join(dir, next));
    }
  };
  walk("");
  return out;
}

async function stepPages(args) {
  const root = args.root;
  const sourceCommit = args.sourceCommit ?? gitText(["rev-parse", "HEAD"], { root });
  const head = fetchSignedHead({ root });
  if (!head.present) {
    console.error(`::error::there is no \`${SIGNED_BRANCH}\` to deploy (${head.reason}); the publish job makes it first (D1)`);
    return 1;
  }
  const arming = armingState({ root, sourceCommit });
  const { files, list_source } = pagesRegistryFiles({ root, head, arming, sourceCommit });
  const { tree, overwritten } = pagesTree({ site: readTree(args.site), registry: files });
  const out = args.out ?? "dist/pages";
  fs.rmSync(out, { recursive: true, force: true });
  for (const [rel, bytes] of Object.entries(tree)) {
    const file = path.join(out, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
  }

  // D5: deploy whenever Pages serves different bytes, so one failed deploy
  // cannot age the list. Unreachable counts as different — the cost of a
  // needless deploy is a minute, and the cost of the other answer is a
  // withdrawal list nobody is serving.
  const served = await fetchServed({ base: PAGES_BASE });
  const differing = [];
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const there = served[name];
    if (!there?.ok) differing.push(`${rel} (${there?.error ?? "no answer"})`);
    else if (there.body !== files[rel]) differing.push(rel);
  }

  // D5: "On a render failure, `pages` redeploys the newest `pages-site` with
  // the new `registry/v1/*` and alerts." The redeploy is the workflow's two
  // steps above this one; the ALERT is this, and it is read from the step's
  // outcome rather than decided in the workflow, so that the one place it can
  // be got wrong has a test. A non-fatal step that nobody hears about is a
  // website that quietly stops being rebuilt.
  const siteFailed = (process.env.ASTRA_SIGNER_SITE_OUTCOME ?? "").trim() === "failure";
  const codes = siteFailed ? [CODES.siteRender] : [];

  const record = {
    schema: "astra.registry.signer-run/1",
    step: "pages",
    source_commit: sourceCommit,
    signed_head: head.sha,
    armed: arming.armed,
    latch_commit: arming.latch_commit,
    list_source,
    site_files: Object.keys(tree).length - Object.keys(files).length,
    site_rendered: !siteFailed,
    overwritten,
    differing,
    deploy: differing.length > 0,
    codes,
    hexes: [sourceCommit],
    status: codes.length ? "red" : "green",
  };
  writeRecord(args.record, record);
  if (siteFailed) {
    console.log(
      `::warning::the site did not render this run; the four documents are deployed over the newest pages-site ` +
      `artifact (D5, MOD-46). The catalogue and the withdrawal list are this run's.`,
    );
  }
  console.log(
    `ok    ${out}: ${Object.keys(tree).length} file(s), list from ${list_source}` +
    `${arming.armed ? ` (armed at ${arming.latch_commit?.slice(0, 12)})` : " (not armed)"}; ` +
    `${differing.length ? `deploying — Pages differs on ${differing.join(", ")}` : "Pages already serves these bytes"}`,
  );
  output({
    deploy: String(record.deploy),
    list_source,
    armed: String(arming.armed),
    status: record.status,
    codes: codes.join(" "),
    hexes: record.hexes.join(" "),
  });
  return 0;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.step === "sign") return stepSign(args);
  if (args.step === "commit") return stepCommit(args);
  if (args.step === "pages") return stepPages(args);
  throw new Error(`unknown --step ${JSON.stringify(args.step)}; it is one of sign, commit, pages`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main(process.argv.slice(2)));
}
