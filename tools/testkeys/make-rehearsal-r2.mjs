#!/usr/bin/env node
// The ROLL-60 rehearsal series (RC-R2-5), produced by the real signer.
//
//   node tools/testkeys/make-rehearsal-r2.mjs          # rewrite fixtures/rehearsal-r2/
//   node tools/testkeys/make-rehearsal-r2.mjs --check  # rebuild in a temp tree, compare, write nothing
//   node tools/testkeys/make-rehearsal-r2.mjs --print-commands   # the commands, without running them
//
// ── what this is for ────────────────────────────────────────────────────────
//
// ROLL-60 says R2 may not exit until a staging service on this directory's
// roots, and a debug 0.2.x daemon built with `insecure-test-trust-roots` and
// pointed at it, accept a key rotation: a trust.json at serial + 1, a new index
// key under SERVE-30, a dual-signed withdrawal list an idle daemon also
// accepts, and a root.json change under SERVE-16 and SERVE-92. Neither the
// service nor the daemon can be asked to accept any of that until the bytes
// exist. **This file makes the bytes.** It is the registry's half of the
// rehearsal and it gates R2's exit for that reason and no other.
//
// ── why none of it is hand-assembled ────────────────────────────────────────
//
// A rotation is not a property of a document. It is a decision `signRun` makes
// about four documents at once, out of `signed`'s own history: which key may
// sign the catalogue yet (SERVE-30's seven hours), which keys sign the list and
// in what order, whether a document may be carried, and whether every document
// verifies against the trust.json committed beside it (SERVE-95). A fixture
// built by calling a signature function five times would agree with itself
// perfectly and would say nothing at all about the program that will do this
// for real. So every document below comes out of
//
//     node tools/signer/run.mjs --step sign --test-key … --test-key …
//
// against a throwaway registry with real git history, and the `signed` branch
// the next step plans against is made by `--step commit`. The commands are
// printed as they run, and `--print-commands` prints them without running
// anything.
//
// ── the keys, and the one borrowed id ───────────────────────────────────────
//
// Everything here is signed with the TEST keys in this directory, whose private
// halves are committed to a public repository on purpose. Nothing a user
// installs may be signed with them and no shipped Astra build can compile the
// roots in (../README.md).
//
// The outgoing index key is published under the id **`astra-index-2026a`** over
// TEST-ONLY-DO-NOT-TRUST-index-2026a's bytes. That is not decoration and not an
// oversight: `tools/signer/key-window.mjs`'s `WINDOW_EXEMPT_KEY_IDS` is keyed on
// that literal id, and without the exemption the run that CREATES `signed` is
// the one run that cannot succeed — no commit has delegated anything, so every
// key's window reads as having started this instant, so the catalogue may not be
// signed, so there is nothing to carry, so the branch is never created.
// `tools/selftest/signer-run.mjs`'s BOOTSTRAP borrows the same id for the same
// reason. The incoming key keeps its own test id, because nothing forces it not
// to and a fixture should look like what it is.
//
// ── determinism ─────────────────────────────────────────────────────────────
//
// `--check` compares committed bytes against a fresh build, so every input that
// reaches a signature or a commit sha is fixed here: the author and committer
// identities, every commit date, and the `--now` of every signer run. Ed25519 is
// deterministic and `stableStringify` is canonical, so two runs of this file
// produce the same bytes or something has changed that ought to be looked at.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { stableStringify } from "../lib/canonical.mjs";
import { TRUST_SCHEMA } from "../../bot/lib/sign.mjs";
import { loadTestRoot } from "./regenerate.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..", "..");

export const FIXTURE_DIR = path.join(HERE, "fixtures", "rehearsal-r2");
export const MANIFEST_FILE = path.join(FIXTURE_DIR, "manifest.json");

/** The four files D2 puts in every `signed` commit, relative to a step directory. */
export const DOCUMENTS = [
  "registry/v1/index.json",
  "registry/v1/revocations.json",
  "registry/v1/trust.json",
  "registry/v1/root.json",
];

// ── the keys ────────────────────────────────────────────────────────────────

/** The outgoing index key's PUBLISHED id. See the header: it is borrowed. */
export const OUTGOING_KEY_ID = "astra-index-2026a";
export const OUTGOING_TEST_KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
/** The incoming index key, under its own test id. */
export const INCOMING_KEY_ID = "TEST-ONLY-DO-NOT-TRUST-index-2026b";
export const INCOMING_TEST_KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026b";

const ROOT_A = "TEST-ONLY-DO-NOT-TRUST-root-a";
const ROOT_B = "TEST-ONLY-DO-NOT-TRUST-root-b";

/** `--test-key` specs, in the order the environment would hold them: outgoing first. */
const BOTH_KEYS = [`${OUTGOING_KEY_ID}=${OUTGOING_TEST_KEY}`, `${INCOMING_KEY_ID}=${INCOMING_TEST_KEY}`];
const OUTGOING_ONLY = [`${OUTGOING_KEY_ID}=${OUTGOING_TEST_KEY}`];
const INCOMING_ONLY = [`${INCOMING_KEY_ID}=${INCOMING_TEST_KEY}`];

const BANNER =
  "TEST-ONLY REHEARSAL FIXTURE (RC-R2-5 / ROLL-60). Signed with the throwaway keys in " +
  "tools/testkeys/, whose private halves are published in this repository. No production daemon " +
  "trusts these roots and nothing a user installs may be signed with them.";

// ── the clock, and the commit identities ────────────────────────────────────

/** T0. Every `--now` and every commit date below is an offset from it. */
export const T0 = "2026-09-22T00:00:00Z";
const HOUR_MS = 3600 * 1000;
const at = (hours) => new Date(Date.parse(T0) + hours * HOUR_MS).toISOString().replace(/\.\d{3}Z$/, "Z");

const MAIN_IDENTITY = { name: "rehearsal fixture", email: "rehearsal@users.noreply.invalid" };

/** The run URL the D2 commit message carries. Fixed, so the message is a fixture. */
const RUN_ENV = {
  GITHUB_SERVER_URL: "https://github.com",
  GITHUB_REPOSITORY: "mihailinl/astra-registry",
  GITHUB_RUN_ID: "0",
};

// ── the throwaway registry's contents ───────────────────────────────────────

const listing = (id, summary) => ({
  schema: "astra.registry.plugin/1",
  id,
  name: id.replace(/-/g, " "),
  summary,
  license: "MIT",
  source: { kind: "github", repo: `someone/${id}` },
  added_at: "2026-08-10",
});

const release = (id, version) => ({
  schema: "astra.registry.version/1",
  id,
  version,
  published_at: "2026-08-10T00:00:00Z",
  release: { kind: "github_release", repo: `someone/${id}`, tag: `v${version}` },
  protocol: 1,
  capabilities: ["tools"],
  artifacts: {
    "linux-x64": {
      url: `https://github.com/someone/${id}/releases/download/v${version}/${id}-${version}-linux-x64.astraplugin`,
      filename: `${id}-${version}-linux-x64.astraplugin`,
      sha256: "a".repeat(64),
      size: 1234,
    },
  },
});

const advisory = (id, pluginId, reason) => ({
  id,
  published: "2026-09-22",
  severity: "high",
  action: "block_install",
  reason,
  entries: [{ kind: "id", value: pluginId }],
});

/** root.json, whose `roots` member is what SERVE-16 compares. Unsigned by design. */
const rootDocument = (roots) => ({
  $comment: BANNER,
  schema: "astra.registry.root/1",
  status: "provisioned",
  generated_at: "2026-08-11T17:31:46Z",
  roots: roots.map(({ keyId, role }) => {
    const key = loadTestRoot(keyId);
    return {
      key_id: key.key_id,
      role,
      algorithm: "ed25519",
      public_key: key.publicKeyB64,
      fingerprint_sha256: key.fingerprint,
      signs: "trust.json",
    };
  }),
});

/** SERVE-92's two root sets. The change drops the retiring active root (step 3). */
const ROOT_SET_A = [{ keyId: ROOT_A, role: "active" }, { keyId: ROOT_B, role: "reserve" }];
const ROOT_SET_B = [{ keyId: ROOT_B, role: "active" }];

/**
 * The `signed` payload of a trust.json.
 *
 * `issued_at` and `expires_at` are arguments rather than clock reads because
 * SERVE-20 lets a trust.json be re-signed at the SAME serial only when its
 * `signed` payload is byte-identical — which is exactly what the root change
 * below does, and it can only do it if nothing in here moves.
 */
const trustPayload = ({ serial, keyIds, issuedAt, expiresAt }) => ({
  schema: TRUST_SCHEMA,
  serial,
  issued_at: issuedAt,
  expires_at: expiresAt,
  index_keys: keyIds.map((keyId) => {
    const testKeyId = keyId === OUTGOING_KEY_ID ? OUTGOING_TEST_KEY : keyId;
    return { key_id: keyId, public_key: loadTestRoot(testKeyId).publicKeyB64, not_before: issuedAt };
  }),
  reusable_workflow_shas: ["e3329df252a46d747676cb540ae4b986af68a3ad"],
});

const TRUST_ISSUED = "2026-09-01T00:00:00Z";
const TRUST_EXPIRES = "2027-09-01T00:00:00Z";

// ── running things, and saying what was run ─────────────────────────────────

const commands = [];

/**
 * The two directories this run happens to have been given, spelled as names.
 *
 * `--check` compares committed bytes against a fresh build, and a fresh build
 * gets a different `mkdtemp` every time. A command line with an absolute temp
 * path in it is therefore the one part of this fixture that cannot be a
 * fixture — it would make `--check` red on every machine for a reason that has
 * nothing to do with a signature. Redacting it also makes the recorded commands
 * readable, which is what they are recorded for: `$WORK` is the throwaway
 * registry and `$OUT` is the fixture directory.
 */
let redactions = [];

const redact = (text) => redactions.reduce((acc, [from, to]) => acc.split(from).join(to), text);

function record(argv, opts = {}) {
  const shown = redact(argv.join(" "));
  commands.push({ command: shown, ...(opts.env ? { env: opts.env } : {}) });
  return shown;
}

function run(argv, { cwd = REPO, env = {}, allowFailure = false } = {}) {
  record(argv, { env: Object.keys(env).length ? env : undefined });
  try {
    return execFileSync(argv[0], argv.slice(1), {
      cwd,
      encoding: "utf8",
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    if (allowFailure) return { failed: true, status: e.status, stdout: String(e.stdout ?? ""), stderr: String(e.stderr ?? "") };
    throw new Error(`${argv.join(" ")} exited ${e.status}\n${String(e.stderr ?? "")}`);
  }
}

// ── the throwaway registry ──────────────────────────────────────────────────

/**
 * A registry with real git history, an `origin` that is itself, and no network.
 *
 * `origin` points at the directory so that `fetchSignedHead` and `pushSigned`
 * — the real signer's own functions, which take a remote and not a path — work
 * unchanged. A remote that is a local path is still a remote.
 */
function makeRegistry(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const git = (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trimEnd();
  git("init", "-q", "-b", "main");
  git("config", "user.email", MAIN_IDENTITY.email);
  git("config", "user.name", MAIN_IDENTITY.name);
  git("config", "commit.gpgsign", "false");
  git("remote", "add", "origin", dir);

  const write = (rel, value) => {
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === "string" ? value : stableStringify(value));
  };

  /** A main commit at a fixed instant, so its sha is a fixture too. */
  const commit = (message, when) => {
    git("add", "-A");
    execFileSync("git", ["-C", dir, "commit", "-qm", message], {
      encoding: "utf8",
      env: { ...process.env, GIT_AUTHOR_DATE: when, GIT_COMMITTER_DATE: when },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return git("rev-parse", "HEAD");
  };

  return { dir, git, write, commit };
}

/**
 * Write main's trust.json, signed by a TEST root with the real test-root signer.
 *
 * `tools/testkeys/sign-trust.mjs` is the script the daemon's own trust fixtures
 * come out of; the production ceremony is `tools/sign-trust.mjs` and it is a
 * different script because the real root private key never comes near this
 * repository (../README.md, SECURITY.md).
 */
function signTrustOnMain(reg, { rootKeyId, payload, step }) {
  const unsigned = path.join(reg.dir, `.trust-unsigned-${step}.json`);
  fs.writeFileSync(unsigned, `${stableStringify({ signed: payload })}\n`);
  const out = path.join(reg.dir, "registry", "v1", "trust.json");
  fs.mkdirSync(path.dirname(out), { recursive: true });
  run([
    "node", path.join("tools", "testkeys", "sign-trust.mjs"),
    "--key", rootKeyId,
    "--in", unsigned,
    "--out", out,
    "--banner", BANNER,
  ]);
  fs.rmSync(unsigned);
}

// ── one rehearsal step ──────────────────────────────────────────────────────

/**
 * Sign at a Source-Commit, save the four documents, and advance `signed`.
 *
 * Returns the signer's own record. Nothing here inspects a signature or a key:
 * the expectations are asserted by the caller against the record the signer
 * wrote, which is the only account of the run that a reviewer can check against
 * the code that produced it.
 */
function signStep(reg, { id, sourceCommit, now, testKeys, outDir, commitIt = true }) {
  const tree = path.join(reg.dir, ".dist-signed");
  const recordFile = path.join(reg.dir, `.record-${id.replace(/\//g, "-")}.json`);
  const signArgv = [
    "node", path.join("tools", "signer", "run.mjs"), "--step", "sign",
    "--root", reg.dir,
    "--source-commit", sourceCommit,
    "--now", now,
    ...testKeys.flatMap((k) => ["--test-key", k]),
    "--out", tree,
    "--record", recordFile,
  ];
  const signed = run(signArgv, { allowFailure: true });
  const rec = JSON.parse(fs.readFileSync(recordFile, "utf8"));
  rec.$command = redact(signArgv.join(" "));
  rec.notes = signerNotes(rec.notes);

  if (rec.commit && commitIt) {
    const commitArgv = [
      "node", path.join("tools", "signer", "run.mjs"), "--step", "commit",
      "--root", reg.dir, "--record", recordFile, "--tree", tree,
    ];
    run(commitArgv, { env: { ...RUN_ENV, GIT_AUTHOR_DATE: now, GIT_COMMITTER_DATE: now } });
    rec.$signed_sha = reg.git("rev-parse", "refs/heads/signed");
    rec.$commit_message = reg.git("log", "-1", "--format=%B", "refs/heads/signed");
  } else {
    rec.$signed_sha = null;
    rec.$commit_message = null;
    rec.$sign_exit = typeof signed === "object" && signed.failed ? signed.status : 0;
  }

  const dir = path.join(outDir, ...id.split("/"));
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  if (rec.commit && commitIt) {
    for (const rel of DOCUMENTS) {
      const from = path.join(tree, rel);
      const to = path.join(dir, rel);
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.writeFileSync(to, fs.readFileSync(from));
    }
    fs.writeFileSync(path.join(dir, "commit-message.txt"), rec.$commit_message);
  }
  fs.writeFileSync(path.join(dir, "record.json"), `${JSON.stringify(rec, null, 2)}\n`);
  fs.rmSync(tree, { recursive: true, force: true });
  fs.rmSync(recordFile, { force: true });
  return rec;
}

const must = (cond, message) => {
  if (!cond) throw new Error(`rehearsal fixture: ${message}`);
};

/**
 * The notes a rehearsal step keeps: the signer's own, never the gate's.
 *
 * `signRun` returns `[...plan.notes, ...keys.notes]`. The first half is
 * `tools/validate.mjs`'s — one line per cross-repository check it could not
 * run, plus counts read out of unrelated repository code — and **none of it is
 * a property of this rehearsal.** It is a property of the checkout the
 * generator happened to run in.
 *
 * That is not a theoretical objection. The first version of this file saved the
 * notes whole, and the first unrelated pull request to land afterwards —
 * `bot/locale-digest-vectors`, which added a sixth "NOT verified" line — turned
 * `--check` red on all eight steps, with every signature still correct. A
 * fixture that goes red when another team adds a check is a fixture somebody
 * regenerates without reading, and the next time it goes red for a real reason
 * they will regenerate it then too.
 *
 * So the filter is by SUBJECT: a note is kept when it names one of the index
 * keys this series rotates, which is exactly the set `key-window.mjs` emits —
 * the compromise-mode line, the seven-hour window lines, and the "in the
 * environment and not delegated" line. Those are the run's reasoning about the
 * rotation, they are what a reader of a rehearsal fixture wants, and they move
 * only when the signer's own decisions move.
 */
function signerNotes(notes) {
  const ids = [OUTGOING_KEY_ID, INCOMING_KEY_ID];
  return (notes ?? []).filter((n) => ids.some((id) => n.includes(id)));
}

// ── the series ──────────────────────────────────────────────────────────────

/**
 * Build the whole series into `outDir` and return the manifest.
 *
 * Every expectation below is asserted here rather than only in the selftest,
 * because a generator that quietly produced the wrong shape would write a
 * fixture the selftest then judged against the same wrong shape.
 */
export function buildSeries({ outDir, work }) {
  commands.length = 0;
  // Longest first, so a path that is a prefix of the other cannot eat it.
  redactions = [[path.resolve(work), "$WORK"], [path.resolve(outDir), "$OUT"]]
    .sort((a, b) => b[0].length - a[0].length);
  const reg = makeRegistry(work);
  const steps = [];

  const note = (id, rec, expectations) => {
    steps.push({
      id,
      now: rec.now,
      key_mode: rec.key_mode,
      dropped_keys: rec.dropped_keys,
      source_commit: rec.source_commit,
      parent: rec.parent,
      signed_sha: rec.$signed_sha,
      committed: rec.commit,
      serials: rec.serials,
      documents: rec.documents,
      command: rec.$command,
      ...expectations,
    });
  };

  // ── rotation/00-baseline ──────────────────────────────────────────────────
  // The run that creates `signed`. One index key, so one signature on each
  // document; the catalogue is signable at all only because the outgoing key's
  // published id is the one `WINDOW_EXEMPT_KEY_IDS` names.
  reg.write("plugins/dice-roller/plugin.json", listing("dice-roller", "Rolls dice, so the catalogue is not empty."));
  reg.write("plugins/dice-roller/versions/1.0.0.json", release("dice-roller", "1.0.0"));
  reg.write("plugins/note-taker/plugin.json", listing("note-taker", "Takes notes, so the catalogue has two listings."));
  reg.write("plugins/note-taker/versions/1.0.0.json", release("note-taker", "1.0.0"));
  reg.write("tools/revocations/ASTRA-2026-0001.json", advisory("ASTRA-2026-0001", "dice-roller",
    "A fixture advisory, long enough to be a sentence a user could act on."));
  reg.write("registry/v1/root.json", rootDocument(ROOT_SET_A));
  signTrustOnMain(reg, {
    rootKeyId: ROOT_A,
    step: "baseline",
    payload: trustPayload({ serial: 2, keyIds: [OUTGOING_KEY_ID], issuedAt: TRUST_ISSUED, expiresAt: TRUST_EXPIRES }),
  });
  const mainBaseline = reg.commit("two listings, an advisory, trust.json at serial 2 and root set A", at(0));

  let rec = signStep(reg, {
    id: "rotation/00-baseline", sourceCommit: mainBaseline, now: at(0),
    testKeys: OUTGOING_ONLY, outDir,
  });
  must(rec.commit, "the run that creates `signed` did not commit");
  must(rec.key_mode === "normal", `baseline ran in ${rec.key_mode} mode`);
  must(rec.documents.index.signed_by?.join(",") === OUTGOING_KEY_ID, "the baseline catalogue is not signed by the outgoing key alone");
  note("rotation/00-baseline", rec, {
    what: "The state the rehearsal starts from: one index key, one signature on each document.",
    trust_serial: 2,
  });

  // ── rotation/01-delegate ──────────────────────────────────────────────────
  // trust.json at SERIAL + 1, delegating the incoming key beside the outgoing
  // one (SERVE-30 keeps the outgoing key delegated until R9b). From this commit
  // every list is dual-signed, outgoing signature first — and the catalogue is
  // NOT signed by the incoming key for seven hours.
  signTrustOnMain(reg, {
    rootKeyId: ROOT_A,
    step: "delegate",
    payload: trustPayload({
      serial: 3, keyIds: [OUTGOING_KEY_ID, INCOMING_KEY_ID], issuedAt: TRUST_ISSUED, expiresAt: TRUST_EXPIRES,
    }),
  });
  reg.write("plugins/dice-roller/versions/1.1.0.json", release("dice-roller", "1.1.0"));
  // An advisory, because SERVE-30's dual signature only exists on a run that
  // SIGNS the list. D4 calls an unchanged list `unchanged` and re-commits the
  // head's bytes — single-signed by the outgoing key — until it is 20 hours old
  // (RESIGN_AFTER_HOURS), so a delegating commit with no advisory in it carries
  // the incoming key into circulation nowhere. See the README.
  reg.write("tools/revocations/ASTRA-2026-0002.json", advisory("ASTRA-2026-0002", "note-taker",
    "An advisory in the delegating commit, so the list this run publishes is a signed one."));
  const mainDelegate = reg.commit("trust.json at serial 3 delegates the incoming index key; a release and an advisory", at(1));

  rec = signStep(reg, {
    id: "rotation/01-delegate", sourceCommit: mainDelegate, now: at(1),
    testKeys: BOTH_KEYS, outDir,
  });
  must(rec.commit, "the delegating run did not commit");
  must(rec.key_mode === "normal", `the delegating run read as ${rec.key_mode} mode`);
  must(
    rec.documents.revocations.signed_by?.join(",") === `${OUTGOING_KEY_ID},${INCOMING_KEY_ID}`,
    `the list is not dual-signed outgoing-first: ${rec.documents.revocations.signed_by}`,
  );
  must(
    rec.documents.index.signed_by?.join(",") === OUTGOING_KEY_ID,
    `the catalogue was signed by ${rec.documents.index.signed_by} inside the incoming key's seven hours`,
  );
  // `signerNotes` keeps the run's reasoning about the rotation and drops the
  // gate's. A filter that kept nothing would be indistinguishable from a signer
  // that said nothing, so the two steps whose reasoning matters are asserted to
  // still have some.
  must(
    rec.notes.some((n) => n.includes(INCOMING_KEY_ID) && n.includes("7 h")),
    `the delegating run kept no seven-hour note: ${JSON.stringify(rec.notes)}`,
  );
  note("rotation/01-delegate", rec, {
    what: "ROLL-60's trust.json at serial + 1. Dual-signed list; catalogue by the outgoing key alone.",
    trust_serial: 3,
    delegated_at: at(1),
    hours_since_delegation: 0,
  });
  const delegatedAt = at(1);

  // ── rotation/02-mid-window ────────────────────────────────────────────────
  reg.write("plugins/note-taker/versions/1.1.0.json", release("note-taker", "1.1.0"));
  reg.write("tools/revocations/ASTRA-2026-0003.json", advisory("ASTRA-2026-0003", "dice-roller",
    "A second advisory, three hours in."));
  const mainMidWindow = reg.commit("a release and an advisory, three hours after the delegating commit", at(4));
  rec = signStep(reg, {
    id: "rotation/02-mid-window", sourceCommit: mainMidWindow, now: at(4),
    testKeys: BOTH_KEYS, outDir,
  });
  must(rec.commit, "the mid-window run did not commit");
  must(
    rec.documents.index.signed_by?.join(",") === OUTGOING_KEY_ID,
    `three hours in, the catalogue was signed by ${rec.documents.index.signed_by}`,
  );
  must(rec.documents.revocations.signed_by?.length === 2, "the mid-window list is not dual-signed");
  note("rotation/02-mid-window", rec, {
    what: "Three hours after the delegation: SERVE-30's seven still have not passed.",
    trust_serial: 3,
    delegated_at: delegatedAt,
    hours_since_delegation: 3,
  });
  const mainAtFork = mainMidWindow;
  const signedAtFork = reg.git("rev-parse", "refs/heads/signed");

  // ── compromise/00-drop-2026a ──────────────────────────────────────────────
  // D10, forked from the mid-window state ON PURPOSE. At the fork `signed`'s
  // catalogue is signed by the outgoing key ALONE, which is what makes both of
  // D10 step 4's waivers load-bearing: the seven-hour window has not opened for
  // the incoming key, and a carried catalogue would not verify against the
  // trust.json that drops the key that signed it. Fork it after the window
  // opens instead and the head is dual-signed, the carry verifies, and the
  // fixture proves nothing — which is the case `key-window.mjs`'s header calls
  // the R9b retirement.
  signTrustOnMain(reg, {
    rootKeyId: ROOT_A,
    step: "compromise",
    payload: trustPayload({ serial: 4, keyIds: [INCOMING_KEY_ID], issuedAt: TRUST_ISSUED, expiresAt: TRUST_EXPIRES }),
  });
  reg.write("tools/revocations/ASTRA-2026-0900.json", advisory("ASTRA-2026-0900", "note-taker",
    "D10 step 5: an advisory naming the retired index key's fingerprint."));
  reg.write("plugins/dice-roller/versions/1.2.0.json", release("dice-roller", "1.2.0"));
  const mainCompromise = reg.commit(
    "D10: trust.json at serial 4 drops the compromised index key; the advisory and a release", at(5),
  );
  rec = signStep(reg, {
    id: "compromise/00-drop-2026a", sourceCommit: mainCompromise, now: at(5),
    testKeys: INCOMING_ONLY, outDir,
  });
  must(rec.commit, `the compromise run did not commit: ${rec.refusals.join(" | ")}`);
  must(rec.key_mode === "compromise", `the compromise run read as ${rec.key_mode} mode`);
  must(rec.dropped_keys.join(",") === OUTGOING_KEY_ID, `dropped ${rec.dropped_keys.join(",")}`);
  must(rec.documents.index.decision === "changed", `the compromise catalogue was ${rec.documents.index.decision}, not re-signed`);
  must(rec.documents.index.signed_by?.join(",") === INCOMING_KEY_ID, "the compromise catalogue is not signed by the incoming key alone");
  must(rec.documents.revocations.signed_by?.join(",") === INCOMING_KEY_ID, "the compromise list is not signed by the incoming key alone");
  must(
    rec.notes.some((n) => n.includes("compromise mode (D10)")),
    `the compromise run kept no compromise-mode note: ${JSON.stringify(rec.notes)}`,
  );
  note("compromise/00-drop-2026a", rec, {
    what: "D10 as proposed, as ONE commit that verifies whole: trust.json at serial + 2 dropping the " +
      "outgoing key, a list signed by the incoming key alone, and the catalogue re-signed with it.",
    trust_serial: 4,
    forks_from: "rotation/02-mid-window",
    delegated_at: delegatedAt,
    hours_since_delegation: 4,
    waivers: ["SERVE-30's seven hours", "the carry"],
  });
  reg.git("branch", "-f", "compromise-source", mainCompromise);

  // ── compromise/01-trust-only-blocked ──────────────────────────────────────
  // D10's OWN inputs, and nothing else: a Source-Commit that changes trust.json
  // alone. No documents come out of this step, because the signer commits
  // nothing — see the manifest entry and this step's record.json.
  reg.git("update-ref", "refs/heads/signed", signedAtFork);
  run(["git", "-C", reg.dir, "reset", "-q", "--hard", mainAtFork]);
  signTrustOnMain(reg, {
    rootKeyId: ROOT_A,
    step: "blocked",
    payload: trustPayload({ serial: 4, keyIds: [INCOMING_KEY_ID], issuedAt: TRUST_ISSUED, expiresAt: TRUST_EXPIRES }),
  });
  const mainTrustOnly = reg.commit("D10 steps 3 and 4 with nothing else in the commit", at(5));
  rec = signStep(reg, {
    id: "compromise/01-trust-only-blocked", sourceCommit: mainTrustOnly, now: at(5),
    testKeys: INCOMING_ONLY, outDir,
  });
  must(!rec.commit, "the trust-only compromise run committed; this step records that it cannot");
  must(rec.codes.includes("SIGNER_TRUST_REFUSED_DOCUMENT"), `the refusal is not SERVE-95's: ${rec.codes.join(" ")}`);
  must(rec.documents.index.decision === "unchanged", `the catalogue read ${rec.documents.index.decision}`);
  note("compromise/01-trust-only-blocked", rec, {
    what: "D10's procedure with nothing in the Source-Commit but trust.json. The signer commits NOTHING: " +
      "both documents are `unchanged`, so the head's bytes — signed by the dropped key — would be " +
      "re-committed, and SERVE-95 refuses them. No documents, a record only.",
    trust_serial: 4,
    forks_from: "rotation/02-mid-window",
    documents_present: false,
  });

  // ── back to the rotation line ─────────────────────────────────────────────
  reg.git("update-ref", "refs/heads/signed", signedAtFork);
  run(["git", "-C", reg.dir, "reset", "-q", "--hard", mainAtFork]);

  // ── rotation/03-window-open ───────────────────────────────────────────────
  reg.write("plugins/note-taker/versions/1.2.0.json", release("note-taker", "1.2.0"));
  reg.write("tools/revocations/ASTRA-2026-0004.json", advisory("ASTRA-2026-0004", "note-taker",
    "A third advisory, eight hours in."));
  const mainWindowOpen = reg.commit("a release and an advisory, eight hours after the delegating commit", at(9));
  rec = signStep(reg, {
    id: "rotation/03-window-open", sourceCommit: mainWindowOpen, now: at(9),
    testKeys: BOTH_KEYS, outDir,
  });
  must(rec.commit, "the window-open run did not commit");
  must(
    rec.documents.index.signed_by?.join(",") === `${OUTGOING_KEY_ID},${INCOMING_KEY_ID}`,
    `eight hours in, the catalogue was signed by ${rec.documents.index.signed_by}`,
  );
  note("rotation/03-window-open", rec, {
    what: "Eight hours after the delegation: SERVE-30's seven have passed and the catalogue is dual-signed.",
    trust_serial: 3,
    delegated_at: delegatedAt,
    hours_since_delegation: 8,
  });

  // ── rotation/04-root-change ───────────────────────────────────────────────
  // SERVE-92 step 3, the one the daemon has a leg in: root.json drops the
  // retiring root, and the trust.json beside it is re-signed by the incoming
  // root at the SAME serial with a byte-identical `signed` payload, which is
  // the only thing SERVE-20 lets a trust.json do at an unchanged serial.
  reg.write("registry/v1/root.json", rootDocument(ROOT_SET_B));
  signTrustOnMain(reg, {
    rootKeyId: ROOT_B,
    step: "rootchange",
    payload: trustPayload({
      serial: 3, keyIds: [OUTGOING_KEY_ID, INCOMING_KEY_ID], issuedAt: TRUST_ISSUED, expiresAt: TRUST_EXPIRES,
    }),
  });
  reg.write("plugins/dice-roller/versions/1.3.0.json", release("dice-roller", "1.3.0"));
  reg.write("tools/revocations/ASTRA-2026-0005.json", advisory("ASTRA-2026-0005", "dice-roller",
    "An advisory in the root-change commit."));
  const mainRootChange = reg.commit("SERVE-92 step 3: root set B, trust.json re-signed by the new active root", at(10));
  rec = signStep(reg, {
    id: "rotation/04-root-change", sourceCommit: mainRootChange, now: at(10),
    testKeys: BOTH_KEYS, outDir,
  });
  must(rec.commit, "the root-change run did not commit");
  note("rotation/04-root-change", rec, {
    what: "SERVE-16 and SERVE-92: root.json drops the retiring root and trust.json is re-signed by the " +
      "new active root at the same serial, with a byte-identical `signed` payload (SERVE-20).",
    trust_serial: 3,
    root_set: ROOT_SET_B.map((r) => r.keyId),
    trust_signed_by: ROOT_B,
  });

  // ── rotation/05-after-root ────────────────────────────────────────────────
  reg.write("plugins/note-taker/versions/1.3.0.json", release("note-taker", "1.3.0"));
  reg.write("tools/revocations/ASTRA-2026-0006.json", advisory("ASTRA-2026-0006", "note-taker",
    "An advisory after the root change."));
  const mainAfterRoot = reg.commit("a release and an advisory after the root change", at(11));
  rec = signStep(reg, {
    id: "rotation/05-after-root", sourceCommit: mainAfterRoot, now: at(11),
    testKeys: BOTH_KEYS, outDir,
  });
  must(rec.commit, "the after-root run did not commit");
  note("rotation/05-after-root", rec, {
    what: "ROLL-60's last clause: the trust.json and catalogue that FOLLOW the root change, which the " +
      "daemon must keep accepting because it compiles both test roots and reads root.json never.",
    trust_serial: 3,
    root_set: ROOT_SET_B.map((r) => r.keyId),
  });

  return {
    schema: "astra.registry.rehearsal-r2/1",
    generated_by: "tools/testkeys/make-rehearsal-r2.mjs",
    task: "RC-R2-5",
    exit_condition: "ROLL-60",
    t0: T0,
    keys: {
      roots: { active_at_start: ROOT_A, active_after_root_change: ROOT_B },
      index: {
        outgoing: { key_id: OUTGOING_KEY_ID, test_key: OUTGOING_TEST_KEY, id_borrowed: true },
        incoming: { key_id: INCOMING_KEY_ID, test_key: INCOMING_TEST_KEY, id_borrowed: false },
      },
    },
    documents: DOCUMENTS,
    // What a different answer to the question this series was built around
    // would have cost, by step, so that the owner was told a measured number
    // rather than an estimate. Measured on this series, not reasoned about:
    // the `carry_still_refused` column below is the answer `verifyEnvelope`
    // gives for each candidate fork point, and `tools/selftest/rehearsal-r2.mjs`
    // asserts the one this series uses. The question is DECIDED — D10 as
    // proposed, on 2026-09-23 — and the answer it took re-cuts nothing, which
    // the selftest also asserts rather than this comment.
    open_questions: {
      "OPEN-OWNER-25, compromise half": {
        status: "decided",
        decided: {
          on: "2026-09-23",
          by: "the coordinator, at the owner's delegation",
          answer: "D10 as proposed",
          published_as: "contract 0.38.0's SERVE-30 (ops.12a's G10)",
        },
        built_to: "D10 as proposed, including step 4's two waivers",
        published_as: "SERVE-30's amendment G10 (ops.12a)",
        untouched_by_any_answer: [
          "rotation/00-baseline", "rotation/01-delegate", "rotation/02-mid-window",
          "rotation/03-window-open", "rotation/04-root-change", "rotation/05-after-root",
        ],
        recut_by_an_answer_that_differs: ["compromise/00-drop-2026a", "compromise/01-trust-only-blocked"],
        answers: [
          {
            answer: "D10 as proposed",
            recut: [],
            note: "Nothing moves.",
          },
          {
            answer:
              "keep D10's no-carry rule but replace it with `no carry that fails refusesDroppedKey`, " +
              "which tools/signer/key-window.mjs's own header offers in one line",
            recut: [],
            note:
              "A code change, not a fixture change. In this series the carried catalogue genuinely " +
              "fails refusesDroppedKey, so the same bytes are produced either way.",
          },
          {
            answer: "refuse the seven-hour waiver, or refuse the same-run re-sign — the compromise must wait out SERVE-30",
            recut: ["compromise/00-drop-2026a", "compromise/01-trust-only-blocked"],
            also_costs:
              "RC-R2-5's SECOND canary leg stops being watchable. The fork point moves to " +
              "rotation/03-window-open, where the head's catalogue is already dual-signed, so a carried " +
              "catalogue VERIFIES under the trust.json that drops the outgoing key and there is no " +
              "refusal left to watch. The plan entry's Canary line would need amending with the fixture.",
            carry_still_refused: { "rotation/02-mid-window": true, "rotation/03-window-open": false },
          },
          {
            answer: "expire the compromised key with a `not_after` instead of dropping it from index_keys",
            recut: ["compromise/00-drop-2026a", "compromise/01-trust-only-blocked"],
            also_costs:
              "keyPlan reads compromise mode off a key DISAPPEARING from index_keys, so an expiry is " +
              "`normal` mode: the window applies, the catalogue is carried, and refusesDroppedKey passes " +
              "because delegatedVerifierKeys does not filter by window. Compromise mode would stop " +
              "having a trigger.",
          },
          {
            answer: "no key is ever dropped before R9b; a compromise only adds the incoming key",
            recut: ["compromise/00-drop-2026a", "compromise/01-trust-only-blocked"],
            note: "Deleted rather than re-cut: with nothing dropped there is no compromise mode to rehearse.",
          },
        ],
        independent_of_the_answer:
          "D10's literal inputs — a Source-Commit carrying only trust.json — commit nothing today, " +
          "whatever the answer: both documents read `unchanged`, the head's bytes are re-committed, and " +
          "SERVE-95 refuses them. compromise/01-trust-only-blocked is that run's record.",
      },
    },
    steps,
    commands,
  };
}

// ── the CLI ─────────────────────────────────────────────────────────────────

/** Every file under a directory, repository-relative, sorted. */
function treeOf(dir) {
  const out = [];
  const walk = (rel) => {
    const abs = path.join(dir, rel);
    for (const entry of fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const next = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(next);
      else out.push(next);
    }
  };
  if (fs.existsSync(dir)) walk("");
  return out;
}

function writeManifest(dir, manifest) {
  fs.writeFileSync(path.join(dir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function main(argv) {
  const check = argv.includes("--check");
  const printOnly = argv.includes("--print-commands");

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "rehearsal-r2-"));
  const outDir = check || printOnly
    ? fs.mkdtempSync(path.join(os.tmpdir(), "rehearsal-r2-out-"))
    : FIXTURE_DIR;

  try {
    if (!check && !printOnly) {
      // README.md is the one file here a person wrote, and a regeneration must
      // not eat it. Everything else goes, because a step that stops being
      // generated must stop being served — a stale directory left behind is a
      // commit the staging service would replay and nothing would judge.
      const readme = path.join(FIXTURE_DIR, "README.md");
      const kept = fs.existsSync(readme) ? fs.readFileSync(readme) : null;
      fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
      fs.mkdirSync(FIXTURE_DIR, { recursive: true });
      if (kept) fs.writeFileSync(readme, kept);
    }
    fs.mkdirSync(outDir, { recursive: true });
    const manifest = buildSeries({ outDir, work });
    writeManifest(outDir, manifest);

    if (printOnly) {
      for (const c of manifest.commands) console.log(c.command);
      return 0;
    }

    if (!check) {
      console.error(`wrote ${path.relative(REPO, FIXTURE_DIR)}: ${treeOf(FIXTURE_DIR).length} files, ${manifest.steps.length} steps`);
      return 0;
    }

    const fresh = treeOf(outDir);
    const committed = treeOf(FIXTURE_DIR).filter((f) => f !== "README.md");
    const problems = [];
    for (const rel of new Set([...fresh, ...committed])) {
      const a = path.join(FIXTURE_DIR, rel);
      const b = path.join(outDir, rel);
      if (!fs.existsSync(a)) problems.push(`${rel} is not committed; a fresh build produces it`);
      else if (!fs.existsSync(b)) problems.push(`${rel} is committed and a fresh build does not produce it`);
      else if (!fs.readFileSync(a).equals(fs.readFileSync(b))) problems.push(`${rel} differs from a fresh build`);
    }
    if (problems.length) {
      console.error("FAIL  the committed rehearsal fixtures are not what this generator produces:");
      for (const p of problems) console.error(`      - ${p}`);
      return 1;
    }
    console.error(`ok    ${committed.length} committed files match a fresh build`);
    return 0;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
    if (outDir !== FIXTURE_DIR) fs.rmSync(outDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exit(main(process.argv.slice(2)));
}
