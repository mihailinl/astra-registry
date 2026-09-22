// The ROLL-60 rehearsal fixtures (RC-R2-5), judged the way the staging service
// will judge them — not the way they were built.
//
// `tools/testkeys/make-rehearsal-r2.mjs` asserts its own expectations against
// the record the signer wrote, which catches a generator that produced the
// wrong shape. It cannot catch a generator and a fixture that are wrong in the
// same direction, because it is one program reading its own output. So
// everything below re-derives the verdict from the BYTES: root keys out of each
// step's own `root.json`, index keys out of each step's own `trust.json`, and
// `verifyEnvelope` with the domain from its own constant — SERVE-15's five
// clauses, in the order SERVE-15 lists them.
//
// ── what these bytes are for ────────────────────────────────────────────────
//
// ROLL-60 is an R2 exit condition and this fixture series is the registry's
// half of it: until it exists, minice-be's staging service and the debug 0.2.x
// daemon built with `insecure-test-trust-roots` have nothing to accept. One day
// a real index key will be rotated, or a real one will be compromised, and the
// confidence that the pipeline can do it at all will rest on a rehearsal these
// bytes made possible. A fixture that merely agrees with itself would spend
// that confidence without earning it.
//
// ── the two canary legs RC-R2-5 names, and what each was watched failing on ──
//
//   1. a list that carries fewer signatures than the trust.json beside it
//      delegates — SERVE-30's dual signature, missing. Watched by re-signing
//      `rotation/01-delegate`'s list with the outgoing key alone.
//   2. the compromise commit's catalogue not verifying under the trust.json
//      that commit carries. Watched by putting the parent's catalogue back into
//      `compromise/00-drop-2026a`, which is the exact mistake D10 step 4 exists
//      to prevent and which SERVE-91 would answer by refusing all four
//      documents.
//
// Both were watched red before this file was committed, and both are stated
// here rather than in a comment on the generator because a guard nobody has
// seen fail is a guard somebody is guessing about.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import {
  INDEX_SCHEMA,
  REVOCATIONS_SCHEMA,
  TRUST_SCHEMA,
  publicKeyFromBase64,
  verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { TEST_KEYS, loadTestRoot } from "../testkeys/regenerate.mjs";
import { DOCUMENTS, OUTGOING_KEY_ID, INCOMING_KEY_ID } from "../testkeys/make-rehearsal-r2.mjs";
import { INDEX_KEY_WINDOW_HOURS } from "../signer/key-window.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

const FIXTURES = path.join(REPO_ROOT, "tools", "testkeys", "fixtures", "rehearsal-r2");

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const stepDir = (id) => path.join(FIXTURES, ...id.split("/"));
const docOf = (id, name) => readJson(path.join(stepDir(id), "registry", "v1", name));

/** The root keys a step publishes, as verifier keys. SERVE-16's comparand. */
const rootKeysOf = (root) =>
  (root.roots ?? []).map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) }));

/** The index keys a trust.json delegates, as verifier keys. */
const indexKeysOf = (trust) =>
  (trust?.signed?.index_keys ?? []).map((k) => ({ key_id: k.key_id, publicKey: publicKeyFromBase64(k.public_key) }));

/**
 * One step, judged whole.
 *
 * SERVE-91 refuses the entire candidate commit when it refuses any document in
 * it, so this returns one verdict for four files and never a per-file opinion
 * a caller could accidentally read as a pass.
 */
function judge(id) {
  const root = docOf(id, "root.json");
  const trust = docOf(id, "trust.json");
  const index = docOf(id, "index.json");
  const revocations = docOf(id, "revocations.json");

  const trustVerdict = verifyEnvelope(trust, TRUST_SCHEMA, rootKeysOf(root));
  const keys = indexKeysOf(trust);
  const indexVerdict = verifyEnvelope(index, INDEX_SCHEMA, keys);
  const listVerdict = verifyEnvelope(revocations, REVOCATIONS_SCHEMA, keys);

  const refusals = [];
  if (!trustVerdict.ok) refusals.push(`trust.json: ${trustVerdict.reason}`);
  if (!indexVerdict.ok) refusals.push(`index.json: ${indexVerdict.reason}`);
  if (!listVerdict.ok) refusals.push(`revocations.json: ${listVerdict.reason}`);

  return {
    id, root, trust, index, revocations, keys,
    accepted: refusals.length === 0,
    refusals,
    trustVerdict, indexVerdict, listVerdict,
    delegated: keys.map((k) => k.key_id),
  };
}

const hoursBetween = (from, to) => (Date.parse(to) - Date.parse(from)) / 3_600_000;

export async function run() {
  console.log("\nthe ROLL-60 rehearsal fixtures (RC-R2-5)");

  const manifest = readJson(path.join(FIXTURES, "manifest.json"));
  const withDocuments = manifest.steps.filter((s) => s.documents_present !== false);

  await test("the manifest and the fixture tree are one set, and every step holds D2's four documents", () => {
    // A step on disk that the manifest does not name is a step nothing below
    // judges: the loops here walk the manifest, so an unnamed directory would
    // be served to the staging service and checked by nothing.
    const onDisk = new Set();
    const walk = (rel) => {
      for (const entry of fs.readdirSync(path.join(FIXTURES, rel), { withFileTypes: true })) {
        const next = rel ? `${rel}/${entry.name}` : entry.name;
        if (!entry.isDirectory()) continue;
        if (fs.existsSync(path.join(FIXTURES, next, "record.json"))) onDisk.add(next);
        else walk(next);
      }
    };
    walk("");
    const named = new Set(manifest.steps.map((s) => s.id));
    assertEqual([...onDisk].sort().join(" "), [...named].sort().join(" "), "the manifest and the tree disagree");
    assert(manifest.steps.length >= 7, `only ${manifest.steps.length} steps; the series is shorter than ROLL-60 needs`);

    for (const step of withDocuments) {
      for (const rel of DOCUMENTS) {
        assert(fs.existsSync(path.join(stepDir(step.id), rel)), `${step.id} has no ${rel} (D2 wants all four)`);
      }
      assert(fs.existsSync(path.join(stepDir(step.id), "commit-message.txt")),
        `${step.id} has no commit message, so the series cannot be replayed onto a \`signed\` branch`);
    }
  });

  await test("every step verifies whole, the way the plugins service will (SERVE-15, SERVE-91)", () => {
    for (const step of withDocuments) {
      const v = judge(step.id);
      assert(v.accepted, `${step.id} would be refused whole: ${v.refusals.join("; ")}`);
      // The domain is taken from this module's own constants, never from the
      // `schema` member of the file being read — a signature over a trust.json
      // must never verify as a signature over a catalogue.
      assertEqual(v.trust.signed.schema, TRUST_SCHEMA, `${step.id} trust.json schema`);
      assertEqual(v.index.signed.schema, INDEX_SCHEMA, `${step.id} index.json schema`);
      assertEqual(v.revocations.signed.schema, REVOCATIONS_SCHEMA, `${step.id} revocations.json schema`);
    }
  });

  await test("nothing in the series is signed by a key that is not one of tools/testkeys'", () => {
    // The rule this fixture directory exists under: the root private key never
    // reaches an agent, and nothing a user installs may be signed here. Every
    // public key in every trust.json and root.json is re-derived from a seed
    // phrase in ../testkeys/README.md, so a key that came from anywhere else —
    // a real root, a real index key, a paste — fails by name.
    const known = new Map(TEST_KEYS.map((k) => [loadTestRoot(k.key_id).publicKeyB64, k.key_id]));
    const borrowed = new Map([[OUTGOING_KEY_ID, loadTestRoot("TEST-ONLY-DO-NOT-TRUST-index-2026a").publicKeyB64]]);
    for (const step of withDocuments) {
      const v = judge(step.id);
      for (const r of v.root.roots ?? []) {
        assertEqual(known.get(r.public_key), r.key_id, `${step.id} root.json publishes ${r.key_id}, which is not a test key`);
      }
      for (const k of v.trust.signed.index_keys ?? []) {
        const expected = borrowed.get(k.key_id) ?? null;
        assert(
          expected ? k.public_key === expected : known.has(k.public_key),
          `${step.id} trust.json delegates ${k.key_id} with a public key that is not a test key's`,
        );
      }
    }
  });

  // ── SERVE-30, and canary leg 1 ────────────────────────────────────────────

  await test("SERVE-30's seven hours: the incoming key signs the list at once and the catalogue only after", () => {
    const delegate = manifest.steps.find((s) => s.id === "rotation/01-delegate");
    assert(delegate, "the series has no delegating step");
    const delegatedAt = delegate.delegated_at;

    for (const id of ["rotation/01-delegate", "rotation/02-mid-window", "rotation/03-window-open"]) {
      const step = manifest.steps.find((s) => s.id === id);
      const v = judge(id);
      const age = hoursBetween(delegatedAt, step.now);
      const cataloguePartyCount = v.index.signatures.length;
      if (age < INDEX_KEY_WINDOW_HOURS) {
        assertEqual(cataloguePartyCount, 1,
          `${id} is ${age} h after the delegating commit and its catalogue carries ${cataloguePartyCount} ` +
          `signatures; the incoming key may not sign a catalogue for ${INDEX_KEY_WINDOW_HOURS} h`);
        assertEqual(v.index.signatures[0].key_id, OUTGOING_KEY_ID, `${id} catalogue signer inside the window`);
      } else {
        assertEqual(cataloguePartyCount, 2,
          `${id} is ${age} h after the delegating commit and its catalogue still carries ` +
          `${cataloguePartyCount} signature(s); the window has passed`);
      }
      // The outgoing signature goes FIRST, on both documents. A shipped client
      // checks only the first signature that verifies against its own window
      // (SERVE-30's Why), so the order is not cosmetic.
      assertEqual(v.revocations.signatures[0].key_id, OUTGOING_KEY_ID, `${id}: the list's first signature`);
    }
  });

  await test("CANARY: no list outside the compromise series carries fewer signatures than its trust.json delegates", () => {
    // RC-R2-5's first canary leg, spelled as the thing that can actually go
    // wrong. "A single-signed list" is only a fault where more than one key is
    // delegated: at `rotation/00-baseline` one key exists and one signature is
    // arithmetic, and in the compromise series one signature is REQUIRED,
    // because the other key is the compromised one. Everywhere else a list
    // short of a delegated key's signature is SERVE-30's rotation failing
    // silently — the incoming key never reaches the idle daemons that read
    // lists and never fetch a catalogue, which is the population SERVE-30 is
    // written for.
    //
    // Watched failing by re-signing `rotation/01-delegate`'s list with the
    // outgoing key alone: two delegated keys, one signature, red.
    for (const step of withDocuments) {
      if (step.id.startsWith("compromise/")) continue;
      const v = judge(step.id);
      const signed = new Set(v.revocations.signatures.map((s) => s.key_id));
      for (const keyId of v.delegated) {
        assert(
          signed.has(keyId),
          `${step.id}: the withdrawal list beside a trust.json delegating ${v.delegated.join(", ")} carries ` +
          `signatures from ${[...signed].join(", ") || "nothing"} — ${keyId} is missing (SERVE-30)`,
        );
      }
    }
  });

  // ── D10, and canary leg 2 ─────────────────────────────────────────────────

  await test("the compromise commit is ONE commit that verifies whole, with the dropped key on nothing in it", () => {
    const v = judge("compromise/00-drop-2026a");
    assert(v.accepted, `the compromise commit would be refused whole: ${v.refusals.join("; ")}`);
    assertEqual(v.delegated.join(","), INCOMING_KEY_ID, "the compromise trust.json still delegates the dropped key");

    const parent = judge("rotation/02-mid-window");
    assertEqual(v.trust.signed.serial, parent.trust.signed.serial + 1,
      "the compromise trust.json is not one serial past the trust.json it replaces");

    // The list is signed by the incoming key ALONE — there is no outgoing key
    // to go first, because the outgoing key is the compromised one.
    assertEqual(v.revocations.signatures.length, 1, "the compromise list is not signed by one key");
    assertEqual(v.revocations.signatures[0].key_id, INCOMING_KEY_ID, "the compromise list's signer");
    for (const [name, doc] of Object.entries({ "index.json": v.index, "revocations.json": v.revocations })) {
      for (const sig of doc.signatures) {
        assert(sig.key_id !== OUTGOING_KEY_ID,
          `the compromise commit's ${name} still carries a signature by the dropped key ${OUTGOING_KEY_ID}`);
      }
    }
  });

  await test("CANARY: the compromise commit's catalogue verifies under the trust.json that commit carries", () => {
    // RC-R2-5's second canary leg. D10 step 4 waives the seven-hour window and
    // the carry together, and the carry is the half that matters: a carried
    // catalogue is the PARENT's bytes, signed by the key the new trust.json has
    // just dropped, so SERVE-15 refuses it and SERVE-91 then refuses the whole
    // commit — withholding the new trust.json and the repaired list along with
    // it, and leaving the compromised key's last bytes served.
    //
    // Watched failing by copying `rotation/02-mid-window`'s index.json into
    // `compromise/00-drop-2026a` and running this module: refused, by name.
    const v = judge("compromise/00-drop-2026a");
    assert(v.indexVerdict.ok,
      `the compromise catalogue does not verify under its own trust.json: ${v.indexVerdict.reason} ` +
      `(offered ${v.indexVerdict.offered?.join(", ") || "nothing"}; delegated ${v.delegated.join(", ")})`,
    );
    assertEqual(v.indexVerdict.key_id, INCOMING_KEY_ID, "the compromise catalogue was not re-signed by the incoming key");

    // And the premise the leg rests on: the parent's catalogue really would be
    // refused. Without this, "it verifies" could be true of a carry too, and
    // the canary above would be watching nothing. (That is the R9b case
    // `tools/signer/key-window.mjs`'s header names: after the window opens the
    // head is dual-signed and a carry is safe, which is why this fixture forks
    // the compromise from INSIDE the window.)
    const parentCatalogue = docOf("rotation/02-mid-window", "index.json");
    const carried = verifyEnvelope(parentCatalogue, INDEX_SCHEMA, v.keys);
    assert(!carried.ok,
      "the parent's catalogue verifies under the compromise trust.json, so carrying it would be safe and " +
      "this canary is watching a case that cannot arise. The compromise must fork from inside the " +
      "seven-hour window, where the head's catalogue is signed by the dropped key alone.");
    assert(stableStringify(parentCatalogue) !== stableStringify(v.index),
      "the compromise catalogue is byte-identical to the parent's: it was carried, not re-signed");
  });

  await test("D10's own inputs alone commit nothing, and this step records it", () => {
    // Not a decoration and not a passing thought. A compromise is repaired by a
    // root ceremony that publishes a trust.json and nothing else, and on that
    // Source-Commit neither the catalogue nor the list has changed — so D4 calls
    // both `unchanged`, `unchanged` re-commits `signed`'s head bytes exactly as
    // a carry does, those bytes are signed by the key being dropped, and
    // SERVE-95 refuses the run. D10's "no carry" (`carryCatalogueAllowed`) is
    // consulted only where the GATES failed, so it never reaches this path.
    //
    // The compromise fixture above therefore has an advisory and a release in
    // its Source-Commit, which is what makes both documents `changed`. That is
    // a property of the fixture and the operator must not read it as a property
    // of the procedure, so the blocked run is kept here beside it, with the
    // signer's own record as the evidence. When D10 is amended under
    // OPEN-OWNER-25 and G10, this goes red and says so.
    const record = readJson(path.join(stepDir("compromise/01-trust-only-blocked"), "record.json"));
    assertEqual(record.key_mode, "compromise", "the trust-only run did not read as a compromise");
    assertEqual(record.commit, false, "a Source-Commit carrying only trust.json now commits; D10 can be amended");
    assert(record.codes.includes("SIGNER_TRUST_REFUSED_DOCUMENT"),
      `the refusal is not SERVE-95's: ${record.codes.join(" ")}`);
    assertEqual(record.documents.index.decision, "unchanged", "the catalogue's decision");
    assertEqual(record.documents.revocations.decision, "unchanged", "the list's decision");
    assert(!fs.existsSync(path.join(stepDir("compromise/01-trust-only-blocked"), "registry", "v1", "index.json")),
      "the blocked step has documents; a run that commits nothing produces none");
  });

  // ── ROLL-60's other three clauses ─────────────────────────────────────────

  await test("ROLL-60's idle daemon: a client holding the OLD trust.json accepts every rotation list", () => {
    // The population SERVE-30 is written for. A daemon whose user never opens
    // the store runs only the 30-minute list tick, verifies against the
    // trust.json it already holds, and never refreshes it — so a list signed by
    // the incoming key alone would be refused there indefinitely and
    // withdrawals would stop reaching running plugins.
    const oldKeys = indexKeysOf(docOf("rotation/00-baseline", "trust.json"));
    for (const step of withDocuments) {
      if (step.id.startsWith("compromise/")) continue;
      if (step.id === "rotation/00-baseline") continue;
      const v = verifyEnvelope(docOf(step.id, "revocations.json"), REVOCATIONS_SCHEMA, oldKeys);
      assert(v.ok, `an idle daemon on the baseline trust.json refuses ${step.id}'s list: ${v.reason}`);
    }
    // And D10's accepted cost, asserted so that it stays a stated cost rather
    // than a surprise: the compromise list is refused there until the client
    // refreshes trust.json.
    const compromised = verifyEnvelope(docOf("compromise/00-drop-2026a", "revocations.json"), REVOCATIONS_SCHEMA, oldKeys);
    assert(!compromised.ok,
      "an idle daemon on the baseline trust.json accepts the compromise list, so the fixture is not " +
      "exercising the cost D10 states");
  });

  await test("SERVE-16 and SERVE-92: the root set changes, and the trust.json beside it is re-signed by the new root", () => {
    const before = judge("rotation/03-window-open");
    const change = judge("rotation/04-root-change");
    const after = judge("rotation/05-after-root");

    const setOf = (v) => (v.root.roots ?? []).map((r) => r.public_key).sort().join(",");
    assert(setOf(before) !== setOf(change),
      "root.json's key set does not change across the root-change step, so SERVE-16 compares nothing");
    assertEqual(setOf(change), setOf(after), "the root set moves again after the change");

    // SERVE-20: at an unchanged serial the `signed` payload must be identical,
    // so a re-signature by the incoming root is the only thing that may differ.
    assertEqual(change.trust.signed.serial, before.trust.signed.serial, "the root change moved trust.json's serial");
    assertEqual(stableStringify(change.trust.signed), stableStringify(before.trust.signed),
      "trust.json's `signed` payload changed at an unchanged serial (SERVE-20)");
    // SERVE-92's clause, and until 2026-09-22 it was an inequality alone.
    // `verifyEnvelope` returns `key_id: undefined` on a document it refused, and
    // `undefined !== "…root-a"` is true — so a trust.json signed by NOBODY
    // satisfied "signed by a different root".
    //
    // Measured: overwriting rotation/04-root-change's trust.json with the parent
    // step's, which is the exact state of a root ceremony that published
    // root.json and never re-signed the document beside it, left this check
    // printing `ok`. Two other checks went red for it — `every step verifies
    // whole` and the regeneration `--check` — and neither is named for this
    // clause, so the register read the coverage off a name nothing held.
    //
    // The verdict is therefore asserted on BOTH sides before the key_ids are
    // compared: an inequality where either side may be `undefined` is an
    // inequality that passes for the failure it is watching for.
    for (const v of [before, change]) {
      assert(v.trustVerdict.ok,
        `${v.id}'s trust.json does not verify under the root.json committed beside it (${v.trustVerdict.reason}), ` +
        "so the root comparison below would be between a key and nothing");
    }
    assert(change.trustVerdict.key_id !== before.trustVerdict.key_id,
      "the trust.json after the root change is signed by the same root as before it");

    // The daemon's leg: it compiles both test roots and reads root.json never,
    // so what must keep working is the trust.json and catalogue that FOLLOW.
    const compiled = ["TEST-ONLY-DO-NOT-TRUST-root-a", "TEST-ONLY-DO-NOT-TRUST-root-b"]
      .map((id) => ({ key_id: id, publicKey: publicKeyFromBase64(loadTestRoot(id).publicKeyB64) }));
    for (const v of [change, after]) {
      const seen = verifyEnvelope(v.trust, TRUST_SCHEMA, compiled);
      assert(seen.ok, `a debug daemon compiling both test roots refuses ${v.id}'s trust.json: ${seen.reason}`);
    }
  });

  await test("serials never fall along the rotation line (SERVE-36, SERVE-19)", () => {
    const line = manifest.steps.filter((s) => s.id.startsWith("rotation/"));
    for (let i = 1; i < line.length; i++) {
      for (const kind of ["index", "revocations"]) {
        assert(line[i].serials[kind] >= line[i - 1].serials[kind],
          `${kind} serial falls from ${line[i - 1].id} (${line[i - 1].serials[kind]}) to ` +
          `${line[i].id} (${line[i].serials[kind]})`);
      }
    }
  });

  await test("`--test-key` refuses the three ways it could publish something a daemon would reject", () => {
    // The flag that makes this whole directory possible also puts a
    // throwaway key into the program that publishes the real catalogue, so
    // each of its guards is exercised rather than trusted. The third is the
    // one that matters: the failure it is for is not a fixture author's, it is
    // `--test-key` reaching `sign.yml`, where the run would hold the real key,
    // ignore it, and publish a `signed` commit every daemon refuses — green,
    // with a warning in a log nobody reads.
    const refuses = (args, env = {}) => {
      let status = 0;
      let stderr = "";
      try {
        execFileSync("node", ["tools/signer/run.mjs", "--step", "sign", ...args], {
          cwd: REPO_ROOT,
          env: { ...process.env, ...env },
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (e) {
        status = e.status;
        stderr = String(e.stderr);
      }
      return { status, stderr };
    };
    const testKey = "TEST-ONLY-DO-NOT-TRUST-index-2026a";

    const beside = refuses(["--test-key", testKey, "--out", path.join(REPO_ROOT, "dist", "never")],
      { ASTRA_INDEX_SIGNING_KEY: "irrelevant", ASTRA_INDEX_SIGNING_KEY_ID: "irrelevant" });
    assertEqual(beside.status, 2, `a real key beside --test-key exited ${beside.status}`);
    assert(beside.stderr.includes("also holds ASTRA_INDEX_SIGNING_KEY"), beside.stderr);

    const intoRegistry = refuses(["--test-key", testKey, "--out", path.join(REPO_ROOT, "registry", "v1")]);
    assertEqual(intoRegistry.status, 2, `writing into registry/ exited ${intoRegistry.status}`);
    assert(intoRegistry.stderr.includes("refusing to write TEST-key signatures"), intoRegistry.stderr);

    const twice = refuses(["--test-key", testKey, "--test-key", `second=${testKey}`,
      "--out", path.join(REPO_ROOT, "dist", "never")]);
    assertEqual(twice.status, 2, `one key under two names exited ${twice.status}`);
    assert(twice.stderr.includes("are not a rotation"), twice.stderr);

    assert(!fs.existsSync(path.join(REPO_ROOT, "dist", "never")), "a refused run still wrote a tree");
  });

  await test("the cost of OPEN-OWNER-25's answer is measured from these bytes, not stated", () => {
    // The owner's page says a different answer to OPEN-OWNER-25's compromise
    // half re-cuts "exactly one of five rehearsal fixtures". That number is
    // this fixture's to make true, so it is checked here rather than asserted
    // in prose that nothing reads.
    const open = manifest.open_questions?.["OPEN-OWNER-25, compromise half"];
    assert(open, "the manifest records no cost for the one open question this series is built around");
    assertEqual(open.status, "open", "the open question's status");

    // Every step an answer could re-cut is in the compromise series, and every
    // step of the rotation is untouched: that is what "one of five" means, and
    // it is checkable because the two lists together must be the whole series.
    const named = [...open.untouched_by_any_answer, ...open.recut_by_an_answer_that_differs].sort();
    assertEqual(named.join(" "), manifest.steps.map((s) => s.id).sort().join(" "),
      "the re-cut accounting does not cover every step, so its number cannot be read as a cost");
    for (const id of open.recut_by_an_answer_that_differs) {
      assert(id.startsWith("compromise/"), `${id} is named as re-cuttable and is not part of the compromise series`);
    }
    for (const id of open.untouched_by_any_answer) {
      assert(id.startsWith("rotation/"), `${id} is named as untouched and is part of the compromise series`);
    }

    // And the claim that costs more than a re-cut: an answer that pushes the
    // compromise past SERVE-30's seven hours takes canary leg 2 away with it,
    // because at the later fork point the head is dual-signed and a carried
    // catalogue verifies. Each row of `carry_still_refused` is re-derived.
    const compromiseKeys = indexKeysOf(docOf("compromise/00-drop-2026a", "trust.json"));
    const rows = open.answers.flatMap((a) => Object.entries(a.carry_still_refused ?? {}));
    assert(rows.length >= 2, "no answer records what a carry would do at its fork point, so nothing is measured");
    for (const [forkId, claimed] of rows) {
      const carried = verifyEnvelope(docOf(forkId, "index.json"), INDEX_SCHEMA, compromiseKeys);
      assertEqual(!carried.ok, claimed,
        `the manifest says a catalogue carried from ${forkId} would ${claimed ? "be refused" : "verify"} ` +
        `under the compromise trust.json, and it ${carried.ok ? "verifies" : "is refused"}`);
    }
  });

  await test("the committed fixtures are what the real signer produces today", () => {
    // The fixtures are bytes in git, and bytes in git are editable by hand. A
    // hand edit here is an edit to what a staging service and a debug daemon
    // will one day accept a rotation on the strength of, so the generator is
    // re-run and the result compared. It takes about a second: eight signer
    // runs against a throwaway registry, with no network and no secret.
    execFileSync("node", ["tools/testkeys/make-rehearsal-r2.mjs", "--check"], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
  });
}
