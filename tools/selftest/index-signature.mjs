// The signing half of why a daemon believes the catalogue: a signature verifies
// only under a key trust.json delegates to, a lying key_id changes nothing in
// either direction, one edited byte is refused, nothing outside `signed` is
// covered, no replay across document domains, the 30-day window from the signing
// instant, the committed fixtures the daemon's Rust test embeds, and the CI route
// through ASTRA_INDEX_SIGNING_KEY.
//
// And, since RC-R1-3, the signed-set vectors: one corpus of eleven signed
// documents with their expected verdicts, which this repository and
// `astra-daemon` both read. That section is here rather than in a module of its
// own because the runner's module list lives in `tools/selftest.mjs` and a
// sixteenth module cannot be added without editing it; every import the corpus
// needs — `loadTestRoot`, `verifyEnvelope`, all three domains — was already at
// the top of this file, which is the other half of why it belongs here.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { buildIndex } from "../build-index.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import {
  SIGNED_SET_FLOOR, SIGNED_SET_VERDICTS, loadSignedSetVectors, loadTestRoot,
} from "../testkeys/regenerate.mjs";
import { signIndex } from "../../bot/sign-index.mjs";
import { fixtureCatalogue, FIXTURE_ISSUED_AT } from "../../bot/fixtures/index/regenerate.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, TRUST_SCHEMA, publicKeyFromBase64,
  signingDigest, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";
import { TEST_INDEX_KEY, TEST_STRANGER_KEY, trustFixture, trustedIndexKeys } from "./fixtures.mjs";

// ─────────────────────── the signed-set verifier (RC-R1-3) ──────────────────
//
// The JS half of the corpus's two readers. It is built out of
// `bot/lib/sign.mjs` — `signingDigest` for the canonicalisation, `verifyEnvelope`
// for the signatures — and adds only what that file deliberately does not know
// about: the window `trust.json` gave the key, and the accepted state a document
// is judged against. Neither belongs in the signer's library, and both are in
// the daemon.
//
// The outcome string each branch returns is the README's "the JS verifier"
// column, written at the point of observation rather than looked up. That is
// what makes the table's assertion mean something: a branch whose behaviour
// changes and whose sentence does not turns the table red.

const DOMAIN_OF = { index: INDEX_SCHEMA, revocations: REVOCATIONS_SCHEMA };
const OTHER_DOMAIN = { index: REVOCATIONS_SCHEMA, revocations: INDEX_SCHEMA };

const VECTORS_README = path.join(REPO_ROOT, "tools", "testkeys", "vectors", "README.md");

/**
 * The daemon column of the mapping table, pinned here.
 *
 * A second copy on purpose, and the only kind of check available: this CI has
 * no Astra checkout and Astra's has no registry checkout, so neither side can
 * compile the other's column. What two copies buy is that an edit to one side
 * of the table goes red on the other — which is the whole reason the table is
 * written down at all. Three of these rows are weaker than they read; the
 * README's "What the daemon column does not claim" says which and why, and
 * whoever closes those gaps edits both copies in one pass.
 */
const DAEMON_COLUMN = {
  accepted: "`SignatureState::Verified`",
  bad_domain: "`SignatureState::Invalid`",
  unknown_key: "`SignatureState::Invalid`",
  key_outside_window: "`SignatureState::KeyOutsideWindow`",
  unsafe_integer: "`EnvelopeError::Malformed`",
  no_signatures: "`UnsignedReason::NoSignatures`",
  serial_reused: "`TrustError::SerialReused`",
  entries_shrank: "`RevocationSet::merged_with`",
  older_issued_at: "`(none today)`",
};

/** `entry_count`'s two spellings, one per document kind. */
function entryCount(kind, signed) {
  const list = kind === "index" ? signed.plugins : signed.revocations;
  return Array.isArray(list) ? list.length : 0;
}

function delegatedKeys(trustDoc) {
  return (trustDoc?.signed?.index_keys ?? []).map((e) => ({
    key_id: e.key_id,
    publicKey: publicKeyFromBase64(e.public_key),
    not_before: e.not_before,
    not_after: e.not_after,
  }));
}

/**
 * One vector's verdict, derived rather than read.
 *
 * The rule order is `tools/testkeys/vectors/README.md`'s, stated there because
 * more than one rule can be true of one document and the two readers have to
 * name the same one.
 */
function judge(vector) {
  const doc = vector.document;
  const kind = vector.document_kind;
  const keys = delegatedKeys(vector.trust_json);

  // 1. Canonicalisation, before anything looks at a signature. A document with
  //    a number no canonicaliser here will emit has no signable bytes, so
  //    "does a trusted key vouch for it" is not yet a question.
  try {
    signingDigest(DOMAIN_OF[kind], doc.signed);
  } catch (e) {
    if (/safe integer/.test(String(e?.message))) {
      return { verdict: "unsafe_integer", outcome: "verifyEnvelope throws out of jcs()" };
    }
    throw e;
  }

  // 2. Nothing offered is not the same event as nothing verified, and the two
  //    must never be reported as one: unsigned is the registry before the root
  //    ceremony, and a failed signature is tampering.
  if (!Array.isArray(doc.signatures) || doc.signatures.length === 0) {
    return { verdict: "no_signatures", outcome: "signatures is empty; nothing was offered" };
  }

  const verified = verifyEnvelope(doc, DOMAIN_OF[kind], keys);
  if (!verified.ok) {
    // The domain separator's own test: if these bytes verify under the other
    // document's domain, the signature is genuine and was made for something
    // else. Reporting that as "unknown key" would send the reader hunting for a
    // key rotation that never happened.
    if (verifyEnvelope(doc, OTHER_DOMAIN[kind], keys).ok) {
      return {
        verdict: "bad_domain",
        outcome: "verifyEnvelope refuses; the same bytes verify under the other domain",
      };
    }
    return { verdict: "unknown_key", outcome: "verifyEnvelope refuses under every delegated key" };
  }

  // 3. A delegated key is delegated FOR A WINDOW. The key that actually
  //    verified, never the one the document named.
  const key = keys.find((k) => k.key_id === verified.key_id);
  const now = Date.parse(vector.now);
  const before = key?.not_before ? now < Date.parse(key.not_before) : false;
  const after = key?.not_after ? now > Date.parse(key.not_after) : false;
  if (before || after) {
    return {
      verdict: "key_outside_window",
      outcome: "verifyEnvelope ok; now is outside the verifying key's window",
    };
  }

  // 4. And what the document says against what has already been accepted. Only
  //    at an EQUAL serial: a greater one replaces outright, and a lower one is a
  //    rollback, which this corpus does not carry a verdict for.
  const prior = vector.prior_state;
  if (prior && doc.signed.serial === prior.serial) {
    if (Date.parse(doc.signed.issued_at) < Date.parse(prior.issued_at)) {
      return { verdict: "older_issued_at", outcome: "equal serial; issued_at before the accepted state" };
    }
    const n = entryCount(kind, doc.signed);
    if (n < prior.entry_count) {
      return { verdict: "entries_shrank", outcome: "equal serial; entry_count below the accepted state" };
    }
    if (n > prior.entry_count) {
      return { verdict: "serial_reused", outcome: "equal serial; entry_count above the accepted state" };
    }
  }

  return { verdict: "accepted", outcome: "verifyEnvelope ok" };
}

/**
 * The mapping table as the README states it.
 *
 * The parse is the thing the three tests below stand on, so it reports itself
 * failing rather than reporting nine missing verdicts: a table that has been
 * renamed or reshaped would otherwise read as a table that disagrees with
 * everything.
 */
function mappingTable() {
  const text = fs.readFileSync(VECTORS_README, "utf8");
  const after = text.split("## The mapping table")[1];
  const section = after?.split("Where each daemon symbol lives")[0];
  if (!section) {
    throw new Error(
      "could not find the section between `## The mapping table` and `Where each daemon symbol lives` in " +
      "tools/testkeys/vectors/README.md; the table these tests read has been renamed or reshaped, and every " +
      "verdict below would report as missing for the wrong reason",
    );
  }
  return [...section.matchAll(/^\| `([a-z_]+)` \| (.+?) \| (.+?) \|$/gm)].map(([, verdict, daemon, js]) => ({
    verdict,
    daemon: daemon.trim(),
    js: js.trim(),
  }));
}

export async function run() {
  // ── the catalogue signature ─────────────────────────────────────────────────
  //
  // Task 3.2. The daemon believes this catalogue because an index key that a
  // root-signed trust.json delegates to signed it — never because of the host it
  // was fetched from. Everything below is the signing half of that; the verifying
  // half lives in astra-daemon's plugins::trust tests, and bot/fixtures/index/
  // is the one artefact both halves read.
  console.log("\ncatalogue signature");


  function signedFixture(keyId = TEST_INDEX_KEY, serial = 12) {
    const k = loadTestRoot(keyId);
    return signIndex(fixtureCatalogue(serial), {
      signer: { key_id: k.key_id, privateKey: k.privateKey },
      issuedAt: FIXTURE_ISSUED_AT,
    });
  }

  await test("a signed catalogue verifies under the key trust.json delegates to", () => {
    const doc = signedFixture();
    const r = verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys);
    assert(r.ok, `did not verify: ${r.reason}`);
    assert(r.key_id === TEST_INDEX_KEY, `verified under ${r.key_id}`);
  });
  await test("a catalogue signed by a key trust.json does not name is refused", () => {
    // Syntactically perfect, correctly domain-separated, real Ed25519. The only
    // thing wrong with it is WHOSE key it is, which is the only thing that may
    // decide the outcome.
    const doc = signedFixture(TEST_STRANGER_KEY);
    const r = verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys);
    assert(!r.ok, "a stranger's signature was accepted");
    assert(r.offered.includes(TEST_STRANGER_KEY), `the refusal must name what was offered: ${JSON.stringify(r.offered)}`);
  });
  await test("a key_id that lies does not change the outcome", () => {
    const doc = signedFixture(TEST_STRANGER_KEY);
    doc.signatures[0].key_id = TEST_INDEX_KEY;   // claim to be the trusted key
    assert(!verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
      "a document verified because it claimed the right key_id");

    const honest = signedFixture(TEST_INDEX_KEY);
    honest.signatures[0].key_id = "who-knows";    // and the converse
    assert(verifyEnvelope(honest, INDEX_SCHEMA, trustedIndexKeys).ok,
      "a genuine signature was refused because its key_id was wrong");
  });
  await test("one byte edited after signing is refused", () => {
    const doc = signedFixture();
    doc.signed.plugins[0].releases[0].artifacts["linux-x64"].sha256 =
      "2222222222222222222222222222222222222222222222222222222222222222";
    assert(!verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
      "the digest — the one field the whole chain exists to pin — was editable after signing");
  });
  await test("nothing outside `signed` is covered, and nothing outside it is read", () => {
    const doc = signedFixture();
    doc.$comment = "an attacker wrote this";
    doc.serial = 9999;
    assert(verifyEnvelope(doc, INDEX_SCHEMA, trustedIndexKeys).ok,
      "editing an unauthenticated member broke the signature, so something outside `signed` is being hashed");
  });
  await test("a signature cannot be replayed across document types", () => {
    const doc = signedFixture();
    assert(!verifyEnvelope(doc, TRUST_SCHEMA, trustedIndexKeys).ok,
      "an index signature verified as a trust.json signature; the domain separator is not doing its job");
    assert(!verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
      "an index signature verified as a revocations.json signature");
  });
  await test("the freshness window is 30 days from the signing instant, not from the content", () => {
    const doc = signedFixture();
    assert(doc.signed.issued_at === "2026-08-15T00:00:00Z", doc.signed.issued_at);
    const days = (Date.parse(doc.signed.expires_at) - Date.parse(doc.signed.issued_at)) / 86400000;
    assert(days === CATALOG_TTL_DAYS, `${days} days, expected ${CATALOG_TTL_DAYS}`);
    // And the generator, which reads no clock, stamps neither.
    assert(buildIndex({ serial: 1 }).signed.issued_at === undefined,
      "the generator stamped a timestamp; its output is no longer reproducible");
  });
  await test("the signer refuses a document that is not a catalogue", () => {
    let threw = false;
    try {
      signIndex({ signed: { schema: TRUST_SCHEMA, serial: 1 } }, { signer: loadTestRoot(TEST_INDEX_KEY) });
    } catch { threw = true; }
    assert(threw, "the index key signed a document under the wrong domain");
  });
  await test("the committed fixtures are exactly what the signer produces", () => {
    // These bytes are embedded in a daemon unit test. If this repository's JCS
    // and Rust's ever disagree, one of the two suites has to notice, and a
    // fixture regenerated silently on every run could not be the one that does.
    execFileSync("node", ["bot/fixtures/index/regenerate.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
  });
  // `--test-key` runs of the CLI, with the two real-key variables stripped from
  // the environment unless a case names one. Stripped because the guard below
  // refuses on either of them, and a registry/ case that inherited one would be
  // refused by the wrong guard and pass without asking its own.
  const testKeyRun = (args, extraEnv = {}) => {
    const env = { ...process.env };
    delete env.ASTRA_INDEX_SIGNING_KEY;
    delete env.ASTRA_INDEX_SIGNING_KEY_NEXT;
    let status = 0;
    let stderr = "";
    try {
      execFileSync("node", ["bot/sign-index.mjs", "--test-key", TEST_INDEX_KEY, ...args], {
        cwd: REPO_ROOT, stdio: "pipe", env: { ...env, ...extraEnv },
      });
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    return { status, stderr };
  };
  await test("`sign-index.mjs --test-key` will not write into registry/", () => {
    const { status, stderr } = testKeyRun(["--in", "registry/v1/index.json", "--out", "registry/v1/index.json"]);
    assert(status === 2, `exit ${status}: a catalogue that LOOKS signed and is signed with a published key is worse than an unsigned one`);
    assert(stderr.includes("refusing to write a TEST-key signature"), `refused, but not by the registry/ guard: ${stderr}`);
  });
  await test("`sign-index.mjs --test-key` will not run at all beside ASTRA_INDEX_SIGNING_KEY or ASTRA_INDEX_SIGNING_KEY_NEXT", () => {
    // tools/signer/run.mjs's third guard, ported (ops couplings entry 126). The
    // failure it is for is `--test-key` reaching a job that holds the real key:
    // the run ignores that key, signs with a committed one and exits 0. Each
    // variable is asked on its own, since the condition is an OR and a guard
    // that read only the first would pass a one-variable case. The value is a
    // plain word — the guard reads presence, so no key material is needed to
    // ask it — and `--out` is outside registry/, so the other guard cannot be
    // the one that answers. The control run first: the same invocation with
    // neither variable signs, so a refusal below is the variable's doing.
    const control = path.join(tmp, "test-key-control.json");
    const ok = testKeyRun(["--in", "registry/v1/index.json", "--out", control]);
    assert(ok.status === 0 && fs.existsSync(control),
      `the control run, with neither variable, did not sign (exit ${ok.status}): ${ok.stderr}`);
    for (const name of ["ASTRA_INDEX_SIGNING_KEY", "ASTRA_INDEX_SIGNING_KEY_NEXT"]) {
      const out = path.join(tmp, `test-key-beside-${name}.json`);
      const { status, stderr } = testKeyRun(["--in", "registry/v1/index.json", "--out", out], { [name]: "present" });
      assert(status === 2,
        `${name} beside --test-key exited ${status}: a test-key run in a job holding the real key signs with the committed one`);
      assert(stderr.includes("also holds ASTRA_INDEX_SIGNING_KEY or ASTRA_INDEX_SIGNING_KEY_NEXT"),
        `${name} beside --test-key: refused, but not by this guard: ${stderr}`);
      assert(!fs.existsSync(out), `${name} beside --test-key: the refused run still wrote ${out}`);
    }
  });
  await test("the CI path — key from the environment, verified against trust.json — works end to end", () => {
    // The real signing route, exercised with a throwaway key: the seed arrives in
    // ASTRA_INDEX_SIGNING_KEY as base64 and never on a command line. This is the
    // only test that covers `privateKeyFromSeed`, which is the one piece of the
    // signer that production uses and the --test-key path does not.
    const key = loadTestRoot(TEST_INDEX_KEY);
    const out = path.join(tmp, "ci-index.json");
    execFileSync("node", ["bot/sign-index.mjs", "--in", "registry/v1/index.json", "--out", out], {
      cwd: REPO_ROOT,
      stdio: "pipe",
      env: {
        ...process.env,
        ASTRA_INDEX_SIGNING_KEY: key.seed.toString("base64"),
        ASTRA_INDEX_SIGNING_KEY_ID: key.key_id,
      },
    });
    const signed = JSON.parse(fs.readFileSync(out, "utf8"));
    assert(verifyEnvelope(signed, INDEX_SCHEMA, trustedIndexKeys).ok,
      "a catalogue signed through the environment did not verify");

    // And the verify subcommand CI runs after signing, against a trust.json
    // rather than against the key it just used.
    const trustFile = path.join(tmp, "trust.json");
    fs.writeFileSync(trustFile, JSON.stringify(trustFixture));
    execFileSync("node", ["bot/sign-index.mjs", "--verify", out, "--trust", trustFile], {
      cwd: REPO_ROOT, stdio: "pipe",
    });

    // The content is still exactly what the generator produces — signing adds a
    // timestamp and a signature and touches nothing else.
    execFileSync("node", ["tools/build-index.mjs", "--check", "--out", path.relative(REPO_ROOT, out)], {
      cwd: REPO_ROOT, stdio: "pipe",
    });
  });
  await test("`sign-index.mjs` with no key at all fails loudly rather than emitting an unsigned file", () => {
    let status = 0;
    let stderr = "";
    try {
      execFileSync("node", ["bot/sign-index.mjs", "--in", "registry/v1/index.json"], {
        cwd: REPO_ROOT, stdio: "pipe",
        env: { ...process.env, ASTRA_INDEX_SIGNING_KEY: "", ASTRA_INDEX_SIGNING_KEY_ID: "" },
      });
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 2, `exit ${status}`);
    assert(stderr.includes("ASTRA_INDEX_SIGNING_KEY"), stderr);
  });

  // ── the signed-set vectors ──────────────────────────────────────────────────
  //
  // RC-R1-3. One corpus, read here through `bot/lib/sign.mjs`'s verifier and in
  // Astra by a Rust test over a vendored copy. Everything above this line proves
  // that this repository agrees with itself; these prove that the corpus the
  // other repository is handed says what this one thinks it says.
  console.log("\nsigned-set vectors");

  await test("the corpus is at least the eleven vectors both readers are promised", () => {
    // `loadSignedSetVectors` is where the floor and the closed vocabulary are
    // asserted, so this case is as much about that loader existing as about the
    // count: a reader that iterates whatever it finds reports PASS over a
    // truncated file, and every reader would otherwise have to remember to
    // check.
    const vectors = loadSignedSetVectors();
    assert(vectors.length >= SIGNED_SET_FLOOR, `${vectors.length} vectors, floor ${SIGNED_SET_FLOOR}`);

    // A floor on the count says nothing about the SPREAD. Nine verdicts and
    // eleven vectors could be eleven `accepted`s and a green suite that has
    // never watched a refusal — which is the defect this whole corpus exists to
    // stop one repository away.
    const unexercised = SIGNED_SET_VERDICTS.filter((v) => !vectors.some((x) => x.verdict === v));
    assertEqual(unexercised.join(", "), "",
      "a verdict in the closed vocabulary has no vector, so neither reader has ever produced it");
  });

  await test("the committed corpus is exactly what the generator produces", () => {
    // These bytes are vendored into astra-daemon/testdata/signed-set-vectors/.
    // A hand edit here is a hand edit to another repository's fixtures, and a
    // corpus regenerated silently on every run could not be the thing that
    // notices. `--check` covers the test keys in the same pass, because a
    // corpus signed by a key that has since been rederived verifies nowhere.
    execFileSync("node", ["tools/testkeys/regenerate.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
  });

  await test("every vector's trust.json is signed by a root the vector itself carries", () => {
    // The reason `root_json` is in every vector: a reader needs nothing from
    // this repository but the file. If the anchor did not verify, every verdict
    // below would be a judgement about a chain that does not exist.
    const broken = [];
    for (const v of loadSignedSetVectors()) {
      const roots = (v.root_json?.roots ?? []).map((r) => ({
        key_id: r.key_id,
        publicKey: publicKeyFromBase64(r.public_key),
      }));
      if (roots.length === 0) broken.push(`vector ${v.id}: root_json publishes no roots`);
      else if (!verifyEnvelope(v.trust_json, TRUST_SCHEMA, roots).ok) {
        broken.push(`vector ${v.id}: trust_json does not verify under its own root_json`);
      }
    }
    assertEqual(broken.join("; "), "", "a vector's trust anchor does not verify, so its verdict judges nothing");
  });

  await test("the verifier returns the verdict every vector claims", () => {
    // The corpus says what should happen; this is what does. Failing by vector
    // id, the way the client plan's C1.8 reader does, so the two repositories
    // name the same vector when they disagree.
    const wrong = [];
    for (const v of loadSignedSetVectors()) {
      const got = judge(v);
      if (got.verdict !== v.verdict) {
        wrong.push(`vector ${v.id} (${v.name}): claims ${v.verdict}, the verifier says ${got.verdict}`);
      }
    }
    assertEqual(wrong.join("; "), "",
      "the signer and the verifier disagree about a vector; one of the two is what a daemon will do");
  });

  await test("vector 10 really does carry the outgoing key's signature first", () => {
    // The vector's NAME is a claim about signature order, and nothing else in
    // the corpus checks it: `verifyEnvelope` tries every key against every
    // signature, so a corpus that quietly put the incoming key first would pass
    // every other case here and still not be the document SERVE-30 describes.
    const v = loadSignedSetVectors().find((x) => x.id === 10);
    assert(v, "vector 10 is gone");
    assertEqual(v.document.signatures.map((s) => s.key_id).join(", "),
      "TEST-ONLY-DO-NOT-TRUST-index-2026a, TEST-ONLY-DO-NOT-TRUST-index-2026b",
      "the dual-signed vector must carry the outgoing key's signature first");
  });

  await test("the README's mapping table is the closed vocabulary, in order", () => {
    const rows = mappingTable();
    assertEqual(rows.map((r) => r.verdict).join(", "), SIGNED_SET_VERDICTS.join(", "),
      "tools/testkeys/vectors/README.md's mapping table and the vocabulary in tools/testkeys/regenerate.mjs are " +
      "two statements of one list; a verdict renamed on one side is a verdict the other reader has never heard of, " +
      "and a reader that has never heard of a verdict skips the vector or reads it as \"not accepted\"");
  });

  await test("the README's JS column is what the verifier actually produced", () => {
    const stated = new Map(mappingTable().map((r) => [r.verdict, r.js]));
    const observed = new Map();
    for (const v of loadSignedSetVectors()) {
      const got = judge(v);
      observed.set(got.verdict, got.outcome);
    }
    const disagree = [];
    for (const verdict of SIGNED_SET_VERDICTS) {
      const want = observed.get(verdict);
      const have = stated.get(verdict);
      // `\`x\`` in the table, plain text out of the verifier.
      if (have?.replace(/`/g, "") !== want) {
        disagree.push(`${verdict}: the README says ${JSON.stringify(have)}, the verifier produced ${JSON.stringify(want)}`);
      }
    }
    assertEqual(disagree.join("; "), "",
      "the README describes a JS outcome the verifier no longer produces; the table is what the daemon's reader is " +
      "handed, so a sentence that has outlived its branch is a sentence another repository is asserting against");
  });

  await test("the README's daemon column has not been renamed on one side", () => {
    const stated = new Map(mappingTable().map((r) => [r.verdict, r.daemon]));
    const disagree = [];
    for (const verdict of SIGNED_SET_VERDICTS) {
      if (stated.get(verdict) !== DAEMON_COLUMN[verdict]) {
        disagree.push(
          `${verdict}: the README says ${JSON.stringify(stated.get(verdict))}, this suite pins ` +
          `${JSON.stringify(DAEMON_COLUMN[verdict])}`,
        );
      }
    }
    assertEqual(disagree.join("; "), "",
      "neither CI has the other repository checked out, so these two copies are the only thing that fails when the " +
      "daemon's names and the table drift apart");
  });
}
