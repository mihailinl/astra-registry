// The signing half of why a daemon believes the catalogue: a signature verifies
// only under a key trust.json delegates to, a lying key_id changes nothing in
// either direction, one edited byte is refused, nothing outside `signed` is
// covered, no replay across document domains, the 30-day window from the signing
// instant, the committed fixtures the daemon's Rust test embeds, and the CI route
// through ASTRA_INDEX_SIGNING_KEY.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { buildIndex } from "../build-index.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { signIndex } from "../../bot/sign-index.mjs";
import { fixtureCatalogue, FIXTURE_ISSUED_AT } from "../../bot/fixtures/index/regenerate.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, TRUST_SCHEMA, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { test, assert, tmp } from "./harness.mjs";
import { TEST_INDEX_KEY, TEST_STRANGER_KEY, trustFixture, trustedIndexKeys } from "./fixtures.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 12;

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
  await test("`sign-index.mjs --test-key` will not write into registry/", () => {
    let status = 0;
    try {
      execFileSync("node", [
        "bot/sign-index.mjs", "--test-key", TEST_INDEX_KEY,
        "--in", "registry/v1/index.json", "--out", "registry/v1/index.json",
      ], { cwd: REPO_ROOT, stdio: "pipe" });
    } catch (e) {
      status = e.status;
    }
    assert(status === 2, `exit ${status}: a catalogue that LOOKS signed and is signed with a published key is worse than an unsigned one`);
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
}
