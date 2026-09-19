// The withdrawal list, every test a refusal: the advisory shapes checkAdvisory
// rejects, the generator flattening and refusing, and the signed envelope — a
// stranger's key, the index/revocation domain swap in both directions, the 7-day
// TTL against the catalogue's 30, one edited byte, and the committed document's
// shape.

import fs from "node:fs";
import path from "node:path";

import { stableStringify } from "../lib/canonical.mjs";
import { buildRevocations, checkAdvisory } from "../lib/revocations.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { FIXTURE_ISSUED_AT } from "../../bot/fixtures/index/regenerate.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, REVOCATION_TTL_DAYS, TRUST_SCHEMA,
  signEnvelope, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { test, assert, tmp } from "./harness.mjs";
import { TEST_INDEX_KEY, TEST_STRANGER_KEY, trustedIndexKeys } from "./fixtures.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 18;

export async function run() {
  // ═══════════════════ 3.9 — the withdrawal list ═══════════════════
  //
  // Revocation is the only mechanism here that helps after a bad plugin is
  // already on somebody's machine, so every test below asserts a REFUSAL: an
  // advisory the daemon could not act on, a signature replayed across domains, a
  // document signed under the wrong one. A test that proves the format parses
  // proves nothing anyone cares about.

  console.log("\nwithdrawal list");

  function signedRevocations(keyId = TEST_INDEX_KEY, serial = 3, entries = []) {
    const k = loadTestRoot(keyId);
    return signRevocations(
      { signed: { schema: REVOCATIONS_SCHEMA, serial, revocations: entries } },
      { signer: { key_id: k.key_id, privateKey: k.privateKey }, issuedAt: FIXTURE_ISSUED_AT },
    );
  }

  const GOOD_ADVISORY = {
    id: "ASTRA-2026-0001",
    published: "2026-08-14",
    severity: "critical",
    action: "disable",
    reason: "Exfiltrates the clipboard to a third-party host.",
    advisory_url: "https://example.test/advisories/ASTRA-2026-0001",
    // A digest AND an id. Not decoration: a `digest` entry cannot match a
    // sideloaded source directory (no archive, so no bundle digest), so an
    // advisory that carries only digests leaves "run the same code from a folder"
    // open. `checkAdvisory` now refuses that shape, and the fixture has to be a
    // shape it accepts.
    entries: [
      { kind: "digest", value: "a".repeat(64) },
      { kind: "id", value: "dice-roller" },
    ],
  };

  await test("a well-formed advisory validates", () => {
    assert(checkAdvisory(GOOD_ADVISORY).length === 0, JSON.stringify(checkAdvisory(GOOD_ADVISORY)));
  });
  await test("a digest-only advisory is refused: it cannot see a sideloaded directory", () => {
    // The registry's default and recommended advisory shape was a `digest` entry
    // over the `.astraplugin`. `sideload_plugin` builds a subject with an id, a
    // version and the binary hashes — and NO artifact digest, because a directory
    // has no archive. So the withdrawal was fully in force and matched nothing on
    // the one route with nothing else to key on.
    const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "digest", value: "a".repeat(64) }] });
    assert(errs.some((e) => e.includes("SIDELOADED SOURCE DIRECTORY")), errs.join("; "));
    // `identity` and `publisher_key` do not close it either — a sideloaded
    // directory has neither.
    const weak = checkAdvisory({
      ...GOOD_ADVISORY,
      entries: [{ kind: "digest", value: "a".repeat(64) }, { kind: "identity", value: "github:o/r" }],
    });
    assert(weak.some((e) => e.includes("SIDELOADED SOURCE DIRECTORY")), weak.join("; "));
    // And each of the four that DOES cover a directory is enough.
    for (const entry of [
      { kind: "binary", value: "b".repeat(64) },
      { kind: "id", value: "dice-roller" },
      { kind: "id_version", value: "dice-roller@1.0.0" },
      { kind: "version_range", value: "dice-roller", versions: { introduced: "1.0.0", fixed: "1.2.0" } },
    ]) {
      const ok = checkAdvisory({
        ...GOOD_ADVISORY,
        entries: [{ kind: "digest", value: "a".repeat(64) }, entry],
      });
      assert(ok.length === 0, `${entry.kind} must be enough: ${ok.join("; ")}`);
    }
  });
  await test("a kind the daemon does not read is refused", () => {
    // The failure this catches is silent by nature: an unknown `kind` matches
    // nothing in the daemon, so the advisory publishes, the workflow is green,
    // and the withdrawal never happens.
    const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "author", value: "someone" }] });
    assert(errs.some((e) => e.includes("not one the daemon reads")), errs.join("; "));
  });
  await test("an uppercase or truncated digest is refused", () => {
    for (const value of ["A".repeat(64), "abc", "a".repeat(63)]) {
      const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "digest", value }] });
      assert(errs.length > 0, `${value} was accepted as a digest`);
    }
  });
  await test("an action the daemon does not know is refused at the source", () => {
    // The daemon reads an unknown action as `disable`, which is the safe
    // direction — but "safe" is not "intended", and a typo that silently disables
    // more than the maintainer meant is still a bad day. Caught here, where it
    // costs a rerun.
    const errs = checkAdvisory({ ...GOOD_ADVISORY, action: "quarantine" });
    assert(errs.some((e) => e.includes("action")), errs.join("; "));
  });
  await test("a version range whose bounds are equal covers nothing and is refused", () => {
    const errs = checkAdvisory({
      ...GOOD_ADVISORY,
      entries: [
        { kind: "version_range", value: "example", versions: { introduced: "1.0.0", fixed: "1.0.0" } },
      ],
    });
    assert(errs.some((e) => e.includes("covers nothing")), errs.join("; "));
  });
  await test("a versions window on a kind that has no versions is refused", () => {
    const errs = checkAdvisory({
      ...GOOD_ADVISORY,
      entries: [{ kind: "digest", value: "a".repeat(64), versions: { fixed: "1.0.0" } }],
    });
    assert(errs.some((e) => e.includes("does not take a versions window")), errs.join("; "));
  });
  await test("a reason carrying a bidi override is refused", () => {
    // It is shown to the user verbatim, in a notification the daemon marks
    // persistent. A withdrawal notice is the last place to allow invisible
    // reordering of the sentence.
    const errs = checkAdvisory({ ...GOOD_ADVISORY, reason: "Safe‮elbadaolnwod si" });
    assert(errs.some((e) => e.includes("bidirectional")), errs.join("; "));
  });
  await test("an identity value must be the spelling the daemon pins", () => {
    const ok = checkAdvisory({
      ...GOOD_ADVISORY,
      // Paired with an id, because an identity-only advisory is refused for a
      // different reason — see the sideload test above.
      entries: [{ kind: "identity", value: "github:owner/repo" }, { kind: "id", value: "dice-roller" }],
    });
    assert(ok.length === 0, ok.join("; "));
    const bad = checkAdvisory({
      ...GOOD_ADVISORY,
      entries: [{ kind: "identity", value: "https://github.com/owner/repo" }],
    });
    assert(bad.length > 0, "a URL was accepted where AuthorIdentity::revocation_key was required");
  });
  await test("the generator flattens an advisory into one entry per key, carrying the advisory", () => {
    const dir = path.join(tmp, "revsrc");
    fs.mkdirSync(path.join(dir, "tools/revocations"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "tools/revocations/ASTRA-2026-0001.json"),
      JSON.stringify({
        ...GOOD_ADVISORY,
        entries: [
          { kind: "digest", value: "b".repeat(64) },
          { kind: "version_range", value: "example", versions: { introduced: "1.0.0", fixed: "1.2.0" } },
        ],
      }),
    );
    const built = buildRevocations({ root: dir, serial: 4 });
    assert(built.signed.revocations.length === 2, JSON.stringify(built.signed.revocations));
    for (const entry of built.signed.revocations) {
      assert(entry.id === "ASTRA-2026-0001", "the advisory id must travel with every entry");
      assert(entry.action === "disable" && entry.severity === "critical", JSON.stringify(entry));
      assert(entry.reason.length > 0 && entry.advisory_url.startsWith("https://"), JSON.stringify(entry));
    }
    // Deterministic: same sources + same serial -> same bytes, which is what makes
    // `--check` and the CI diff mean anything.
    assert(
      stableStringify(built) === stableStringify(buildRevocations({ root: dir, serial: 4 })),
      "the withdrawal-list generator is not deterministic",
    );
    // And it reads no clock — the freshness window is stamped at signing time,
    // for the same reason the catalogue's is.
    assert(built.signed.issued_at === undefined, "the generator stamped a timestamp");
  });
  await test("the generator refuses to build from an invalid advisory", () => {
    const dir = path.join(tmp, "revbad");
    fs.mkdirSync(path.join(dir, "tools/revocations"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "tools/revocations/ASTRA-2026-0002.json"),
      JSON.stringify({ ...GOOD_ADVISORY, id: "ASTRA-2026-0002", entries: [{ kind: "author", value: "x" }] }),
    );
    let threw = false;
    try {
      buildRevocations({ root: dir, serial: 1 });
    } catch {
      threw = true;
    }
    assert(threw, "an advisory the daemon could not act on was built into a deployable document");
  });
  await test("a signed withdrawal list verifies under the key trust.json delegates to", () => {
    const doc = signedRevocations();
    const r = verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys);
    assert(r.ok, `did not verify: ${r.reason}`);
    assert(r.key_id === TEST_INDEX_KEY, `verified under ${r.key_id}`);
  });
  await test("a withdrawal list signed by a stranger is refused", () => {
    const doc = signedRevocations(TEST_STRANGER_KEY);
    assert(
      !verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
      "a key trust.json does not delegate to signed a withdrawal list and it was believed",
    );
  });
  await test("A REVOCATION SIGNED AS AN INDEX IS REJECTED, AND THE CONVERSE", () => {
    // The acceptance criterion, and the reason REVOCATIONS_SCHEMA exists as a
    // separate constant. One key signs both documents (§5.1: "there is no
    // separate revocation role"), so the domain is the ONLY thing keeping them
    // apart. Without it, anyone who could get a single catalogue signed could
    // publish an EMPTY withdrawal list under the same signature and switch off
    // the one mechanism that helps after bad code is already installed.
    const k = loadTestRoot(TEST_INDEX_KEY);
    const payload = { schema: REVOCATIONS_SCHEMA, serial: 3, revocations: [] };
    const asIndex = signEnvelope({
      domain: INDEX_SCHEMA,
      signed: payload,
      signers: [{ key_id: k.key_id, privateKey: k.privateKey }],
    });
    assert(
      verifyEnvelope(asIndex, INDEX_SCHEMA, trustedIndexKeys).ok,
      "the fixture must be a genuine signature, or this test proves nothing",
    );
    assert(
      !verifyEnvelope(asIndex, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
      "a signature made under the catalogue's domain verified as a withdrawal list",
    );

    const asRevocations = signedRevocations();
    assert(
      !verifyEnvelope(asRevocations, INDEX_SCHEMA, trustedIndexKeys).ok,
      "a withdrawal-list signature verified as a catalogue signature",
    );
    assert(
      !verifyEnvelope(asRevocations, TRUST_SCHEMA, trustedIndexKeys).ok,
      "a withdrawal-list signature verified as a trust.json signature",
    );
  });
  await test("the signer refuses a document that is not a withdrawal list", () => {
    let threw = false;
    try {
      const k = loadTestRoot(TEST_INDEX_KEY);
      signRevocations(
        { signed: { schema: INDEX_SCHEMA, serial: 1 } },
        { signer: { key_id: k.key_id, privateKey: k.privateKey } },
      );
    } catch {
      threw = true;
    }
    assert(threw, "the index key signed a catalogue under the withdrawal list's domain");
  });
  await test("the withdrawal list's TTL is 7 days, against the catalogue's 30", () => {
    const doc = signedRevocations();
    const days = (Date.parse(doc.signed.expires_at) - Date.parse(doc.signed.issued_at)) / 86400000;
    assert(days === REVOCATION_TTL_DAYS, `${days} days, expected ${REVOCATION_TTL_DAYS}`);
    assert(
      REVOCATION_TTL_DAYS < CATALOG_TTL_DAYS,
      "the asymmetry IS the freshness policy: a stale catalogue is a banner, a stale withdrawal list is a hard block",
    );
  });
  await test("one byte edited after signing is refused", () => {
    const doc = signedRevocations(TEST_INDEX_KEY, 3, [
      { kind: "digest", value: "c".repeat(64), id: "ASTRA-2026-0002", action: "disable" },
    ]);
    assert(verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok, "baseline");
    doc.signed.revocations[0].action = "warn";
    assert(
      !verifyEnvelope(doc, REVOCATIONS_SCHEMA, trustedIndexKeys).ok,
      "the action — which decides whether an installed plugin is stopped — was editable after signing",
    );
  });
  await test("the committed withdrawal list is a signed envelope the daemon's schema names", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/revocations.json"), "utf8"));
    assert(doc.signed?.schema === REVOCATIONS_SCHEMA, JSON.stringify(doc.signed?.schema));
    assert(Number.isSafeInteger(doc.signed.serial) && doc.signed.serial >= 1,
      "serial 0 is reserved for 'this daemon has never seen a list'");
    assert(Array.isArray(doc.signed.revocations), "revocations must be an array, even when empty");
  });
}
