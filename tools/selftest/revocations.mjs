// The withdrawal list, every test a refusal: the advisory shapes checkAdvisory
// rejects, the generator flattening and refusing, and the signed envelope — a
// stranger's key, the index/revocation domain swap in both directions, the 7-day
// TTL against the catalogue's 30, one edited byte, and the committed document's
// shape.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { stableStringify } from "../lib/canonical.mjs";
import { KINDS, REFUSED_ADVISORY_HOSTS, buildRevocations, checkAdvisory } from "../lib/revocations.mjs";
import { FLAG_PATH, FLAG_SCHEMA, flagPermanenceProblems } from "../signer/pages.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { FIXTURE_ISSUED_AT } from "../../bot/fixtures/index/regenerate.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, REVOCATION_TTL_DAYS, TRUST_SCHEMA,
  signEnvelope, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";
import { TEST_INDEX_KEY, TEST_STRANGER_KEY, trustedIndexKeys } from "./fixtures.mjs";

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

  // ── the kind vocabulary, and the two legs that do not exist ────────────────
  //
  // `KINDS` is hand-maintained, and its own docstring says why: "`astra-daemon/
  // src/plugins/trust.rs`'s `RevocationKind` is the authority; this table exists
  // so the registry cannot publish a kind the daemon would silently ignore."
  //
  // NOTHING COMPARES THE TWO. Measured on 2026-09-19, each side opened rather
  // than inferred:
  //
  //   * here — `KINDS` appears in three places repo-wide, all in
  //     `tools/lib/revocations.mjs`: its definition and its two uses. Before
  //     this test no test imported it and nothing named the seven, so this
  //     floor is the FIRST assertion about the list's membership rather than a
  //     second copy of one;
  //   * the daemon — `pub enum RevocationKind` is at
  //     `astra-daemon/src/plugins/trust.rs`, seven variants under
  //     `#[serde(rename_all = "snake_case")]`, which is the enum this list is
  //     about. `consistency.rs` does not mention it: 0 occurrences. What is
  //     absent there is the COMPARISON, not the enum — the sibling-checkout
  //     pair belongs to the client plan's C1.4 and has not been written;
  //   * the plugins service — no reader, reported by that session's own grep
  //     of its tree (zero hits for `AV-7`, `advisory_kind` or `advisory
  //     kinds`), which this repository has not verified for itself. Their
  //     words, recorded as theirs: it has no design entry to be unimplemented
  //     from.
  //
  // So all three legs are absent as comparisons and this floor is the only one
  // that will notice an eighth key. The cost of missing it is AV-7's: ONE
  // unknown kind makes the daemon refuse the WHOLE list, so every armed build
  // of that population blocks installs seven days later — the failure is not
  // gradual, and it arrives a week after the publish that caused it.
  //
  // The literal list is the point. A test that compared `KINDS` with itself,
  // or counted it, would pass on a renamed key.
  await test("KINDS is exactly the seven kinds the daemon parses, and nothing else compares them (TRUST-26; AV-7)", () => {
    const SEVEN = ["digest", "binary", "id", "id_version", "version_range", "identity", "publisher_key"];
    const listed = Object.keys(KINDS);

    // The floor first, so a `KINDS` that lost half its entries cannot be
    // reported as a set that merely differs.
    assert(listed.length >= 7,
      `KINDS holds ${listed.length} kind(s) and the daemon's RevocationKind has 7 variants; a kind the registry ` +
      `stopped accepting is a withdrawal an author cannot publish`);

    const extra = listed.filter((k) => !SEVEN.includes(k));
    const missing = SEVEN.filter((k) => !listed.includes(k));
    assertEqual(extra.join(", "), "",
      "KINDS accepts a kind that is not in astra-daemon/src/plugins/trust.rs's RevocationKind. AV-7: one unknown " +
      "kind makes the daemon refuse the WHOLE list, so every armed client blocks installs 7 days later. Add the " +
      "variant to the daemon FIRST, then to this list and to the literal in this test");
    assertEqual(missing.join(", "), "",
      "a kind the daemon parses is no longer one this registry will publish; the withdrawal it is for cannot be " +
      "written at all");

    // The reason, asserted where it is written rather than paraphrased here: a
    // hand-maintained table whose explanation has been deleted is a table the
    // next reader tidies.
    // Unwrapped before it is searched for: the sentence is three lines of a
    // block comment, and a needle that only matches one line's worth of it
    // would go red the next time somebody reflows the paragraph.
    const src = fs.readFileSync(path.join(REPO_ROOT, "tools/lib/revocations.mjs"), "utf8")
      .split("\n").map((l) => l.replace(/^\s*\*\s?|^\s*\/\/\s?/, "")).join(" ").replace(/\s+/g, " ");
    assert(src.includes("this table exists so the registry cannot publish a kind the daemon would silently ignore"),
      "the sentence explaining why KINDS is hand-maintained has left tools/lib/revocations.mjs, and it is the only " +
      "place a reader learns that the daemon's enum is the authority");

    // M-T3.1 and `checkAdvisory` compile only TRUST-26's four, which is a
    // SUBSET of the seven and must stay one: a compiler emitting a kind this
    // list does not accept would fail its own validation.
    for (const k of ["digest", "id", "id_version", "version_range"]) {
      assert(listed.includes(k), `TRUST-26's ${k} is not in KINDS, so the compiler emits what the registry refuses`);
    }
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
  await test("an advisory_url on GitHub is refused, because a signed link outlives the page (ROLL-50)", () => {
    // The field is optional, and that is exactly why refusing these two hosts
    // costs nothing. A withdrawal list is SIGNED and kept by every client that
    // fetched it, so a URL inside one outlives the page it names — and every
    // address this project has on github.com or *.github.io stops resolving
    // when the Pages deployment is retired at R9a. What is left is a signed
    // advisory whose only explanation is a 404, on the one document a user
    // reads after something has already gone wrong.
    //
    // Subdomains included, because `<owner>.github.io` is where Pages serves
    // and the bare host is not what anyone would write.
    for (const url of [
      "https://github.com/mihailinl/astra-registry/security/advisories/ASTRA-2026-0001",
      "https://mihailinl.github.io/astra-registry/advisories/ASTRA-2026-0001",
      "https://github.io/anything",
      "https://raw.github.com/mihailinl/astra-registry/main/advisory.md",
      "https://GitHub.com/mihailinl/astra-registry/advisories/1",
    ]) {
      const errs = checkAdvisory({ ...GOOD_ADVISORY, advisory_url: url });
      assert(errs.some((e) => e.includes("ROLL-50")),
        `${url} was accepted into a signed document: ${errs.join("; ") || "no error at all"}`);
    }
    // Both directions: a host that is not one of these, and the field omitted
    // entirely, are what an advisory is supposed to look like today.
    assert(checkAdvisory({ ...GOOD_ADVISORY, advisory_url: "https://astra.minice.ai/plugins/_/advisories/ASTRA-2026-0001" }).length === 0,
      "the project's own advisory host was refused");
    const { advisory_url, ...withoutUrl } = GOOD_ADVISORY;
    assert(checkAdvisory(withoutUrl).length === 0, "omitting the optional field was refused");
    // And the rule names both hosts rather than one, which is the half a
    // one-host check would silently lose.
    assertEqual(REFUSED_ADVISORY_HOSTS.slice().sort().join(","), "github.com,github.io",
      "the refused-host list changed; ROLL-50 names github.com and github.io");
  });
  await test("the arming flag, once added, is never changed and never deleted — no R9b exception", () => {
    // D5's latch is HISTORY: `armingState` asks whether any commit reachable
    // from the Source-Commit ADDED `policy/pages-withdrawal-list.json`, and it
    // deliberately cannot notice the file being edited or deleted afterwards.
    // That is the right shape for the field — a client that has armed does not
    // disarm, so a revert must not put an unsigned list back in front of it
    // and look green — but it leaves the file itself unguarded. This is the
    // guard.
    //
    // Watched on a fixture repository rather than only on this one, because
    // the flag has not been added here yet: on the real tree every assertion
    // below is about an empty history, which is a rule nobody has seen work.
    // The fixture is the same rule at the three ways it is broken.
    const problemsFor = (build) => {
      const dir = path.join(tmp, `flag-${build.name}`);
      fs.rmSync(dir, { recursive: true, force: true });
      fs.mkdirSync(path.join(dir, "policy"), { recursive: true });
      const git = (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      git("init", "-q", "-b", "main");
      git("config", "user.email", "flag-fixture@example.invalid");
      git("config", "user.name", "flag fixture");
      git("config", "commit.gpgsign", "false");
      const write = (value) => fs.writeFileSync(path.join(dir, FLAG_PATH), `${JSON.stringify(value, null, 2)}\n`);
      const commit = (m) => { git("add", "-A"); git("commit", "-qm", m); };
      build({ write, commit, remove: () => fs.rmSync(path.join(dir, FLAG_PATH)), dir });
      return flagPermanenceProblems({ root: dir }).problems;
    };
    const armed = { schema: FLAG_SCHEMA, armed_at: "2026-09-20T09:00:00Z" };

    const honest = problemsFor(function honest({ write, commit }) {
      write(armed); commit("arm Pages' withdrawal list");
    });
    assertEqual(honest.join("\n"), "", "an arming commit that does nothing else was refused");

    const edited = problemsFor(function edited({ write, commit }) {
      write(armed); commit("arm");
      write({ ...armed, armed_at: "2026-10-01T09:00:00Z" }); commit("tidy the date");
    });
    assert(edited.some((p) => p.includes("modified, renamed or deleted")),
      `an edit of the flag after the arming commit produced no problem: ${edited.join("\n") || "none at all"}`);

    const deleted = problemsFor(function deleted({ write, commit, remove }) {
      write(armed); commit("arm");
      remove(); commit("Pages is retired at R9b, so this is moot");
    });
    assert(deleted.some((p) => p.includes("modified, renamed or deleted")),
      `a deletion justified by R9b passed: ${deleted.join("\n") || "no problem at all"}`);

    const readded = problemsFor(function readded({ write, commit, remove }) {
      write(armed); commit("arm");
      remove(); commit("drop it");
      write({ ...armed, armed_at: "2027-01-01T09:00:00Z" }); commit("arm again, later");
    });
    assert(readded.some((p) => p.includes("added 2 times")),
      `a delete-then-re-add produced no problem: ${readded.join("\n") || "none at all"}`);

    const extra = problemsFor(function extra({ write, commit }) {
      write({ ...armed, note: "temporary, remove after R9b" }); commit("arm, with a note");
    });
    assert(extra.some((p) => p.includes("must hold exactly")),
      `a third field in the flag produced no problem: ${extra.join("\n") || "none at all"}`);

    // And this repository, which is the subject the rule exists for. Today it
    // says nothing because the flag is not here; the day it is added this
    // assertion starts checking it with nobody having to remember.
    const real = flagPermanenceProblems({ root: REPO_ROOT });
    assertEqual(real.problems.join("\n"), "", "the arming flag in this repository is not permanent");
    assertEqual(real.present, fs.existsSync(path.join(REPO_ROOT, FLAG_PATH)),
      "the rule disagrees with the filesystem about whether the flag is here");
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
