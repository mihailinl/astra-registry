// The withdrawal list, every test a refusal: the advisory shapes checkAdvisory
// rejects, the generator flattening and refusing, the serial a regeneration
// writes before its commit against the one the signer assigns at it (entry
// 69), and the signed envelope — a stranger's key, the index/revocation domain
// swap in both directions, the 7-day TTL against the catalogue's 30, one
// edited byte, and the committed document's shape.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fixtureEnv } from "../lib/git-env.mjs";

import { stableStringify } from "../lib/canonical.mjs";
import {
  KINDS, OUTPUT_FILE, REFUSED_ADVISORY_HOSTS, SERIAL_PATHSPEC, SOURCE_DIR, buildRevocations, checkAdvisory, resolveSerial,
} from "../lib/revocations.mjs";
import { FLAG_PATH, FLAG_SCHEMA, flagPermanenceProblems } from "../signer/pages.mjs";
import { serialsAt } from "../signer/plan.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { signRevocations } from "../sign-revocations.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import { FIXTURE_ISSUED_AT } from "../../bot/fixtures/index/regenerate.mjs";
import {
  CATALOG_TTL_DAYS, INDEX_SCHEMA, REVOCATIONS_SCHEMA, REVOCATION_TTL_DAYS, TRUST_SCHEMA,
  signEnvelope, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";
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
    advisory_url: "https://astra.minice.ai/plugins/_/advisories/ASTRA-2026-0001",
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
  // Contract §0.7 since 2.16.0: a version is at most 256 characters, pre-release
  // and build included. An advisory names versions in two places, an
  // `id_version` value and a `version_range` window, and both reach the signed
  // withdrawal list, which the plugins service mirrors and every client reads.
  // A version the service cannot hold there is a list it cannot mirror.
  await test("an advisory's versions are at most 256 characters: an id_version value and a version_range window admit 256 and refuse 257 (contract §0.7, 2.16.0)", () => {
    const v256 = `1.0.0-${"a".repeat(125)}+${"b".repeat(124)}`;
    const v257 = `${v256}b`;
    assertEqual(v256.length, 256, "the fixture is not 256 characters");
    const withEntry = (entry) => checkAdvisory({ ...GOOD_ADVISORY, entries: [{ kind: "digest", value: "a".repeat(64) }, entry] });
    const idVersion = (v) => withEntry({ kind: "id_version", value: `dice-roller@${v}` });
    // `fixed` is 2.0.0 so the window stays forward whichever bound is long.
    const introduced = (v) => withEntry({ kind: "version_range", value: "dice-roller", versions: { introduced: v, fixed: "2.0.0" } });
    const fixed = (v) => withEntry({ kind: "version_range", value: "dice-roller", versions: { introduced: "0.1.0", fixed: v.replace(/^1/, "3") } });
    const wrong = [];
    for (const [what, check] of [["id_version", idVersion], ["versions.introduced", introduced], ["versions.fixed", fixed]]) {
      const at256 = check(v256);
      if (at256.length) wrong.push(`${what} refused 256: ${at256.join("; ")}`);
      if (check(v257).length === 0) wrong.push(`${what} admitted 257`);
    }
    assertEqual(wrong.join("\n"), "", "an advisory does not hold its versions to contract §0.7's bound");
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
  // WHY THE FIXTURE CARRIES AN `id` AND THE ASSERTION READS THE MESSAGE.
  // Until 2026-09-22 this check built a digest-ONLY advisory and asserted
  // `errs.length > 0`. A digest-only advisory is refused by the sideload rule
  // above whatever the digest says, so the count was never zero and the digest
  // grammar in this check's name was asserted by nothing: loosening `SHA256` in
  // tools/lib/revocations.mjs to `/^[0-9a-fA-F]{1,64}$/` — which accepts
  // `A`×64, `abc` and `a`×63 — left the whole suite at 317 passed, 0 failed,
  // and this check printing `ok`. So the entry is PAIRED with an `id`, which
  // satisfies the sideload rule and leaves the digest as the only thing that
  // can be wrong, and the assertion names the rule instead of counting errors.
  await test("an uppercase or truncated digest is refused", () => {
    // The control first. If the paired shape were refused for some other
    // reason, every assertion below would pass on that reason and this check
    // would be back where it started.
    const paired = (value) => [{ kind: "digest", value }, { kind: "id", value: "dice-roller" }];
    assertEqual(checkAdvisory({ ...GOOD_ADVISORY, entries: paired("a".repeat(64)) }).join("; "), "",
      "a well-formed lowercase digest paired with an id was refused, so nothing below separates the digest " +
      "grammar from whatever refused this");

    for (const value of ["A".repeat(64), "abc", "a".repeat(63)]) {
      const errs = checkAdvisory({ ...GOOD_ADVISORY, entries: paired(value) });
      assert(errs.some((e) => e.includes("64 lowercase hex characters")),
        `${JSON.stringify(value)} was accepted as a digest, or was refused for something other than its ` +
        `grammar: ${errs.join("; ") || "no error at all"}`);
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
  // THE SAME REPAIR AS THE DIGEST CHECK ABOVE, for the same reason and measured
  // the same way. The negative fixture used to be an identity-ONLY advisory and
  // the assertion was `bad.length > 0` — so the sideload rule refused it
  // whatever the identity grammar said. Extending `IDENTITY` in
  // tools/lib/revocations.mjs with `|https:\/\/.+`, which accepts exactly the
  // URL this check exists to refuse, left the suite at 317 passed, 0 failed and
  // this check printing `ok`. Only the POSITIVE half was load-bearing. So the
  // negative is paired with an `id` too, and it asserts the identity rule by
  // the symbol the daemon side is named after rather than by a count.
  await test("an identity value must be the spelling the daemon pins", () => {
    // Both spellings `AuthorIdentity::revocation_key` produces, not one. A
    // check that only ever passed `github:` would stay green on an IDENTITY
    // that had lost its `origin:` alternative, and `origin:host` is the
    // spelling every non-GitHub author gets.
    for (const value of ["github:owner/repo", "origin:plugins.example.test"]) {
      const ok = checkAdvisory({
        ...GOOD_ADVISORY,
        // Paired with an id, because an identity-only advisory is refused for a
        // different reason — see the sideload test above.
        entries: [{ kind: "identity", value }, { kind: "id", value: "dice-roller" }],
      });
      assertEqual(ok.join("; "), "", `${value} is what the daemon pins and it was refused`);
    }
    for (const value of ["https://github.com/owner/repo", "github.com/owner/repo", "github:owner", "GitHub:owner/repo"]) {
      const bad = checkAdvisory({
        ...GOOD_ADVISORY,
        entries: [{ kind: "identity", value }, { kind: "id", value: "dice-roller" }],
      });
      assert(bad.some((e) => e.includes("AuthorIdentity::revocation_key")),
        `${JSON.stringify(value)} was accepted where AuthorIdentity::revocation_key is required, or was refused ` +
        `for something else: ${bad.join("; ") || "no error at all"}`);
    }
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

  // M-T3.9 (MOD-13's registry half). Until this, `checkAdvisory` accepted any
  // https URL on any host but GitHub's, so an advisory carrying
  // `https://advisories.example.invalid/…` — or the project's own base with
  // ANOTHER advisory's id — was signed into the withdrawal list and shown to a
  // user on the screen that says their plugin was disabled. MOD-13 records one
  // base (OPEN-MBE-15, closed at 0.12.0) and the service serves one page per
  // id under it, so the only URL that names THIS advisory's page is the base
  // plus this advisory's id. Everything else is somebody's guess, signed.
  await test("MOD-13: advisory_url is the advisory page base plus this advisory's own id, or absent (M-T3.9)", async () => {
    const { ADVISORY_URL_BASE } = await import("../lib/revocations.mjs");
    const { ADVISORY_URL_BASE: COMPILED, tokenAdvisoryBase } = await import("../../bot/lib/compile-decision.mjs");
    assertEqual(ADVISORY_URL_BASE, "https://astra.minice.ai/plugins/_/advisories/",
      "tools/lib/revocations.mjs's advisory base is not MOD-13's");
    assertEqual(COMPILED, ADVISORY_URL_BASE,
      "bot/lib/compile-decision.mjs compiles a base the validator does not accept, so every advisory the bot " +
      "writes would be refused by the gate that runs before its push");
    assertEqual(ADVISORY_URL_BASE, tokenAdvisoryBase({ root: REPO_ROOT }),
      "the token file's page:MOD-13-advisory-base is not the base this repository checks, and the service " +
      "serves the token file's");
    const id = GOOD_ADVISORY.id;
    assertEqual(checkAdvisory({ ...GOOD_ADVISORY, advisory_url: `${ADVISORY_URL_BASE}${id}` }).join("; "), "",
      "base + id, the one URL the bot compiles, was refused");
    const { advisory_url, ...withoutUrl } = GOOD_ADVISORY;
    assertEqual(checkAdvisory(withoutUrl).join("; "), "", "an advisory with no advisory_url was refused");
    for (const [what, url] of [
      ["a foreign prefix", `https://advisories.example.invalid/${id}`],
      ["the base with another advisory's id", `${ADVISORY_URL_BASE}ASTRA-2026-0002`],
      ["the base alone", ADVISORY_URL_BASE],
      ["base + id with a query", `${ADVISORY_URL_BASE}${id}?from=mail`],
      ["base + id with a fragment", `${ADVISORY_URL_BASE}${id}#details`],
      ["base + id with a trailing slash", `${ADVISORY_URL_BASE}${id}/`],
      ["the base on plain http", `${ADVISORY_URL_BASE.replace("https://", "http://")}${id}`],
      ["the base's host in another case", `${ADVISORY_URL_BASE.replace("astra.minice.ai", "Astra.Minice.AI")}${id}`],
      ["a path under the base's host but not the base", `https://astra.minice.ai/plugins/${id}`],
    ]) {
      const errs = checkAdvisory({ ...GOOD_ADVISORY, advisory_url: url });
      assert(errs.some((e) => e.includes("MOD-13")),
        `${what} (${url}) was accepted into a signed document: ${errs.join("; ") || "no error at all"}`);
    }
  });
  // A fixture repository with its whole history, built by `build`: the flag
  // rule's subject, at whatever state of breakage a check needs. Shared by the
  // two checks below, because the second one clones the first one's violation.
  const gitIn = (dir, ...a) =>
    execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(dir) }).trim();
  const flagFixture = (build) => {
    const dir = path.join(tmp, `flag-${build.name}`);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(path.join(dir, "policy"), { recursive: true });
    const git = (...a) => gitIn(dir, ...a);
    git("init", "-q", "-b", "main");
    git("config", "user.email", "flag-fixture@example.invalid");
    git("config", "user.name", "flag fixture");
    git("config", "commit.gpgsign", "false");
    const write = (value) => fs.writeFileSync(path.join(dir, FLAG_PATH), `${JSON.stringify(value, null, 2)}\n`);
    const commit = (m) => { git("add", "-A"); git("commit", "-qm", m); };
    build({ write, commit, remove: () => fs.rmSync(path.join(dir, FLAG_PATH)), dir });
    return dir;
  };
  const armed = { schema: FLAG_SCHEMA, armed_at: "2026-09-20T09:00:00Z" };
  function editedAfterArming({ write, commit, dir }) {
    // A commit before the arming one, so that a depth-2 clone below is missing
    // a real parent rather than stopping at the root.
    fs.writeFileSync(path.join(dir, "README.md"), "a registry before the latch\n"); commit("before");
    write(armed); commit("arm");
    write({ ...armed, armed_at: "2026-10-01T09:00:00Z" }); commit("tidy the date");
  }

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
    // The fixture is the same rule at the three ways it is broken. The real
    // tree is the check after the next one.
    const problemsFor = (build) => {
      const r = flagPermanenceProblems({ root: flagFixture(build) });
      // A fixture `git init`ed here holds its whole history, so everything
      // was asked; if it ever reads as shallow, a clean answer below means
      // nothing.
      assertEqual(r.notAsked, null, `the ${build.name} fixture has its whole history and the guard said it did not`);
      return r.problems;
    };

    const honest = problemsFor(function honest({ write, commit }) {
      write(armed); commit("arm Pages' withdrawal list");
    });
    assertEqual(honest.join("\n"), "", "an arming commit that does nothing else was refused");

    const edited = problemsFor(editedAfterArming);
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

    // `armed_at` is a §0.7 time (contract B.4, 2.11.0). Until 2.11.0 nothing
    // read its type: `armingState` takes it only if it is a string, and
    // nothing decides on it. But the file can never be edited once it is on
    // `main` (above), so a malformed time that merged would be a red suite for
    // good. The suite runs on the flag's own pull request, which is the one
    // place this can still be refused. Each is a way a hand-written time goes
    // wrong: an offset instead of `Z`, a day February does not have, a
    // fraction, a number, and a date with no time.
    for (const [how, value] of [
      ["an offset instead of Z", "2026-09-24T12:00:00+00:00"],
      ["a day its month does not have", "2026-02-30T00:00:00Z"],
      ["a fraction of a second", "2026-09-24T12:00:00.5Z"],
      ["a number", 1790000000],
      ["a date with no time", "2026-09-24"],
    ]) {
      const bad = problemsFor(Object.defineProperty(function badTime({ write, commit }) {
        write({ ...armed, armed_at: value }); commit("arm");
      }, "name", { value: `bad-time-${how.replace(/[^a-z]+/gi, "-")}` }));
      assert(bad.some((p) => p.includes("armed_at") && p.includes("§0.7")),
        `a flag whose armed_at is ${how} (${JSON.stringify(value)}) produced no problem: ${bad.join("\n") || "none at all"}`);
    }
  });

  // GAP 75. The guard's own precondition, watched on the checkout
  // `actions/checkout` makes when nobody sets `fetch-depth`.
  //
  // Measured on 2026-09-22, at dac28bc and again at b661b09: this repository
  // with the flag added and then edited, cloned at depth 1, printed `ok` for
  // the check above and exited 0 (`INCOMPLETE 322 passed, 0 failed, 1 not
  // asked` at dac28bc) — while a full clone of the same history failed it,
  // naming the editing commit. The commit at a shallow
  // boundary has no parent, so git reports the edit as the ADD, and a guard
  // whose passing condition is an absence of later changes finds none.
  //
  // Three clauses, and each has its own fixture, because each is a different
  // way to get this wrong: a guard that never asks whether it is shallow
  // (depth 1 reads clean), a guard that gives up entirely when it is (depth 1
  // loses the shape half, which needs no history), and a guard that stops
  // reading history when it is (depth 2 holds the edit AND its parent, so the
  // change is in front of it and must still be reported).
  await test("through a shallow clone the flag guard says NOT ASKED about the history it cannot see, and still reports what it can", () => {
    const clone = (origin, depth) => {
      const dir = `${origin}-depth${depth}`;
      fs.rmSync(dir, { recursive: true, force: true });
      execFileSync("git", ["clone", "-q", "--depth", String(depth), `file://${origin}`, dir],
        { stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(dir) });
      // The control. `git clone --depth` of a plain path is silently a FULL
      // clone ("--depth is ignored in local clones"), which is why the origin
      // is a file:// URL — and why this is asserted rather than assumed.
      assertEqual(gitIn(dir, "rev-parse", "--is-shallow-repository"), "true",
        `the depth-${depth} clone is not shallow, so nothing below is about a shallow clone`);
      assertEqual(gitIn(dir, "rev-list", "--count", "HEAD"), String(depth),
        `the depth-${depth} clone does not hold ${depth} commit(s)`);
      return dir;
    };

    const violated = flagFixture(editedAfterArming);
    const whole = flagPermanenceProblems({ root: violated });
    assert(whole.problems.some((p) => p.includes("modified, renamed or deleted")) && whole.notAsked === null,
      `the fixture's own history is not a visible violation, so its clones prove nothing: ${JSON.stringify(whole)}`);

    // (1) Depth 1: the edit IS the one fetched commit, and reads as the add.
    const one = flagPermanenceProblems({ root: clone(violated, 1) });
    assert(one.shallow === true && typeof one.notAsked === "string" && one.notAsked.includes("shallow checkout"),
      `through a depth-1 clone the guard answered as if it had asked a history that edits the flag — clean, ` +
      `to a caller that reads only \`problems\`: ${JSON.stringify(one)}`);

    // (2) Depth 2: the edit and its parent are both here, so the change is in
    // front of the clone — shallow or not, it is a real change.
    const two = flagPermanenceProblems({ root: clone(violated, 2) });
    assert(two.problems.some((p) => p.includes("modified, renamed or deleted")),
      `a depth-2 clone holds the editing commit and its parent, and the guard did not report the edit: ` +
      `${JSON.stringify(two)}`);
    assert(two.notAsked !== null, "a depth-2 clone is still shallow, and the guard said it had asked everything");

    // (3) The shape half needs no history, so a shallow clone still asks it.
    const noted = flagFixture(function notedFlag({ write, commit }) {
      write({ ...armed, note: "temporary, remove after R9b" }); commit("arm, with a note");
    });
    const shape = flagPermanenceProblems({ root: clone(noted, 1) });
    assert(shape.problems.some((p) => p.includes("must hold exactly")),
      `through a depth-1 clone a third field in the flag was not reported: ${JSON.stringify(shape)}`);
  });

  // And this repository, which is the subject the rule exists for. Today it
  // says nothing because the flag is not here; the day it is added this starts
  // checking it with nobody having to remember.
  //
  // WHERE IT IS ASKED, and the one live lane where it deliberately is not.
  // A red comes first and at any depth: a change among the fetched commits is
  // a real change. What a shallow checkout cannot do is say "clean", so there
  // it is NOT ASKED. The runner derives which live lanes reach this suite with
  // the whole history, prints them under the totals, and fails when there are
  // none — this check is found by that derivation because its body tests
  // `shallow` and calls `neverAsk`, so do not split the two apart.
  //
  // `ingest.yml`'s `selftest` job checks out at depth 1 and is LEFT there, on
  // purpose. Measured 2026-09-22, not argued: (a) it adds no detection. The
  // commit it asks about is `github.sha`, which its own run's `publish` job
  // checks out at `fetch-depth: 0` and asks again, through
  // `bot/publish-apply.mjs`, before anything commits; and which
  // `build-index.yml` (`fetch-depth: 0`) asks of the whole history on every
  // push to main, every pull request and every hour. (b) It would add an
  // outage. `main` is append-only, so a breach is red for good (gap 74), and
  // `selftest` is the job every submission's `check` waits on: asking it there
  // too turns a record-keeping breach from "nothing publishes" into "nothing
  // is judged", permanently. (c) Cost is not the reason, and was measured so
  // that nobody thinks it is: three full clones of this repository from
  // GitHub took 0.57-0.63 s against 0.69-0.81 s at depth 1 (5.6 MB of .git
  // against 2.8 MB), and in ingest run 35504547656 the publish job's full
  // fetch took 0.49 s against the selftest job's shallow one at 0.74 s.
  await test("this repository's arming flag has not changed since it was added, asked of its whole history", () => {
    const real = flagPermanenceProblems({ root: REPO_ROOT });
    assertEqual(real.problems.join("\n"), "", "the arming flag in this repository is not permanent");
    assertEqual(real.present, fs.existsSync(path.join(REPO_ROOT, FLAG_PATH)),
      "the rule disagrees with the filesystem about whether the flag is here");
    if (real.shallow) {
      neverAsk(real.notAsked,
        "a checkout with its whole history asks it: the runner prints the live lanes that reach this suite " +
        "with it under the totals and goes red when there are none (`node tools/selftest.mjs --lanes`). " +
        "ingest.yml's `selftest` job is left at depth 1 on purpose — its run's `publish` job asks the same " +
        "commit with the whole history before anything commits, and a breach is permanent, so asking it " +
        "there too would add an outage and no detection; the comment above this check has the measurement");
    }
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
  // Contract §0.7 (since 2.16.0), on the generator's own output. The daemon
  // parses the withdrawal list WHOLE, like the catalogue, and a list it cannot
  // parse is a list it cannot refresh: seven days later every shipped client
  // blocks every install with REVOCATIONS_STALE. `checkAdvisory` already
  // refuses an unpaired surrogate in a reason (it is display text), so the
  // case the source rules let through is a NONCHARACTER — valid Unicode, and
  // outside I-JSON, which RFC 8785 is defined over. Asked first, so the
  // refusal below is the generator's and not the loader's.
  await test("the generator does not emit a withdrawal list carrying a string that is not I-JSON, and names the advisory", () => {
    const dir = path.join(tmp, "revnonchar");
    fs.mkdirSync(path.join(dir, "tools/revocations"), { recursive: true });
    const doc = { ...GOOD_ADVISORY, reason: "Exfiltrates the clipboard to a third-party host.￿" };
    assertEqual(checkAdvisory(doc).join("; "), "",
      "the advisory rules refuse the fixture themselves, so the generator's refusal below would be unreachable");
    fs.writeFileSync(path.join(dir, "tools/revocations/ASTRA-2026-0001.json"), JSON.stringify(doc));
    let thrown = null;
    try {
      buildRevocations({ root: dir, serial: 1 });
    } catch (e) {
      thrown = String(e.message);
    }
    assert(thrown !== null && thrown.includes("not valid Unicode") && thrown.includes("(ASTRA-2026-0001)") &&
      thrown.includes("noncharacter U+FFFF"),
      `a withdrawal list carrying a noncharacter was generated, or refused without naming it: ${thrown ?? "it built"}`);
  });

  // ── entry 69: the hand path, regenerated before its commit ────────────────
  //
  // A maintainer writes an advisory, regenerates the list — the suite's
  // `build-revocations.mjs --check` refuses a tree whose list does not carry
  // its advisories — and commits both. Until 2026-09-23 `resolveSerial` stopped
  // at `HEAD`, so every such commit carried the serial `signed` already
  // served, while the signer assigned one more at that very commit; and
  // `--check` compares at the file's own serial, so nothing saw it. Measured
  // on clones of `5526f1a` with the CLI itself: written 4, `serialsAt` 5.
  //
  // So this does the hand path, once per kind of pending change, in a
  // repository built from committed material — this directory's README, the
  // committed list, and the advisory above — and compares the committed
  // file's serial with `serialsAt` at the commit that landed it. The
  // regeneration is `buildRevocations({ root })`, which is exactly the call
  // `build-revocations.mjs` makes without `--serial` (its root is this
  // checkout, so the CLI itself cannot be pointed at a fixture).
  //
  // Each step is a clause with a mutation that reds it: the clean steps an
  // unconditional +1; the pending ones the +1 removed; the README step a
  // pathspec narrowed to the advisories; two changes at once a count of
  // status lines; the step outside the directory a pathspec widened to
  // `tools/` or to the tree. And at every step `pending: false` stops at
  // `HEAD`, which is what the moderation commit job adds its own commit to.
  // The landing is a commit on the tip, as RUNBOOK §7.1 pushes one; a merge
  // commit adds one more that no regeneration can foresee (`resolveSerial`'s
  // comment has the measurement).
  await test("entry 69 — a list regenerated before its commit carries the serial the signer assigns at the commit that lands it: untracked, staged, unstaged, a README, two at once, and nothing for a clean tree or a change outside the directory", () => {
    const dir = path.join(tmp, "entry69-hand-path");
    fs.mkdirSync(dir, { recursive: true });
    const git = (...a) =>
      execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: fixtureEnv(dir) }).trimEnd();
    git("init", "-q", "-b", "main");
    git("config", "user.email", "entry69-fixture@example.invalid");
    git("config", "user.name", "entry 69 fixture");
    git("config", "commit.gpgsign", "false");
    const put = (rel, body) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    };
    // `--allow-empty`: the last clean regeneration rewrites nothing, and its
    // commit is still a landing to compare.
    const commitAll = (message) => {
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", message);
      return git("rev-parse", "HEAD");
    };
    // A hand-written advisory omits `advisory_url` (the directory's README).
    const { advisory_url: _url, ...handWritten } = GOOD_ADVISORY;
    const advisory = (n, over = {}) => {
      const id = `ASTRA-2026-${String(n).padStart(4, "0")}`;
      const doc = { ...handWritten, id, entries: [{ kind: "id", value: `fixture-${n}` }], ...over };
      const errs = checkAdvisory(doc, id);
      assert(errs.length === 0, `the fixture's advisory ${id} is not one: ${errs.join("; ")}`);
      return [`${SOURCE_DIR}/${id}.json`, `${JSON.stringify(doc, null, 2)}\n`];
    };

    // Committed material: the directory's README and main's list, then a
    // commit outside the directory, so a wider pathspec has history to see.
    put(`${SOURCE_DIR}/README.md`, fs.readFileSync(path.join(REPO_ROOT, SOURCE_DIR, "README.md"), "utf8"));
    put(OUTPUT_FILE, fs.readFileSync(path.join(REPO_ROOT, OUTPUT_FILE), "utf8"));
    commitAll("seed: the directory and the list, as main has them");
    put("tools/README-fixture.md", "under tools/, outside the list's directory\n");
    put("plugins/fixture/plugin.json", "{}\n");
    commitAll("seed: outside the directory");

    const steps = [
      ["a clean tree", false, () => {}],
      ["an advisory, untracked", true, () => put(...advisory(1))],
      ["an advisory, staged before the regeneration", true, () => {
        put(...advisory(2));
        git("add", "--", SOURCE_DIR);
      }],
      ["a committed advisory edited, unstaged", true, () => put(...advisory(1, { severity: "moderate" }))],
      ["the directory's README alone", true, () =>
        fs.appendFileSync(path.join(dir, SOURCE_DIR, "README.md"), "\nOne more line.\n")],
      ["two at once, an advisory added and one withdrawn", true, () => {
        put(...advisory(3));
        fs.rmSync(path.join(dir, advisory(2)[0]));
      }],
      ["a change outside the directory only", false, () => {
        put("tools/README-fixture.md", "under tools/, outside the list's directory, edited\n");
        put("plugins/fixture/plugin.json", "{ }\n");
      }],
      ["a clean tree again", false, () => {}],
    ];

    const override = process.env.ASTRA_REVOCATIONS_SERIAL;
    delete process.env.ASTRA_REVOCATIONS_SERIAL;
    const rows = [];
    const wrong = [];
    try {
      for (const [what, inside, prepare] of steps) {
        const head = git("rev-parse", "HEAD");
        prepare();
        // The fixture guard: each step is the case it names, or its verdict
        // is about a case it did not build.
        const pending = git("status", "--porcelain", "--", SERIAL_PATHSPEC);
        assertEqual(pending !== "", inside,
          `${what}: git status under ${SERIAL_PATHSPEC}/ reads ${JSON.stringify(pending)}, so the fixture is not the case it names`);
        if (what.startsWith("two at once")) {
          assertEqual(pending.split("\n").length, 2, `${what}: git status reads ${JSON.stringify(pending)}, not two changes`);
        }
        if (what.startsWith("a change outside")) {
          assert(git("status", "--porcelain", "--", "tools") !== "" && git("status", "--porcelain", "--", ".") !== "",
            `${what}: neither tools/ nor the tree shows a pending change, so a widened pathspec could not be told apart`);
        }

        const atHead = serialsAt({ root: dir, sha: head }).revocations;
        const stopped = resolveSerial({ root: dir, pending: false });
        if (stopped !== atHead) {
          wrong.push(`${what}: resolveSerial with pending: false gives ${stopped} and HEAD's serial is ${atHead}; the ` +
            "moderation commit job adds its own commit to that, so it must stop at HEAD or the job writes one past the signer's serial");
        }

        // The hand path: regenerate, then commit everything.
        put(OUTPUT_FILE, stableStringify(buildRevocations({ root: dir })));
        const landed = commitAll(`entry 69: ${what}`);
        const written = JSON.parse(git("show", `${landed}:${OUTPUT_FILE}`)).signed.serial;
        const signer = serialsAt({ root: dir, sha: landed }).revocations;
        rows.push(`${what}: HEAD ${atHead}, written ${written}, the signer ${signer}`);
        if (written !== signer) {
          wrong.push(`${what}: the list regenerated before its commit carries serial ${written}, and the signer ` +
            `assigns ${signer} at the commit that landed it (HEAD's was ${atHead})`);
        }
      }
      assertEqual(git("status", "--porcelain"), "", "the fixture was left with a pending change");
    } finally {
      if (override !== undefined) process.env.ASTRA_REVOCATIONS_SERIAL = override;
    }
    assertEqual(rows.length, steps.length, `the hand path ran ${rows.length} of ${steps.length} steps`);
    assert(wrong.length === 0,
      `${wrong.join("; ")} — ops register entry 69. Every step: ${rows.join(" | ")}`);
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
