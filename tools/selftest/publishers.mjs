// Who may claim what: publisher records against their schema, every badge
// resolving and no record shipped unused, the no-publishers/ fail-closed case,
// expiry firing, homoglyph display-name collisions, `covers` in both orderings,
// reserved prefixes, whole-line proof, and the four re-check outcomes.
//
// Two tests below declare their own `const tmp` inside the test body, shadowing
// the harness one. Those are per-test trees and the shadows are deliberate,
// which is why this module imports no `tmp` at all.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildIndex } from "../build-index.mjs";
import { validate as validateSchema } from "../lib/jsonschema.mjs";
import { reservedPrefixViolation } from "../lib/reserved.mjs";
import { REPO_ROOT, expiredPublishers, loadPublishers, publisherNameCollisions } from "../lib/sources.mjs";
import { proofNamesOwner, recheck } from "../../bot/recheck-publishers.mjs";
import { test, assert } from "./harness.mjs";

export async function run() {
  await test("every publishers/ record validates against schema/publisher-v1.json", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema/publisher-v1.json"), "utf8"));
    const { errors, publishers } = loadPublishers(REPO_ROOT);
    assert(errors.length === 0, errors.map((e) => `${e.file}: ${e.message}`).join("\n"));
    assert(publishers.size >= 1, "no publisher records, so this test proves nothing");
    for (const { file, doc } of publishers.values()) {
      const errs = validateSchema(schema, doc);
      assert(errs.length === 0, `${file}: ` + errs.map((e) => `${e.path} ${e.message}`).join("\n"));
    }
  });

  // The badge's whole safety property, asserted on the shipped document rather
  // than on the code that writes it: a listing may only name a publisher the
  // catalogue actually carries a reviewed record for. A dangling key would be a
  // badge a client cannot resolve, and the tempting way to render that is "some
  // publisher" — which is a badge for an account nobody reviewed.
  await test("every listing's publisher resolves, and no record is shipped unused", () => {
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry/v1/index.json"), "utf8"));
    const map = doc.signed.publishers ?? {};
    const named = new Set(doc.signed.plugins.map((p) => p.publisher).filter(Boolean));
    for (const key of named) {
      assert(Object.hasOwn(map, key), `${key} is named by a listing and absent from signed.publishers`);
    }
    for (const key of Object.keys(map)) {
      assert(named.has(key), `${key} ships a record no listing points at`);
    }
  });

  // Fail closed, and exercised rather than asserted over an empty set. Every
  // listing today HAS a publisher record, so a test that walked the shipped
  // document looking for owners without one would loop over nothing and pass for
  // that reason — the exact vacuity this suite exists to refuse. So the generator
  // is run against a tree with no publishers/ at all, which is also the state
  // every fork and every first day is in.
  await test("with no publishers/ at all, no listing carries a publisher key", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-nopub-"));
    try {
      for (const dir of ["plugins", "registry", "policy", "schema"]) {
        const from = path.join(REPO_ROOT, dir);
        if (fs.existsSync(from)) fs.cpSync(from, path.join(tmp, dir), { recursive: true });
      }
      assert(!fs.existsSync(path.join(tmp, "publishers")), "the copy must not carry publishers/");
      const doc = buildIndex({ root: tmp, serial: 1 });
      assert(doc.signed.plugins.length >= 1, "no listings in the copy, so this proves nothing");
      assert(!Object.hasOwn(doc.signed, "publishers"),
        "signed.publishers is present with no records behind it");
      const badged = doc.signed.plugins.filter((e) => Object.hasOwn(e, "publisher"));
      assert(badged.length === 0,
        `no record exists and ${badged.length} listing(s) still carry a publisher key`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  // The expiry has to be able to fire, or it is a comment. `verified` is stored
  // as live evidence plus the date it last held, precisely so a tier granted once
  // and never revisited cannot go on asserting who somebody used to be.
  await test("an expired publisher record is reported, and a current one is not", () => {
    const stale = new Map([["ghost", { file: "publishers/ghost.json", doc: { owner: "ghost", expires_at: "2020-01-01" } }]]);
    assert(expiredPublishers(stale).length === 1, "an expired record went unreported");
    const fresh = new Map([["ghost", { file: "publishers/ghost.json", doc: { owner: "ghost", expires_at: "2999-01-01" } }]]);
    assert(expiredPublishers(fresh).length === 0, "a current record was reported as expired");
    const committed = loadPublishers(REPO_ROOT).publishers;
    assert(expiredPublishers(committed).length === 0,
      "a committed publisher record is past its own expiry: " +
      expiredPublishers(committed).map((e) => `${e.file} (${e.expires_at})`).join(", "));
  });

  // The display name is the word a user reads beside a trust mark, so two
  // publishers rendering as the same word is an impersonation whether or not
  // anyone meant one. A CLIENT cannot catch this — homoglyphs are exactly as
  // indistinguishable to a renderer as to a reader — so review is the only place
  // it can be caught, and review is what forgets.
  await test("no two publishers render as the same word", () => {
    const { publishers } = loadPublishers(REPO_ROOT);
    const clashes = publisherNameCollisions(publishers);
    assert(clashes.length === 0, clashes.map((c) => `${c.a} vs ${c.b}: ${c.why}`).join("\n"));

    // Exercised, not asserted over a set of two that happens to be fine. This
    // repository contains the pair that motivates it: a capital i against a
    // lowercase L, which case folding leaves distinct and nobody can see.
    const planted = new Map([
      ["one", { file: "publishers/one.json", doc: { owner: "someone-else", display_name: "KNICE" } }],
      ["two", { file: "publishers/two.json", doc: { owner: "KnlCE", display_name: "KNICE" } }],
    ]);
    assert(publisherNameCollisions(planted).length === 1, "two records displaying the same word must clash");

    const distinct = new Map([
      ["one", { file: "publishers/one.json", doc: { owner: "mihailinl", display_name: "Mihailin" } }],
      ["two", { file: "publishers/two.json", doc: { owner: "KnlCE", display_name: "KNICE" } }],
    ]);
    assert(publisherNameCollisions(distinct).length === 0, "two genuinely different publishers must not clash");
  });

  // `covers` lets ONE reviewed record speak for several owner logins, because a
  // person's plugins do not all live under their personal one. Three things have
  // to hold, and the second is the one that would have gone unnoticed.
  await test("a covered owner resolves to the same record, and cannot be claimed twice", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-covers-"));
    const write = (name, doc) =>
      fs.writeFileSync(path.join(tmp, "publishers", name), JSON.stringify(doc, null, 2));
    const load = () => loadPublishers(tmp);
    fs.mkdirSync(path.join(tmp, "publishers"));

    // 1. Every claimed login finds the record, and finds the SAME object.
    write("someone.json", { owner: "someone", covers: ["SOMEONE-TECH"], display_name: "Someone" });
    const { errors, publishers } = load();
    assert(errors.length === 0, `a well-formed record errored: ${JSON.stringify(errors)}`);
    assert(publishers.has("someone") && publishers.has("someone-tech"),
      "a covered login did not resolve; the badge would reach only the personal account");
    assert(publishers.get("someone") === publishers.get("someone-tech"),
      "the two keys must be one record, or a rename becomes two edits that can disagree");

    // 2. The collision check must not see one record as two publishers. Without
    //    `publisherRecords` deduplicating by identity this compares the record
    //    with itself, finds its display name equal to its display name, and
    //    reports every multi-login publisher as impersonating itself.
    assert(publisherNameCollisions(publishers).length === 0,
      "one record under two keys was reported as two publishers colliding");

    // 3. A `covers` entry must not take a login another record owns — in EITHER
    //    direction. `publishers/` is walked in sorted order and a record's file
    //    name must equal its owner, so the two orderings are two different pairs
    //    of names: "aaa.json" cover-first, "contested.json" owner-first. A check
    //    that handled only one of them would pass on half the alphabet.
    fs.rmSync(path.join(tmp, "publishers", "someone.json"));

    write("aaa.json", { owner: "aaa", covers: ["contested"], display_name: "Aaa" });
    write("contested.json", { owner: "contested", display_name: "Contested" });
    const coverFirst = load().errors;
    assert(coverFirst.some((e) => e.file === "publishers/contested.json"),
      `an owner already claimed by a cover was accepted: ${JSON.stringify(coverFirst)}`);

    fs.rmSync(path.join(tmp, "publishers", "aaa.json"));
    write("zzz.json", { owner: "zzz", covers: ["contested"], display_name: "Zzz" });
    const ownerFirst = load().errors;
    assert(ownerFirst.some((e) => e.file === "publishers/zzz.json"),
      `a cover of an already-owned login was accepted: ${JSON.stringify(ownerFirst)}`);

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  // The reserved-prefix rule used to live twice — in `tools/validate.mjs` for a
  // listing already in the tree, and in `bot/lib/derive.mjs` for a submission
  // arriving at ingest. Identical behaviour, two files, and widening the
  // exception is precisely the edit that updates one of them. It is one function
  // now, and this is what says so: both allowlists, both directions, and the
  // malformed case.
  await test("a reserved prefix is refused unless the repo or its owner is first-party", () => {
    const policy = {
      reserved_prefixes: ["astra-", "official-"],
      first_party_repos: ["mihailinl/AstraPlugins"],
      first_party_owners: ["MINICE-AI"],
    };
    const hit = (id, repo) => reservedPrefixViolation(id, repo, policy);

    assert(hit("astra-chess", "somebody/astra-chess")?.prefix === "astra-",
      "an outsider took a reserved prefix");
    assert(hit("astra-chess", "MINICE-AI/astra-chess") === null,
      "a first-party OWNER was refused its own prefix");
    assert(hit("astra-chess", "minice-ai/astra-chess") === null,
      "owner matching must be case-insensitive; GitHub logins are");
    assert(hit("doom", "somebody/doom") === null,
      "an id with no reserved prefix was refused");
    assert(hit("official-thing", "mihailinl/AstraPlugins") === null,
      "a first-party REPO was refused a reserved prefix");
    assert(hit("official-thing", "mihailinl/something-else")?.prefix === "official-",
      "the repo allowlist must match the repo, not its owner — first_party_owners is the wider knob");

    // A listing with no `source.repo` must not buy itself a prefix by being
    // malformed.
    assert(hit("astra-chess", undefined)?.prefix === "astra-", "a missing repo was treated as first-party");
    assert(hit("astra-chess", "")?.prefix === "astra-", "an empty repo was treated as first-party");

    // And the same pair against a policy carrying an EMPTY allowlist entry,
    // which is what makes the two assertions above mean anything. A blank line
    // in JSON is one keystroke, and without the guard in reserved.mjs it turns
    // every malformed listing — no repo, or a repo the caller failed to read —
    // into a first-party one. Written this way because the first version of this
    // test passed with the guard REMOVED: it was asserting behaviour that held
    // for an unrelated reason, which is the same as not asserting it.
    const blank = { ...policy, first_party_repos: [""], first_party_owners: [""] };
    assert(reservedPrefixViolation("astra-chess", "", blank)?.prefix === "astra-",
      "an empty allowlist entry matched an empty repo and granted the prefix");
    assert(reservedPrefixViolation("astra-chess", undefined, blank)?.prefix === "astra-",
      "an empty allowlist entry matched a missing repo and granted the prefix");

    // And the COMMITTED policy really does admit the repository this was widened
    // for, and still refuses everybody else. Asserted against the real file
    // rather than the fixture above, because a fixture cannot notice that
    // somebody edited the policy back.
    const real = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "policy/reserved-ids.json"), "utf8"));
    assert(reservedPrefixViolation("astra-chess", "MINICE-AI/astra-chess", real) === null,
      "policy/reserved-ids.json no longer admits MINICE-AI (named KNICE-TECH until its rename); issue #33 is blocked again");
    // The organisation's OLD login is free for anybody to register once GitHub
    // has renamed it, so it must never be first-party again as an owner. Only
    // the one frozen repository pair survives, and only while every listing
    // under it stays out of the catalogue: that pair plus a listed plugin is
    // exactly the takeover the rename opened.
    assert((real.first_party_owners ?? []).every((o) => o.toLowerCase() !== "knice-tech"),
      "policy/reserved-ids.json trusts the freed login KNICE-TECH as an owner again; anybody who registers it gets every astra- id");
    assert(reservedPrefixViolation("astra-anything", "KNICE-TECH/anything", real)?.prefix === "astra-",
      "a repository under the freed login KNICE-TECH was admitted to a reserved prefix");
    const frozenPairs = (real.first_party_repos ?? []).filter((r) => r.toLowerCase().startsWith("knice-tech/"));
    const pluginsRoot = path.join(REPO_ROOT, "plugins");
    for (const dir of fs.readdirSync(pluginsRoot)) {
      const file = path.join(pluginsRoot, dir, "plugin.json");
      if (!fs.existsSync(file)) continue;
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      const repo = String(doc.source?.repo ?? "").toLowerCase();
      if (frozenPairs.some((r) => r.toLowerCase() === repo)) {
        assert(doc.unlisted === true,
          `plugins/${dir} is listed from ${doc.source.repo}, a repository under the freed login KNICE-TECH that policy/reserved-ids.json keeps only for a frozen listing`);
      }
    }
    assert(reservedPrefixViolation("astra-anything", "someone-else/x", real)?.prefix === "astra-",
      "policy/reserved-ids.json admits everybody; the prefix is no longer reserved");
  });

  // A `verified` badge rests on a document that keeps saying the same thing. The
  // whole-line test is the part that matters: a page MENTIONING a login — a blog
  // post, a directory, somebody else's README — is not that person asserting it,
  // and `includes` would take any of them for proof.
  await test("proof must name the owner on a line of its own", () => {
    assert(proofNamesOwner("knlce\n", "KnlCE"), "an exact line, case-insensitively, is proof");
    assert(proofNamesOwner("# owner\nKnlCE\n", "KnlCE"), "a line among lines is still proof");
    assert(!proofNamesOwner("plugins by KnlCE are great", "KnlCE"), "a mention in prose is not an assertion");
    assert(!proofNamesOwner("KnlCE-fan", "KnlCE"), "a longer word that contains it is not it");
    assert(!proofNamesOwner("", "KnlCE"), "an empty document proves nothing");
  });

  // Four outcomes, each on a tree of its own, because the interesting ones are
  // the three where NOTHING should move. A re-check that quietly renewed a badge
  // whose evidence had gone would be the failure this whole mechanism exists to
  // prevent.
  await test("a re-check renews on proof, and moves nothing without it", async () => {
    const mk = (over = {}) => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "astra-recheck-"));
      fs.mkdirSync(path.join(root, "publishers"));
      fs.writeFileSync(path.join(root, "publishers", "someone.json"), JSON.stringify({
        schema: "astra.registry.publisher/1", owner: "someone", display_name: "Someone",
        tier: "verified", verified_at: "2026-01-01", expires_at: "2099-01-01",
        evidence: { kind: "domain", domain: "example.com", proof: "https://example.com/p" },
        ...over,
      }, null, 2) + "\n");
      return root;
    };
    const read = (root) => JSON.parse(fs.readFileSync(path.join(root, "publishers", "someone.json"), "utf8"));
    const today = new Date().toISOString().slice(0, 10);

    let root = mk();
    let r = await recheck({ root, write: true, fetcher: async () => ({ ok: true, body: "someone\n" }) });
    assert(r.results[0].state === "confirmed", JSON.stringify(r.results));
    assert(read(root).last_confirmed_at === today, "a confirmed proof records the day it held");
    assert(read(root).expires_at > today, "the window moves forward from today");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk();
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: false, why: "HTTP 503" }) });
    assert(r.results[0].state === "unreachable", JSON.stringify(r.results));
    assert(!read(root).last_confirmed_at, "an unreachable document must renew nothing");
    assert(read(root).expires_at === "2099-01-01", "and must not move the window");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk();
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: true, body: "somebody-else\n" }) });
    assert(r.results[0].state === "mismatched", JSON.stringify(r.results));
    assert(!read(root).last_confirmed_at, "a document naming somebody else must renew nothing");
    fs.rmSync(root, { recursive: true, force: true });

    root = mk({ expires_at: "2020-01-01" });
    r = await recheck({ root, write: true, fetcher: async () => ({ ok: false, why: "HTTP 404" }) });
    assert(r.expired.length === 1, "an expired record is withdrawn");
    assert(!fs.existsSync(path.join(root, "publishers", "someone.json")), "the record is gone, so the badge is");
    fs.rmSync(root, { recursive: true, force: true });
  });
}
