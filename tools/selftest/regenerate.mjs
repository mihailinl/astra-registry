// RC-R2-4. `tools/regenerate-signed.mjs`, run as a carrier would run it.
//
// The failure this module is built against is the quiet one. A regenerator that
// produces PLAUSIBLE output — the right shape, the right listings, a serial
// that looks like a serial — passes every eye and proves nothing, because the
// question it exists to answer is byte equality with a document somebody signed.
// So the first tests here are not shape assertions: they regenerate this
// repository's own head catalogue and compare it, byte for byte, with the one
// in the tree at that commit. There are two because the serial's value needs
// the whole history and nothing else does (gap 81).
//
// Everything is run as a SUBPROCESS, through the real command line. The tool's
// no-network legs install throwing globals into the process they run in, and an
// in-process call would leave those installed for every module the runner loads
// after this one — `harness.mjs` alone would then be running under a `fetch`
// that throws, which is a change to the suite nobody asked for and nobody would
// find. Running the command is also the only way to exercise its exit codes,
// and a sidecar reads those before it reads anything else.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import { buildIndex, indexContent } from "../build-index.mjs";
import { isShallow } from "../coverage/git.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, neverAsk, tmp } from "./harness.mjs";

const TOOL = path.join(REPO_ROOT, "tools", "regenerate-signed.mjs");
const FIXTURE = path.join(REPO_ROOT, "tests", "fixtures", "regenerate-signed");

/** The command, as a carrier runs it. Never imported; always spawned. */
function regen(args, { cwd = REPO_ROOT, wrapper = [] } = {}) {
  const argv = [...wrapper, process.execPath, TOOL, ...args];
  const r = spawnSync(argv[0], argv.slice(1), {
    cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

function gitIn(dir) {
  return (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/**
 * A throwaway clone holding the fixture inputs and a copy of this checkout's
 * generator.
 *
 * The generator is COPIED rather than committed into `tests/fixtures/`, and
 * that is the difference between a fixture and a second implementation. A
 * committed copy of `tools/build-index.mjs` would be a generator nobody
 * maintains: it would keep passing this module's tests for months after the
 * real one changed, and the day the two disagreed the fixture would be the one
 * that looked right.
 */
function fixtureClone(name) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const git = gitIn(dir);
  git("init", "-q", "-b", "main");
  git("config", "user.email", "fixture@example.invalid");
  git("config", "user.name", "Fixture");
  git("config", "commit.gpgsign", "false");

  for (const rel of ["tools/build-index.mjs", "tools/lib", "bot/lib"]) {
    const dest = path.join(dir, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.cpSync(path.join(REPO_ROOT, rel), dest, { recursive: true });
  }
  for (const rel of ["plugins", "publishers"]) {
    fs.cpSync(path.join(FIXTURE, rel), path.join(dir, rel), { recursive: true });
  }
  git("add", "-A");
  git("commit", "-qm", "the fixture tree");
  return { dir, git, head: () => git("rev-parse", "HEAD") };
}

/** The document the command printed, parsed. */
function parsed(r) {
  assertEqual(r.status, 0, `the command exited ${r.status}\n${r.stderr}`);
  return JSON.parse(r.stdout);
}

/**
 * Two catalogues, and the first line they disagree on.
 *
 * Not `assertEqual`: the documents here are half a megabyte each, and a
 * failure that prints both of them in full is a failure nobody reads. The
 * line number and the two lines are the whole diagnosis.
 */
function assertSameDocument(got, want, message) {
  if (got === want) return;
  const a = got.split("\n");
  const b = want.split("\n");
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      const cut = (s) => (s === undefined ? "<end of document>" : s.length > 120 ? `${s.slice(0, 120)}…` : s);
      throw new Error(
        `${message}\n  first difference at line ${i + 1} of ${Math.max(a.length, b.length)}:\n` +
        `    regenerated: ${cut(a[i])}\n    committed:   ${cut(b[i])}`,
      );
    }
  }
  throw new Error(`${message}\n  the two differ in length only: ${a.length} lines against ${b.length}`);
}

export async function run() {
  // Its own section header, which is what makes this module's position in the
  // runner's list a free choice. Two boundaries in that list are places where
  // one module's names print under the previous module's header; a module that
  // printed none could only be appended after another that does, and would take
  // those names with it if anybody moved it. This one can go anywhere after a
  // module that prints a header.
  console.log("\nthe commit-pinned regeneration command (RC-R2-4)");

  // ── the real catalogue ────────────────────────────────────────────────────

  // The head catalogue, regenerated once and compared by the two checks below.
  // One run, because the two are one claim — this document regenerates from its
  // own commit, byte for byte — split where a checkout decides what can be
  // asked of it.
  //
  // From the COMMIT, not from `registry/v1/index.json` on disk. This suite runs
  // in workspaces that are not clean checkouts — `ingest.yml`'s publish job
  // holds a stranger's downloaded bundle, and on a developer's machine a
  // neighbouring branch's edits are one `git checkout` away. A comparison whose
  // right-hand side came off the disk would pass on bytes nobody can ever
  // regenerate, which is exactly the failure this whole tool is against.
  let headRun = null;
  const headRegeneration = () => {
    if (headRun) return headRun;
    const git = gitIn(REPO_ROOT);
    const head = git("rev-parse", "HEAD");
    const committed = JSON.parse(git("show", `${head}:registry/v1/index.json`));
    const r = regen(["--generator", head, "--source", head, "--quiet"]);
    assertEqual(r.status, 0, `the regeneration failed:\n${r.stderr}`);
    const want = stableStringify(indexContent(committed));
    assert(want.length > 1000,
      `the committed catalogue's content is ${want.length} bytes; this comparison has nothing in it`);
    assert(committed.signed.plugins.length >= 5,
      `${committed.signed.plugins.length} listing(s) in the committed catalogue — an empty read passes anything`);
    headRun = { committed, r, regenerated: JSON.parse(r.stdout) };
    return headRun;
  };

  // GAP 81. The serial is the one member that needs history rather than
  // content. A shallow checkout counts only the commits it holds: at 97c0b0d
  // `git rev-list --count HEAD -- plugins` answered 1 at depth 1 and 52 with
  // the whole history. Until 2026-09-22 this was one check that zeroed the
  // serial on both sides when the checkout was shallow, printed a note, and
  // then `ok` under the name "byte for byte", so `ingest.yml`'s `selftest` job
  // counted a clause that nothing had compared.
  //
  // Now the clauses are two checks. This one is every byte but the serial's
  // value, asked at any depth. The committed content with the REGENERATED
  // serial put in its place is compared byte for byte with what the command
  // printed, so key order, formatting and every other member still count. The
  // check below it is the serial, and it says NOT ASKED where it cannot be
  // taken. Together they are the old claim, with nothing zeroed away.
  await test("this repository's head catalogue regenerates from its own commit, byte for byte but for the serial's value", () => {
    const { committed, r, regenerated } = headRegeneration();
    // Its VALUE is the check below. That it is there, and is a count, is shape,
    // and substituting a missing one would compare equal by leaving it out.
    assert(Number.isSafeInteger(regenerated.serial) && regenerated.serial >= 0,
      `the regeneration's serial is ${JSON.stringify(regenerated.serial)}, which is not a commit count`);
    assertSameDocument(r.stdout, stableStringify({ ...indexContent(committed), serial: regenerated.serial }),
      "the regeneration of HEAD differs from the catalogue committed at HEAD in something other than the serial. " +
      "This is the tool's whole claim: if it is false, every downstream comparison a carrier makes is a " +
      "comparison with a plausible document");
  });

  // Found by the runner by reading it (a `neverAsk(` first in the block of an
  // `if` whose whole condition is the shallowness question), so keep the gate
  // written that way. No red comes before it: a count taken in a shallow checkout is
  // wrong, so a mismatch there says nothing about the catalogue.
  await test("this repository's head catalogue carries the serial its own commit's history counts, asked of its whole history", () => {
    if (isShallow(REPO_ROOT)) {
      neverAsk(
        "this checkout is shallow, and the serial is `git rev-list --count <commit> -- plugins`, which counts " +
        "only the commits this checkout holds (1 at depth 1, against 52 with the whole history at 97c0b0d), so " +
        "the serial the regeneration writes here is not the history's",
        "a checkout with its whole history asks it: the runner prints the live lanes that reach this suite with " +
        "it under the totals and goes red when there are none (`node tools/selftest.mjs --lanes`)",
      );
    }
    const { committed, regenerated } = headRegeneration();
    // Only the value. Every other byte is the check above, so a member that
    // differs reds that one and not this, and each name says what broke.
    assertEqual(regenerated.serial, committed.signed.serial,
      "the regeneration of HEAD counts a different serial from the one the catalogue committed at HEAD carries, " +
      "so the signed document claims a place in the listings' history that the history does not give it");
  });

  await test("the whole document reaches a pipe, not the part that fitted", () => {
    // A found defect, kept as a test because nothing else in this module would
    // have caught it in isolation and the shape is general.
    //
    // `process.stdout.write` is asynchronous when stdout is a pipe, and the
    // first draft of this command ended with `process.exit(code)`, which does
    // not wait for the flush. Every `--out` check passed — a file write is
    // synchronous — while every piped consumer got a TRUNCATED catalogue:
    // 145,897 bytes of 575,341, cut in the middle of an icon, exit status 0
    // and nothing on stderr. A sidecar reading the command through a pipe
    // would have compared a carried catalogue against a quarter of a document
    // and reported a mismatch that had nothing to do with the catalogue.
    //
    // Watched failing by putting `process.exit()` back.
    const git = gitIn(REPO_ROOT);
    const head = git("rev-parse", "HEAD");
    const file = path.join(tmp, "piped-vs-file.json");
    const toFile = regen(["--generator", head, "--source", head, "--quiet", "--out", file]);
    assertEqual(toFile.status, 0, toFile.stderr);
    const piped = regen(["--generator", head, "--source", head, "--quiet"]);
    assertEqual(piped.status, 0, piped.stderr);

    const onDisk = fs.readFileSync(file, "utf8");
    assert(Buffer.byteLength(onDisk) > 64 * 1024,
      `the document is ${Buffer.byteLength(onDisk)} bytes; below a pipe buffer this test cannot fail`);
    assertEqual(Buffer.byteLength(piped.stdout), Buffer.byteLength(onDisk),
      `the piped document is ${Buffer.byteLength(piped.stdout)} bytes and the written one is ` +
      `${Buffer.byteLength(onDisk)}; stdout was not flushed before the process exited`);
    assert(piped.stdout === onDisk, "the piped document and the written one differ in content, not only in length");
  });

  await test("the command reads the commit and not the working tree", () => {
    // The one failure a shared checkout can produce and no reviewer can see.
    // `tools/build-index.mjs --check` reads the disk — that is its job, it is
    // checking THIS tree — and a regenerator that did the same would answer a
    // carrier's question with whatever happened to be lying around.
    const git = gitIn(REPO_ROOT);
    const head = git("rev-parse", "HEAD");
    const before = regen(["--generator", head, "--source", head, "--quiet"]);
    assertEqual(before.status, 0, before.stderr);

    // Perturb a listing in a THROWAWAY clone of this repository rather than in
    // the checkout itself: a suite that dirties the tree it runs in is a suite
    // that loses somebody's work the first time it is interrupted.
    const dir = path.join(tmp, "worktree-vs-commit");
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("git", ["clone", "-q", "--no-hardlinks", "--shared", REPO_ROOT, dir],
      { stdio: ["ignore", "pipe", "pipe"] });

    // WHICH listing is perturbed decides whether this check can fail at all,
    // and until 2026-09-22 it was `readdirSync(plugins).sort()[0]` — which on
    // this tree is `plugins/astra-chess/`, a listing carrying `"unlisted": true`
    // since 2026-09-12. Nothing about an unlisted listing can appear in a
    // generated catalogue, so the perturbation dirtied the clone (satisfying
    // the guard below) and then changed no byte of the document whether the
    // tool read the commit or the disk.
    //
    // Measured: with assemble() made to copy the live checkout over the
    // archived inputs — exactly the defect this name is about — the suite stayed
    // at `317 passed, 0 failed`, exit 0, and this check printed `ok`.
    //
    // So the subject is chosen from the document rather than from the
    // directory listing, and the choice is ARMED: the committed value of the
    // field about to be perturbed must be found in the unperturbed output
    // first. A field that does not reach the document cannot be a test of
    // whether an edit to it reaches the document.
    const beforeDoc = JSON.parse(before.stdout);
    const listed = new Set(beforeDoc.plugins.map((e) => e.id));
    let chosen = null;
    for (const name of fs.readdirSync(path.join(dir, "plugins")).sort()) {
      const file = path.join(dir, "plugins", name, "plugin.json");
      if (!fs.existsSync(file)) continue;
      const doc = JSON.parse(fs.readFileSync(file, "utf8"));
      if (listed.has(doc.id)) { chosen = { file, doc }; break; }
    }
    assert(chosen !== null,
      `no listing under plugins/ reaches the regenerated catalogue (${listed.size} entry/entries in it), so ` +
      "there is no edit this check could make that the document could carry");
    const entry = beforeDoc.plugins.find((e) => e.id === chosen.doc.id);
    assertEqual(entry.description, chosen.doc.summary,
      `${chosen.doc.id}'s summary is not what the catalogue carries as its description, so perturbing it ` +
      "would be invisible in the output for a reason that has nothing to do with commits");

    const PERTURBED = "PERTURBED — an uncommitted edit that must not reach a regenerated document";
    chosen.doc.summary = PERTURBED;
    fs.writeFileSync(chosen.file, `${JSON.stringify(chosen.doc, null, 2)}\n`);
    assert(gitIn(dir)("status", "--porcelain", "--", "plugins") !== "",
      "the perturbation did not dirty the clone, so the assertion below proves nothing");

    const after = regen(["--generator", head, "--source", head, "--quiet", "--repo", dir], { cwd: dir });
    assertEqual(after.status, 0, after.stderr);
    assert(!after.stdout.includes(PERTURBED),
      `an uncommitted edit to plugins/${path.basename(path.dirname(chosen.file))}/plugin.json is in the ` +
      "regenerated document, so the output is a function of somebody's disk rather than of two commit ids");
    assertSameDocument(after.stdout, before.stdout,
      "an uncommitted edit under plugins/ changed the regenerated document, so the output is a function of " +
      "somebody's disk rather than of two commit ids");
  });

  // ── the pin ───────────────────────────────────────────────────────────────

  await test("the generator comes from --generator and never from the Source-Commit", () => {
    const { dir, git, head } = fixtureClone("pin");
    const c1 = head();

    // (i) inputs move.
    const listing = path.join(dir, "plugins", "fixture-alpha", "plugin.json");
    const doc = JSON.parse(fs.readFileSync(listing, "utf8"));
    doc.summary = "A listing edited at the Source-Commit";
    fs.writeFileSync(listing, `${JSON.stringify(doc, null, 2)}\n`);
    git("add", "-A"); git("commit", "-qm", "a listing changes");
    const c2 = head();

    // (ii) the generator moves, in a way the output cannot hide. This is the
    // edit a listing's author could make if the generator came from their
    // commit: one line, and every card in the catalogue carries a member the
    // reviewers never read.
    const gen = path.join(dir, "tools", "build-index.mjs");
    const src = fs.readFileSync(gen, "utf8");
    const marked = src.replace(
      "    signed: {\n      schema: INDEX_SCHEMA,",
      "    signed: {\n      fixture_marker: \"written by the Source-Commit's generator\",\n      schema: INDEX_SCHEMA,",
    );
    assert(marked !== src, "the fixture could not perturb tools/build-index.mjs; this test would prove nothing");
    fs.writeFileSync(gen, marked);
    git("add", "-A"); git("commit", "-qm", "the generator changes");
    const c3 = head();

    const pinned = parsed(regen(["--generator", c1, "--source", c3, "--quiet", "--repo", dir]));
    const unpinned = parsed(regen(["--generator", c3, "--source", c3, "--quiet", "--repo", dir]));

    // Both halves, because either alone is satisfied by a tool that does
    // nothing at all.
    assertEqual(unpinned.fixture_marker, "written by the Source-Commit's generator",
      "the perturbed generator produced no marker, so the assertion below is about a generator that never changed");
    assertEqual(pinned.fixture_marker, undefined,
      "the Source-Commit's generator rendered the catalogue. At the Source-Commit the generator is a file like " +
      "any other and whoever wrote the listing could have written it (TRUST-4)");

    // And the inputs really are the Source-Commit's, so "pinned" is not just
    // "regenerated the reviewed commit and ignored --source".
    const alpha = pinned.plugins.find((p) => p.id === "fixture-alpha");
    assertEqual(alpha.description, "A listing edited at the Source-Commit",
      "the inputs did not come from --source");

    // The serial counts commits under plugins/, so the generator commit did
    // not move it and the listing commit did.
    assertEqual(parsed(regen(["--generator", c1, "--source", c1, "--quiet", "--repo", dir])).serial, 1, "serial at c1");
    assertEqual(parsed(regen(["--generator", c1, "--source", c2, "--quiet", "--repo", dir])).serial, 2, "serial at c2");
    assertEqual(pinned.serial, 2,
      "a commit that changes only the generator moved the catalogue's serial; the serial is a property of the " +
      "listings' history and of nothing else");
  });

  await test("an annotated tag is peeled to the commit it points at", () => {
    // `init-ci` shipped this defect and it survived every review: `git
    // rev-parse v0.2.0` on an ANNOTATED tag returns the TAG OBJECT's id. Here
    // the id is printed as the Source-Commit a second party must resolve, so a
    // tag object would be a value that resolves to nothing for them.
    const { dir, git, head } = fixtureClone("annotated-tag");
    const commit = head();
    git("tag", "-a", "fixture-v1", "-m", "an annotated tag, whose own object id is not the commit's");
    const tagObject = git("rev-parse", "fixture-v1");
    assert(tagObject !== commit,
      "the tag resolved straight to the commit, so this fixture is not annotated and proves nothing");

    const byTag = regen(["--generator", "fixture-v1", "--source", "fixture-v1", "--repo", dir]);
    assertEqual(byTag.status, 0, byTag.stderr);
    assert(byTag.stderr.includes(commit),
      `the command reported ${tagObject.slice(0, 12)} where the commit ${commit.slice(0, 12)} belonged`);
    assert(!byTag.stderr.includes(tagObject), "the tag object's id was printed as a commit id");

    const bySha = regen(["--generator", commit, "--source", commit, "--quiet", "--repo", dir]);
    assertSameDocument(byTag.stdout, bySha.stdout, "the tag and the commit it names regenerated different documents");
  });

  // ── the serial a candidate claims ─────────────────────────────────────────

  await test("a candidate's serial is ignored; the serial is counted from --source", () => {
    const { dir, head } = fixtureClone("candidate");
    const commit = head();
    const document = path.join(tmp, "candidate-good.json");
    const agreeing = regen(["--generator", commit, "--source", commit, "--repo", dir, "--out", document]);
    assertEqual(agreeing.status, 0, agreeing.stderr);

    // The carrier's document, whole: a signed envelope with a publication
    // stamp and a signature on it, because that is what a carrier holds and
    // the comparison has to reach through both.
    const content = JSON.parse(fs.readFileSync(document, "utf8"));
    const envelope = {
      $comment: "a carried catalogue",
      signatures: [{ key_id: "TEST-ONLY-DO-NOT-TRUST-index-2026a", sig: "not checked here" }],
      signed: { ...content, issued_at: "2026-09-21T00:00:00Z", expires_at: "2026-10-21T00:00:00Z" },
    };
    const carried = path.join(tmp, "candidate-envelope.json");
    fs.writeFileSync(carried, `${JSON.stringify(envelope, null, 2)}\n`);
    const ok = regen(["--generator", commit, "--source", commit, "--repo", dir, "--candidate", carried, "--out", "/dev/null"]);
    assertEqual(ok.status, 0,
      `a signed envelope of exactly this content did not compare equal; the stamp or the signature is reaching ` +
      `the comparison\n${ok.stderr}`);

    // Off by one, in the direction a rollback would go and in the direction a
    // forged bump would go. Neither may change what is regenerated.
    for (const delta of [1, -1]) {
      const bent = JSON.parse(JSON.stringify(envelope));
      bent.signed.serial += delta;
      const file = path.join(tmp, `candidate-${delta > 0 ? "plus" : "minus"}.json`);
      fs.writeFileSync(file, `${JSON.stringify(bent, null, 2)}\n`);
      const r = regen(["--generator", commit, "--source", commit, "--repo", dir, "--candidate", file, "--quiet"]);
      assertEqual(r.status, 1,
        `a candidate claiming serial ${bent.signed.serial} over inputs whose history says ${content.serial} ` +
        "was accepted");
      assertEqual(JSON.parse(r.stdout).serial, content.serial,
        "the candidate's serial reached the regenerated document. The serial is a property of the history; a " +
        "document that could assert its own would be a monotonic counter anybody can set");
    }
  });

  // ── the no-network proof ──────────────────────────────────────────────────

  await test("every fixture listing carries an icon and a README, and the regeneration inlines both", () => {
    // The floor under the three tests below. They are about what the
    // presentation path cannot do; if the fixture tree had no pictures and no
    // prose, that path would never be entered and all three would pass by
    // finding nothing — the exact shape of proof this estate has been bitten
    // by twice.
    const ids = fs.readdirSync(path.join(FIXTURE, "plugins")).sort();
    assert(ids.length >= 3, `the fixture tree has ${ids.length} listing(s); it is meant to have three`);
    const without = [];
    for (const id of ids) {
      const d = path.join(FIXTURE, "plugins", id);
      const doc = JSON.parse(fs.readFileSync(path.join(d, "plugin.json"), "utf8"));
      if (!doc.icon || !fs.existsSync(path.join(d, doc.icon))) without.push(`${id}: no icon on disk`);
      if (!doc.readme || !fs.existsSync(path.join(d, doc.readme))) without.push(`${id}: no README on disk`);
    }
    assertEqual(without.join(", "), "", "a fixture listing has no picture or no prose to read");

    const { dir, head } = fixtureClone("presentation");
    const doc = parsed(regen(["--generator", head(), "--source", head(), "--quiet", "--repo", dir]));
    assertEqual(doc.plugins.length, ids.length, "the regeneration dropped a listing");
    const media = new Set();
    for (const p of doc.plugins) {
      assert(p.icon_url.startsWith("data:image/"),
        `${p.id}'s icon_url is ${JSON.stringify(p.icon_url.slice(0, 40))}, so no bytes were read off disk`);
      media.add(p.icon_url.slice("data:".length, p.icon_url.indexOf(";")));
      assert(typeof p.readme === "string" && p.readme.length > 100,
        `${p.id} carries no inlined README, so the file read was never made`);
    }
    // Three media types, one of them text and two of them binary, so the
    // base64 of real bytes is exercised and not only the base64 of a string.
    assertEqual([...media].sort().join(", "), "image/png, image/svg+xml, image/webp",
      "the fixture tree stopped covering all three icon encodings");
  });

  await test("the archived tree renders what the generator renders from the tree itself", () => {
    // The assembly path, cross-checked against the one this repository already
    // trusts. `git archive | tar -x` is four moving parts between a commit and
    // a file — filter drivers, `core.autocrlf`, a mode bit, a filename with a
    // character the filesystem normalises — and any one of them changes bytes
    // that are about to be inlined into a signed document. A regenerator that
    // mangled an icon would produce a document that is the right shape and the
    // wrong bytes, which is the failure that has no symptom.
    //
    // So the same fixture is rendered twice by two different routes: once by
    // the command, through `git archive`, a temp tree and a subprocess, and
    // once by calling `buildIndex` on the fixture directory in this process.
    // The inputs are the same bytes; if the documents differ, the difference
    // was made by the assembly.
    const { dir, head } = fixtureClone("archive-vs-tree");
    const viaArchive = regen(["--generator", head(), "--source", head(), "--quiet", "--repo", dir]);
    assertEqual(viaArchive.status, 0, viaArchive.stderr);

    const viaTree = stableStringify(indexContent(buildIndex({ root: FIXTURE, serial: 1 })));
    assertSameDocument(viaArchive.stdout, viaTree,
      "the catalogue built from the archived tree is not the catalogue built from the fixture directory, so " +
      "`git archive` or `tar` changed bytes on the way through");
  });

  await test("a network import anywhere in the generator's closure is refused", () => {
    const { dir, git, head } = fixtureClone("net-import");
    const base = head();
    const gen = path.join(dir, "tools", "build-index.mjs");
    const src = fs.readFileSync(gen, "utf8");
    fs.writeFileSync(gen, `import https from "node:https";\n${src}`);
    git("add", "-A"); git("commit", "-qm", "a network client in the generator");
    const withHttps = head();

    const r = regen(["--generator", withHttps, "--source", base, "--quiet", "--repo", dir]);
    assertEqual(r.status, 2, `the regeneration ran with a network client in its closure:\n${r.stderr}`);
    assert(r.stderr.includes("tools/build-index.mjs:1") && r.stderr.includes("node:https"),
      `the refusal does not name the file, the line and the import:\n${r.stderr}`);

    // And the same tree without that line regenerates, which is what makes the
    // refusal about the import rather than about the fixture.
    const clean = regen(["--generator", base, "--source", base, "--quiet", "--repo", dir]);
    assertEqual(clean.status, 0, `the unperturbed fixture does not regenerate either:\n${clean.stderr}`);
  });

  await test("a fetch on a reached code path is refused at run time", () => {
    // The import scan cannot see this one: `fetch` is a global, so a call needs
    // no import at all. Leg (b) is the one that catches it, and it catches it
    // whether or not a network namespace is available — which matters, because
    // the namespace leg below cannot run everywhere.
    const { dir, git, head } = fixtureClone("net-fetch");
    const base = head();
    const gen = path.join(dir, "tools", "build-index.mjs");
    const src = fs.readFileSync(gen, "utf8");
    const marked = src.replace(
      "export function buildIndex({ root = REPO_ROOT, serial } = {}) {",
      "export function buildIndex({ root = REPO_ROOT, serial } = {}) {\n" +
      "  fetch(\"https://example.invalid/counts\");",
    );
    assert(marked !== src, "the fixture could not add a fetch to buildIndex; this test would prove nothing");
    fs.writeFileSync(gen, marked);
    git("add", "-A"); git("commit", "-qm", "a fetch on the generator's own path");
    const withFetch = head();

    const r = regen(["--generator", withFetch, "--source", base, "--quiet", "--repo", dir]);
    assertEqual(r.status, 2, `a generator that calls fetch() produced a document:\n${r.stderr}`);
    assert(r.stderr.includes("NETWORK REFUSED"),
      `the run failed for some other reason, so the refusal is not the thing being watched:\n${r.stderr}`);
  });

  await test("a dynamic import whose specifier is not a literal is refused", () => {
    // The escape hatch under both legs above: `import(whatever)` makes the
    // closure unknowable, so every sentence this command says about the
    // closure stops being true. Refused rather than followed.
    const { dir, git, head } = fixtureClone("net-dynamic");
    const base = head();
    const gen = path.join(dir, "tools", "build-index.mjs");
    const src = fs.readFileSync(gen, "utf8");
    fs.writeFileSync(gen, src.replace(
      "export function buildIndex({ root = REPO_ROOT, serial } = {}) {",
      "export function buildIndex({ root = REPO_ROOT, serial } = {}) {\n" +
      "  if (process.env.PICK) import(process.env.PICK);",
    ));
    git("add", "-A"); git("commit", "-qm", "a computed import in the generator");
    const r = regen(["--generator", head(), "--source", base, "--quiet", "--repo", dir]);
    assertEqual(r.status, 2, `a generator whose closure cannot be computed produced a document:\n${r.stderr}`);
    assert(r.stderr.includes("not a literal"), `the refusal names something else:\n${r.stderr}`);
  });

  await test("the regeneration is byte-identical with the network switched off", () => {
    // Leg (c). It needs no list of names, which is why it is worth having even
    // though it cannot run everywhere: `unshare -rn` wants unprivileged user
    // namespaces and `sudo -n unshare -n` wants a passwordless sudo, and a
    // hardened host has neither.
    const { dir, head } = fixtureClone("no-network");
    const commit = head();
    const open = regen(["--generator", commit, "--source", commit, "--quiet", "--repo", dir]);
    assertEqual(open.status, 0, open.stderr);

    const wrappers = [["unshare", "-rn"], ["sudo", "-n", "unshare", "-n"]];
    const usable = wrappers.find((w) => {
      const probe = spawnSync(w[0], [...w.slice(1), "true"], { encoding: "utf8" });
      return !probe.error && probe.status === 0;
    });
    if (!usable) {
      // A note rather than a silent pass: the two legs above ran, this one did
      // not, and a reader is entitled to know which proof they are holding.
      console.log(
        "      (no usable network namespace here — tried `unshare -rn` and `sudo -n unshare -n`. Legs (a) and " +
        "(b), the closure scan and the throwing globals, ran in every test above.)",
      );
      return;
    }
    const sealed = regen(["--generator", commit, "--source", commit, "--quiet", "--repo", dir], { wrapper: usable });
    assertEqual(sealed.status, 0, `the command failed with the network switched off:\n${sealed.stderr}`);
    assertSameDocument(sealed.stdout, open.stdout,
      `the document regenerated under \`${usable.join(" ")}\` differs from the one regenerated with a network`);
  });
}
