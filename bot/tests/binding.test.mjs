// The binding line, against thirty-one files a stranger could commit.
//
// Registry plan B-T2.4. Two halves, and they fail for different reasons:
//
//   * the CORPUS half runs `bot/lib/binding.mjs` over `tests/binding-line/`,
//     which is a shared fact — AstraPlugins mirrors it byte for byte (AP-6,
//     rule C31) and the plugins service pins it. A failure here is either this
//     parser drifting from ID-23/ID-24 or the corpus having been hand-edited,
//     and the two say so in different words;
//
//   * the READ half drives ID-22 through the real `bot/lib/github.mjs` with a
//     stubbed `fetch`, so what is asserted is the URLs that actually go out —
//     by repository id, never by name — and the order of the two reads, which
//     is the whole difference between "no binding line" and "we could not
//     look".
//
// ── the floors, and why they are first ─────────────────────────────────────
//
// Everything below iterates something. A corpus that failed to load, a walk
// that lost its directory and a glob that matched nothing all report PASS, for
// ever, while reading as coverage. So the counts are asserted before a single
// case is parsed, and each floor's own message says which of the two things
// broke — the rule, or the scan.
//
// The one that enumerates the tree (`tests/vectors/` holds no directory) is
// measured against `git ls-files` and not against a working directory, because
// a working directory answers about whatever happens to be on this disk.

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  BINDING_CODES,
  CLI_WRITE_SOURCE,
  ID_23_SOURCE,
  ID_24_PREFIX_SOURCE,
  OUTCOMES,
  OWNER_FILE,
  WINDOW_BYTES,
  parseBindingFile,
  readBindingLine,
  wouldCliWrite,
} from "../lib/binding.mjs";
import * as gh from "../lib/github.mjs";
import { policyCodeDef } from "../lib/policy/constants.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const CORPUS = path.join(REPO_ROOT, "tests", "binding-line");

const API = "https://api.github.com";
const COMMIT = "b".repeat(40);
const REPO_ID = "1203676452";

// ───────────────────────────────────────────────────────────────────────────
// The corpus, before anything reads a case out of it
// ───────────────────────────────────────────────────────────────────────────

test("the committed corpus is what its generator produces", () => {
  // Watched failing by flipping one vector's recorded outcome in vectors.json.
  // Without this the corpus is a file anybody can edit to make a red suite
  // green, and the edit travels to two other repositories.
  const out = execFileSync("node", [path.join(CORPUS, "generate.mjs"), "--check"], {
    cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
  assert.match(out, /^ok\s/, out);
});

test("SHA256SUMS covers vectors.json, and matches it", () => {
  const sums = fs.readFileSync(path.join(CORPUS, "SHA256SUMS"), "utf8");
  const rows = sums.split("\n").filter(Boolean).map((l) => l.split(/\s+/));
  assert.equal(rows.length, 1, `SHA256SUMS has ${rows.length} rows; it covers vectors.json and nothing else`);
  assert.equal(rows[0][1], "vectors.json");
  const got = crypto.createHash("sha256").update(fs.readFileSync(path.join(CORPUS, "vectors.json"))).digest("hex");
  assert.equal(got, rows[0][0],
    "tests/binding-line/vectors.json does not hash to its SHA256SUMS. These bytes are mirrored into " +
    "AstraPlugins as testdata/binding-line/vectors.json and pinned for the plugins service, so a hand edit " +
    "here is a hand edit to two other repositories' fixtures. Re-run tests/binding-line/generate.mjs.");
});

/** The corpus, loaded loudly. A missing file is never a skip. */
function loadCorpus() {
  const p = path.join(CORPUS, "vectors.json");
  if (!fs.existsSync(p)) {
    throw new Error(
      `${p} is missing. It is registry-canonical (B-T2.4) and is regenerated with ` +
      "`node tests/binding-line/generate.mjs`. A suite that skipped when its fixtures were absent would " +
      "pass for ever.",
    );
  }
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  assert.equal(doc.schema, "astra.testdata.binding-line/1", `unexpected corpus schema ${JSON.stringify(doc.schema)}`);
  return doc;
}

test("the corpus's floors, asserted before a single case is parsed", () => {
  const doc = loadCorpus();
  const cases = doc.cases ?? [];

  assert.ok(cases.length >= 31,
    `${cases.length} cases, floor 31. A reader that iterates what it finds would have reported PASS over ` +
    "the remainder — this is a corpus that lost cases, not a smaller rule");

  const vectors = new Set(cases.map((c) => c.vector));
  assert.equal(vectors.size, 25,
    `${vectors.size} of B-T2.4's 25 vector numbers are present. The numbering is read by AP-6 and AP-8 as ` +
    "well as by this file");
  for (let n = 1; n <= 25; n++) assert.ok(vectors.has(n), `vector ${n} has no case`);

  // 31 cases and one outcome would be a corpus that has never watched a
  // refusal. Spread, not only size.
  for (const outcome of OUTCOMES) {
    const n = cases.filter((c) => c.outcome === outcome).length;
    assert.ok(n >= 1, `no case answers ${outcome}; the corpus covers ${OUTCOMES.length - 1} of 3 outcomes`);
  }
  assert.equal(
    cases.filter((c) => !OUTCOMES.includes(c.outcome)).map((c) => c.case).join(", "), "",
    "a case answers an outcome this parser has no name for. The vocabulary is closed on purpose: an open " +
    "one lets each of the three readers invent an answer the others have never heard of, and a reader " +
    "meeting an unknown answer skips the case — green, on both sides, meaning nothing",
  );
  assert.equal(cases.filter((c) => c.outcome === "B_UNBOUND").length, 0,
    "`B_UNBOUND` is not an outcome of reading a file. Whether a listing NEEDED a line is ID-25's, decided " +
    "by bot/lib/listing-state.mjs from the deadline and log/cutover.json");

  // Both sides of byte 4096 — the edge the whole window rule exists for.
  const inside = cases.filter((c) => c.bytes >= WINDOW_BYTES && c.outcome === "one");
  const outside = cases.filter((c) => c.bytes > WINDOW_BYTES && c.outcome === "none");
  assert.ok(inside.length >= 1, "no case has a line that is ≥ 4096 bytes into the file and still counts");
  assert.ok(outside.length >= 1, "no case has a line the window excludes; the window rule is untested");

  const bytesOf = (c) => Buffer.from(c.file_b64, "base64");
  assert.ok(
    cases.some((c) => { const b = bytesOf(c); return b.toString("utf8").includes("�"); }),
    "no case is invalid UTF-8. A reader that decoded before it counted would pass every remaining case",
  );
  assert.ok(cases.some((c) => bytesOf(c).subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))),
    "no case carries a BOM");

  assert.equal(doc.window_bytes, WINDOW_BYTES, "the corpus and bot/lib/binding.mjs disagree about the window");
  assert.equal(doc.window_unit, "bytes",
    "the corpus does not state its unit. `4096` with no unit is bytes here, UTF-16 units in " +
    "bot/lib/ownership.mjs:283 and code points in a third reader, and vector 15 is the file that tells " +
    "them apart");
});

test("the grammars in the corpus are the grammars the parser compiles", () => {
  // Three copies of ID-23's regex exist by design — the contract is in another
  // repository and CI has no checkout of it — so the strongest available form
  // of "this is still §2.3" is copies that are compared. Watched failing by
  // changing `{16,128}` to `{16,129}` in bot/lib/binding.mjs.
  const doc = loadCorpus();
  assert.equal(doc.grammar.id_23, ID_23_SOURCE);
  assert.equal(doc.grammar.id_24_prefix, ID_24_PREFIX_SOURCE);
  assert.equal(doc.grammar.cli_write, CLI_WRITE_SOURCE);
  assert.notEqual(ID_23_SOURCE, ID_24_PREFIX_SOURCE,
    "ID-23 and ID-24's prefix have collapsed into one pattern. ID-24 is deliberately WIDER — any case, and " +
    "`[ \\t]*` before the colon — and that width is what makes a typo a refusal instead of an absence");
});

test("every case parses to the outcome the corpus records", () => {
  const doc = loadCorpus();
  const problems = [];
  for (const c of doc.cases) {
    const file = Buffer.from(c.file_b64, "base64");
    assert.equal(file.length, c.bytes, `${c.case}: base64 decoded to ${file.length} bytes and says ${c.bytes}`);
    const got = parseBindingFile(file);
    if (got.outcome !== c.outcome) {
      problems.push(`${c.case} (${c.title}): the corpus says ${c.outcome} and this parser says ${got.outcome} — ${got.reason}`);
      continue;
    }
    if ((got.token ?? null) !== (c.token ?? null)) {
      problems.push(`${c.case}: the corpus says token ${JSON.stringify(c.token)} and this parser read ${JSON.stringify(got.token)}`);
    }
    if (c.outcome === "malformed" && got.code !== BINDING_CODES.B_BINDING_MALFORMED) {
      problems.push(`${c.case}: malformed without B_BINDING_MALFORMED (${got.code})`);
    }
    if (c.outcome !== "malformed" && got.code !== null) {
      problems.push(`${c.case}: ${c.outcome} carrying code ${got.code}`);
    }
  }
  assert.equal(problems.join("\n"), "",
    "bot/lib/binding.mjs and tests/binding-line/vectors.json disagree. The corpus is the shared fact — " +
    "AstraPlugins mirrors it and the plugins service pins it — so the parser is what moved unless the " +
    "corpus was hand-edited, which the generator check above would have caught first");
});

test("a refusal never quotes the line a stranger wrote", () => {
  // The token is public (DEC-2) and is quoted only after it matched
  // [A-Za-z0-9_-]{16,128}. Nothing else from the file may reach a reason,
  // because a reason ends up in a public comment.
  const hostile = Buffer.from("astra-binding: <img src=x onerror=alert(1)> \u0007\n", "utf8");
  const got = parseBindingFile(hostile);
  assert.equal(got.outcome, "malformed");
  assert.ok(!got.reason.includes("onerror"), got.reason);
  assert.ok(got.reason.includes(OWNER_FILE) && got.reason.includes("ID-24"), got.reason);

  // And nothing smuggled through a second way: a refusal is printable text,
  // so a control character, a bidirectional override or a zero-width joiner
  // out of a stranger's file cannot reach a public comment by riding one.
  const control = Buffer.concat([
    Buffer.from("astra-binding: "),
    Buffer.from([0x00, 0x1b]),
    Buffer.from("\u202e\u200b", "utf8"),
    Buffer.from("\n"),
  ]);
  const second = parseBindingFile(control);
  assert.equal(second.outcome, "malformed");
  // eslint-disable-next-line no-control-regex
  assert.equal(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e]/.test(second.reason), false,
    "a control or bidirectional character out of a stranger's file reached the refusal text");
});

test("the CLI's write column is computed, and present only where FLOW-50 differs", () => {
  // Watched failing by widening CLI_WRITE_SOURCE to {16,128}, which makes the
  // two `refuse` rows unexplainable, and by adding `cli_write` to a row where
  // both sides agree.
  const doc = loadCorpus();
  const refused = [];
  for (const c of doc.cases) {
    if (c.outcome !== "one") {
      assert.ok(!("cli_write" in c),
        `${c.case} is ${c.outcome} and carries a cli_write. The column records a DISAGREEMENT between a ` +
        "reader that accepts and a writer that refuses; there is nothing to disagree about here");
      continue;
    }
    const writes = wouldCliWrite(c.token);
    if (writes) {
      assert.ok(!("cli_write" in c),
        `${c.case}: both sides accept this token and the corpus records a cli_write anyway`);
    } else {
      assert.equal(c.cli_write, "refuse",
        `${c.case}: the bot recognises a ${c.token.length}-character token that FLOW-50's {22,128} refuses ` +
        "to write, and the corpus does not say so. AP-8's CLI asserts its writer against this column");
      refused.push(c.case);
    }
  }
  assert.ok(refused.length >= 2,
    `${refused.length} case(s) where ID-23 and FLOW-50 differ, floor 2 (a 16- and a 21-character token). ` +
    "With none, the column is a column nothing disagrees with");
});

// ───────────────────────────────────────────────────────────────────────────
// Where the corpus lives, and where it must not
// ───────────────────────────────────────────────────────────────────────────

test("tests/vectors/ holds no directory, so the vendor sweep cannot reach this corpus", () => {
  // `AstraPlugins/tools/vendor-testdata.sh` refreshes tests/vectors/ and rm -f's
  // everything in it that is not in the bundle corpus's own list. The day
  // somebody tidies tests/binding-line/ into it, this goes red instead of the
  // corpus going missing.
  //
  // Measured against `git ls-files`: a readdir answers about this disk, and an
  // untracked file is a file CI never sees.
  const listed = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "tests/vectors/"], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }).split("\0").filter(Boolean);
  assert.ok(listed.length >= 27,
    `git ls-files found ${listed.length} files under tests/vectors/ and there were 30 on 2026-09-20; this ` +
    "is a broken walk rather than a smaller corpus, and a loop over nothing finds no subdirectory");
  const nested = listed.filter((rel) => rel.slice("tests/vectors/".length).includes("/"));
  assert.equal(nested.join(", "), "",
    "tests/vectors/ has a subdirectory. AstraPlugins' tools/vendor-testdata.sh sweeps that directory with " +
    "rm -f, so anything in it that the bundle corpus does not list is deleted by the next vendor run — " +
    "tests/binding-line/ is outside it for exactly this reason (B-T2.4)");

  const corpus = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z", "tests/binding-line/"], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }).split("\0").filter(Boolean).sort();
  assert.deepEqual(corpus, ["tests/binding-line/README.md", "tests/binding-line/SHA256SUMS",
    "tests/binding-line/generate.mjs", "tests/binding-line/vectors.json"].sort(),
    "tests/binding-line/ is not the four tracked files B-T2.4 commits. An untracked corpus is a corpus CI " +
    "never sees, and every assertion above would be asking its questions about a file that is not there. " +
    "Adding a fifth file to a directory two other repositories mirror is a decision, so this list is a " +
    "list somebody edits on purpose rather than an absence nobody notices");
});

test("every code this module can emit is declared in the policy vocabulary", () => {
  // An undeclared code does not throw: policyCodeDef falls through to level
  // `error` with the title "undeclared policy code …". So a rename on one side
  // is silent, and what it silently does is turn a WAIT into a recorded
  // refusal — the one conversion FLOW-72 exists to forbid.
  const names = Object.values(BINDING_CODES);
  assert.ok(names.length >= 2, `${names.length} codes; this check would prove little`);
  const levels = { B_BINDING_MALFORMED: "error", W_GITHUB_RATE_LIMITED: "wait" };
  for (const code of names) {
    const def = policyCodeDef(code, { path: "service" });
    assert.ok(!def.title.startsWith("undeclared"),
      `${code} is not declared in bot/lib/policy/constants.mjs, so bot/lib/policy/decision.mjs would treat ` +
      "it as an ordinary error and record it");
    assert.equal(def.level, levels[code], `${code} is declared ${def.level} and this module means ${levels[code]}`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// ID-22: the read, by id, at the attested commit
// ───────────────────────────────────────────────────────────────────────────

/**
 * A `fetch` that answers a fixed route table and REFUSES every by-name URL.
 *
 * The refusal is the assertion: ID-22 forbids a name lookup, and a stub that
 * merely did not route one would let a name read fall through to a generic
 * "not told about this URL" that reads like any other stub miss.
 */
function stubFetch(routes, { allowNames = false } = {}) {
  const seen = [];
  const impl = async (url) => {
    const u = String(url);
    seen.push(u);
    if (!allowNames && u.startsWith(`${API}/repos/`)) {
      throw new Error(
        `this read went to a NAME: ${u}. ID-22 reads by repository id — a name is a string its owner can ` +
        "give away, and the freed login is registrable by anybody",
      );
    }
    const route = routes[u];
    if (!route) throw new Error(`the stub was not told about ${u}`);
    const headers = new Map(Object.entries(route.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    return {
      status: route.status,
      ok: route.status >= 200 && route.status < 300,
      headers: { get: (k) => headers.get(k.toLowerCase()) ?? null },
      async text() { return route.body ?? ""; },
    };
  };
  impl.seen = seen;
  return impl;
}

const commitUrl = (id = REPO_ID) => `${API}/repositories/${id}/commits/${COMMIT}`;
const fileUrl = (id = REPO_ID) =>
  `${API}/repositories/${id}/contents/${OWNER_FILE.split("/").map(encodeURIComponent).join("/")}?ref=${COMMIT}`;

/** The real github.mjs reads, so what is asserted is the URL that goes out. */
function depsFrom(fetchImpl) {
  return {
    commitInRepository: (id, sha) => gh.commitInRepository(id, sha, { fetchImpl }),
    fileAtCommit: (id, sha, file) => gh.fileAtCommit(id, sha, file, { fetchImpl }),
  };
}

test("a renamed repository, whose old name 404s, still yields the line by id", async () => {
  const line = `astra-binding: ${"a".repeat(32)}\n`;
  // The fixture is a repository whose login was given up: the name the lease,
  // the listing and the certificate's `.12` all carry is gone, and the id is
  // the only handle left that still points at the right thing. So the name is
  // measured first — it 404s — and the same stub then answers the by-id read.
  const named = stubFetch({ [`${API}/repos/someone/old-name`]: { status: 404 } }, { allowNames: true });
  const gone = await gh.fetchRepositoryIds("someone/old-name", { fetchImpl: named });
  assert.equal(gone.status, "not_found", "the fixture's premise: the old name is not a repository");

  const impl = stubFetch({
    [commitUrl()]: { status: 200, body: JSON.stringify({ sha: COMMIT }) },
    [fileUrl()]: { status: 200, body: line },
  });
  const got = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(impl) });
  assert.equal(got.outcome, "one");
  assert.equal(got.token, "a".repeat(32));
  // The stub throws on any `/repos/<owner>/<name>` URL, so reaching here is
  // the assertion. This is stated twice on purpose: a lease, a listing and a
  // certificate all carry the name, and it is the convenient thing to hand to
  // a read.
  assert.equal(impl.seen.filter((u) => u.includes("/repos/")).length, 0, impl.seen.join("\n"));
  assert.equal(impl.seen.length, 2, `${impl.seen.length} reads; ID-22 is two — the commit, then the file`);
});

test("a commit missing from its repository is a wait with an alert, and no record", async () => {
  // The mutation this exists for: delete step 1 and let step 2's 404 answer.
  // `GET /repositories/{id}/contents/...?ref={sha}` answers 404 for a missing
  // FILE and for a missing COMMIT alike, so without step 1 an attestation
  // naming a commit that is not in the repository is recorded as "this author
  // committed no binding line" — a fact about a person written out of a fact
  // about a certificate, and one that cannot be un-written.
  const impl = stubFetch({
    [commitUrl()]: { status: 404 },
    [fileUrl()]: { status: 404 },
  });
  const got = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(impl) });
  assert.equal(got.outcome, "wait");
  assert.equal(got.code, BINDING_CODES.W_GITHUB_RATE_LIMITED);
  assert.equal(got.alert, true, "a commit missing from its own repository pages an operator");
  assert.equal(got.token, null);
  assert.equal(impl.seen.length, 1, "the file was read anyway; step 1 must stop the run");
});

test("a rate-limited read of either step is a wait, and never an absence", async () => {
  const limited = { status: 403, headers: { "x-ratelimit-remaining": "0" } };

  const atCommit = stubFetch({ [commitUrl()]: limited });
  const one = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(atCommit) });
  assert.equal(one.outcome, "wait");
  assert.equal(one.alert, false, "a rate limit is not an operator page; it is a run that asks again");
  assert.match(one.reason, /not an absence of a binding line/);

  const atFile = stubFetch({
    [commitUrl()]: { status: 200, body: JSON.stringify({ sha: COMMIT }) },
    [fileUrl()]: limited,
  });
  const two = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(atFile) });
  assert.equal(two.outcome, "wait");
  assert.equal(two.code, BINDING_CODES.W_GITHUB_RATE_LIMITED);
  assert.equal(two.token, null);
});

test("no owner file at a commit that exists is `none`, and says which 404 it was", async () => {
  const impl = stubFetch({
    [commitUrl()]: { status: 200, body: JSON.stringify({ sha: COMMIT }) },
    [fileUrl()]: { status: 404 },
  });
  const got = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(impl) });
  assert.equal(got.outcome, "none");
  assert.equal(got.code, null, "a release with no binding line is not a refusal here. ID-25 decides that");
  assert.match(got.reason, /[Tt]he commit itself was found first/);
});

test("a malformed file at the attested commit refuses, and the read still cost two calls", async () => {
  const impl = stubFetch({
    [commitUrl()]: { status: 200, body: JSON.stringify({ sha: COMMIT }) },
    [fileUrl()]: { status: 200, body: `Astra-Binding: ${"a".repeat(32)}\n` },
  });
  const got = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps: depsFrom(impl) });
  assert.equal(got.outcome, "malformed");
  assert.equal(got.code, BINDING_CODES.B_BINDING_MALFORMED);
  assert.equal(got.token, null);
});

test("bytes are preferred to a decoded string when the transport offers them", async () => {
  // bot/lib/github.mjs's fileAtCommit returns res.text() today, so an owner
  // file that is not valid UTF-8 arrives with its bad bytes already replaced
  // by U+FFFD — three bytes where one stood, every later byte three places
  // right. This module reads `contentBytes` first so that the day that read
  // returns bytes it is already using them, and this case is what would go red
  // if the preference were dropped.
  const token = "a".repeat(32);
  const raw = Buffer.concat([Buffer.from("# "), Buffer.from([0x80, 0xfe, 0xff]),
    Buffer.from(`\nastra-binding: ${token}\n`)]);
  const deps = {
    commitInRepository: async () => ({ status: "found", reason: "HTTP 200", sha: COMMIT }),
    fileAtCommit: async () => ({ status: "found", reason: "HTTP 200", content: raw.toString("utf8"), contentBytes: raw }),
  };
  const got = await readBindingLine({ repositoryId: REPO_ID, commit: COMMIT, deps });
  assert.equal(got.outcome, "one");
  assert.equal(got.token, token);
  assert.equal(got.windowBytes, raw.length,
    "the parser measured the decoded string rather than the bytes the transport handed it");
});

test("the parser answers on bytes, a Buffer and a string alike", () => {
  const token = "a".repeat(32);
  const text = `astra-binding: ${token}\n`;
  for (const input of [text, Buffer.from(text), new TextEncoder().encode(text)]) {
    const got = parseBindingFile(input);
    assert.equal(got.outcome, "one", `${typeof input}`);
    assert.equal(got.token, token);
  }
  assert.equal(parseBindingFile(null).outcome, "none");
  assert.equal(parseBindingFile(undefined).outcome, "none");
});
