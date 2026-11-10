// tools/trust31-pr-check.mjs: does a pull request change the tree the owner
// acknowledged for the bot (contract TRUST-31)?
//
// On 2026-11-09 pull request #498, one line in `policy/spdx-allowlist.json`,
// was merged with a note "no acknowledgement needed", written from memory. The
// file is in the set, and three releases sat unpublished for a day. The check
// under test answers that question on every pull request, so what is held here
// is that its answer is the SERVICE's: the two digests by the service's
// recipe, reproduced against values the owner read off the site, and each way
// a pull request can move them.
//
// Three kinds of test. The owner's vector, from a fixture of `git ls-tree`
// lines and of the set as `main` had it, because CI's clone of this
// repository is one commit deep and the vector's commit is not in it (the
// workflow `trust31-set.yml` asserts the same two values live, where it has
// the history). Real git repositories, because "what `main` would carry" is a
// statement about a merge. And the read of a pre-acknowledgement against a
// fake `fetch`, one case per answer the service could give.
//
// This suite is OUTSIDE TRUST-31's set, like every suite here but
// `workflows.test.mjs`, and so are the tool and its workflow: a change to this
// check is not a change the owner acknowledges.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { fixtureEnv } from "../../tools/lib/git-env.mjs";
import {
  CANNOT_SAY, CHANGED, CannotRead, NOT_TOUCHED, NO_READ_YET, PRE_ACKNOWLEDGED, TOKEN_MEMBER,
  compare, covers, lineText, main, parseEntries, proposedRead, readEndpoint, report, setDigest, shown,
  sortEntries, stateOf, treeLines, parseLsTree,
} from "../../tools/trust31-pr-check.mjs";

const HERE = import.meta.dirname;
const FIXTURES = path.join(HERE, "fixtures", "trust31-pr-check");
const TOOL = path.resolve(HERE, "..", "..", "tools", "trust31-pr-check.mjs");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ── the owner's vector ──────────────────────────────────────────────────────

// Registry `main` at 6a961d64c486033397e215d13bbde9b868e321e0. The owner
// confirmed both digests on the site's operator page on 2026-11-10.
const VECTOR = {
  set: "3fdab6458ab377dfa53bdc2f562d13fd8597a9c944eccfcfc5c0cee621830e3e",
  tree: "d0e5d1b8229fba7d7e5f6a7abd0bbe2736833adf74a7679be3e3e7b2de94f20f",
};
const vectorSet = fs.readFileSync(path.join(FIXTURES, "set-6a961d6.txt"), "utf8");
const vectorLsTree = fs.readFileSync(path.join(FIXTURES, "ls-tree-6a961d6.txt"), "utf8");

test("the owner's vector: both digests at 6a961d6 are the ones the site shows", () => {
  const state = stateOf({ source: vectorSet, lsTree: vectorLsTree });
  assert.equal(state.entries.length, 74);
  assert.equal(state.set, VECTOR.set);
  assert.equal(state.tree, VECTOR.tree);
  assert.deepEqual(state.unresolved, []);
});

test("the set has 74 entries where a count of the strings in ENTRIES finds 72", () => {
  // `ENTRIES` opens with `...WORKFLOWS`. A reader that counts quoted strings
  // between its brackets loses the two bot workflows, and a digest over 72
  // entries is one no site will ever show.
  const block = vectorSet.slice(vectorSet.indexOf("export const ENTRIES = ["));
  assert.equal(block.split("\n").filter((l) => /^\s*"[^"]+",$/.test(l)).length, 72);
  const entries = parseEntries(vectorSet);
  assert.equal(entries.length, 74);
  assert.ok(entries.includes(".github/workflows/plugins-ingest.yml"));
  assert.ok(entries.includes(".github/workflows/plugins-moderation.yml"));
});

// ── the reader of the set ───────────────────────────────────────────────────

test("the set's reader takes strings, comments and spreads, and refuses everything else", () => {
  const ok = [
    "const A = [\"x/\", 'y.json'];",
    "export const ENTRIES = [",
    "  ...A, // a spread",
    "  /* a block",
    "     comment with \"quotes\" and a ] */",
    "  \"z/w.mjs\", // a `comment` with a \"string\" and a ]",
    "];",
  ].join("\n");
  assert.deepEqual(parseEntries(ok), ["x/", "y.json", "z/w.mjs"]);

  const refused = {
    "a concatenation": "export const ENTRIES = [\"a\" + \"b\"];",
    "a name": "const X = \"a\";\nexport const ENTRIES = [X];",
    "a template": "export const ENTRIES = [`a`];",
    "an escape": "export const ENTRIES = [\"a\\u002fb\"];",
    "a call": "export const ENTRIES = [...list()];",
    "a spread of nothing in the file": "export const ENTRIES = [...ELSEWHERE];",
    "a spread of itself": "export const ENTRIES = [...ENTRIES];",
    "no list": "export const OTHER = [\"a\"];",
    "two lists": "export const ENTRIES = [\"a\"];\nexport const ENTRIES = [\"b\"];",
    "an unclosed list": "export const ENTRIES = [\"a\",",
    "an empty set": "export const ENTRIES = [];",
    "an entry twice": "export const ENTRIES = [\"a\", \"a\"];",
    "a file and a directory of one name": "export const ENTRIES = [\"a\", \"a/\"];",
    "a glob": "export const ENTRIES = [\"tools/selftest/**\"];",
    "a dot-dot": "export const ENTRIES = [\"a/../b\"];",
    "an absolute path": "export const ENTRIES = [\"/a\"];",
    "a space": "export const ENTRIES = [\"a b\"];",
  };
  for (const [what, source] of Object.entries(refused)) {
    assert.throws(() => parseEntries(source), CannotRead, what);
  }
});

test("entries are sorted by bytes, not by a locale's order", () => {
  // A locale puts `_x` and `B` elsewhere and ignores the difference between
  // `.` and `/`; the service sorts bytes.
  assert.deepEqual(sortEntries(["b", "a/", "B", "a.b", "_x", ".github/x", "a-b"]),
    [".github/x", "B", "_x", "a-b", "a.b", "a/", "b"]);
});

test("the set's digest is every entry followed by a newline, the last one too", () => {
  assert.equal(setDigest(["b", "a"]), sha256("a\nb\n"));
  assert.notEqual(setDigest(["b", "a"]), sha256("a\nb"));
});

// ── the tree, from lines ────────────────────────────────────────────────────

const SET = [
  "const WORKFLOWS = [\".github/workflows/plugins-ingest.yml\"];",
  "export const ENTRIES = [...WORKFLOWS, \"bot/ingest.mjs\", \"bot/lib/\", \"policy/limits.json\"];",
].join("\n");
const oid = (n) => String(n).repeat(40).slice(0, 40);
const ls = (rows) => rows.map(([mode, type, id, p]) => `${mode} ${type} ${id}\t${p}\n`).join("");
const BASE_ROWS = [
  ["100644", "blob", oid(1), ".github/workflows/plugins-ingest.yml"],
  ["100644", "blob", oid(2), "bot/ingest.mjs"],
  ["040000", "tree", oid(3), "bot/lib"],
  ["100644", "blob", oid(4), "policy/limits.json"],
];
const state = (rows, source = SET) => stateOf({ source, tokenText: JSON.stringify({ [TOKEN_MEMBER]: setDigest(parseEntries(source)) }), lsTree: ls(rows) });
const swap = (p, row) => BASE_ROWS.map((r) => (r[3] === p ? row : r)).filter(Boolean);

test("an untouched pull request moves neither digest", () => {
  const d = compare(state(BASE_ROWS), state(BASE_ROWS), [{ status: "M", path: "README.md", modeBefore: "100644", modeAfter: "100644" }]);
  assert.deepEqual([d.setChanged, d.treeChanged, d.changed, d.disagreement], [false, false, [], null]);
});

test("a changed single-file entry moves the tree and is named", () => {
  const files = [{ status: "M", path: "policy/limits.json", modeBefore: "100644", modeAfter: "100644" }];
  const d = compare(state(BASE_ROWS), state(swap("policy/limits.json", ["100644", "blob", oid(9), "policy/limits.json"])), files);
  assert.equal(d.setChanged, false);
  assert.equal(d.treeChanged, true);
  assert.deepEqual(d.changed.map((c) => c.entry), ["policy/limits.json"]);
  assert.equal(d.disagreement, null);
});

test("a changed file under a directory entry moves the tree, and the file is named under its entry", () => {
  const files = [
    { status: "M", path: "bot/lib/deep/x.mjs", modeBefore: "100644", modeAfter: "100644" },
    { status: "A", path: "bot/library/y.mjs", modeBefore: "000000", modeAfter: "100644" },
  ];
  const d = compare(state(BASE_ROWS), state(swap("bot/lib", ["040000", "tree", oid(9), "bot/lib"])), files);
  assert.equal(d.treeChanged, true);
  assert.deepEqual(d.changed.map((c) => [c.entry, c.files.map((f) => f.path)]), [["bot/lib/", ["bot/lib/deep/x.mjs"]]]);
});

test("an entry that resolves to nothing is `<entry> - -`, and its removal moves the tree", () => {
  const after = state(swap("bot/ingest.mjs", null));
  assert.deepEqual(after.unresolved, ["bot/ingest.mjs"]);
  assert.ok(after.lines.map(lineText).includes("bot/ingest.mjs - -"));
  const d = compare(state(BASE_ROWS), after, [{ status: "D", path: "bot/ingest.mjs", modeBefore: "100644", modeAfter: "000000" }]);
  assert.equal(d.treeChanged, true);
  assert.deepEqual(d.changed.map((c) => [c.entry, c.merged.mode, c.merged.oid]), [["bot/ingest.mjs", "-", "-"]]);
});

test("a mode change alone, 100644 to 100755, moves the tree", () => {
  const files = [{ status: "M", path: "bot/ingest.mjs", modeBefore: "100644", modeAfter: "100755" }];
  const d = compare(state(BASE_ROWS), state(swap("bot/ingest.mjs", ["100755", "blob", oid(2), "bot/ingest.mjs"])), files);
  assert.equal(d.treeChanged, true);
  assert.deepEqual(d.changed.map((c) => [c.base.mode, c.merged.mode, c.base.oid === c.merged.oid]), [["100644", "100755", true]]);
});

test("a path that only shares a prefix with an entry is outside it", () => {
  assert.equal(covers("bot/ingest.mjs", "bot/ingest.mjs"), true);
  assert.equal(covers("bot/ingest.mjs", "bot/ingest.mjs.bak"), false);
  assert.equal(covers("bot/lib/", "bot/lib/x.mjs"), true);
  assert.equal(covers("bot/lib/", "bot/library/x.mjs"), false);
  assert.equal(covers("bot/lib/", "bot/lib.mjs"), false);

  // In the lines too: a listing that holds the `.bak` and not the file
  // resolves the entry to nothing, never to its neighbour.
  const rows = parseLsTree(ls([...swap("bot/ingest.mjs", null), ["100644", "blob", oid(7), "bot/ingest.mjs.bak"]]));
  const line = treeLines(parseEntries(SET), rows).find((l) => l.entry === "bot/ingest.mjs");
  assert.equal(lineText(line), "bot/ingest.mjs - -");

  // And in the verdict: the neighbour added is an untouched pull request.
  const files = [{ status: "A", path: "bot/ingest.mjs.bak", modeBefore: "000000", modeAfter: "100644" }];
  const d = compare(state(BASE_ROWS), state(BASE_ROWS), files);
  assert.deepEqual([d.treeChanged, d.changed, d.disagreement], [false, [], null]);
});

test("a changed list moves the set's digest, and says which entries came and went", () => {
  const wider = SET.replace("\"policy/limits.json\"", "\"policy/limits.json\", \"policy/new.json\"");
  const d = compare(state(BASE_ROWS), state(BASE_ROWS, wider), []);
  assert.equal(d.setChanged, true);
  assert.deepEqual([d.added, d.removed], [["policy/new.json"], []]);
  assert.equal(d.treeChanged, true, "the new entry's `- -` line is a line the base's tree did not have");

  const narrower = SET.replace(", \"policy/limits.json\"", "");
  const n = compare(state(BASE_ROWS), state(swap("policy/limits.json", null), narrower), []);
  assert.deepEqual([n.setChanged, n.added, n.removed], [true, [], ["policy/limits.json"]]);
});

test("the token file's digest moving alone is a changed set", () => {
  const moved = stateOf({ source: SET, tokenText: JSON.stringify({ [TOKEN_MEMBER]: "0".repeat(64) }), lsTree: ls(BASE_ROWS) });
  assert.equal(compare(state(BASE_ROWS), moved, []).setChanged, true);
});

test("the lines and git's diff are asked separately, and a disagreement is said", () => {
  const silent = compare(state(BASE_ROWS), state(swap("bot/lib", ["040000", "tree", oid(9), "bot/lib"])), []);
  assert.match(silent.disagreement, /lines differ .* names no path/);
  const loud = compare(state(BASE_ROWS), state(BASE_ROWS), [{ status: "M", path: "bot/lib/x.mjs", modeBefore: "100644", modeAfter: "100644" }]);
  assert.match(loud.disagreement, /do not differ .* names path/);
});

// ── the verdict's text ──────────────────────────────────────────────────────

const HEAD = "a".repeat(40);
const refs = (more = {}) => ({
  base: "b".repeat(40), head: HEAD, mergedNote: "commit `cccc`", branch: "policy/spdx", repo: "mihailinl/astra-registry",
  headRepo: "mihailinl/astra-registry", ...more,
});
const touched = () => {
  const base = state(BASE_ROWS);
  const merged = state(swap("policy/limits.json", ["100644", "blob", oid(9), "policy/limits.json"]));
  const diff = compare(base, merged, [{ status: "M", path: "policy/limits.json", modeBefore: "100644", modeAfter: "100644" }]);
  return { base, merged, head: merged, diff };
};

test("untouched is exit 0 with the one line; changed is exit 1 with the branch, the head and the three values", () => {
  const base = state(BASE_ROWS);
  const clean = report({ base, merged: base, head: base, diff: compare(base, base, []), refs: refs() });
  assert.equal(clean.exit, 0);
  assert.equal(clean.verdict, NOT_TOUCHED);
  assert.equal(clean.verdict, "TRUST-31: this PR does not touch the bot's acknowledged tree; no acknowledgement is needed");
  assert.doesNotMatch(clean.text, /What to do/);

  const t = touched();
  const red = report({ ...t, refs: refs(), read: { ok: false, kind: "unset", reason: NO_READ_YET } });
  assert.equal(red.exit, 1);
  assert.equal(red.verdict, "TRUST-31: this PR changes the bot's acknowledged tree. Merging it before the owner " +
    "acknowledges the tree puts every bot call in shadow (no release publishes).");
  assert.match(red.text, /The owner acknowledges branch `policy\/spdx` at head `a{40}` on the site's operator page \(Workshop → operator → "pre-acknowledge"\)/);
  assert.match(red.text, /merge within 72 hours and without pushing again: a new head needs a new acknowledgement/);
  assert.ok(red.text.includes(`job_workflow_sha (candidate: the head)  ${HEAD}`));
  assert.ok(red.text.includes(`tracked_set_sha256                      ${t.head.set}`));
  assert.ok(red.text.includes(`tree_sha256                             ${t.head.tree}`));
  assert.ok(red.text.includes(NO_READ_YET));
  assert.ok(red.text.includes("- `policy/limits.json`: 100644 4444444444444444444444444444444444444444 → 100644 9999999999999999999999999999999999999999"));
  assert.ok(red.text.includes("  - M `policy/limits.json`"));
});

test("a pre-acknowledged pull request is green only for the one answer, and never for a fork or a stale head", () => {
  const t = touched();
  const yes = { ok: true, kind: "acknowledged", reason: "acknowledged, until 2026-11-12T00:00:00.000Z", expiresAt: "2026-11-12T00:00:00.000Z" };
  const green = report({ ...t, refs: refs(), read: yes });
  assert.equal(green.exit, 0);
  assert.ok(green.verdict.startsWith(PRE_ACKNOWLEDGED));
  assert.match(green.verdict, /before 2026-11-12T00:00:00\.000Z/);

  for (const kind of ["not-acknowledged", "no-answer", "mismatch", "expired", "unreadable", "refused", "misconfigured"]) {
    const r = report({ ...t, refs: refs(), read: { ok: false, kind, reason: `because ${kind}` } });
    assert.equal(r.exit, 1, kind);
    assert.equal(r.verdict, CHANGED, kind);
    assert.ok(r.text.includes(`Red: because ${kind}.`), kind);
  }

  const fork = report({ ...t, refs: refs({ headRepo: "stranger/astra-registry" }), read: yes });
  assert.equal(fork.exit, 1);
  assert.match(fork.text, /A fork's branch can never be pre-acknowledged/);
  assert.match(fork.text, /A maintainer pushes the same commits to a branch here/);
  assert.doesNotMatch(fork.text, /The owner acknowledges branch/);

  // `main` moved inside the set after the branch left it: the head's tree is
  // not the one the merge would put on `main`.
  const stale = report({ ...t, head: t.base, refs: refs(), read: yes });
  assert.equal(stale.exit, 1);
  assert.match(stale.text, /Update the branch first/);
  assert.doesNotMatch(stale.text, /The owner acknowledges branch/);
});

test("a fork that touches nothing is still green", () => {
  const base = state(BASE_ROWS);
  const r = report({ base, merged: base, head: base, diff: compare(base, base, []), refs: refs({ headRepo: "stranger/astra-registry" }) });
  assert.equal(r.exit, 0);
});

test("a list the token file does not name is no answer, changed or not", () => {
  const base = state(BASE_ROWS);
  const off = stateOf({ source: SET, tokenText: JSON.stringify({ [TOKEN_MEMBER]: "0".repeat(64) }), lsTree: ls(BASE_ROWS) });
  const r = report({ base: off, merged: off, head: off, diff: compare(off, off, []), refs: refs() });
  assert.equal(r.exit, 1);
  assert.ok(r.verdict.startsWith(CANNOT_SAY));
  assert.match(r.verdict, /is not the set the contract's token file names/);

  const none = stateOf({ source: SET, tokenText: null, lsTree: ls(BASE_ROWS) });
  const n = report({ base, merged: none, head: none, diff: compare(base, none, []), refs: refs() });
  assert.equal(n.exit, 1);
  assert.ok(n.verdict.startsWith(CANNOT_SAY));
});

test("two answers to one question is exit 2, never a verdict", () => {
  const base = state(BASE_ROWS);
  const r = report({ base, merged: base, head: base, refs: refs(),
    diff: compare(base, base, [{ status: "M", path: "bot/lib/x.mjs", modeBefore: "100644", modeAfter: "100644" }]) });
  assert.equal(r.exit, 2);
  assert.ok(r.verdict.startsWith(CANNOT_SAY));
});

test("a branch or a file name a stranger chose is printed as inert text", () => {
  assert.equal(shown("a`b\n::error::x\u0007"), "`a?b?::error::x?`");
  const t = touched();
  const r = report({ ...t, refs: refs({ branch: "x`\n## owned" }) });
  assert.ok(!r.text.split("\n").some((l) => l.startsWith("## owned")));
});

// ── the read of a pre-acknowledgement, against a fake fetch ─────────────────

const NOW = Date.parse("2026-11-10T12:00:00Z");
const DIGESTS = { set: "1".repeat(64), tree: "2".repeat(64) };
const answer = (body, status = 200) => async () => ({ status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
const acknowledged = (more = {}) => ({
  acknowledged: true, tree_sha256: DIGESTS.tree, tracked_set_sha256: DIGESTS.set, expires_at: NOW / 1000 + 3600, ...more,
});
const ask = (fetch, more = {}) => proposedRead({ url: "https://plugins.example", head: HEAD, ...DIGESTS, fetch, now: NOW, ...more });

test("the read: unset is red and says the service has no read yet, without asking anything", async () => {
  let asked = 0;
  const r = await ask(async () => { asked += 1; }, { url: "" });
  assert.deepEqual([r.ok, r.kind, r.reason, asked], [false, "unset", NO_READ_YET, 0]);
  assert.equal(r.reason, "the service has no read for a pre-acknowledgement yet; this check stays red, and the merge waits for the owner's word");
});

test("the read: asks exactly the agreed address, with no credential", async () => {
  const seen = [];
  const fetch = async (url, init) => { seen.push([url, init.method, init.redirect, Object.keys(init.headers)]); return answer(acknowledged())(); };
  for (const url of ["https://plugins.example", "https://plugins.example/", "https://plugins.example/plugins/v1/trust31/proposed"]) await ask(fetch, { url });
  assert.deepEqual(seen, Array(3).fill([`https://plugins.example/plugins/v1/trust31/proposed?head=${HEAD}`, "GET", "error", ["accept"]]));
  assert.equal(readEndpoint("https://host/base/", HEAD), `https://host/base/plugins/v1/trust31/proposed?head=${HEAD}`);

  let asked = 0;
  const count = async () => { asked += 1; return answer(acknowledged())(); };
  for (const url of ["http://plugins.example", "https://user:pw@plugins.example", "https://plugins.example/?x=1", "not a url"]) {
    assert.equal((await ask(count, { url })).kind, "misconfigured", url);
  }
  for (const head of ["A".repeat(40), "a".repeat(39), `${"a".repeat(40)}&x=1`]) assert.equal((await ask(count, { head })).kind, "misconfigured", head);
  assert.equal(asked, 0);
});

test("the read: green only for acknowledged, the same two digests and a time still ahead", async () => {
  const seconds = await ask(answer(acknowledged()));
  assert.deepEqual([seconds.ok, seconds.kind, seconds.expiresAt], [true, "acknowledged", "2026-11-10T13:00:00.000Z"]);
  const rfc = await ask(answer(acknowledged({ expires_at: "2026-11-13T11:59:00Z" })));
  assert.deepEqual([rfc.ok, rfc.expiresAt], [true, "2026-11-13T11:59:00.000Z"]);
  assert.equal((await ask(answer(acknowledged({ expires_at: "2026-11-10T15:00:00.5+02:00" })))).ok, true);

  const red = {
    "mismatch": [
      acknowledged({ tree_sha256: "3".repeat(64) }),
      acknowledged({ tracked_set_sha256: "3".repeat(64) }),
    ],
    "expired": [
      acknowledged({ expires_at: NOW / 1000 }),
      acknowledged({ expires_at: NOW / 1000 - 1 }),
      acknowledged({ expires_at: "2026-11-10T11:59:59Z" }),
    ],
    "not-acknowledged": [
      { acknowledged: false, tree_sha256: null, tracked_set_sha256: null, expires_at: null },
    ],
    "unreadable": [
      acknowledged({ expires_at: NOW + 3600_000 }), // milliseconds, read as seconds: the year 58000
      acknowledged({ expires_at: NOW / 1000 + 73 * 3600 }),
      acknowledged({ expires_at: "2026-11-10 13:00:00" }),
      acknowledged({ expires_at: "tomorrow" }),
      acknowledged({ expires_at: null }),
      acknowledged({ expires_at: -5 }),
      acknowledged({ tree_sha256: DIGESTS.tree.toUpperCase().replace(/2/g, "A") }),
      acknowledged({ tree_sha256: DIGESTS.tree.slice(1) }),
      acknowledged({ tracked_set_sha256: null }),
      acknowledged({ acknowledged: "true" }),
      acknowledged({ acknowledged: 1 }),
      acknowledged({ branch: "x" }),
      { acknowledged: true, tree_sha256: DIGESTS.tree, tracked_set_sha256: DIGESTS.set },
      { acknowledged: false, tree_sha256: DIGESTS.tree, tracked_set_sha256: null, expires_at: null },
      { acknowledged: false },
      [acknowledged()],
      null,
      "true",
      "<html>",
      "",
      " ".repeat(70_000),
    ],
  };
  for (const [kind, bodies] of Object.entries(red)) {
    for (const body of bodies) {
      const r = await ask(answer(body));
      assert.deepEqual([r.ok, r.kind], [false, kind], JSON.stringify(body)?.slice(0, 120));
      assert.ok(r.reason.length > 10);
    }
  }
});

test("the read: 429, 5xx, a refused connection and ten seconds are \"did not answer\", apart from \"not acknowledged\"", async () => {
  for (const status of [429, 500, 502, 503, 599]) {
    const r = await ask(answer(acknowledged(), status));
    assert.deepEqual([r.ok, r.kind], [false, "no-answer"], String(status));
    assert.match(r.reason, new RegExp(`HTTP ${status}.*again later`));
  }
  const refused = await ask(async () => { throw new TypeError("fetch failed"); });
  assert.deepEqual([refused.ok, refused.kind], [false, "no-answer"]);
  const slowBody = await ask(async () => ({ status: 200, text: () => new Promise(() => {}) }), { timeoutMs: 20 });
  assert.deepEqual([slowBody.ok, slowBody.kind], [false, "no-answer"]);
  let aborted = false;
  const never = await ask((url, init) => new Promise(() => { init.signal.addEventListener("abort", () => { aborted = true; }); }), { timeoutMs: 20 });
  assert.deepEqual([never.ok, never.kind, aborted], [false, "no-answer", true]);
  assert.match(never.reason, /no answer in 0\.02 s/);

  assert.equal((await ask(answer(acknowledged(), 422))).kind, "refused");
  for (const status of [201, 204, 301, 302, 401, 403, 404]) {
    const r = await ask(answer(acknowledged(), status));
    assert.deepEqual([r.ok, r.kind], [false, "unreadable"], String(status));
  }
});

// ── real repositories ───────────────────────────────────────────────────────

const roots = [];
test.after(() => { for (const r of roots) fs.rmSync(r, { recursive: true, force: true }); });

const git = (root, ...args) => execFileSync("git", ["-C", root, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
  "-c", "commit.gpgsign=false", ...args], { encoding: "utf8", env: fixtureEnv(root) }).trim();

const setFile = (entries) => [
  "const WORKFLOWS = [",
  "  \".github/workflows/plugins-ingest.yml\",",
  "];",
  "export const ENTRIES = [",
  "  ...WORKFLOWS,",
  ...entries.map((e) => `  ${JSON.stringify(e)}, // a comment, with a "string" in it`),
  "];",
  "",
].join("\n");
const LIST = ["bot/ingest.mjs", "bot/lib/", "policy/limits.json", "policy/absent.json"];
const tokenFile = (entries) => `${JSON.stringify({ [TOKEN_MEMBER]: setDigest([".github/workflows/plugins-ingest.yml", ...entries]) })}\n`;

/** A registry in miniature on `main`, and `change(write, root)` committed on branch `pr`. */
function repository(change, { mainMoves = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "trust31-pr-check-"));
  roots.push(root);
  const write = (rel, text) => {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  };
  git(root, "init", "-q", "-b", "main");
  write("bot/tests/code-paths.test.mjs", setFile(LIST));
  write("schema/contract-tokens-v1.json", tokenFile(LIST));
  write(".github/workflows/plugins-ingest.yml", "name: ingest\n");
  write("bot/ingest.mjs", "export const a = 1;\n");
  write("bot/lib/deep/x.mjs", "export const x = 1;\n");
  write("policy/limits.json", "{}\n");
  write("README.md", "a registry\n");
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", "base");
  git(root, "checkout", "-q", "-b", "pr");
  change(write, root);
  git(root, "add", "-A");
  git(root, "commit", "-q", "--allow-empty", "-m", "the pull request");
  const head = git(root, "rev-parse", "HEAD");
  git(root, "checkout", "-q", "main");
  if (mainMoves) {
    mainMoves(write, root);
    git(root, "add", "-A");
    git(root, "commit", "-q", "-m", "main moves");
  }
  return { root, base: git(root, "rev-parse", "main"), head };
}

async function run(repo, extra = [], { env = {}, fetch } = {}) {
  let out = "";
  const exit = await main(["--dir", repo.root, "--base", repo.base, "--head", repo.head, "--branch", "pr", ...extra],
    { env, write: (s) => { out += s; }, fetch });
  return { exit, out };
}

test("in a repository: a pull request outside the set is green, neighbours of entries included", async () => {
  const repo = repository((write) => {
    write("README.md", "a registry, described\n");
    write("bot/ingest.mjs.bak", "export const a = 0;\n");
    write("bot/library/y.mjs", "export const y = 1;\n");
    write("bot/tests/other.test.mjs", "// a suite\n");
  });
  const r = await run(repo);
  assert.equal(r.exit, 0, r.out);
  assert.ok(r.out.includes(NOT_TOUCHED));
  assert.match(r.out, /which `git merge-tree` writes/);
  assert.match(r.out, /\| base \| `[0-9a-f]{64}` \| `[0-9a-f]{64}` \| 5 \|/);
});

test("in a repository: a file under a directory entry, a single-file entry, a removal and a mode are each red", async () => {
  const cases = {
    "a file under a directory entry": [(write) => write("bot/lib/deep/x.mjs", "export const x = 2;\n"),
      /- `bot\/lib\/`: 040000 [0-9a-f]{40} → 040000 [0-9a-f]{40}\n {2}- M `bot\/lib\/deep\/x\.mjs`/],
    "a file added under a directory entry": [(write) => write("bot/lib/new.mjs", "export const n = 1;\n"), / {2}- A `bot\/lib\/new\.mjs`/],
    "a single-file entry": [(write) => write("policy/limits.json", "{\"a\":1}\n"),
      /- `policy\/limits\.json`: 100644 [0-9a-f]{40} → 100644 [0-9a-f]{40}\n {2}- M `policy\/limits\.json`/],
    "an entry removed": [(write, root) => fs.rmSync(path.join(root, "bot/ingest.mjs")), /- `bot\/ingest\.mjs`: 100644 [0-9a-f]{40} → - -\n {2}- D `bot\/ingest\.mjs`/],
    "a mode alone": [(write, root) => fs.chmodSync(path.join(root, "bot/ingest.mjs"), 0o755),
      /- `bot\/ingest\.mjs`: 100644 ([0-9a-f]{40}) → 100755 \1\n {2}- M `bot\/ingest\.mjs` \(mode 100644 → 100755\)/],
    "an entry that resolved to nothing, arriving": [(write) => write("policy/absent.json", "{}\n"), /- `policy\/absent\.json`: - - → 100644 [0-9a-f]{40}/],
  };
  for (const [what, [change, expected]] of Object.entries(cases)) {
    const repo = repository(change);
    const r = await run(repo);
    assert.equal(r.exit, 1, `${what}\n${r.out}`);
    assert.ok(r.out.includes(CHANGED), what);
    assert.match(r.out, expected, what);
    assert.ok(r.out.includes(`The owner acknowledges branch \`pr\` at head \`${repo.head}\``), what);
    assert.ok(r.out.includes(NO_READ_YET), what);
    assert.match(r.out, /- the set \(which paths count\): unchanged/, what);
  }
});

test("in a repository: the entry that resolves to nothing is listed with the head's three values", async () => {
  const repo = repository((write) => write("policy/limits.json", "{\"a\":1}\n"));
  const r = await run(repo);
  assert.match(r.out, /Entries that resolve to nothing at the head \(1\), which the site lists too: `policy\/absent\.json`\./);
  const at = spawnSync(process.execPath, [TOOL, "--dir", repo.root, "--at", repo.head], { encoding: "utf8" });
  assert.equal(at.status, 0, at.stderr);
  const [, set] = /tracked_set_sha256 {2}([0-9a-f]{64})/.exec(at.stdout);
  const [, tree] = /tree_sha256 {9}([0-9a-f]{64})/.exec(at.stdout);
  assert.ok(r.out.includes(`tracked_set_sha256                      ${set}`));
  assert.ok(r.out.includes(`tree_sha256                             ${tree}`));
});

test("in a repository: a changed list is red, and a list the token file does not follow is no answer", async () => {
  const wider = [...LIST, "policy/new.json"];
  const both = repository((write) => {
    write("bot/tests/code-paths.test.mjs", setFile(wider));
    write("schema/contract-tokens-v1.json", tokenFile(wider));
  });
  const r = await run(both);
  assert.equal(r.exit, 1, r.out);
  assert.ok(r.out.includes(CHANGED));
  assert.match(r.out, /- the set \(which paths count\): \*\*changed\*\*; added `policy\/new\.json`/);
  assert.match(r.out, /\| merge result \| `[0-9a-f]{64}` \| `[0-9a-f]{64}` \| 6 \|/);

  const listOnly = repository((write) => write("bot/tests/code-paths.test.mjs", setFile(wider)));
  const l = await run(listOnly);
  assert.equal(l.exit, 1, l.out);
  assert.ok(l.out.includes(CANNOT_SAY));
  assert.match(l.out, /is not the set the contract's token file names/);

  const unreadable = repository((write) => write("bot/tests/code-paths.test.mjs", "export const ENTRIES = [...compute()];\n"));
  const u = await run(unreadable);
  assert.equal(u.exit, 2, u.out);
  assert.ok(u.out.includes(CANNOT_SAY));
});

test("in a repository: what is compared is what `main` would carry, not the branch", async () => {
  // `main` moved inside the set after the branch left it, and the branch does
  // not touch the set: the merge carries `main`'s tree, so nothing to
  // acknowledge, although the head's own tree is not the base's.
  const behind = repository((write) => write("README.md", "described\n"),
    { mainMoves: (write) => write("policy/limits.json", "{\"main\":1}\n") });
  const b = await run(behind);
  assert.equal(b.exit, 0, b.out);
  assert.ok(b.out.includes(NOT_TOUCHED));
  const rows = [...b.out.matchAll(/^\| (base|merge result|head) \| `([0-9a-f]{64})` \| `([0-9a-f]{64})`/gm)].map((m) => m[3]);
  assert.equal(rows[0], rows[1]);
  assert.notEqual(rows[1], rows[2]);

  // The branch touches the set too: the head's tree is not the merge's, so an
  // acknowledgement of this head would not cover the merge.
  const stale = repository((write) => write("bot/ingest.mjs", "export const a = 2;\n"),
    { mainMoves: (write) => write("policy/limits.json", "{\"main\":1}\n") });
  const s = await run(stale, [], { env: { TRUST31_PROPOSED_READ_URL: "https://plugins.example" }, fetch: answer(acknowledged()) });
  assert.equal(s.exit, 1, s.out);
  assert.match(s.out, /Update the branch first/);
  assert.match(s.out, /Not asked: an acknowledgement of this head would not cover the merge/);
  assert.doesNotMatch(s.out, /The owner acknowledges branch/);
});

test("in a repository: a merge commit is read when one is given, and names its own base and head", async () => {
  const repo = repository((write) => write("policy/limits.json", "{\"a\":1}\n"),
    { mainMoves: (write) => write("README.md", "main moved, outside the set\n") });
  const stale = git(repo.root, "rev-parse", "main~1");
  git(repo.root, "merge", "-q", "--no-ff", "-m", "Merge pull request", "pr");
  const merge = git(repo.root, "rev-parse", "HEAD");

  const r = await run({ ...repo, base: stale }, ["--merge", merge]);
  assert.equal(r.exit, 1, r.out);
  assert.ok(r.out.includes(`commit \`${merge}\`, the pull request's merge commit`));
  assert.ok(r.out.includes(`- base: \`${repo.base}\` (the merge commit's first parent; \`--base\` named ${stale}, which \`main\` has left since)`));

  let out = "";
  assert.equal(await main(["--dir", repo.root, "--merge", merge], { env: {}, write: (s) => { out += s; } }), 1);
  assert.ok(out.includes(`- head: \`${repo.head}\``));

  out = "";
  assert.equal(await main(["--dir", repo.root, "--merge", merge, "--head", repo.base], { env: {}, write: (s) => { out += s; } }), 2);
  assert.match(out, /and the head named is/);
  out = "";
  assert.equal(await main(["--dir", repo.root, "--merge", repo.head], { env: {}, write: (s) => { out += s; } }), 2);
  assert.match(out, /is not a merge of two commits/);
  out = "";
  assert.equal(await main(["--dir", repo.root, "--base", "0".repeat(40), "--head", repo.head], { env: {}, write: (s) => { out += s; } }), 2);
  assert.match(out, /is not a commit this checkout has/);
});

test("in a repository: the read turns a changed pull request green for the one answer, and a fork never", async () => {
  const repo = repository((write) => write("policy/limits.json", "{\"a\":1}\n"));
  const values = await run(repo);
  const set = /tracked_set_sha256 {22}([0-9a-f]{64})/.exec(values.out)[1];
  const tree = /tree_sha256 {29}([0-9a-f]{64})/.exec(values.out)[1];
  const env = { TRUST31_PROPOSED_READ_URL: "https://plugins.example" };
  const now = Math.floor(Date.now() / 1000);
  const yes = { acknowledged: true, tree_sha256: tree, tracked_set_sha256: set, expires_at: now + 3600 };

  const asked = [];
  const green = await run(repo, [], { env, fetch: async (url) => { asked.push(url); return answer(yes)(); } });
  assert.equal(green.exit, 0, green.out);
  assert.ok(green.out.includes(PRE_ACKNOWLEDGED));
  assert.deepEqual(asked, [`https://plugins.example/plugins/v1/trust31/proposed?head=${repo.head}`]);

  const other = await run(repo, [], { env, fetch: answer({ ...yes, tree_sha256: "0".repeat(64) }) });
  assert.equal(other.exit, 1);
  assert.match(other.out, /Red: the acknowledgement is of another tree/);
  const down = await run(repo, [], { env, fetch: answer("", 503) });
  assert.equal(down.exit, 1);
  assert.match(down.out, /Red: the service did not answer \(HTTP 503\); run this check again later/);
  const no = await run(repo, [], { env, fetch: answer({ acknowledged: false, tree_sha256: null, tracked_set_sha256: null, expires_at: null }) });
  assert.equal(no.exit, 1);
  assert.match(no.out, /Red: the service holds no pre-acknowledgement for this head/);

  let forkAsked = 0;
  const fork = await run(repo, ["--repo", "mihailinl/astra-registry", "--head-repo", "stranger/astra-registry"],
    { env, fetch: async () => { forkAsked += 1; return answer(yes)(); } });
  assert.equal(fork.exit, 1);
  assert.equal(forkAsked, 0);
  assert.match(fork.out, /A fork's branch can never be pre-acknowledged/);

  let cleanAsked = 0;
  const clean = await run(repository((write) => write("README.md", "x\n")), [], { env, fetch: async () => { cleanAsked += 1; return answer(yes)(); } });
  assert.deepEqual([clean.exit, cleanAsked], [0, 0]);
});

test("in a repository: the command itself exits 1 on a changed tree, writes the summary, and says when it judged itself", async () => {
  const repo = repository((write) => {
    write("policy/limits.json", "{\"a\":1}\n");
    write("tools/trust31-pr-check.mjs", "process.exit(0);\n");
  });
  const summary = path.join(repo.root, "summary.md");
  const r = spawnSync(process.execPath, [TOOL, "--dir", repo.root, "--base", repo.base, "--head", repo.head, "--branch", "pr",
    "--judged-by", "the base's copy of the check"],
    { encoding: "utf8", env: { ...process.env, GITHUB_STEP_SUMMARY: summary, GITHUB_ACTIONS: "true", TRUST31_PROPOSED_READ_URL: "" } });
  assert.equal(r.status, 1, r.stderr);
  assert.ok(r.stdout.includes(CHANGED));
  assert.ok(r.stdout.includes("::error title=TRUST-31 set::TRUST-31: this PR changes the bot's acknowledged tree\n"));
  const written = fs.readFileSync(summary, "utf8");
  assert.ok(written.includes(CHANGED));
  assert.ok(!written.includes("::error"));
  assert.match(written, /this pull request changes the check itself \(`tools\/trust31-pr-check\.mjs`\)\. It was judged by the base's copy of the check\./);

  const clean = repository((write) => write("README.md", "x\n"));
  const g = spawnSync(process.execPath, [TOOL, "--dir", clean.root, "--base", clean.base, "--head", clean.head], { encoding: "utf8" });
  assert.equal(g.status, 0, g.stderr);
  assert.ok(g.stdout.includes(NOT_TOUCHED));

  const wrong = spawnSync(process.execPath, [TOOL, "--dir", clean.root, "--at", clean.head, "--expect-tree", "0".repeat(64)], { encoding: "utf8" });
  assert.equal(wrong.status, 1);
  assert.match(wrong.stdout, /WRONG: tree_sha256 is/);
  assert.equal(spawnSync(process.execPath, [TOOL, "--bogus", "x"], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync(process.execPath, [TOOL], { encoding: "utf8" }).status, 2);
});
