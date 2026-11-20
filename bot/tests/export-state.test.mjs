// `state_sha256` (tools/lib/export-state.mjs) against its published vector,
// and against a git tree. The plugins service implements the same definition
// and reads the same vector, so a change here that the vector does not follow
// is a change that makes the two sides disagree.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  compareStatePaths, exportFiles, filesMember, stateAt, stateLines, stateSha256, statePathProblem,
} from "../../tools/lib/export-state.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { makeRegistry } from "./fixtures/export-history.mjs";

const VECTOR = path.join(REPO_ROOT, "tools", "vectors", "export-state-v1.json");
const vector = JSON.parse(fs.readFileSync(VECTOR, "utf8"));
const decode = (files) => new Map(Object.entries(files).map(([p, b]) => [p, Buffer.from(b, "base64")]));

test("the vector has the cases the definition turns on", () => {
  const names = vector.cases.map((c) => c.name);
  for (const n of ["empty", "one-listing", "bytes-as-stored", "byte-order"]) assert.ok(names.includes(n), `no ${n} case`);
  assert.equal(vector.cases.find((c) => c.name === "empty").state_sha256, crypto.createHash("sha256").update("").digest("hex"));
});

test("every vector case reproduces: lines and state_sha256", () => {
  for (const c of vector.cases) {
    const files = decode(c.files);
    assert.equal(stateLines(files), c.lines, `${c.name}: lines`);
    assert.equal(stateSha256(files), c.state_sha256, `${c.name}: state_sha256`);
    // Insertion order is not an input.
    assert.equal(stateSha256(new Map([...files].reverse())), c.state_sha256, `${c.name}: order of the input`);
  }
});

test("byte order, not UTF-16 order: the case a JavaScript sort() gets wrong", () => {
  const c = vector.cases.find((x) => x.name === "byte-order");
  const files = decode(c.files);
  const utf16 = [...files.keys()].sort().map((p) => `${crypto.createHash("sha256").update(files.get(p)).digest("hex")} ${p}\n`).join("");
  const wrong = crypto.createHash("sha256").update(utf16).digest("hex");
  assert.equal(wrong, c.not_this_utf16_order_gives);
  assert.notEqual(wrong, c.state_sha256, "the case no longer separates the two orders");
  assert.ok(compareStatePaths("plugins/Ａ/x", "plugins/\u{1F600}/x") < 0);
  assert.ok(compareStatePaths("plugins/a-b/x", "plugins/a/b") < 0);
});

test("one changed byte, one dropped file and one added file each move the digest", () => {
  const c = vector.cases.find((x) => x.name === "one-listing");
  const files = decode(c.files);
  const [first] = files.keys();
  const changed = new Map(files);
  const bytes = Buffer.from(changed.get(first));
  bytes[0] ^= 1;
  changed.set(first, bytes);
  const dropped = new Map(files);
  dropped.delete(first);
  const added = new Map(files).set("log/extra.json", Buffer.from("{}"));
  for (const [what, m] of [["changed", changed], ["dropped", dropped], ["added", added]]) {
    assert.notEqual(stateSha256(m), c.state_sha256, what);
  }
});

test("a path outside plugins/ and log/, or off the grammar, is refused", () => {
  for (const p of ["registry/v1/index.json", "plugins", "pluginsx/a", "/plugins/a", "plugins//a", "plugins/./a",
    "plugins/../a", "plugins/a\\b", "plugins/a\nb", ""]) {
    assert.ok(statePathProblem(p), `${JSON.stringify(p)} accepted`);
    assert.throws(() => stateSha256({ [p]: Buffer.alloc(0) }), undefined, JSON.stringify(p));
  }
  assert.equal(statePathProblem("log/decisions/2026/11/x.json"), null);
});

test("an export's base64 is read strictly, and a round trip through filesMember is exact", () => {
  const c = vector.cases.find((x) => x.name === "bytes-as-stored");
  const { files, problems } = exportFiles({ files: c.files });
  assert.deepEqual(problems, []);
  assert.deepEqual(filesMember(files), c.files);
  assert.deepEqual(Object.keys(filesMember(files)), Object.keys(c.files), "keys in byte order");
  const loose = exportFiles({ files: { "plugins/a/x": "e30=\n", "plugins/a/y": "e30", "registry/x": "e30=" } });
  assert.equal(loose.files.size, 0);
  assert.equal(loose.problems.length, 3);
});

test("at a commit: git objects only, never the working tree, and only 100644 files", () => {
  const r = makeRegistry("export-state");
  r.write("plugins/a/plugin.json", "{}\n");
  r.write("log/x.json", "[]\n");
  r.write("registry/v1/index.json", "not in the state\n");
  const c = r.commit("one");
  const want = stateSha256({ "plugins/a/plugin.json": Buffer.from("{}\n"), "log/x.json": Buffer.from("[]\n") });
  assert.equal(stateAt({ root: r.dir, commit: c }).state_sha256, want);

  // An uncommitted edit, an untracked file and an ignored one change nothing.
  r.write("plugins/a/plugin.json", "{\"edited\":true}\n");
  r.write("plugins/a/untracked.json", "{}\n");
  r.write(".gitignore", "log/ignored.json\n");
  r.write("log/ignored.json", "{}\n");
  assert.equal(stateAt({ root: r.dir, commit: c }).state_sha256, want);

  // A link under plugins/ is refused rather than digested as its target text.
  r.remove("plugins/a/untracked.json");
  r.git(["checkout", "-q", "--", "plugins/a/plugin.json"]);
  fs.symlinkSync("plugin.json", path.join(r.dir, "plugins", "a", "link.json"));
  const linked = r.commit("link");
  assert.throws(() => stateAt({ root: r.dir, commit: linked }), /mode 120000/);
});
