// The replay harness (tools/export-replay.mjs) and the stub export it is
// proved with (tools/export-stub.mjs): Phase 2 step 1's gate. The stub at
// every commit of a fixture history must replay equal, and each of the three
// ways an export can be wrong must fail naming the path.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";

import { exportText, stubExport } from "../../tools/export-stub.mjs";
import { renderReport, replay, replayExport, serialLine } from "../../tools/export-replay.mjs";
import { stateSha256 } from "../../tools/lib/export-state.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { addLogOnly, exportHistory, scratch } from "./fixtures/export-history.mjs";

const h = exportHistory();
const line = serialLine({ root: h.dir });

/** An export re-digested after an edit, so the harness cannot pass it on a stale digest. */
function edited(doc, edit) {
  const files = { ...doc.files };
  edit(files);
  const decoded = new Map(Object.entries(files).map(([p, b]) => [p, Buffer.from(b, "base64")]));
  return { ...doc, files, state_sha256: stateSha256(decoded) };
}

test("the stub's serial is DEC-9's count over plugins/", () => {
  const { c1, c2, c3, c4 } = h.commits;
  assert.deepEqual([c1, c2, c3, c4].map((c) => stubExport({ root: h.dir, commit: c }).serial), [1, 2, 3, 3]);
  assert.deepEqual(Object.keys(stubExport({ root: h.dir, commit: c4 })), ["serial", "state_sha256", "files"]);
});

test("the stub at every commit of the history replays equal, catalogue included", () => {
  for (const [name, commit] of Object.entries(h.commits)) {
    const r = replayExport({ root: h.dir, doc: stubExport({ root: h.dir, commit }), line });
    assert.equal(r.equal, true, `${name}: ${renderReport({ reports: [{ file: name, ...r }] })}`);
    assert.ok(r.index.bytes > 0, `${name}: no catalogue was compared`);
  }
  // c3 and c4 share serial 3; the commit replayed is the LAST one.
  const r3 = replayExport({ root: h.dir, doc: stubExport({ root: h.dir, commit: h.commits.c3 }), line });
  assert.equal(r3.commit, h.commits.c4);
});

test("one byte changed, one file dropped, one file added: each fails and names its path", () => {
  const base = stubExport({ root: h.dir, commit: h.commits.c4 });
  const target = "plugins/alpha/plugin.json";
  const flipped = edited(base, (f) => {
    const b = Buffer.from(f[target], "base64");
    b[b.length - 2] ^= 1;
    f[target] = b.toString("base64");
  });
  const dropped = edited(base, (f) => delete f["log/decisions/2026/11/00000000000000000000000000000002.json"]);
  const added = edited(base, (f) => { f["plugins/beta/extra.txt"] = Buffer.from("x").toString("base64"); });

  const r1 = replayExport({ root: h.dir, doc: flipped, line });
  assert.equal(r1.equal, false);
  assert.deepEqual(r1.differing, [target]);
  assert.equal(r1.index.equal, false, "a changed plugin.json byte is a changed catalogue");

  const r2 = replayExport({ root: h.dir, doc: dropped, line });
  assert.equal(r2.equal, false);
  assert.deepEqual(r2.missing, ["log/decisions/2026/11/00000000000000000000000000000002.json"]);

  const r3 = replayExport({ root: h.dir, doc: added, line });
  assert.equal(r3.equal, false);
  assert.deepEqual(r3.extra, ["plugins/beta/extra.txt"]);

  assert.match(renderReport({ reports: [{ file: "x", ...r1 }] }), /differing: plugins\/alpha\/plugin\.json/);
});

test("a stale or lying state_sha256 fails even when the files are right", () => {
  const base = stubExport({ root: h.dir, commit: h.commits.c4 });
  const r = replayExport({ root: h.dir, doc: { ...base, state_sha256: "0".repeat(64) }, line });
  assert.equal(r.equal, false);
  assert.ok(r.problems.some((p) => /not the digest of its own files/.test(p)));
});

test("a path off the grammar is refused, not written", () => {
  const base = stubExport({ root: h.dir, commit: h.commits.c4 });
  const r = replayExport({ root: h.dir, doc: { ...base, files: { ...base.files, "plugins/../escape": "eA==" } }, line });
  assert.equal(r.equal, false);
  assert.ok(r.problems.some((p) => p.includes("plugins/../escape")));
});

test("a serial main never had, and a serial superseded by a log-only commit, say which", () => {
  const r = replayExport({ root: h.dir, doc: { ...stubExport({ root: h.dir, commit: h.commits.c4 }), serial: 99 }, line });
  assert.equal(r.equal, false);
  assert.ok(r.problems.some((p) => /no commit .* serial 99/.test(p)));

  const g = exportHistory("export-history-log-only");
  const before = stubExport({ root: g.dir, commit: g.commits.c4 });
  addLogOnly(g);
  const later = replayExport({ root: g.dir, doc: before, line: serialLine({ root: g.dir }) });
  assert.equal(later.equal, false);
  assert.equal(later.commit, g.commits.c5);
  assert.deepEqual(later.missing, ["log/cutover.json"]);
  assert.ok(later.problems.some((p) => p.includes(g.commits.c4.slice(0, 12)) && /log-only/.test(p)));
});

test("the CLI: a directory of exports, exit 0 when all equal and 1 when one differs", () => {
  const leftovers = () => fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("export-replay-") && !f.startsWith("export-replay-cli-"));
  const before = leftovers().length;
  const dir = scratch("export-replay-cli");
  for (const [name, commit] of Object.entries(h.commits)) {
    fs.writeFileSync(path.join(dir, `${name}.json`), exportText(stubExport({ root: h.dir, commit })));
  }
  const run = () => spawnSync(process.execPath, [path.join(REPO_ROOT, "tools", "export-replay.mjs"), "--export", dir, "--registry", h.dir], { encoding: "utf8" });
  const ok = run();
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /4 of 4 export\(s\) reproduce main/);

  const doc = JSON.parse(fs.readFileSync(path.join(dir, "c2.json"), "utf8"));
  fs.writeFileSync(path.join(dir, "c2.json"), exportText(edited(doc, (f) => delete f["plugins/beta/plugin.json"])));
  const bad = run();
  assert.equal(bad.status, 1, bad.stdout + bad.stderr);
  assert.match(bad.stdout, /missing: plugins\/beta\/plugin\.json/);
  assert.equal(replay({ root: h.dir, exportPath: dir }).equal, false);

  // Every scratch tree it made is removed.
  assert.equal(leftovers().length, before);
});
