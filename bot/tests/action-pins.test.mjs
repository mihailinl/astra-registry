// Every third-party action is pinned by full commit SHA.
//
// A tag (`actions/checkout@v4`) is a pointer its owner can move, and so can
// whoever compromises the owner: the next run then executes new code with this
// repository's tokens, including the jobs that hold the index signing key and
// push to `main`. A 40-hex commit SHA makes a run execute exactly the code that
// was reviewed. This suite reads every workflow and composite action and fails
// on any remote `uses:` that is not `@<40 lowercase hex>`.
//
// Allowed without a pin: local actions (`./...`) and `docker://...@sha256:<64 hex>`.
// Comment lines are not steps and are skipped.
//
// There is no exception. Until fix No. 2 a `TRACKED_UNPINNED` list let the 67
// lines in TRUST-31's tracked set (bot/tests/code-paths.test.mjs ENTRIES) stay on
// tags, because those files could not be edited without a pre-acknowledgement;
// fix No. 2 pinned them under one and deleted the list, so a tag anywhere in
// `.github/` is red, the bot's own two workflows included.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function files(dir, out = []) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) files(p, out);
    else if (/\.ya?ml$/.test(n)) out.push(p);
  }
  return out;
}

const PINNED = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.\/-]+@[0-9a-f]{40}(\s+#.*)?$/;
const DOCKER = /^docker:\/\/\S+@sha256:[0-9a-f]{64}(\s+#.*)?$/;

/** Every non-comment `uses:` line: { file, line, ref } with file repo-relative. */
export function usesLines() {
  const found = [];
  const targets = [
    ...files(join(root, ".github/workflows")),
    ...files(join(root, ".github/actions")),
  ];
  for (const abs of targets) {
    const file = abs.slice(root.length + 1).split("\\").join("/");
    readFileSync(abs, "utf8").split("\n").forEach((raw, i) => {
      const t = raw.trim();
      if (t.startsWith("#")) return;
      const m = /^(?:-\s+)?(uses:\s*(.*))$/.exec(t);
      if (m) found.push({ file, n: i + 1, line: m[1].trim(), ref: m[2].trim() });
    });
  }
  return found;
}

const isLocal = (r) => r.startsWith("./");
const isPinned = (r) => PINNED.test(r) || DOCKER.test(r);

test("scan finds the workflows and the actions (it is not scanning nothing)", () => {
  const all = usesLines();
  assert.ok(all.length > 100, `only ${all.length} uses: lines found`);
  assert.ok(all.some((u) => u.file.startsWith(".github/actions/")));
  assert.ok(all.some((u) => u.file.startsWith(".github/workflows/")));
});

test("every remote action is pinned by a full commit SHA, the tracked workflows included", () => {
  const all = usesLines();
  const bad = all.filter((u) => !isLocal(u.ref) && !isPinned(u.ref)).map((u) => `${u.file}:${u.n}  ${u.line}`);
  assert.deepEqual(bad, [], `not pinned to a 40-hex commit SHA:\n${bad.join("\n")}`);
  // The two files that were last to be pinned are read, not merely allowed:
  // a scan that skipped them would pass on exactly the lines this replaced.
  for (const f of [".github/workflows/plugins-ingest.yml", ".github/workflows/plugins-moderation.yml", ".github/actions/alert-state/action.yml"]) {
    assert.ok(all.some((u) => u.file === f && !isLocal(u.ref)), `${f} has no remote uses: line in the scan`);
  }
});

test("the pin grammar accepts and refuses what it should", () => {
  const sha = "a".repeat(40);
  assert.ok(isPinned(`actions/checkout@${sha} # v4`));
  assert.ok(isPinned(`actions/cache/restore@${sha}`));
  assert.ok(isPinned(`docker://alpine@sha256:${"b".repeat(64)}`));
  assert.ok(!isPinned("actions/checkout@v4"));
  assert.ok(!isPinned(`actions/checkout@${"a".repeat(39)}`));
  assert.ok(!isPinned(`actions/checkout@${"a".repeat(41)}`));
  assert.ok(!isPinned(`actions/checkout@${"A".repeat(40)}`));
  assert.ok(!isPinned("docker://alpine:3"));
});
