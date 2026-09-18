// What the workflow files may and may not say.
//
// The other suites test code. This one tests the YAML, because several of the
// properties this registry depends on are properties of the workflows and of
// nothing else: which job can reach a signing key, whether a shell re-derives a
// predicate that already has one implementation, and whether a dispatch can
// name a submitter. A reviewer checks those by reading; this file checks them
// every run.
//
// Line-oriented, with no YAML parser, for the same reason the rest of the
// repository has no dependencies: the gate has to still run when a lockfile is
// being argued about (registry plan B-T0.3 creates this file; B-T0.5 and B-T0.6
// extend it).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const DIR = path.join(REPO, ".github", "workflows");
const files = fs.readdirSync(DIR).filter((n) => n.endsWith(".yml") || n.endsWith(".yaml"));
const read = (n) => fs.readFileSync(path.join(DIR, n), "utf8");

test("there are workflows to check at all", () => {
  assert.ok(files.length >= 5, `only ${files.length} workflow(s) found; this suite would prove nothing`);
});

// B-T0.5 (ROLL-51, ID-65). A plugin id becomes a directory name on a stranger's
// disk. `tools/lib/ids.mjs` is the one place that decides what one is, and the
// copy that used to live in `ingest.yml` was wrong: its second character group
// was optional, so it accepted a one-character id the rest of the registry
// refuses. A second copy of a predicate is a second answer waiting to happen.
test("no workflow carries its own plugin-id pattern", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      if (line.includes("tools/lib/ids.mjs")) return;
      if (/\[a-z0-9\][^\n]*\{0,\d\d\}/.test(line)) offenders.push(`${name}:${i + 1}`);
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow re-derives what a plugin id is");
});

test("the publish guard asks ids.mjs", () => {
  const ingest = read("ingest.yml");
  assert.match(
    ingest,
    /node tools\/lib\/ids\.mjs --check/,
    "ingest.yml no longer calls the one id predicate at its publish guard",
  );
});

// B-T0.6 (AV-5, INV-6, OPEN-OPS-6). A dispatch that names a submitter lets
// whoever may dispatch decide whose ownership gets re-proved. The submitter is
// resolved from the release instead, and nothing in the workflows may hand one
// in.
test("no workflow lets a caller name the submitter", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      // Comments are excluded on purpose: the rule is about what a workflow
      // reads, not about what it says. `ingest.yml` names the field in a comment
      // precisely to record that it is NOT read, and a test that forbade the
      // words would delete the explanation and keep the behaviour.
      if (line.trim().startsWith("#")) return;
      if (/inputs\.submitter|client_payload\.submitter|INPUT_SUBMITTER|DISPATCH_SUBMITTER/.test(line)) {
        offenders.push(`${name}:${i + 1}`);
      }
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow takes the submitter from its caller");
});

// B-T0.3. `bot/publish-apply.mjs` takes `--skip-checks` so its own tests can run
// against a toy repository with no catalogue in it. That flag turns off
// `validate.mjs`, `build-index.mjs --check` and `selftest.mjs` — every rule this
// registry holds a publication to. An escape hatch CI can reach is not an escape
// hatch, it is the behaviour, so the one place it may appear is a test file.
test("no workflow turns the publish path's own checks off", () => {
  const offenders = [];
  for (const name of files) {
    read(name).split("\n").forEach((line, i) => {
      if (line.trim().startsWith("#")) return;
      if (line.includes("--skip-checks") || line.includes("--no-push")) offenders.push(`${name}:${i + 1}`);
    });
  }
  assert.equal(offenders.join(", "), "", "a workflow passes publish-apply.mjs a flag meant for its tests");
});

test("ingest's manual dispatch takes no inputs", () => {
  const ingest = read("ingest.yml").split("\n");
  const at = ingest.findIndex((l) => /^\s{2}workflow_dispatch:/.test(l));
  assert.ok(at >= 0, "ingest.yml has no workflow_dispatch trigger");
  // Everything indented under the trigger, up to the next two-space key.
  let end = at + 1;
  while (end < ingest.length && (ingest[end].trim() === "" || /^\s{4}/.test(ingest[end]))) end++;
  const body = ingest.slice(at + 1, end).filter((l) => l.trim() && !l.trim().startsWith("#"));
  assert.equal(
    body.join("\n"),
    "",
    "a no-input dispatch runs the drain and the backstop; inputs let a caller aim one run at one release",
  );
});
