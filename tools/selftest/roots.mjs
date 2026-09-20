// The published root keys, held against the ones the bot compiles in
// (registry plan B-T1.5, BOT-7).
//
// **Why here and not only in `bot/tests/roots.test.mjs`.** The bot's suite
// asks how the bot BEHAVES — that a trust.json signed by any other key is
// refused, that no argument reaches past the compiled set — and it runs where
// the bot's suites run. This module asks one thing about the committed
// DOCUMENTS: `registry/v1/root.json` publishes the keys `bot/lib/roots.mjs`
// holds. That question belongs to the same family as `root-delegation.mjs`
// above it, and it needs to be answered on the path a commit that edits
// root.json actually takes — which is `build-index.yml`, on every push to
// `main` and every pull request, where this suite runs and the bot's does not.
//
// A divergence is never a typo. Either a rotation is under way and
// `bot/lib/roots.mjs` is the half that has to move next (SERVE-92), or
// somebody published a key the verifier that guards the catalogue has never
// heard of. `bot/check-roots.mjs` is the same comparison, run in `ingest.yml`
// and alarmed through environment `alerts`; this is that comparison in the
// place where the commit is still somebody's open branch.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";
import { checkRoots } from "../../bot/check-roots.mjs";
import { COMPILED_ROOTS, compiledSetProblems, fingerprintOf } from "../../bot/lib/roots.mjs";
import { test, assert, assertEqual } from "./harness.mjs";

export async function run() {
  console.log("\nthe compiled root keys (bot/lib/roots.mjs)");

  await test("the compiled table does not contradict itself", () => {
    // First, because a comparison between two corrupted halves can agree.
    // `fingerprint_sha256` is redundant with `public_key` on purpose: one
    // character changed in either is caught here without reference to any
    // other file.
    assertEqual(compiledSetProblems().join(" | "), "");
    assert(COMPILED_ROOTS.length >= 1, "no root key is compiled in, so this bot would verify no trust.json");
  });

  await test("registry/v1/root.json publishes exactly the compiled set", () => {
    const out = checkRoots();
    assertEqual(
      out.problems.join(" | "),
      "",
      "the published root keys and the ones bot/lib/roots.mjs compiles in are not the same set. If a rotation " +
      "is under way, SERVE-92's order is: compiled set first, root.json second, the outgoing key dropped from " +
      "the compiled set last — and only the first of those three leaves them disagreeing without an alarm.",
    );
    assertEqual(
      out.expected.join(" | "),
      "",
      "the compiled set holds a key registry/v1/root.json does not publish. That is SERVE-92 step 1 and it is " +
      "correct for as long as the rotation takes; the commit that publishes the key clears this.",
    );
    assertEqual(out.verdict.status, "green");
  });

  await test("each published fingerprint is sha256 over its own key", () => {
    // `tools/keygen-root.sh`: `openssl pkey -pubout -outform DER | tail -c 32
    // | openssl dgst -sha256`. A fingerprint nobody can recompute is a
    // fingerprint nobody can check a ceremony against.
    const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry", "v1", "root.json"), "utf8"));
    assert(Array.isArray(doc.roots) && doc.roots.length >= 1, "registry/v1/root.json publishes no roots");
    assertEqual(doc.status, "provisioned", "root.json says the ceremony has not been run and the bot holds its output");
    for (const r of doc.roots) {
      assertEqual(fingerprintOf(r.public_key), r.fingerprint_sha256, `${r.key_id}'s fingerprint is not its key's`);
    }
  });
}
