// sign-trust.mjs, the once-a-year offline command: a key that is not a published
// root writes nothing, a delegation round-trips through its own verifier, a
// delegation to nothing is refused, a movable tag cannot reach the attestation
// allowlist, a TEST index key cannot be delegated to, and keygen-index.sh emits a
// seed whose public half matches.
//
// INDEX_PUB stays here; testRootPem, sandboxWithRoot and TRUST_ROOT_A moved to
// ./fixtures.mjs because the update section uses all three.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import { privateKeyFromSeed, publicKeyBase64 } from "../../bot/lib/sign.mjs";
import { test, assert, tmp } from "./harness.mjs";
import { TRUST_ROOT_A, sandboxWithRoot } from "./fixtures.mjs";

export async function run() {
  // ── the root delegation ─────────────────────────────────────────────────────
  //
  // `sign-trust.mjs` is run once a year, by hand, on an offline machine, with the
  // root key out of its envelope. That is the least-rehearsed command in the whole
  // system and the most expensive one to get wrong: a mistake is discovered when a
  // user's catalogue still reads UNSIGNED, and fixing it means another trip. So
  // its guards are tested here rather than trusted.

  console.log("\nroot delegation (sign-trust.mjs)");

  const INDEX_PUB = path.join(tmp, "index-pub.json");
  fs.writeFileSync(
    INDEX_PUB,
    JSON.stringify({
      key_id: "selftest-index",
      algorithm: "ed25519",
      // Any valid 32-byte key; the delegation is what is under test, not this key.
      public_key: publicKeyBase64(crypto.generateKeyPairSync("ed25519").privateKey),
    }),
  );

  await test("a key that is not a published root is refused, and writes nothing", () => {
    const stranger = path.join(tmp, "stranger.pem");
    fs.writeFileSync(
      stranger,
      crypto.generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
    );
    const out = path.join(tmp, "must-not-exist.json");
    let status = 0;
    let stderr = "";
    try {
      execFileSync(
        "node",
        ["tools/sign-trust.mjs", "--root-key", stranger, "--index-key-file", INDEX_PUB,
         "--workflow-sha", "1".repeat(40), "--out", out],
        { cwd: REPO_ROOT, stdio: "pipe" },
      );
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 1, `exit ${status}`);
    assert(stderr.includes("not one of the roots published"), stderr);
    assert(!fs.existsSync(out), "it wrote a document signed by a key no daemon trusts");
  });

  await test("a signed delegation round-trips through its own verifier", () => {
    const dir = sandboxWithRoot("trust-ok", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const out = path.join(dir, "registry", "v1", "trust.json");
    execFileSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
       "--workflow-sha", "A".repeat(40), "--serial", "9", "--out", out],
      { cwd: dir, stdio: "pipe" },
    );
    const doc = JSON.parse(fs.readFileSync(out, "utf8"));
    assert(doc.signed.serial === 9, "serial");
    assert(doc.signed.schema === "astra.registry.trust/1", doc.signed.schema);
    // Lowercased on the way in: the bot compares it against what `gh` reports.
    assert(doc.signed.reusable_workflow_shas[0] === "a".repeat(40), "sha not normalised");
    execFileSync("node", ["tools/sign-trust.mjs", "--verify", out], { cwd: dir, stdio: "pipe" });
  });

  await test("a delegation to nothing is refused", () => {
    // A trust.json with no index key verifies perfectly and grants nothing, so
    // every catalogue would still read UNSIGNED — the failure that looks like
    // success, and the one an operator would not think to check for.
    const dir = sandboxWithRoot("trust-empty", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    let status = 0;
    let stderr = "";
    try {
      execFileSync(
        "node",
        ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--workflow-sha", "1".repeat(40),
         "--out", path.join(dir, "trust.json")],
        { cwd: dir, stdio: "pipe" },
      );
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 1, `exit ${status}`);
    assert(stderr.includes("no index key"), stderr);
  });

  await test("a movable tag cannot reach the attestation allowlist", () => {
    // The allowlist is commit SHAs precisely because a tag can be repointed, and
    // this workflow runs inside every plugin author's repository.
    const dir = sandboxWithRoot("trust-tag", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    let status = 0;
    let stderr = "";
    try {
      execFileSync(
        "node",
        ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
         "--workflow-sha", "plugin-release/v1", "--out", path.join(dir, "trust.json")],
        { cwd: dir, stdio: "pipe" },
      );
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 1, `exit ${status}`);
    assert(stderr.includes("not a 40-character commit SHA"), stderr);
  });

  await test("a TEST index key cannot be delegated to", () => {
    // Its private half is committed to this public repository.
    const dir = sandboxWithRoot("trust-testkey", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    let status = 0;
    let stderr = "";
    try {
      execFileSync(
        "node",
        ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file,
         "--index-key-file", path.join(REPO_ROOT, "tools", "testkeys", "TEST-ONLY-DO-NOT-TRUST-index-2026a.pub.json"),
         "--workflow-sha", "1".repeat(40), "--out", path.join(dir, "trust.json")],
        { cwd: dir, stdio: "pipe" },
      );
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 1, `exit ${status}`);
    assert(stderr.includes("TEST key"), stderr);
  });

  await test("keygen-index.sh emits a 32-byte seed and the matching public key", () => {
    const dir = path.join(tmp, "idxkey");
    execFileSync("sh", ["tools/keygen-index.sh", "--id", "selftest-index-key", "--out", dir], {
      cwd: REPO_ROOT,
      stdio: "pipe",
    });
    const seed = Buffer.from(fs.readFileSync(path.join(dir, "selftest-index-key.seed.b64"), "utf8").trim(), "base64");
    assert(seed.length === 32, `seed was ${seed.length} bytes; ASTRA_INDEX_SIGNING_KEY takes 32`);
    const pub = JSON.parse(fs.readFileSync(path.join(dir, "selftest-index-key.pub.json"), "utf8"));
    // The seed in the GitHub secret and the public key in trust.json must be two
    // halves of one key, or the catalogue is signed by a key nobody delegated to.
    assert(publicKeyBase64(privateKeyFromSeed(seed)) === pub.public_key, "seed and public key disagree");
  });
}
