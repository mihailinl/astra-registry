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

  // ── --not-after (contract 5.8.0's renewal; ROLL-45) ────────────────────────
  //
  // The renewal gives `astra-index-2026a` a `not_after`. Every reader puts a
  // key out at `now > not_after`, so a wrong value here is a date on which
  // every catalogue stops verifying, and a DROPPED value is an end of life
  // removed by a ceremony that never decided to.

  const signTrust = (dir, extra) => {
    try {
      const stdout = execFileSync(
        "node",
        ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
         "--workflow-sha", "1".repeat(40), "--out", path.join(dir, "registry", "v1", "trust.json"), ...extra],
        { cwd: dir, stdio: "pipe" },
      );
      return { status: 0, stderr: "", stdout: String(stdout) };
    } catch (e) {
      return { status: e.status, stderr: String(e.stderr), stdout: String(e.stdout) };
    }
  };
  const NOT_AFTER = "2099-01-02T03:04:05Z";

  // Watched failing with the spread that writes the member removed: the
  // document verified and carried no not_after.
  await test("--not-after writes the window on the named key, and --verify shows it", () => {
    const dir = sandboxWithRoot("trust-not-after", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const r = signTrust(dir, ["--not-after", `selftest-index=${NOT_AFTER}`]);
    assert(r.status === 0, r.stderr);
    const out = path.join(dir, "registry", "v1", "trust.json");
    const key = JSON.parse(fs.readFileSync(out, "utf8")).signed.index_keys[0];
    assert(key.not_after === NOT_AFTER, `not_after ${key.not_after}`);
    const v = String(execFileSync("node", ["tools/sign-trust.mjs", "--verify", out], { cwd: dir, stdio: "pipe" }));
    assert(v.includes(`(until ${NOT_AFTER})`), v);
  });

  // Watched failing with each refusal in notAfterFlags commented out in turn.
  await test("--not-after refuses a malformed time, an impossible date, an undelegated key, a key named twice, and a past instant", () => {
    const cases = [
      [["--not-after", "selftest-index=2099-01-02"], "not a real"],
      [["--not-after", "selftest-index=2099-02-30T00:00:00Z"], "not a real"],
      [["--not-after", "selftest-index=2099-01-02T03:04:05.000Z"], "not a real"],
      [["--not-after", `somebody-else=${NOT_AFTER}`], "does not delegate"],
      [["--not-after", `selftest-index=${NOT_AFTER}`, "--not-after", `selftest-index=${NOT_AFTER}`], "twice"],
      [["--not-after", "selftest-index=2000-01-01T00:00:00Z"], "not after now"],
      [["--not-after", NOT_AFTER], "is not KEY_ID="],
    ];
    for (const [extra, says] of cases) {
      const dir = sandboxWithRoot(`trust-na-bad-${crypto.randomUUID()}`, TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
      const r = signTrust(dir, extra);
      assert(r.status === 1, `${extra.join(" ")}: exit ${r.status}`);
      assert(r.stderr.includes(says), `${extra.join(" ")}: ${r.stderr}`);
      assert(!fs.existsSync(path.join(dir, "registry", "v1", "trust.json")), `${extra.join(" ")} wrote a document`);
    }
  });

  // Watched failing with the `carried` loop removed: the second signing wrote a
  // document whose key had no not_after, and exited 0.
  await test("a not_after the published document carries is never dropped by omission", () => {
    const dir = sandboxWithRoot("trust-na-carry", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    assert(signTrust(dir, ["--not-after", `selftest-index=${NOT_AFTER}`]).status === 0, "first signing");
    const out = path.join(dir, "registry", "v1", "trust.json");
    const before = fs.readFileSync(out, "utf8");
    const dropped = signTrust(dir, []);
    assert(dropped.status === 1, `exit ${dropped.status}`);
    assert(dropped.stderr.includes(`--not-after selftest-index=${NOT_AFTER} to keep it`), dropped.stderr);
    assert(fs.readFileSync(out, "utf8") === before, "the refused signing changed the published document");
    const kept = signTrust(dir, ["--not-after", `selftest-index=${NOT_AFTER}`]);
    assert(kept.status === 0, kept.stderr);
    assert(JSON.parse(fs.readFileSync(out, "utf8")).signed.index_keys[0].not_after === NOT_AFTER, "restated value");
  });

  // Watched failing with the NOT_AFTER loop removed from the script: sign-trust
  // refused the re-sign (the guard above), so the allowlist could not widen.
  await test("ceremony-allowlist-workflow.sh carries a key's not_after forward while it widens the allowlist", () => {
    const dir = sandboxWithRoot("trust-na-allowlist", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    fs.copyFileSync(path.join(REPO_ROOT, "tools", "ceremony-allowlist-workflow.sh"), path.join(dir, "tools", "ceremony-allowlist-workflow.sh"));
    assert(signTrust(dir, ["--not-after", `selftest-index=${NOT_AFTER}`]).status === 0, "first signing");
    execFileSync("bash", ["tools/ceremony-allowlist-workflow.sh", TRUST_ROOT_A.file, "2".repeat(40)], { cwd: dir, stdio: "pipe" });
    const s = JSON.parse(fs.readFileSync(path.join(dir, "registry", "v1", "trust.json"), "utf8")).signed;
    assert(s.index_keys[0].not_after === NOT_AFTER, `not_after ${s.index_keys[0].not_after}`);
    assert(JSON.stringify(s.reusable_workflow_shas) === JSON.stringify(["1".repeat(40), "2".repeat(40)]), String(s.reusable_workflow_shas));
  });
}
