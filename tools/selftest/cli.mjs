// The five exit codes the workflows depend on: build-index --check and
// build-revocations --check clean on the committed tree, sign-revocations
// refusing to write a TEST signature into registry/ and refusing to emit an
// unsigned file with no key, and validate.mjs exiting 1 without --allow-staging.

import { execFileSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert } from "./harness.mjs";
import { TEST_INDEX_KEY } from "./fixtures.mjs";

/** How many tests run() reports. The runner asserts exactly this many, so
 *  adding a test here is one line of arithmetic in this file and nowhere else. */
export const TESTS = 5;

export async function run() {
  console.log("\ncli surface");
  await test("`build-index.mjs --check` exits 0 on the committed tree", () => {
    execFileSync("node", ["tools/build-index.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
  });
  await test("`build-revocations.mjs --check` exits 0 on the committed tree", () => {
    execFileSync("node", ["tools/build-revocations.mjs", "--check"], { cwd: REPO_ROOT, stdio: "pipe" });
  });
  await test("`sign-revocations.mjs` refuses to write a TEST signature into registry/", () => {
    let status = 0;
    let stderr = "";
    try {
      execFileSync(
        "node",
        ["tools/sign-revocations.mjs", "--test-key", TEST_INDEX_KEY, "--in", "registry/v1/revocations.json"],
        { cwd: REPO_ROOT, stdio: "pipe" },
      );
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 2, `exit ${status}`);
    assert(stderr.includes("refusing to write a TEST-key signature"), stderr);
  });
  await test("`sign-revocations.mjs` with no key at all fails loudly rather than emitting an unsigned file", () => {
    let status = 0;
    let stderr = "";
    try {
      execFileSync("node", ["tools/sign-revocations.mjs", "--in", "registry/v1/revocations.json"], {
        cwd: REPO_ROOT,
        stdio: "pipe",
        env: { ...process.env, ASTRA_INDEX_SIGNING_KEY: "", ASTRA_INDEX_SIGNING_KEY_ID: "" },
      });
    } catch (e) {
      status = e.status;
      stderr = String(e.stderr);
    }
    assert(status === 2, `exit ${status}`);
    assert(stderr.includes("ASTRA_INDEX_SIGNING_KEY"), stderr);
  });
  await test("`validate.mjs` exits non-zero without --allow-staging", () => {
    let code = 0;
    try {
      execFileSync("node", ["tools/validate.mjs"], { cwd: REPO_ROOT, stdio: "pipe" });
    } catch (e) {
      code = e.status;
    }
    assert(code === 1, `exit code was ${code}, expected 1`);
  });
}
