// The fixtures more than one module reads, moved here rather than duplicated.
// Nothing in this file prints; it only builds fixtures, and two of them are PEMs
// written into `tmp` at import time.
//
// The test root's key id is spelled ONCE, as `ROOT_A_KEY_ID`. It used to be
// typed twice — at the `testRootPem` call that publishes the PEM as the sandbox's
// active root, and at the `loadTestRoot` call that handed the update signer its
// private half, before RC-R3-4(b) moved that signer and its cases into Astra —
// and a sandbox works only because the two are the same key. Two files with the
// string typed twice is one typo away from every test failing with "does not
// verify", which names nothing.

import fs from "node:fs";
import path from "node:path";

import { runValidation } from "../validate.mjs";
import { REPO_ROOT } from "../lib/sources.mjs";
import { privateKeyFromSeed } from "../../bot/lib/sign.mjs";
import { indexKeysFromTrust } from "../../bot/sign-index.mjs";
import { tmp } from "./harness.mjs";

/** Run the real validator with $ASTRA_PLUGINS_DIR pointed at a fake checkout. */
export async function withFakeAstraPlugins(dirName, limitsYaml, fn) {
  const root = path.join(tmp, dirName);
  fs.mkdirSync(path.join(root, "spec"), { recursive: true });
  fs.writeFileSync(path.join(root, "spec/limits.yaml"), limitsYaml);
  const prev = process.env.ASTRA_PLUGINS_DIR;
  process.env.ASTRA_PLUGINS_DIR = root;
  try {
    const { report } = await runValidation({
      root: REPO_ROOT, allowStaging: true, online: false, artifactsDir: null, index: false,
    });
    await fn(report);
  } finally {
    if (prev === undefined) delete process.env.ASTRA_PLUGINS_DIR;
    else process.env.ASTRA_PLUGINS_DIR = prev;
  }
}

export const TEST_INDEX_KEY = "TEST-ONLY-DO-NOT-TRUST-index-2026a";
export const TEST_STRANGER_KEY = "TEST-ONLY-DO-NOT-TRUST-stranger";
export const trustFixture = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "tools/testkeys/fixtures/trust-reserve-signed.json"), "utf8"),
);
export const trustedIndexKeys = indexKeysFromTrust(trustFixture);

export const ROOT_A_KEY_ID = "TEST-ONLY-DO-NOT-TRUST-root-a";
export const ROOT_B_KEY_ID = "TEST-ONLY-DO-NOT-TRUST-root-b";

/** Build an OpenSSL-shaped PEM for one of the published test roots. */
export function testRootPem(keyId) {
  const secret = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", `${keyId}.SECRET-TEST-KEY.json`), "utf8"),
  );
  // `privateKeyFromSeed` already knows the PKCS#8 wrapper; asking Node to
  // re-export it as PEM beats hand-rolling the base64 line wrapping, which is
  // how the first version of this produced a file OpenSSL would not decode.
  const pem = privateKeyFromSeed(Buffer.from(secret.private_key_seed, "base64")).export({
    format: "pem",
    type: "pkcs8",
  });
  const file = path.join(tmp, `${keyId}.pem`);
  fs.writeFileSync(file, pem);
  return { file, publicKey: secret.public_key, keyId: secret.key_id };
}

/**
 * A copy of the repository whose `root.json` publishes `keyId`, so the tool's
 * "is this a published root" guard can be satisfied without a real root key.
 */
export function sandboxWithRoot(name, keyId, publicKey, extraRoots = []) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(path.join(dir, "registry", "v1"), { recursive: true });
  // Only the four files the tool actually loads. Copying `tools/` and `bot/`
  // wholesale drags in `bot/manifest-probe/target/`, which is a Rust build
  // directory and filled /tmp the first time this was written.
  for (const f of [
    "tools/sign-trust.mjs",
    "tools/lib/canonical.mjs", "tools/lib/semver.mjs", "bot/lib/sign.mjs",
  ]) {
    fs.mkdirSync(path.join(dir, path.dirname(f)), { recursive: true });
    fs.copyFileSync(path.join(REPO_ROOT, f), path.join(dir, f));
  }
  fs.writeFileSync(
    path.join(dir, "registry", "v1", "root.json"),
    JSON.stringify({
      schema: "astra.registry.root/1",
      status: "provisioned",
      roots: [
        { key_id: keyId, role: "active", algorithm: "ed25519", public_key: publicKey, signs: "trust.json" },
        ...extraRoots,
      ],
    }),
  );
  return dir;
}

export const TRUST_ROOT_A = testRootPem(ROOT_A_KEY_ID);
