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
import { execFileSync, spawnSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import { stableStringify } from "../lib/canonical.mjs";
import { TRUST_SCHEMA, privateKeyFromSeed, publicKeyBase64, signEnvelope } from "../../bot/lib/sign.mjs";
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

  // stderr on success too: the signing summary (what was delegated, what was
  // DROPPED) is written there.
  const signTrust = (dir, extra) => {
    const r = spawnSync(
      "node",
      ["tools/sign-trust.mjs", "--root-key", TRUST_ROOT_A.file, "--index-key-file", INDEX_PUB,
       "--workflow-sha", "1".repeat(40), "--out", path.join(dir, "registry", "v1", "trust.json"), ...extra],
      { cwd: dir, stdio: "pipe" },
    );
    return { status: r.status, stderr: String(r.stderr), stdout: String(r.stdout) };
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

  // ── kind_keys (minice content-catalogue design §5 "Keys") ─────────────────
  //
  // The content catalogues' keys: exactly one current and one next per kind,
  // next valid strictly later than current, never an index key. A reader takes
  // a kind whose pair breaks a rule as having NO keys, so a wrong document here
  // switches a whole kind off on every client — and a re-sign that forgets one
  // does the same silently. The writer and --verify share one judge
  // (kindKeyProblems), and each rule is tested from both ends: the writer
  // refuses to write it, and --verify refuses a root-signed document carrying it.

  const KIND_TMP = path.join(tmp, "kind-keys");
  fs.mkdirSync(KIND_TMP, { recursive: true });
  const kindFile = (o) => {
    const f = path.join(KIND_TMP, `${crypto.randomUUID()}.kind-key.json`);
    fs.writeFileSync(f, JSON.stringify({
      key_id: o.key_id,
      algorithm: o.algorithm ?? "ed25519",
      public_key: o.public_key ?? publicKeyBase64(crypto.generateKeyPairSync("ed25519").privateKey),
      kind: o.kind,
      role: o.role,
      ...(o.not_before !== undefined ? { not_before: o.not_before } : {}),
    }));
    return f;
  };
  const pairFiles = (kind) => [
    kindFile({ kind, role: "current", key_id: `astra-${kind}-2026a` }),
    kindFile({ kind, role: "next", key_id: `astra-${kind}-2026b` }),
  ];
  const kindArgs = (files) => files.flatMap((f) => ["--kind-key-file", f]);
  const trustOut = (dir) => path.join(dir, "registry", "v1", "trust.json");
  const verifyOut = (dir) => {
    try {
      return { status: 0, stdout: String(execFileSync("node", ["tools/sign-trust.mjs", "--verify", trustOut(dir)], { cwd: dir, stdio: "pipe" })), stderr: "" };
    } catch (e) {
      return { status: e.status, stdout: String(e.stdout), stderr: String(e.stderr) };
    }
  };
  // A document whose envelope is a PUBLISHED root's — so --verify gets past the
  // signature and has only kind_keys left to judge — with `edit` applied to a
  // well-formed signed member first.
  const resignedWith = (dir, edit) => {
    assert(signTrust(dir, kindArgs(pairFiles("games"))).status === 0, "the base signing");
    const signed = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed;
    edit(signed);
    const privateKey = crypto.createPrivateKey(fs.readFileSync(TRUST_ROOT_A.file));
    const doc = signEnvelope({ domain: TRUST_SCHEMA, signed, signers: [{ key_id: TRUST_ROOT_A.keyId, privateKey }] });
    fs.writeFileSync(trustOut(dir), `${stableStringify(doc)}\n`);
    return verifyOut(dir);
  };
  const plusSeconds = (s, n) => new Date(Date.parse(s) + n * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

  // Watched failing with the `kind_keys` spread removed from `signed`: the
  // document verified and carried no kind keys.
  await test("kind keys: six kinds' pairs are written sorted, current from the signing instant and next 60 s later, and --verify lists them", () => {
    const dir = sandboxWithRoot("trust-kind-ok", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const kinds = ["packs", "games", "commands", "models", "characters", "animsets"];
    const files = kinds.flatMap(pairFiles).reverse();
    const r = signTrust(dir, kindArgs(files));
    assert(r.status === 0, r.stderr);
    const s = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed;
    assert(s.kind_keys.length === 12, `${s.kind_keys.length} kind keys`);
    const order = s.kind_keys.map((k) => `${k.kind}/${k.role}`);
    const want = [...kinds].sort().flatMap((k) => [`${k}/current`, `${k}/next`]);
    assert(JSON.stringify(order) === JSON.stringify(want), order.join(" "));
    for (const k of s.kind_keys) {
      assert(Object.keys(k).sort().join(",") === "alg,key_id,kind,not_before,public_key,role", Object.keys(k).join(","));
      assert(k.alg === "ed25519", k.alg);
      assert(k.key_id === `astra-${k.kind}-2026${k.role === "current" ? "a" : "b"}`, k.key_id);
      const at = k.role === "current" ? s.issued_at : plusSeconds(s.issued_at, 60);
      assert(k.not_before === at, `${k.key_id} not_before ${k.not_before}, want ${at}`);
    }
    assert(!s.index_keys.some((i) => s.kind_keys.some((k) => k.public_key === i.public_key)), "a kind key in index_keys");
    const v = verifyOut(dir);
    assert(v.status === 0, v.stderr);
    for (const k of s.kind_keys) assert(v.stdout.includes(k.key_id), `--verify does not list ${k.key_id}`);
  });

  // Watched failing with the next-after-current comparison removed from
  // kindKeyProblems: both the signing and the --verify exited 0.
  await test("kind keys: a next not later than its current is refused, by the writer and by --verify", () => {
    for (const [cur, nxt] of [["2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"], ["2099-01-01T00:01:00Z", "2099-01-01T00:00:00Z"]]) {
      const dir = sandboxWithRoot(`trust-kind-order-${crypto.randomUUID()}`, TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
      const r = signTrust(dir, kindArgs([
        kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a", not_before: cur }),
        kindFile({ kind: "games", role: "next", key_id: "astra-games-2026b", not_before: nxt }),
      ]));
      assert(r.status === 1, `${cur}/${nxt}: exit ${r.status}`);
      assert(r.stderr.includes("not later than current"), r.stderr);
      assert(!fs.existsSync(trustOut(dir)), `${cur}/${nxt} wrote a document`);
    }
    const dir = sandboxWithRoot("trust-kind-order-verify", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const v = resignedWith(dir, (s) => {
      for (const k of s.kind_keys) k.not_before = "2026-11-02T00:00:00Z";
    });
    assert(v.status === 1, `--verify exit ${v.status}`);
    assert(v.stderr.includes("not later than current"), v.stderr);
  });

  // Watched failing with the exactly-one-current-and-one-next check removed
  // from kindKeyProblems: a second games current was written and verified.
  await test("kind keys: a kind with a second current, a third key or a lone key is refused, by the writer and by --verify", () => {
    const cases = [
      [[...pairFiles("games"), kindFile({ kind: "games", role: "current", key_id: "astra-games-2026c" })], "exactly one current and one next"],
      [[kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a" })], "exactly one current and one next"],
      [[kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a" }), kindFile({ kind: "games", role: "current", key_id: "astra-games-2026b" })], "exactly one current and one next"],
    ];
    for (const [files, says] of cases) {
      const dir = sandboxWithRoot(`trust-kind-dup-${crypto.randomUUID()}`, TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
      const r = signTrust(dir, kindArgs(files));
      assert(r.status === 1, `${files.length} file(s): exit ${r.status}`);
      assert(r.stderr.includes(says), r.stderr);
      assert(!fs.existsSync(trustOut(dir)), `${files.length} file(s) wrote a document`);
    }
    const dir = sandboxWithRoot("trust-kind-dup-verify", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const v = resignedWith(dir, (s) => {
      s.kind_keys.splice(1, 0, {
        ...s.kind_keys[0],
        key_id: "astra-games-2026c",
        public_key: publicKeyBase64(crypto.generateKeyPairSync("ed25519").privateKey),
      });
    });
    assert(v.status === 1, `--verify exit ${v.status}`);
    assert(v.stderr.includes("exactly one current and one next"), v.stderr);
  });

  // Watched failing with the index_keys comparison removed from kindKeyProblems.
  await test("kind keys: a kind key that is also an index key is refused, by the writer and by --verify", () => {
    const indexPub = JSON.parse(fs.readFileSync(INDEX_PUB, "utf8")).public_key;
    const dir = sandboxWithRoot("trust-kind-index", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const r = signTrust(dir, kindArgs([
      kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a", public_key: indexPub }),
      kindFile({ kind: "games", role: "next", key_id: "astra-games-2026b" }),
    ]));
    assert(r.status === 1, `exit ${r.status}`);
    assert(r.stderr.includes("never goes in index_keys"), r.stderr);
    assert(!fs.existsSync(trustOut(dir)), "it wrote a document");
    const dir2 = sandboxWithRoot("trust-kind-index-verify", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const v = resignedWith(dir2, (s) => {
      s.kind_keys[1].public_key = s.index_keys[0].public_key;
    });
    assert(v.status === 1, `--verify exit ${v.status}`);
    assert(v.stderr.includes("never goes in index_keys"), v.stderr);
  });

  // Watched failing with each refusal commented out in turn.
  await test("kind keys: an unknown kind, an unknown role, a non-ed25519 key, a misnamed id, a key in two kinds and a TEST key are refused", () => {
    const shared = publicKeyBase64(crypto.generateKeyPairSync("ed25519").privateKey);
    const testPub = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "tools", "testkeys", "TEST-ONLY-DO-NOT-TRUST-index-2026a.pub.json"), "utf8"));
    const cases = [
      [[kindFile({ kind: "game", role: "current", key_id: "astra-game-2026a" }), kindFile({ kind: "game", role: "next", key_id: "astra-game-2026b" })], "is not one of"],
      [[kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a" }), kindFile({ kind: "games", role: "previous", key_id: "astra-games-2026b" })], "is not current or next"],
      [[kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a", algorithm: "rsa" }), kindFile({ kind: "games", role: "next", key_id: "astra-games-2026b" })], "a kind key is ed25519"],
      [[kindFile({ kind: "games", role: "current", key_id: "astra-packs-2026a" }), kindFile({ kind: "games", role: "next", key_id: "astra-games-2026b" })], "the index key's naming"],
      [[...pairFiles("games"), kindFile({ kind: "packs", role: "current", key_id: "astra-packs-2026a", public_key: shared }),
        kindFile({ kind: "packs", role: "next", key_id: "astra-packs-2026b" }), kindFile({ kind: "models", role: "current", key_id: "astra-models-2026a", public_key: shared }),
        kindFile({ kind: "models", role: "next", key_id: "astra-models-2026b" })], "one key is authorised for one kind"],
      [[kindFile({ kind: "games", role: "current", key_id: testPub.key_id, public_key: testPub.public_key }), kindFile({ kind: "games", role: "next", key_id: "astra-games-2026b" })], "TEST key"],
    ];
    for (const [files, says] of cases) {
      const dir = sandboxWithRoot(`trust-kind-shape-${crypto.randomUUID()}`, TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
      const r = signTrust(dir, kindArgs(files));
      assert(r.status === 1, `${says}: exit ${r.status}`);
      assert(r.stderr.includes(says), `${says}: ${r.stderr}`);
      assert(!fs.existsSync(trustOut(dir)), `${says}: wrote a document`);
    }
  });

  // Watched failing with the `carried` loop in kindKeysToWrite removed: the
  // re-sign without the files exited 0 and wrote a document with no kind_keys.
  await test("kind keys the published document carries are never dropped by omission; restated, they keep their not_before", () => {
    const dir = sandboxWithRoot("trust-kind-carry", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    const games = pairFiles("games");
    assert(signTrust(dir, kindArgs(games)).status === 0, "first signing");
    const before = fs.readFileSync(trustOut(dir), "utf8");
    const first = JSON.parse(before).signed.kind_keys;

    const dropped = signTrust(dir, []);
    assert(dropped.status === 1, `exit ${dropped.status}`);
    assert(dropped.stderr.includes("would drop it") && dropped.stderr.includes("astra-games-2026a"), dropped.stderr);
    assert(fs.readFileSync(trustOut(dir), "utf8") === before, "the refused signing changed the published document");

    const halfDropped = signTrust(dir, kindArgs([games[0]]));
    assert(halfDropped.status === 1 && halfDropped.stderr.includes("astra-games-2026b"), `half: ${halfDropped.status} ${halfDropped.stderr}`);

    const swapped = signTrust(dir, kindArgs([kindFile({ kind: "games", role: "current", key_id: "astra-games-2026a" }), games[1]]));
    assert(swapped.status === 1 && swapped.stderr.includes("a key id names one key for good"), `swapped: ${swapped.status} ${swapped.stderr}`);

    const kept = signTrust(dir, ["--serial", "50", ...kindArgs(games)]);
    assert(kept.status === 0, kept.stderr);
    const again = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed;
    assert(JSON.stringify(again.kind_keys) === JSON.stringify(first), `restated keys changed: ${JSON.stringify(again.kind_keys)}`);

    const unknownDrop = signTrust(dir, [...kindArgs(games), "--drop-kind-key", "astra-packs-2026a"]);
    assert(unknownDrop.status === 1 && unknownDrop.stderr.includes("authorises no kind key"), `unknown drop: ${unknownDrop.status} ${unknownDrop.stderr}`);

    const removed = signTrust(dir, ["--drop-kind-key", "astra-games-2026a", "--drop-kind-key", "astra-games-2026b"]);
    assert(removed.status === 0, `removed: ${removed.stderr}`);
    assert(removed.stderr.includes("DROPPED"), removed.stderr);
    const none = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed;
    assert(!("kind_keys" in none), "a document with no kind keys carries an empty kind_keys member");
  });

  // Watched failing with the kind-key block removed from the script:
  // sign-trust refused the re-sign (the guard above), so the allowlist could not widen.
  await test("ceremony-allowlist-workflow.sh carries the kind keys forward, not_before included", () => {
    const dir = sandboxWithRoot("trust-kind-allowlist", TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey);
    fs.copyFileSync(path.join(REPO_ROOT, "tools", "ceremony-allowlist-workflow.sh"), path.join(dir, "tools", "ceremony-allowlist-workflow.sh"));
    assert(signTrust(dir, kindArgs([...pairFiles("games"), ...pairFiles("commands")])).status === 0, "first signing");
    const first = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed.kind_keys;
    execFileSync("bash", ["tools/ceremony-allowlist-workflow.sh", TRUST_ROOT_A.file, "2".repeat(40)], { cwd: dir, stdio: "pipe" });
    const s = JSON.parse(fs.readFileSync(trustOut(dir), "utf8")).signed;
    assert(JSON.stringify(s.kind_keys) === JSON.stringify(first), `kind_keys ${JSON.stringify(s.kind_keys)}`);
    assert(s.reusable_workflow_shas.includes("2".repeat(40)), "the allowlist did not widen");
  });
}
