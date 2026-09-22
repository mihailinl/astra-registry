// The exit codes the workflows depend on: build-index --check and
// build-revocations --check clean on the committed tree, sign-revocations
// refusing to write a TEST signature into registry/ and refusing to emit an
// unsigned file with no key, validate.mjs exiting 1 without --allow-staging —
// and bot/heartbeat.mjs, run as the alert action runs it, posting from a sound
// table and refusing, by the guard's name, to post from one that is not.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { REPO_ROOT } from "../lib/sources.mjs";
import { test, assert, assertEqual, tmp } from "./harness.mjs";
import { TEST_INDEX_KEY } from "./fixtures.mjs";

// ── the heartbeat, as `.github/actions/alert` runs it (gap 23) ──────────────
//
// `bot/tests/alert.test.mjs` holds the committed receiver table to three
// guards — `tableProblems`, `boundMinutes`, `alertsEnvironmentSecrets` — and
// until gap 23 closed no alert job asked any of them: the suite proved the
// table on `main`, and nothing proved the table a job dials from. They are
// asked now inside `postHeartbeat`, and what has to stay true is that the
// COMMAND the action runs reaches them. An in-process call would prove the
// function and not the path, so these run the CLI, with the arguments the
// action passes, out of a copy of exactly the files the action's own first
// step says its sparse checkout holds.
//
// No network: a preload replaces `fetch` with a recorder that answers 200, so
// "posted" means the recorder saw one POST to the secret's bytes, and
// "refused" means it saw none.

const ACTION = path.join(REPO_ROOT, ".github", "actions", "alert", "action.yml");

/** Exactly one match or a throw: an anchor that matched nothing is a test that asks nothing. */
function once(text, re, what) {
  const hits = [...text.matchAll(new RegExp(re.source, `${re.flags.replace("g", "")}g`))];
  if (hits.length !== 1) throw new Error(`${what}: expected exactly one match of ${re}, found ${hits.length}`);
  return hits[0];
}

/**
 * The action's sparse checkout, as its first step lists it — and a throw
 * unless the action still runs the heartbeat the two ways these tests do, so
 * that a change to how the action calls the CLI is a red here and not a test
 * of a command nobody runs any more.
 */
function actionFiles() {
  const yml = fs.readFileSync(ACTION, "utf8");
  once(yml, /^\s*node bot\/heartbeat\.mjs --check "\$ASTRA_ALERT_CHECK"\s*$/m, "the action's heartbeat step");
  once(yml, /^\s*node bot\/heartbeat\.mjs --check "\$ASTRA_ALERT_ACK_CHECK" --signal start\s*$/m,
    "the action's start signal");
  return once(yml, /for f in ([^;\n]+); do/, "the action's list of the scripts it runs")[1].trim().split(/\s+/);
}

/** A copy of the alert job's checkout, with `tail` appended to its table module. */
function alertCheckout(name, tail = "") {
  const dir = path.join(tmp, `alert-checkout-${name}`);
  fs.rmSync(dir, { recursive: true, force: true });
  const files = actionFiles();
  assert(files.includes("bot/heartbeat.mjs") && files.includes("bot/lib/alert-checks.mjs"),
    `the action's checkout list no longer names the heartbeat and its table: ${files.join(" ")}`);
  for (const rel of files) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(dir, rel));
  }
  if (tail) {
    const table = path.join(dir, "bot", "lib", "alert-checks.mjs");
    const sha = () => crypto.createHash("sha256").update(fs.readFileSync(table)).digest("hex");
    const before = sha();
    fs.appendFileSync(table, `\n${tail}\n`);
    assert(sha() !== before, `the ${name} mutation left the copied bot/lib/alert-checks.mjs byte-identical`);
  }
  return dir;
}

/** `node bot/heartbeat.mjs <args>` in `cwd`, with one whole ping URL in its environment and a recorder for `fetch`. */
function heartbeat(cwd, args, secret, url) {
  const recorder = path.join(tmp, "heartbeat-receiver.mjs");
  fs.writeFileSync(
    recorder,
    "globalThis.fetch = async (url, init = {}) => {\n" +
    "  process.stdout.write(`receiver ${init.method ?? \"GET\"} ${url}\\n`);\n" +
    "  return { ok: true, status: 200 };\n" +
    "};\n",
  );
  const r = spawnSync(
    process.execPath,
    ["--import", pathToFileURL(recorder).href, "bot/heartbeat.mjs", ...args],
    { cwd, encoding: "utf8", env: { PATH: process.env.PATH, [secret]: url } },
  );
  return {
    status: r.status,
    stderr: r.stderr,
    posts: String(r.stdout).split("\n").filter((l) => l.startsWith("receiver ")),
  };
}

/** A table the named guard refuses posts nothing, and the step says which guard. */
function refusedBy(guard, tail) {
  const out = heartbeat(alertCheckout(guard, tail), ["--check", "signer"],
    "ASTRA_DEADMAN_URL_SIGNER", "https://ping.example/signer");
  assertEqual(out.posts.join("\n"), "", `the heartbeat posted from a table ${guard} refuses`);
  assertEqual(out.status, 1, `the heartbeat did not fail on a table ${guard} refuses; stderr: ${out.stderr}`);
  assert(out.stderr.includes(`FAIL  ${guard}: `), `the refusal does not name ${guard}; stderr: ${out.stderr}`);
}

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

  await test("`heartbeat.mjs`, run as the alert action runs it, posts from the committed table", () => {
    // The control for the three refusals below, and a check of this tree in
    // its own right: in the committed checkout AND in a copy of the action's
    // sparse one, both of the action's command shapes post exactly once, to
    // the secret's bytes. Without it, the `exit 1` below could be a copy that
    // cannot run at all.
    for (const [where, dir] of [["the committed tree", REPO_ROOT], ["the action's sparse checkout", alertCheckout("sound")]]) {
      const ran = heartbeat(dir, ["--check", "signer"], "ASTRA_DEADMAN_URL_SIGNER", "https://ping.example/signer");
      assertEqual(ran.status, 0, `--check signer failed in ${where}; stderr: ${ran.stderr}`);
      assertEqual(ran.posts.join("\n"), "receiver POST https://ping.example/signer", `--check signer in ${where}`);
      const start = heartbeat(dir, ["--check", "alarm-ack", "--signal", "start"],
        "ASTRA_DEADMAN_URL_ALARM_ACK_START", "https://ping.example/alarm-ack/start");
      assertEqual(start.status, 0, `--check alarm-ack --signal start failed in ${where}; stderr: ${start.stderr}`);
      assertEqual(start.posts.join("\n"), "receiver POST https://ping.example/alarm-ack/start",
        `--check alarm-ack --signal start in ${where}`);
    }
  });

  await test("`heartbeat.mjs` refuses to post from a table `tableProblems` refuses", () => {
    // A registry check listed twice: one of the two is never created, and the
    // job posting to the other believes it is posting to both.
    refusedBy("tableProblems", "CHECKS.push({ ...CHECKS.find((c) => c.party === \"registry\") });");
  });

  await test("`heartbeat.mjs` refuses to post from a table whose `boundMinutes` falls under BOT-85's floor", () => {
    // An interval that is not a number of seconds: no bound comes out of it,
    // and `tableProblems` does not look at intervals at all.
    refusedBy("boundMinutes",
      "CHECKS.find((c) => c.party === \"registry\" && typeof c.interval_seconds === \"number\")" +
      ".interval_seconds = \"hourly\";");
  });

  await test("`heartbeat.mjs` refuses to post from a table whose `alertsEnvironmentSecrets` resolves another party's check", () => {
    // Two spellings meeting, which `tableProblems` cannot see: a service check
    // named `<registry check>-start` has the secret name of that registry
    // check's start signal, so environment `alerts` would hold its ping URL.
    refusedBy("alertsEnvironmentSecrets",
      "CHECKS.find((c) => c.party === \"plugins-service\").name = " +
      "`${CHECKS.find((c) => c.party === \"registry\" && c.signals.includes(\"start\")).name}-start`;");
  });
}
