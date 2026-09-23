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

// ── the weekly drill, through the alert action's own bash (2026-09-23) ──────
//
// The owner chose ONE alarm group, holding him and KNICE, so the channel he is
// about to create holds the bot token and the alarm chat and no copy chat.
// `bot/tests/alert.test.mjs` proves `runAlert` sends that page once. What it
// cannot prove is the path a workflow takes to it: the action's `channel` step
// decides in bash, before the alarm step runs, whether a channel exists and
// whether it is whole — and until this commit that step counted "two of the
// three secrets" as HALF-CONFIGURED and failed the drill on exactly the
// environment the owner chose, with every unit test of `runAlert` green.
//
// So these run the steps themselves: the drill's own verdict step out of
// `alarm-drill.yml`, then the action's `channel`, alarm and heartbeat steps out
// of `action.yml`, each under bash in a copy of the job's sparse checkout, in
// the order and under the conditions the runner applies — and the drill's
// assertion step when its `if:` would hold. `fetch` is a preload that answers
// as the Bot API and the receiver do and prints what it was asked, so "sent
// once" is a count of requests and not a reading of a log line.

const DRILL = path.join(REPO_ROOT, ".github", "workflows", "alarm-drill.yml");

/**
 * The `run: |` script of the one step in `yml` that `pick` selects, dedented.
 * Throws unless exactly one step matches and it has a script, and unless the
 * script holds no `${{ }}` once `subst` is applied — a template run here would
 * be a test of text, not of the script a runner executes.
 */
function stepScript(yml, pick, what, subst = {}) {
  const lines = yml.split("\n");
  const starts = lines.map((l, i) => (/^\s+- (name|uses):/.test(l) ? i : -1)).filter((i) => i >= 0);
  const steps = starts.map((s, k) => lines.slice(s, k + 1 < starts.length ? starts[k + 1] : lines.length));
  const hits = steps.filter(pick);
  if (hits.length !== 1) throw new Error(`${what}: expected exactly one step, found ${hits.length}`);
  const step = hits[0];
  const at = step.findIndex((l) => /^\s+run:\s*\|\s*$/.test(l));
  if (at < 0) throw new Error(`${what}: the step has no \`run: |\` script`);
  const indent = /^\s*/.exec(step[at])[0].length;
  const body = [];
  for (const l of step.slice(at + 1)) {
    if (l.trim() !== "" && /^\s*/.exec(l)[0].length <= indent) break;
    body.push(l);
  }
  const strip = Math.min(...body.filter((l) => l.trim()).map((l) => /^\s*/.exec(l)[0].length));
  let script = body.map((l) => l.slice(strip)).join("\n");
  for (const [from, to] of Object.entries(subst)) {
    if (!script.includes(from)) throw new Error(`${what}: the script no longer holds ${from}`);
    script = script.split(from).join(to);
  }
  if (script.includes("${{")) throw new Error(`${what}: the script still holds a \${{ }} expression`);
  return script;
}

const byId = (id) => (step) => step.some((l) => new RegExp(`^\\s+id:\\s*${id}\\s*$`).test(l));
const byName = (name) => (step) => step.some((l) => l.trim() === `- name: ${name}`);
const byLine = (needle) => (step) => step.some((l) => l.trim() === needle);

/**
 * The drill, as the runner would run it, with these channel secrets. Returns
 * whether the job ended green, every Bot API `sendMessage` by chat id, every
 * receiver POST, and each step's exit and output.
 */
function drill(name, secrets) {
  const action = fs.readFileSync(ACTION, "utf8");
  const workflow = fs.readFileSync(DRILL, "utf8");
  const dir = alertCheckout(`drill-${name}`);
  const recorder = path.join(tmp, "drill-fetch.mjs");
  fs.writeFileSync(
    recorder,
    "globalThis.fetch = async (url, init = {}) => {\n" +
    "  const u = String(url);\n" +
    "  if (u.startsWith(\"https://api.telegram.org/bot\") && u.endsWith(\"/sendMessage\")) {\n" +
    "    process.stdout.write(`telegram sendMessage ${JSON.stringify(JSON.parse(init.body).chat_id)}\\n`);\n" +
    "    return { ok: true, status: 200, json: async () => ({ ok: true, result: { message_id: 1, date: 1789000000 } }) };\n" +
    "  }\n" +
    "  process.stdout.write(`receiver ${init.method ?? \"GET\"} ${u}\\n`);\n" +
    "  return { ok: true, status: 200 };\n" +
    "};\n",
  );
  const output = path.join(dir, "github-output");
  const base = {
    PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH}`,
    NODE_OPTIONS: `--import=${pathToFileURL(recorder).href}`,
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: path.join(dir, "github-step-summary"),
    ASTRA_DEADMAN_URL_ALARM_DRILL: "https://ping.example/alarm-drill",
    ASTRA_DEADMAN_URL_ALARM_ACK: "https://ping.example/alarm-ack",
    ASTRA_DEADMAN_URL_ALARM_ACK_START: "https://ping.example/alarm-ack-start",
    ...secrets,
  };
  const ran = [];
  const step = (label, script, env = {}) => {
    fs.writeFileSync(output, "");
    const r = spawnSync("bash", ["-c", script], { cwd: dir, encoding: "utf8", env: { ...base, ...env } });
    assert(r.error === undefined, `${label}: bash did not run (${r.error})`);
    const out = { label, status: r.status, stdout: r.stdout, stderr: r.stderr, outputs: fs.readFileSync(output, "utf8") };
    ran.push(out);
    return out;
  };

  const verdict = step("the synthetic alarm", stepScript(workflow, byName("The synthetic alarm BOT-86 sends"),
    "alarm-drill.yml's verdict step", {
      "${{ github.server_url }}": "https://github.com",
      "${{ github.repository }}": "mihailinl/astra-registry",
      "${{ github.run_id }}": "1",
    }));
  let green = verdict.status === 0;
  let configured = "";
  if (green) {
    const channel = step("channel", stepScript(action, byId("channel"), "the action's channel step"));
    configured = /^configured=(.*)$/m.exec(channel.outputs)?.[1] ?? "";
    green = channel.status === 0;
  }
  if (green && configured === "true") {
    const alarm = step("alarm", stepScript(action, byId("alarm"), "the action's alarm step"),
      { ASTRA_ALERT_VERDICT: "verdict.json", ASTRA_ALERT_ACK_CHECK: "alarm-ack" });
    green = alarm.status === 0;
    if (green) {
      const beat = step("heartbeat", stepScript(action, byLine('node bot/heartbeat.mjs --check "$ASTRA_ALERT_CHECK"'),
        "the action's heartbeat step"), { ASTRA_ALERT_CHECK: "alarm-drill", ASTRA_ALERT_NO_HEARTBEAT: "" });
      green = beat.status === 0;
    }
  }
  // The drill's own assertion, under its own condition: every step before it
  // succeeded (the implicit `success()`) and the channel is not configured.
  if (green && configured !== "true") {
    const proved = step("assertion", stepScript(workflow, byName("A drill that sent nothing proved nothing"),
      "alarm-drill.yml's assertion step"));
    green = proved.status === 0;
  }
  const lines = ran.flatMap((r) => r.stdout.split("\n"));
  return {
    green,
    configured,
    ran,
    sends: lines.filter((l) => l.startsWith("telegram sendMessage ")).map((l) => JSON.parse(l.slice(21))),
    posts: lines.filter((l) => l.startsWith("receiver ")),
    said: ran.map((r) => `${r.label} exit ${r.status}\n${r.stdout}${r.stderr}`).join("\n"),
  };
}

const TOKEN = "1234567:AAHselftestNOTAREALTOKENatall";

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

  await test("`heartbeat.mjs` posts from a table holding a row whose name another party still owes", () => {
    // Until 2026-09-23 the committed table held two rows with `name: null` and
    // a `name_pending` note — the plugins service's, before minice-e4 named
    // them — so the control above proved in passing that a job dials from a
    // table holding one. Naming them removed the case from the committed
    // tree, and with it the only proof that `tableRefusals` steps over a row
    // with no name rather than building a secret name out of `null`, which
    // throws and fails every alert job in the estate. So it is built here,
    // from a committed row, as the next party owing a name would list it.
    const tail =
      "{ const owed = CHECKS.find((c) => c.party === \"plugins-service\"); " +
      "owed.name = null; owed.name_pending = \"SYNTHETIC: a check name another party still owes\"; }";
    const ran = heartbeat(alertCheckout("pending-name", tail), ["--check", "signer"],
      "ASTRA_DEADMAN_URL_SIGNER", "https://ping.example/signer");
    assertEqual(ran.status, 0, `--check signer failed beside a pending row; stderr: ${ran.stderr}`);
    assertEqual(ran.posts.join("\n"), "receiver POST https://ping.example/signer", "--check signer beside a pending row");
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

  await test("the drill, through the alert action's own bash, is GREEN on one group with no copy chat and sends the page once", () => {
    // The owner's environment. Red before 2026-09-23's change, at the channel
    // step, as HALF-CONFIGURED: the copy chat was required.
    const d = drill("one-group", { ASTRA_ALERT_TELEGRAM_TOKEN: TOKEN, ASTRA_ALERT_CHAT_ID: "-1001" });
    assert(d.green, `the drill is red on the owner's one-group channel:\n${d.said}`);
    assertEqual(d.configured, "true", "the channel step did not report a configured channel");
    assertEqual(JSON.stringify(d.sends), JSON.stringify(["-1001"]), `one group is one message:\n${d.said}`);
    assert(/^delivered_at=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/m.test(d.ran.find((r) => r.label === "alarm").stdout),
      `the alarm step printed no delivered_at, so TRUST-32 has nothing to gate on:\n${d.said}`);
    assertEqual(d.posts.join("\n"),
      "receiver POST https://ping.example/alarm-ack-start\nreceiver POST https://ping.example/alarm-drill",
      "BOT-86's start signal and BOT-85's heartbeat, in that order, after the alarm");
  });

  await test("the drill sends a copy chat that IS the alarm chat once, and a separate copy chat its own copy", () => {
    const same = drill("same-chat", {
      ASTRA_ALERT_TELEGRAM_TOKEN: TOKEN, ASTRA_ALERT_CHAT_ID: "-1001", ASTRA_ALERT_COPY_CHAT_ID: "-1001",
    });
    assert(same.green, `the drill is red with the copy chat set to the alarm chat:\n${same.said}`);
    assertEqual(JSON.stringify(same.sends), JSON.stringify(["-1001"]),
      `a copy chat that is the alarm chat paged it ${same.sends.length} times`);
    const two = drill("separate", {
      ASTRA_ALERT_TELEGRAM_TOKEN: TOKEN, ASTRA_ALERT_CHAT_ID: "-1001", ASTRA_ALERT_COPY_CHAT_ID: "-1002",
    });
    assert(two.green, `the drill is red with a separate copy chat:\n${two.said}`);
    assertEqual(JSON.stringify(two.sends), JSON.stringify(["-1001", "-1002"]),
      "a separate copy chat gets its copy, after the alarm chat");
  });

  await test("the drill is RED and sends nothing with no channel at all, and with a copy chat and nothing else", () => {
    // A drill that sent nothing proved nothing. With no channel secret the
    // action is green and the drill's own last step is the red one; with a
    // copy chat standing alone the channel step is, as half-configured.
    const none = drill("none", {});
    assert(!none.green, `the drill is green with no alarm channel:\n${none.said}`);
    assertEqual(none.sends.length + none.posts.length, 0, `something was sent with no channel:\n${none.said}`);
    assertEqual(none.configured, "false", "no channel secret at all is the unconfigured state");
    assertEqual(none.ran.at(-1).label, "assertion", `the drill went red somewhere other than its assertion:\n${none.said}`);

    const alone = drill("copy-alone", { ASTRA_ALERT_COPY_CHAT_ID: "-1002" });
    assert(!alone.green, `the drill is green with only a copy chat:\n${alone.said}`);
    assertEqual(alone.sends.length + alone.posts.length, 0, `something was sent from half a channel:\n${alone.said}`);
    const channel = alone.ran.find((r) => r.label === "channel");
    assertEqual(channel?.status, 1, `the channel step did not refuse half a channel:\n${alone.said}`);
    for (const needle of ["HALF-CONFIGURED", "ASTRA_ALERT_TELEGRAM_TOKEN is not set", "ASTRA_ALERT_CHAT_ID is not set"]) {
      assert(`${channel.stdout}${channel.stderr}`.includes(needle), `the channel step never said ${needle}:\n${alone.said}`);
    }
  });
}
