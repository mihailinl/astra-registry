#!/usr/bin/env node
// The alarm channel and the dead-man heartbeat, against a local stub.
//
// Two halves, and the second is the one that matters. The first asks that a
// working channel works: the message goes to the owner, the copy goes to
// KNICE, `delivered_at` comes back as the API's own time. The second asks what
// happens when it does not — a missing secret, a 500, `ok: false`, a 2xx with
// no time in it, a receiver that never answers — and every one of those has to
// end in a non-zero exit with no `delivered_at`, because the failure this
// whole area exists to prevent is an alarm that could not be sent looking
// exactly like nothing having gone wrong.
//
// No network: an http server on 127.0.0.1 stands in for api.telegram.org, and
// the receiver is a recording `fetch`. The heartbeat's stub is a function
// rather than a socket on purpose — what has to be true of it is WHICH URL it
// called, and a loopback server would have forced the https guard off to be
// testable at all.

import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { runAlert, credentialProblems, rfc3339, TELEGRAM_API } from "../alert.mjs";
import { postHeartbeat } from "../heartbeat.mjs";
import { renderVerdict, verdictProblems, runUrl, VERDICT_SCHEMA } from "../lib/alert-verdict.mjs";
import {
  CHECKS,
  MIN_BOUND_MINUTES,
  alertsEnvironmentSecrets,
  boundMinutes,
  secretName,
  tableProblems,
} from "../lib/alert-checks.mjs";

const REPO = path.resolve(import.meta.dirname, "..", "..");

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
  }
}

const quiet = { log: () => {}, error: () => {} };

const TOKEN = "1234567:AAHtesttokenNOBODYSHOULDEVERSEEthis";
const ENV = {
  ASTRA_ALERT_TELEGRAM_TOKEN: TOKEN,
  ASTRA_ALERT_CHAT_ID: "-1001",
  ASTRA_ALERT_COPY_CHAT_ID: "-1002",
};

const VERDICT = {
  schema: VERDICT_SCHEMA,
  check: "served-set",
  status: "red",
  codes: ["SERVE_85_DRIFT"],
  ids: ["astra-chess"],
  hexes: ["0123456789abcdef0123456789abcdef01234567"],
  run: "https://github.com/minice/astra-registry/actions/runs/42",
};

/**
 * A stand-in for api.telegram.org. `plan` decides what each call answers, so a
 * test can make the owner's chat work and KNICE's fail.
 */
function stubApi(plan = () => ({ status: 200, body: { ok: true, result: { date: 1789_000_000 } } })) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const call = { url: req.url, body: JSON.parse(raw || "{}") };
      calls.push(call);
      const answer = plan(call, calls.length);
      res.writeHead(answer.status, { "Content-Type": "application/json" });
      res.end(answer.raw ?? JSON.stringify(answer.body));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        base: `http://127.0.0.1:${server.address().port}`,
        calls,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

console.log("\nthe verdict grammar — what may reach a person's phone\n");

await test("an unknown member is refused, because an unrendered member is one nobody sees", () => {
  const problems = verdictProblems({ ...VERDICT, detail: "the ingest run said something about a stranger" });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /"detail" is not one this channel renders/);
});

await test("a code that is a sentence is not a code", () => {
  const problems = verdictProblems({ ...VERDICT, codes: ["the served list drifted from signed"] });
  assert.match(problems.join("\n"), /is not a fixed code/);
});

await test("§0.7's three hex lengths are carried and a fourth is not", () => {
  for (const n of [16, 40, 64]) {
    assert.deepEqual(verdictProblems({ ...VERDICT, hexes: ["a".repeat(n)] }), [],
      `${n} hex is a fingerprint, a commit or a digest and all three reach alerts`);
  }
  assert.match(verdictProblems({ ...VERDICT, hexes: ["a".repeat(41)] }).join(""), /41 hex characters/);
  assert.match(verdictProblems({ ...VERDICT, hexes: ["A".repeat(40)] }).join(""), /not lowercase hex/);
});

await test("a run URL that is not a github.com Actions run is refused", () => {
  for (const run of [
    "https://evil.example/minice/astra-registry/actions/runs/42",
    "https://github.com.attacker.net/a/b/actions/runs/42",
    "https://github.com/a/b/settings",
  ]) {
    assert.match(verdictProblems({ ...VERDICT, run }).join(""), /is not a github\.com Actions run URL/, run);
  }
});

await test("a plugin id is the one this repository already decides", () => {
  // Not a second copy of the pattern: `tools/lib/ids.mjs` says what an id is
  // here as everywhere else, so an id the registry refuses cannot be smuggled
  // into a message by way of the alarm path.
  assert.match(verdictProblems({ ...VERDICT, ids: ["../../etc"] }).join(""), /is not a plugin id/);
  assert.match(verdictProblems({ ...VERDICT, ids: ["Astra-Chess"] }).join(""), /is not a plugin id/);
});

await test("the rendered message holds the verdict's values and nothing else", () => {
  const text = renderVerdict(VERDICT);
  assert.equal(text, [
    "ASTRA REGISTRY ALARM",
    "check: served-set",
    "status: red",
    "codes: SERVE_85_DRIFT",
    "ids: astra-chess",
    "hex: 0123456789abcdef0123456789abcdef01234567",
    "run: https://github.com/minice/astra-registry/actions/runs/42",
  ].join("\n"));
});

await test("a forged GITHUB_SERVER_URL does not become a link in the message", () => {
  assert.equal(runUrl({
    GITHUB_SERVER_URL: "https://evil.example",
    GITHUB_REPOSITORY: "minice/astra-registry",
    GITHUB_RUN_ID: "42",
  }), null);
  assert.equal(runUrl({
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_REPOSITORY: "minice/astra-registry",
    GITHUB_RUN_ID: "42",
  }), "https://github.com/minice/astra-registry/actions/runs/42");
});

console.log("\nbot/alert.mjs — the channel, and every way it can fail to be one\n");

await test("the alarm reaches the owner's chat and the copy reaches KNICE's", async () => {
  const api = await stubApi();
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 0);
    assert.equal(out.delivered_at, rfc3339(1789_000_000));
    assert.equal(out.copy_delivered, true);
    assert.deepEqual(api.calls.map((c) => c.body.chat_id), ["-1001", "-1002"]);
    assert.equal(api.calls[0].body.text, api.calls[1].body.text, "KNICE gets the same page, not a summary of it");
    // No parse_mode: the API applies no markup, so no value can escape out of
    // an entity it was never put inside.
    assert.equal(api.calls[0].body.parse_mode, undefined);
  } finally {
    await api.close();
  }
});

await test("delivered_at is the API's time and never this machine's clock", async () => {
  const api = await stubApi(() => ({ status: 200, body: { ok: true, result: { date: 1700000000 } } }));
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.delivered_at, "2023-11-14T22:13:20Z");
    assert.match(out.delivered_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, "§0.7: whole seconds, Z");
  } finally {
    await api.close();
  }
});

await test("a 2xx with no result.date yields no delivered_at at all", async () => {
  const api = await stubApi(() => ({ status: 200, body: { ok: true, result: { message_id: 7 } } }));
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 1, "the API said nothing about when, and this run reported a delivery anyway");
    assert.equal(out.delivered_at, null, "TRUST-32 would otherwise gate publication on a time nobody reported");
  } finally {
    await api.close();
  }
});

await test("a non-2xx exits non-zero", async () => {
  // A body that would otherwise read as a success, so the ONLY thing that can
  // refuse this is the status check. An earlier version of this test sent a
  // 502 with an empty body and passed with the status check deleted, because
  // `ok: false` caught it instead.
  const api = await stubApi(() => ({ status: 502, body: { ok: true, result: { date: 1789_000_000 } } }));
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 1, "the Bot API refused the message and the run went green over it");
    assert.equal(out.delivered_at, null);
    assert.match(out.problems.join(""), /HTTP 502/);
  } finally {
    await api.close();
  }
});

await test("`ok: false` exits non-zero, whatever the status line said", async () => {
  const api = await stubApi(() => ({ status: 200, body: { ok: false, description: "chat not found" } }));
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 1, "Telegram answers 200 with `ok: false` for a chat that does not exist");
    assert.match(out.problems.join(""), /ok: false \(chat not found\)/);
  } finally {
    await api.close();
  }
});

await test("no failure message carries the bot token", async () => {
  const api = await stubApi(() => ({ status: 401, body: {} }));
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    const said = out.problems.join("\n");
    assert.ok(!said.includes(TOKEN), "the token is in the URL, so no message may quote the URL");
  } finally {
    await api.close();
  }
});

await test("a failed copy to KNICE never withholds delivered_at", async () => {
  const api = await stubApi((call, n) =>
    n === 1
      ? { status: 200, body: { ok: true, result: { date: 1789_000_000 } } }
      : { status: 500, body: {} });
  try {
    const out = await runAlert({ verdict: VERDICT, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 0, "the owner was paged; a failed copy must not hold a publication");
    assert.equal(out.delivered_at, rfc3339(1789_000_000));
    assert.equal(out.copy_delivered, false);
  } finally {
    await api.close();
  }
});

for (const [name] of [["ASTRA_ALERT_TELEGRAM_TOKEN"], ["ASTRA_ALERT_CHAT_ID"], ["ASTRA_ALERT_COPY_CHAT_ID"]]) {
  await test(`a missing ${name} sends nothing and exits non-zero`, async () => {
    const api = await stubApi();
    try {
      const env = { ...ENV };
      delete env[name];
      const out = await runAlert({ verdict: VERDICT, env, apiBase: api.base, log: quiet });
      assert.equal(out.code, 1,
        `a job with no ${name} exited 0: the alert path went quiet on a missing credential instead of red, ` +
        `which is the state where an estate with no alarm channel looks like an estate with nothing to report`);
      assert.equal(api.calls.length, 0, "nothing may be sent on a channel that is missing a credential");
      assert.match(out.problems.join(""), new RegExp(name));
      assert.match(out.problems.join(""), /environment `alerts`/);
    } finally {
      await api.close();
    }
  });
}

await test("a blank secret is a missing secret", () => {
  assert.equal(credentialProblems({ ...ENV, ASTRA_ALERT_CHAT_ID: "   " }).length, 1,
    "an unset GitHub secret interpolates to the empty string, so `is it defined` is not the question");
  assert.equal(credentialProblems(ENV).length, 0, "three good secrets must not read as a problem");
});

await test("--if-red checks a green verdict and sends nothing", async () => {
  const api = await stubApi();
  try {
    const green = { ...VERDICT, status: "green" };
    const out = await runAlert({ verdict: green, ifRed: true, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 0);
    assert.equal(out.alerted, false);
    assert.equal(api.calls.length, 0);
    // …and a green verdict that would not render is still red in CI, on the
    // run that had nothing to say rather than on the night it mattered.
    const bad = await runAlert({
      verdict: { ...green, codes: ["not a code"] }, ifRed: true, env: ENV, apiBase: api.base, log: quiet,
    });
    assert.equal(bad.code, 1);
  } finally {
    await api.close();
  }
});

await test("--ack with no acknowledgement URL sends no alarm at all", async () => {
  const api = await stubApi();
  try {
    const out = await runAlert({ verdict: VERDICT, ack: true, env: ENV, apiBase: api.base, log: quiet });
    assert.equal(out.code, 1, "the weekly alarm went out with no way to acknowledge it");
    assert.equal(api.calls.length, 0, "an alarm BOT-86 can never see acknowledged escalates for no reason");
    assert.match(out.problems.join(""), /ASTRA_DEADMAN_URL_ALARM_ACK/);
  } finally {
    await api.close();
  }
});

await test("the acknowledgement link comes from the secret, never from the verdict", async () => {
  const api = await stubApi();
  try {
    const env = { ...ENV, ASTRA_DEADMAN_URL_ALARM_ACK: "https://receiver.example/ping/ack-uuid" };
    const out = await runAlert({ verdict: VERDICT, ack: true, env, apiBase: api.base, log: quiet });
    assert.equal(out.code, 0);
    assert.match(api.calls[0].body.text, /\nacknowledge: https:\/\/receiver\.example\/ping\/ack-uuid$/);
  } finally {
    await api.close();
  }
});

await test("api.telegram.org is the only host this script names", () => {
  assert.equal(TELEGRAM_API, "https://api.telegram.org");
  const src = fs.readFileSync(path.join(REPO, "bot", "alert.mjs"), "utf8");
  const hosts = new Set([...src.matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0]));
  assert.deepEqual([...hosts], ["https://api.telegram.org"],
    "a second host in this file is a second place the alarm channel's credential could be sent");
});

await test("the entry point itself exits non-zero with no credentials", () => {
  // The exported function is what every other test above drives. This asks the
  // same of the thing a workflow actually runs, because `process.exit(await
  // main(...))` is one line nothing else covers and an alert step that exits 0
  // on a missing secret is the whole failure.
  const out = spawnSync(process.execPath, ["bot/alert.mjs", "--check-credentials"], {
    cwd: REPO,
    env: { PATH: process.env.PATH },
    encoding: "utf8",
  });
  assert.equal(out.status, 1,
    `node bot/alert.mjs --check-credentials exited ${out.status} with no secrets in the environment; ` +
    `an alert step that exits 0 on a missing secret is a green job that paged nobody`);
  assert.match(out.stderr, /ASTRA_ALERT_TELEGRAM_TOKEN is not set/);
  assert.match(out.stderr, /No alarm can leave this run until he has/);
});

console.log("\nbot/heartbeat.mjs — one whole URL per check, and no base anywhere\n");

function recorder(answer = { ok: true, status: 200 }) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return { ok: answer.ok, status: answer.status };
    },
  };
}

await test("the heartbeat posts to exactly the URL the check's own secret carries", async () => {
  const r = recorder();
  const env = { ASTRA_DEADMAN_URL_SERVED_SET: "https://receiver.example/ping/served-uuid" };
  const out = await postHeartbeat({ check: "served-set", env, fetchImpl: r.fetchImpl, log: quiet });
  assert.equal(out.code, 0, "a heartbeat for a check whose URL is right there did not go out");
  assert.deepEqual(r.calls.map((c) => c.url), ["https://receiver.example/ping/served-uuid"],
    "the URL posted to is not the secret's, so this script is composing one from something else");
  assert.equal(r.calls[0].init.method, "POST");
});

await test("a check name nothing in the table knows is refused before any POST", async () => {
  const r = recorder();
  const out = await postHeartbeat({
    check: "served-sets", env: { ASTRA_DEADMAN_URL_SERVED_SETS: "https://receiver.example/x" },
    fetchImpl: r.fetchImpl, log: quiet,
  });
  assert.equal(out.code, 1);
  assert.equal(r.calls.length, 0);
  assert.match(out.problems.join(""), /no receiver check called "served-sets"/);
});

await test("the registry refuses to post to a check that is another party's", async () => {
  // The half of attack M-5's rule this repository can enforce from inside:
  // even handed a URL, this script will not address a check whose poster is
  // somewhere else. `canary-tag` is the reachable case — B-T1.6 names it, and
  // its poster and its secret both live in the test repository. The two the
  // plugins service posts to cannot even be named yet, which is the stronger
  // form of the same refusal.
  const r = recorder();
  const out = await postHeartbeat({
    check: "canary-tag",
    env: { ASTRA_DEADMAN_URL_CANARY_TAG: "https://receiver.example/ping/canary" },
    fetchImpl: r.fetchImpl,
    log: quiet,
  });
  assert.equal(out.code, 1);
  assert.equal(r.calls.length, 0);
  assert.match(out.problems.join(""), /posted to by test-repository/);
  for (const check of CHECKS.filter((c) => c.party === "plugins-service")) {
    assert.equal(check.name, null, "the two service check names are minice-be's to supply (§1.3 row 8.1)");
  }
});

await test("a missing ping secret fails the step and names it", async () => {
  const r = recorder();
  const out = await postHeartbeat({ check: "detectors", env: {}, fetchImpl: r.fetchImpl, log: quiet });
  assert.equal(out.code, 1,
    "a check that was never pinged looks exactly like a check that is healthy, so a heartbeat that cannot be " +
    "posted has to be a red step");
  assert.equal(r.calls.length, 0);
  assert.match(out.problems.join(""), /ASTRA_DEADMAN_URL_DETECTORS is not set/);
  assert.match(out.problems.join(""), /WHOLE ping URL/);
});

await test("a ping URL that is not https is refused", async () => {
  const r = recorder();
  const out = await postHeartbeat({
    check: "detectors", env: { ASTRA_DEADMAN_URL_DETECTORS: "http://receiver.example/ping/x" },
    fetchImpl: r.fetchImpl, log: quiet,
  });
  assert.equal(out.code, 1);
  assert.equal(r.calls.length, 0);
});

await test("a receiver that answers non-2xx fails the step", async () => {
  const r = recorder({ ok: false, status: 503 });
  const out = await postHeartbeat({
    check: "detectors", env: { ASTRA_DEADMAN_URL_DETECTORS: "https://receiver.example/ping/x" },
    fetchImpl: r.fetchImpl, log: quiet,
  });
  assert.equal(out.code, 1,
    "silence at the receiver and red in the run have to agree; a swallowed 503 is the receiver paging about a " +
    "job whose own log says it succeeded");
  assert.match(out.problems.join(""), /HTTP 503/);
});

await test("the start signal is its own secret and not a suffix on the success one", async () => {
  const r = recorder();
  const env = {
    ASTRA_DEADMAN_URL_ALARM_ACK: "https://receiver.example/ping/ack",
    ASTRA_DEADMAN_URL_ALARM_ACK_START: "https://receiver.example/ping/ack/start",
  };
  const out = await postHeartbeat({ check: "alarm-ack", signal: "start", env, fetchImpl: r.fetchImpl, log: quiet });
  assert.equal(out.code, 0, "BOT-86's start signal did not go out, so the 48-hour clock never starts");
  assert.deepEqual(r.calls.map((c) => c.url), ["https://receiver.example/ping/ack/start"]);

  const r2 = recorder();
  const partial = await postHeartbeat({
    check: "alarm-ack", signal: "start",
    env: { ASTRA_DEADMAN_URL_ALARM_ACK: env.ASTRA_DEADMAN_URL_ALARM_ACK },
    fetchImpl: r2.fetchImpl, log: quiet,
  });
  assert.equal(partial.code, 1, "no URL is composed from the one that is present");
  assert.equal(r2.calls.length, 0);
});

await test("a signal a check does not take is refused", async () => {
  const r = recorder();
  const out = await postHeartbeat({
    check: "detectors", signal: "start",
    env: { ASTRA_DEADMAN_URL_DETECTORS_START: "https://receiver.example/x" },
    fetchImpl: r.fetchImpl, log: quiet,
  });
  assert.equal(out.code, 1);
  assert.equal(r.calls.length, 0);
});

await test("this script holds no URL of its own at all", () => {
  const src = fs.readFileSync(path.join(REPO, "bot", "heartbeat.mjs"), "utf8");
  const hosts = [...src.matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0]);
  assert.deepEqual(hosts, [],
    "a base URL in this file would be a project-level ping key: whoever read one Actions secret could silence " +
    "the check that pages when the plugins service's own box is gone");
});

console.log("\nthe receiver's check table — the list the owner's act is built from\n");

await test("the table is sound", () => {
  assert.deepEqual(tableProblems(), []);
  assert.ok(CHECKS.length >= 10, `only ${CHECKS.length} checks; the list the receiver is built from has shrunk`);
});

await test("every bound is the longer of 3 × the interval and 90 minutes", () => {
  for (const check of CHECKS) {
    const bound = boundMinutes(check);
    if (check.interval_seconds === null) {
      assert.equal(bound, null, `${check.name ?? check.name_pending} has no interval, so it can have no bound yet`);
      continue;
    }
    assert.equal(bound, Math.max(MIN_BOUND_MINUTES, (check.interval_seconds / 60) * 3));
    assert.ok(bound >= MIN_BOUND_MINUTES);
  }
  // The measured case BOT-85's Why names: 3 × 600 s is 30 minutes, and
  // ordinary cron lateness crosses it, so the moderation run's bound is the
  // floor rather than three intervals.
  assert.equal(boundMinutes(CHECKS.find((c) => c.name === "moderation-run")), 90);
  assert.equal(boundMinutes(CHECKS.find((c) => c.name === "detectors")), 180);
});

await test("the two service-posted checks are created disarmed and not yet armed", () => {
  const service = CHECKS.filter((c) => c.party === "plugins-service");
  assert.equal(service.length, 2, "the reach assertion's floor is the number of service check names recorded");
  for (const check of service) {
    assert.equal(check.created_disarmed, true,
      "armed from their first minute they would page every ninety minutes through the whole of R1, and the " +
      "repair reached for on the third night is the one repair that must never be reached for");
    assert.equal(check.armed_at, null, "nothing has posted to it yet; RC-R1-12's exit note reports this");
  }
});

await test("a check another party posts to is created disarmed", () => {
  // The 2026-09-22 rule — armed at creation only if its poster runs on a live
  // schedule — extended on 2026-09-23 to every party but `registry`
  // (dev/couplings.md entry 25; the block above CHECKS). A poster on another
  // machine or in another repository has no schedule this repository can
  // read, so nothing here can show it runs, and a check armed on that promise
  // pages from R1 about a silence that is not an outage. `probe` and
  // `canary-tag` were the two that said otherwise, while the probe host was
  // unchosen and the test repository did not exist.
  const outside = CHECKS.filter((c) => c.party !== "registry");
  assert.ok(outside.length >= 4, `only ${outside.length} checks another party posts to; the table has shrunk`);
  assert.ok(outside.some((c) => c.party === "probe-host") && outside.some((c) => c.party === "test-repository"),
    "the probe host's and the test repository's checks are what this is about; one of them has gone");
  const armed = outside.filter((c) => c.created_disarmed !== true).map((c) => `${c.name ?? c.name_pending} (${c.party})`);
  assert.deepEqual(armed, [],
    "created armed with a poster nothing here can see running: set `created_disarmed: true` in " +
    "bot/lib/alert-checks.mjs; it arms at its first post, recorded in `armed_at`");
});

// Which REGISTRY checks are created disarmed is not asked here. It was, as "no
// registry check is created disarmed", with the failure message "has a poster
// in this repository" — false for five of the thirteen, and its reason ("every
// other check's poster lands in the same step as the check") false with it
// (dev/couplings.md entry 25). The rule that replaced it is computed from the
// workflow files, so it lives with them: `bot/tests/workflows.test.mjs`, "a
// registry check is armed exactly when a workflow here posts to it on a live
// schedule".

await test("environment `alerts` is given no secret that addresses another party's check", () => {
  const secrets = alertsEnvironmentSecrets();
  assert.ok(secrets.length >= 13, `only ${secrets.length} secrets; the owner's list has lost entries`);
  for (const check of CHECKS) {
    if (check.party === "registry") continue;
    if (check.name === null) continue;
    assert.ok(!secrets.includes(secretName(check.name)),
      `${check.name} is ${check.party}'s, and no credential the registry holds may resolve it`);
  }
  assert.ok(secrets.includes("ASTRA_DEADMAN_URL_ALARM_ACK_START"), "BOT-86's start signal needs its own whole URL");
  // The rule is "no secret carries a BASE URL" — `ASTRA_DEADMAN_BASE_URL`,
  // attack M-5's project-level ping key. The first spelling was a substring
  // match for `BASE`, which is a different sentence: the day `baseline-names`
  // was added to the table (B-T3.7b, 2026-09-19) this went red over
  // `ASTRA_DEADMAN_URL_BASELINE_NAMES`, a secret carrying one check's whole
  // URL and nothing like a base. A check that is red about a correct name
  // teaches its next reader to rename around it, and the rename after that is
  // the one that mattered — so it asks the question it means: a secret whose
  // name ENDS in a base rather than in a check.
  assert.ok(!secrets.some((s) => /_BASE(_URL)?$/.test(s) || s === "ASTRA_DEADMAN_BASE_URL"),
    "there is no base URL anywhere in this estate");
});

await test("the heartbeat dials the secret's bytes, and composes nothing onto them", async () => {
  // The rule above asks a question about secret NAMES. This one asks it about
  // behaviour, and the two are not the same sentence: a script can hold no
  // secret called `..._BASE` and still build a URL out of one.
  //
  // It is here because the protection was an accident until tonight. This
  // script takes whole URLs and appends nothing, which was decided against
  // base URLs (attack M-5) and not against composition in general — so it
  // happened to be safe rather than being made safe, and the next suffix
  // anybody adds is the moment the accident stops covering us.
  //
  // What composition costs, measured by minice-be on their own sink tonight
  // and not hypothetical: `rstrip("/") + "/fail"` applied to a ping URL ending
  // `…/u#x` composes `…/u#x/fail`, whose FRAGMENT is `x/fail` — and a fragment
  // is never sent on the wire. So the degraded post fetches the healthy URL,
  // one character in a capability file makes the check permanently green, and
  // nothing anywhere compares the two. A composed URL is a second grammar
  // standing beside the parser, which is the same sentence as their SSRF and
  // as comparing two URLs as text.
  //
  // So: for every shape that composition mangles, the dialled URL must be the
  // secret's bytes, unchanged.
  const shapes = [
    ["a fragment", "https://ping.example/u#x"],
    ["a query", "https://ping.example/u?token=abc"],
    ["a trailing slash", "https://ping.example/u/"],
    ["no path at all", "https://ping.example"],
    ["a query and a fragment", "https://ping.example/u?a=1#frag"],
    ["a percent-encoded segment", "https://ping.example/u%2Fv"],
  ];
  for (const [what, secret] of shapes) {
    let dialled = null;
    const res = await postHeartbeat({
      check: "served-set",
      env: { ASTRA_DEADMAN_URL_SERVED_SET: secret },
      fetchImpl: async (u) => { dialled = u; return { ok: true, status: 200 }; },
      log: { log() {}, error() {} },
    });
    assert.equal(res.code, 0, `${what}: ${res.problems.join("; ")}`);
    assert.equal(dialled, secret,
      `${what}: the heartbeat dialled ${JSON.stringify(dialled)} for a secret carrying ` +
      `${JSON.stringify(secret)}. One whole URL per check means the bytes the owner pasted, not a URL built ` +
      `from them — and a fragment or a query is where the difference stops being visible on the wire.`);
  }
});

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}  bot/tests/alert.test.mjs, ${failures} failed`);
if (failures) process.exit(1);
