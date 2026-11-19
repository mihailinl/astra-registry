// Phase 2 step 2: sign.yml's assert-only export check
// (tools/signer/export-assert.mjs) and its own alert. Equal is quiet; a
// mismatch at the same serial, a non-bot commit that no merged pull request
// explains, and an unreachable export each raise a code; the service at
// another serial and a merged pull request are notes; an unset URL is "not
// asked" and never "equal"; each foreign commit pages once however many heads
// it stays in range for; and nothing here can stop the signature.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { alertDecision } from "../alert.mjs";
import { stubExport } from "../../tools/export-stub.mjs";
import { stateSha256 } from "../../tools/lib/export-state.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { composeVerdict } from "../../tools/served-set/compose.mjs";
import {
  BOT_IDENTITIES, CODES, EXPORT_URL_VAR, MAX_EXPORT_BYTES, assertExport, exportUrl, fetchExport, foreignCommits,
  mergedPullOf, readCapped,
} from "../../tools/signer/export-assert.mjs";
import { BOT, HUMAN, exportHistory } from "./fixtures/export-history.mjs";

const ORIGIN = "https://api.minice.ai";
const ASKED = (serial) => `${ORIGIN}/plugins/v1/export?serial=${serial}`;

/** main's history with a `signed` branch whose one commit signed c2. */
function withSigned(name = "export-assert") {
  const h = exportHistory(name);
  h.git(["checkout", "-q", "--orphan", "signed"]);
  h.git(["rm", "-rq", "--cached", "."]);
  h.commit(`signed: catalogue 2\n\nSource-Commit: ${h.commits.c2}\nSigner: sign.yml\n`);
  h.git(["checkout", "-qf", "main"]);
  return h;
}

/** A service answering `body` with `status`, counting what was minted and fetched. */
function service(body, { status = 200, raw = null } = {}) {
  const calls = { mint: 0, fetch: [] };
  return {
    calls,
    mint: async () => { calls.mint++; return { token: "test-token", claims: {} }; },
    fetchImpl: async (url, init) => {
      calls.fetch.push({ url, auth: init.headers.Authorization });
      return new Response(raw ?? JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    },
  };
}

const quiet = { log() {} };
const noPulls = async () => ({ merged: null, error: null });
const ask = (h, extra) => assertExport({
  root: h.dir, sourceCommit: h.commits.c4, signedRef: "signed", log: quiet, pullOf: noPulls, ...extra,
});
const env = { [EXPORT_URL_VAR]: ORIGIN };

/** c4's export with one file changed and the digest honestly recomputed: same serial, other state. */
function otherStateAtSameSerial(h) {
  const doc = stubExport({ root: h.dir, commit: h.commits.c4 });
  const files = { ...doc.files, "plugins/alpha/README.md": Buffer.from("not main's\n").toString("base64") };
  const decoded = new Map(Object.entries(files).map(([p, b]) => [p, Buffer.from(b, "base64")]));
  return { ...doc, files, state_sha256: stateSha256(decoded) };
}

test("equal: asked at the Source-Commit's serial, the digest is the tree's, every change is the bot's, nothing alerts", async () => {
  const h = withSigned();
  const s = service(stubExport({ root: h.dir, commit: h.commits.c4 }));
  const r = await ask(h, { env, ...s });
  assert.equal(r.status, "green", r.lines.join("\n"));
  assert.deepEqual(r.codes, []);
  assert.deepEqual(r.hexes, []);
  assert.equal(r.export, "equal");
  assert.equal(r.authors, "bot-only");
  assert.equal(s.calls.mint, 1);
  assert.deepEqual(s.calls.fetch, [{ url: ASKED(3), auth: "Bearer test-token" }]);
});

test("a different state at the same serial is SIGNER_EXPORT_STATE_MISMATCH, and the call returns rather than throwing", async () => {
  const h = withSigned();
  const r = await ask(h, { env, ...service(otherStateAtSameSerial(h)) });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, [CODES.stateMismatch]);
  assert.equal(r.export, "differs");
  assert.ok(r.lines.some((l) => /is not the Source-Commit's/.test(l)));

  // An export whose digest does not match its own files is a mismatch too.
  const lie = stubExport({ root: h.dir, commit: h.commits.c4 });
  lie.files = { ...lie.files, "log/extra.json": "e30=" };
  const r2 = await ask(h, { env, ...service(lie) });
  assert.deepEqual(r2.codes, [CODES.stateMismatch]);
  assert.ok(r2.lines.some((l) => /not the digest of its own files/.test(l)));
});

test("the service at another serial is a note, not a mismatch: a 200 at another serial, and a 404 {current_serial}", async () => {
  const h = withSigned();
  // A 200 that answers serial 2 when 3 was asked.
  const r = await ask(h, { env, ...service(stubExport({ root: h.dir, commit: h.commits.c2 })) });
  assert.equal(r.status, "green", r.lines.join("\n"));
  assert.deepEqual(r.codes, []);
  assert.equal(r.export, "other-serial");
  assert.ok(r.lines.includes("note  export: service at serial 2, signed 3; nothing was compared"));

  // The settled 404: the service does not hold serial 3 and says where it is.
  const r404 = await ask(h, { env, ...service({ current_serial: 2 }, { status: 404 }) });
  assert.deepEqual(r404.codes, []);
  assert.equal(r404.export, "other-serial");
  assert.ok(r404.lines.includes("note  export: service at serial 2, signed 3; nothing was compared"));

  // A 404 that does not say where it is cannot be read as a lag.
  const bare = await ask(h, { env, ...service({ error: "not found" }, { status: 404 }) });
  assert.deepEqual(bare.codes, [CODES.unreachable]);
});

test("any other answer is SIGNER_EXPORT_UNREACHABLE: 503, 401, a redirect, not JSON", async () => {
  const h = withSigned();
  for (const [status, raw] of [[503, null], [401, null], [302, null], [200, "<html>"]]) {
    const r = await ask(h, { env, ...service({}, { status, raw }) });
    assert.deepEqual(r.codes, [CODES.unreachable], `HTTP ${status}`);
    assert.equal(r.export, "unreachable");
  }
});

test("the answer is read up to 64 MiB, counted on the bytes, and no further", async () => {
  let pulled = 0;
  const chunk = new Uint8Array(1024 * 1024);
  const endless = new ReadableStream({ pull(c) { pulled++; c.enqueue(chunk); } });
  const over = await readCapped(new Response(endless));
  assert.equal(over.ok, false);
  assert.match(over.error, /larger than 67108864 bytes/);
  assert.ok(pulled <= MAX_EXPORT_BYTES / chunk.byteLength + 2, `read ${pulled} MiB`);

  const small = await readCapped(new Response("{}"), 2);
  assert.deepEqual(small, { ok: true, text: "{}" });
  assert.equal((await readCapped(new Response("{}x"), 2)).ok, false);

  // And fetchExport goes through it: an oversized 200 is unreachable, never parsed.
  const big = await fetchExport({
    base: ORIGIN, serial: 3, mint: async () => ({ token: "t" }), log: quiet,
    // Finite (65 MiB), so a reader without the cap parses and fails here rather than hanging.
    fetchImpl: async () => {
      let left = 65;
      return new Response(new ReadableStream({ pull(c) { if (left-- > 0) c.enqueue(chunk); else c.close(); } }), { status: 200 });
    },
  });
  assert.equal(big.kind, "unreachable");
  assert.match(big.error, /larger than/);
});

test("nothing the service answers is printed raw: digests and serials off their grammar print as a quoted prefix", async () => {
  const h = withSigned();
  const hostile = "::error::forged line\nFAIL  fake\u001b[31m" + "x".repeat(500);
  const doc = { ...stubExport({ root: h.dir, commit: h.commits.c4 }), state_sha256: hostile };
  const r = await ask(h, { env, ...service(doc) });
  assert.deepEqual(r.codes, [CODES.stateMismatch]);
  const other = await ask(h, { env, ...service({ ...doc, serial: hostile }) });
  const far = await ask(h, { env, ...service({ current_serial: hostile }, { status: 404 }) });
  for (const x of [r, other, far]) {
    const text = x.lines.join("\n");
    assert.ok(!text.includes("forged line\n"), "a newline from the answer reached the log");
    assert.ok(!text.includes("\u001b"), "an escape from the answer reached the log");
    assert.ok(!text.includes("x".repeat(100)), "more than 80 characters of the answer reached the log");
  }
  assert.ok(r.lines.some((l) => l.includes(JSON.stringify(hostile).slice(0, 80))));
});

test("the URL is the service's origin plus this file's path, and nothing else gets a token", async () => {
  for (const ok of ["https://api.minice.ai", "https://api.minice.ai/", " https://api.minice.ai "]) {
    const { url, problem } = exportUrl(ok.trim(), 7);
    assert.equal(problem, null, ok);
    assert.equal(url.href, ASKED(7));
  }
  for (const bad of [
    "http://api.minice.ai", "https://api.minice.ai:8443", "https://api.minice.ai.example.invalid",
    "https://user:pw@api.minice.ai", "https://api.minice.ai/plugins/v1/export", "https://api.minice.ai/plugins/v1/",
    "https://api.minice.ai/%2e%2e/admin", "https://api.minice.ai/../x", "https://api.minice.ai/?serial=1",
    "https://api.minice.ai/#x", "https://example.invalid", "api.minice.ai", "",
  ]) {
    const s = service({});
    const got = await fetchExport({ base: bad, serial: 3, mint: s.mint, fetchImpl: s.fetchImpl, log: quiet });
    assert.equal(got.kind, "unreachable", bad);
    assert.equal(s.calls.mint, 0, `${bad} was given a token`);
    assert.equal(s.calls.fetch.length, 0, `${bad} was fetched`);
  }
});

test("a commit to plugins/ or log/ by anybody but the bot raises SIGNER_EXPORT_FOREIGN_COMMIT, and only foreign shas are hexes", async () => {
  const h = withSigned();
  h.write("plugins/alpha/README.md", "a hand edit\n");
  const hand = h.commit("hand edit", HUMAN);
  h.write("README.md", "a human docs change is not a state change\n");
  h.commit("docs", HUMAN);
  // Authored by a person, committed by the bot: still not the bot's change.
  h.write("log/decisions/2026/11/00000000000000000000000000000003.json", "{}\n");
  h.git(["add", "-A"]);
  h.git(["commit", "-qm", "mixed", `--author=${HUMAN.name} <${HUMAN.email}>`], BOT);
  const mixed = h.git(["rev-parse", "HEAD"]);

  const r = await assertExport({ root: h.dir, sourceCommit: mixed, signedRef: "signed", env: {}, log: quiet, pullOf: noPulls });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, [CODES.foreignCommit]);
  assert.deepEqual([...r.hexes].sort(), [hand, mixed].sort(), "the Source-Commit is never a hex");
  assert.ok(r.lines.some((l) => l.includes(hand) && l.includes(`${HUMAN.name} <${HUMAN.email}>`)));
  assert.equal(foreignCommits({ root: h.dir, base: h.commits.c2, head: h.commits.c4 }).length, 0);
});

test("a merged pull request's commit is a note; a failed lookup still counts as foreign", async () => {
  const h = withSigned();
  h.write("plugins/alpha/README.md", "through a reviewed pull request\n");
  const viaPr = h.commit("pr", HUMAN);
  const merged = async ({ sha }) => ({ merged: sha === viaPr ? 41 : null, error: null });
  const r = await assertExport({ root: h.dir, sourceCommit: viaPr, signedRef: "signed", env: {}, log: quiet, pullOf: merged });
  assert.equal(r.status, "green", r.lines.join("\n"));
  assert.deepEqual(r.codes, []);
  assert.equal(r.authors, "bot-or-merged");
  assert.ok(r.lines.some((l) => l.startsWith(`note  ${viaPr}`) && l.includes("#41")));

  const down = async () => ({ merged: null, error: "GitHub answered HTTP 500" });
  const r2 = await assertExport({ root: h.dir, sourceCommit: viaPr, signedRef: "signed", env: {}, log: quiet, pullOf: down });
  assert.deepEqual(r2.codes, [CODES.foreignCommit]);
  assert.ok(r2.lines.some((l) => l.includes("not asked of GitHub: GitHub answered HTTP 500")));
});

test("mergedPullOf reads GitHub's commits/{sha}/pulls: merged into main counts, open or into another branch does not", async () => {
  const sha = "a".repeat(40);
  const gh = (status, body) => {
    const seen = [];
    return { seen, fetchImpl: async (url, init) => { seen.push({ url, auth: init.headers.Authorization }); return new Response(JSON.stringify(body), { status }); } };
  };
  const e = { GITHUB_REPOSITORY: "owner/astra-registry", GITHUB_TOKEN: "ghs_test" };
  const yes = gh(200, [{ number: 7, merged_at: "2026-11-19T00:00:00Z", base: { ref: "main" } }]);
  assert.deepEqual(await mergedPullOf({ sha, env: e, fetchImpl: yes.fetchImpl }), { merged: 7, error: null });
  assert.deepEqual(yes.seen, [{ url: `https://api.github.com/repos/owner/astra-registry/commits/${sha}/pulls`, auth: "Bearer ghs_test" }]);
  for (const body of [
    [{ number: 8, merged_at: null, base: { ref: "main" } }],
    [{ number: 9, merged_at: "2026-11-19T00:00:00Z", base: { ref: "staging" } }],
    [],
  ]) {
    assert.deepEqual(await mergedPullOf({ sha, env: e, fetchImpl: gh(200, body).fetchImpl }), { merged: null, error: null });
  }
  assert.equal((await mergedPullOf({ sha, env: e, fetchImpl: gh(500, {}).fetchImpl })).merged, null);
  assert.match((await mergedPullOf({ sha, env: e, fetchImpl: gh(500, {}).fetchImpl })).error, /HTTP 500/);
  assert.match((await mergedPullOf({ sha, env: {}, fetchImpl: yes.fetchImpl })).error, /GITHUB_REPOSITORY/);
});

test("unset ASTRA_EXPORT_URL: not asked, no token minted, and never reported as equal", async () => {
  const h = withSigned();
  const s = service(null);
  for (const e of [{}, { [EXPORT_URL_VAR]: "" }, { [EXPORT_URL_VAR]: "  " }]) {
    const r = await ask(h, { env: e, ...s });
    assert.equal(r.export, "not-asked");
    assert.notEqual(r.export, "equal");
    assert.ok(r.lines.some((l) => /not asked/.test(l) && /not a pass/.test(l)));
    assert.equal(r.status, "green", "not asked is no alarm by itself");
  }
  assert.equal(s.calls.mint, 0);
  assert.equal(s.calls.fetch.length, 0);
});

test("no signed base to count from raises SIGNER_EXPORT_NO_SIGNED_BASE", async () => {
  const h = exportHistory("export-assert-no-base");
  const r = await assertExport({ root: h.dir, sourceCommit: h.commits.c4, signedRef: null, env: {}, log: quiet, pullOf: noPulls });
  assert.deepEqual(r.codes, [CODES.noBase]);
  h.git(["checkout", "-q", "--orphan", "signed"]);
  h.git(["rm", "-rq", "--cached", "."]);
  h.commit(`signed\n\nSource-Commit: ${h.commits.c4}\n`);
  h.git(["checkout", "-qf", "main"]);
  const r2 = await assertExport({ root: h.dir, sourceCommit: h.commits.c4, signedRef: "signed", env: {}, log: quiet, pullOf: noPulls });
  assert.deepEqual(r2.codes, [CODES.noBase]);
});

// ── the page: once per foreign commit, once per outage ────────────────────

const verdictOf = (r) => composeVerdict({
  check: "signer-export",
  run: null,
  jobs: [{ name: "export-assert", result: "success", status: r.status, codes: r.codes.join(" "), hexes: r.hexes.join(" ") }],
}).verdict;

test("the same foreign commit across many new heads pages once, ever; a new one pages at once", async () => {
  const h = withSigned();
  h.write("log/cutover.json", "{\"by\":\"hand\"}\n");
  const hand = h.commit("a log-only hand edit", HUMAN);
  let state = { checks: {} };
  let now = new Date("2026-11-19T00:00:00Z");
  const decide = async (head) => {
    const r = await assertExport({ root: h.dir, sourceCommit: head, signedRef: "signed", env: {}, log: quiet, pullOf: noPulls });
    const d = alertDecision(verdictOf(r), state, { now });
    state = d.state;
    return d.act;
  };
  assert.equal(await decide(hand), "page");
  // Ten more heads over three days, none of which signs (docs only), so the
  // range still holds the same commit.
  for (let i = 0; i < 10; i++) {
    h.write("README.md", `docs ${i}\n`);
    now = new Date(now.getTime() + 7 * 3600_000);
    assert.equal(await decide(h.commit(`docs ${i}`)), "quiet", `head ${i} paged again`);
  }
  h.write("plugins/beta/README.md", "another hand edit\n");
  assert.equal(await decide(h.commit("second", HUMAN)), "page");
});

test("a persistent outage pages once, not once per head; the signer's own check still repeats daily", () => {
  const down = { schema: "astra.registry.alert-verdict/1", check: "signer-export", status: "red", codes: [CODES.unreachable] };
  let state = { checks: {} };
  let now = new Date("2026-11-19T00:00:00Z");
  const acts = [];
  for (let i = 0; i < 6; i++) {
    const d = alertDecision(down, state, { now });
    acts.push(d.act);
    state = d.state;
    now = new Date(now.getTime() + 12 * 3600_000);
  }
  assert.deepEqual(acts, ["page", "quiet", "quiet", "quiet", "quiet", "quiet"]);
  assert.equal(alertDecision({ ...down, status: "green" }, state, { now }).act, "resolve");

  const signer = { ...down, check: "signer" };
  const first = alertDecision(signer, { checks: {} }, { now: new Date("2026-11-19T00:00:00Z") });
  assert.equal(alertDecision(signer, first.state, { now: new Date("2026-11-20T01:00:00Z") }).act, "page");
});

// ── sign.yml: the job is beside the signature, never in front of it ────────

const SIGN = fs.readFileSync(path.join(REPO_ROOT, ".github", "workflows", "sign.yml"), "utf8");

/** One job's lines, comments dropped. */
function job(name) {
  const lines = SIGN.split("\n");
  const at = lines.findIndex((l) => l === `  ${name}:`);
  assert.ok(at >= 0, `sign.yml has no ${name} job`);
  const end = lines.findIndex((l, i) => i > at && /^  [a-z][a-z0-9-]*:\s*$/.test(l));
  return lines.slice(at + 1, end < 0 ? undefined : end).filter((l) => !l.trim().startsWith("#")).join("\n");
}

test("sign.yml: publish signs without waiting for export-assert, which runs after it at the same Source-Commit", () => {
  const publish = job("publish");
  assert.doesNotMatch(publish, /needs:/, "publish waits for something; assert-only means it waits for nothing new");
  assert.match(publish, /source_commit: \$\{\{ steps\.source\.outputs\.sha \}\}/);
  const assertJob = job("export-assert");
  assert.match(assertJob, /^\s+needs: publish$/m);
  assert.match(assertJob, /if: \$\{\{ !cancelled\(\) \}\}/);
  assert.match(assertJob, /^\s{4}timeout-minutes: 3$/m, "export-assert holds the signer's concurrency group; it gets 3 minutes");
  assert.match(assertJob, /ref: \$\{\{ needs\.publish\.outputs\.source_commit \}\}/);
  assert.match(assertJob, /node tools\/signer\/export-assert\.mjs --source-commit "\$SOURCE_COMMIT"/);
  assert.match(assertJob, /ASTRA_EXPORT_URL: \$\{\{ vars\.ASTRA_EXPORT_URL \}\}/);
  assert.match(assertJob, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.doesNotMatch(assertJob, /secrets\./, "the export is fetched with a minted token, never a stored secret");
  for (const other of ["pages", "alert-state", "alert", "alert-save"]) {
    assert.doesNotMatch(job(other), /export-assert/, `${other} waits for or reports the assertion`);
  }
});

test("sign.yml: export-assert pages through its own alert, check signer-export, with its own state", () => {
  const alert = job("export-alert");
  assert.match(alert, /needs: \[export-assert, export-alert-state\]/);
  assert.match(alert, /ASTRA_SIGNER_JOBS: export-assert$/m);
  for (const v of ["RESULT", "STATUS", "CODES", "HEXES"]) assert.match(alert, new RegExp(`EXPORT_ASSERT_${v}: `));
  assert.match(alert, /--check signer-export$/m);
  assert.match(alert, /state: \$\{\{ needs\.export-alert-state\.outputs\.state \}\}/);
  assert.match(job("export-alert-state"), /key: sign-export-alert$/m);
  assert.match(job("export-alert-save"), /key: sign-export-alert$/m);
  assert.match(job("alert-state"), /key: sign-alert$/m, "the signer's own memory is not shared with this one");
});

test("BOT_IDENTITIES are exactly the identities the committing workflows commit as", () => {
  const dir = path.join(REPO_ROOT, ".github", "workflows");
  const used = new Set();
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".yml"))) {
    const text = fs.readFileSync(path.join(dir, f), "utf8");
    const names = [...text.matchAll(/git config user\.name\s+"([^"]+)"/g)].map((m) => m[1]);
    const emails = [...text.matchAll(/git config user\.email\s+"([^"]+)"/g)].map((m) => m[1]);
    assert.equal(names.length, emails.length, `${f} sets ${names.length} name(s) and ${emails.length} email(s)`);
    names.forEach((name, i) => {
      const pair = JSON.stringify({ name, email: emails[i] });
      assert.ok(BOT_IDENTITIES.some((b) => JSON.stringify({ ...b }) === pair), `${f} commits as ${pair}, which BOT_IDENTITIES does not hold`);
      used.add(pair);
    });
  }
  assert.equal(used.size, BOT_IDENTITIES.length, "an identity in BOT_IDENTITIES is one no workflow commits as");
  assert.ok(BOT_IDENTITIES.some((b) => JSON.stringify({ ...b }) === JSON.stringify({ ...BOT })), "the fixture's bot is not one of the module's");
});
