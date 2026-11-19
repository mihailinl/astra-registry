// Phase 2 step 2: sign.yml's assert-only export check
// (tools/signer/export-assert.mjs). Equal is quiet; a mismatch, a non-bot
// commit and an unreachable export each raise a code; an unset URL is "not
// asked" and never "equal"; and nothing here can stop the signature.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { stubExport } from "../../tools/export-stub.mjs";
import { REPO_ROOT } from "../../tools/lib/sources.mjs";
import { composeVerdict } from "../../tools/served-set/compose.mjs";
import { BOT_IDENTITIES, CODES, EXPORT_URL_VAR, assertExport, foreignCommits } from "../../tools/signer/export-assert.mjs";
import { API_BASE } from "../../bot/lib/service.mjs";
import { BOT, HUMAN, exportHistory } from "./fixtures/export-history.mjs";

const URL_OK = `${API_BASE}export`;

/** main's history with a `signed` branch whose one commit signed c2. */
function withSigned() {
  const h = exportHistory("export-assert");
  h.git(["checkout", "-q", "--orphan", "signed"]);
  h.git(["rm", "-rq", "--cached", "."]);
  h.commit(`signed: catalogue 2\n\nSource-Commit: ${h.commits.c2}\nSigner: sign.yml\n`);
  h.git(["checkout", "-qf", "main"]);
  return h;
}

/** A service that answers `doc`, and a counter of what was minted and fetched. */
function service(doc, { status = 200 } = {}) {
  const calls = { mint: 0, fetch: [] };
  return {
    calls,
    mint: async () => { calls.mint++; return { token: "test-token", claims: {} }; },
    fetchImpl: async (url, init) => {
      calls.fetch.push({ url, auth: init.headers.Authorization });
      return { ok: status < 300, status, json: async () => doc };
    },
  };
}

const quiet = { log() {} };
const ask = (h, extra) => assertExport({ root: h.dir, sourceCommit: h.commits.c4, signedRef: "signed", log: quiet, ...extra });

test("equal: the export's state_sha256 is the Source-Commit's, every change is the bot's, and nothing alerts", async () => {
  const h = withSigned();
  const s = service(stubExport({ root: h.dir, commit: h.commits.c4 }));
  const r = await ask(h, { env: { [EXPORT_URL_VAR]: URL_OK }, ...s });
  assert.equal(r.status, "green", r.lines.join("\n"));
  assert.deepEqual(r.codes, []);
  assert.equal(r.export, "equal");
  assert.equal(r.authors, "bot-only");
  assert.equal(s.calls.mint, 1);
  assert.deepEqual(s.calls.fetch, [{ url: URL_OK, auth: "Bearer test-token" }]);
});

test("a mismatch raises SIGNER_EXPORT_STATE_MISMATCH, and the call returns rather than throwing", async () => {
  const h = withSigned();
  // c2's export against c4's tree: a different state, honestly digested.
  const s = service(stubExport({ root: h.dir, commit: h.commits.c2 }));
  const r = await ask(h, { env: { [EXPORT_URL_VAR]: URL_OK }, ...s });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, [CODES.stateMismatch]);
  assert.equal(r.export, "differs");
  assert.ok(r.lines.some((l) => /is not the Source-Commit's/.test(l)));

  // An export whose digest does not match its own files is a mismatch too.
  const lie = { ...stubExport({ root: h.dir, commit: h.commits.c4 }) };
  lie.files = { ...lie.files, "log/extra.json": "e30=" };
  const r2 = await ask(h, { env: { [EXPORT_URL_VAR]: URL_OK }, ...service(lie) });
  assert.deepEqual(r2.codes, [CODES.stateMismatch]);
  assert.ok(r2.lines.some((l) => /not the digest of its own files/.test(l)));
});

test("a commit to plugins/ or log/ by anybody but the bot raises SIGNER_EXPORT_FOREIGN_COMMIT and names it", async () => {
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

  const r = await assertExport({ root: h.dir, sourceCommit: mixed, signedRef: "signed", env: {}, log: quiet });
  assert.equal(r.status, "red");
  assert.deepEqual(r.codes, [CODES.foreignCommit]);
  assert.deepEqual(r.hexes.slice(1).sort(), [hand, mixed].sort());
  assert.ok(r.lines.some((l) => l.includes(hand) && l.includes(`${HUMAN.name} <${HUMAN.email}>`)));
  assert.equal(foreignCommits({ root: h.dir, base: h.commits.c2, head: h.commits.c4 }).length, 0);
});

test("unset ASTRA_EXPORT_URL: not asked, no token minted, and never reported as equal", async () => {
  const h = withSigned();
  const s = service(null);
  for (const env of [{}, { [EXPORT_URL_VAR]: "" }, { [EXPORT_URL_VAR]: "  " }]) {
    const r = await ask(h, { env, ...s });
    assert.equal(r.export, "not-asked");
    assert.notEqual(r.export, "equal");
    assert.ok(r.lines.some((l) => /not asked/.test(l) && /not a pass/.test(l)));
    assert.equal(r.status, "green", "not asked is no alarm by itself");
  }
  assert.equal(s.calls.mint, 0);
  assert.equal(s.calls.fetch.length, 0);
});

test("an export that cannot be had raises SIGNER_EXPORT_UNREACHABLE; a URL off the service base gets no token", async () => {
  const h = withSigned();
  const down = service(null, { status: 503 });
  const r = await ask(h, { env: { [EXPORT_URL_VAR]: URL_OK }, ...down });
  assert.deepEqual(r.codes, [CODES.unreachable]);
  assert.ok(r.lines.some((l) => /HTTP 503/.test(l)));

  const elsewhere = service(stubExport({ root: h.dir, commit: h.commits.c4 }));
  const r2 = await ask(h, { env: { [EXPORT_URL_VAR]: "https://example.invalid/plugins/v1/export" }, ...elsewhere });
  assert.deepEqual(r2.codes, [CODES.unreachable]);
  assert.equal(elsewhere.calls.mint, 0);
  assert.equal(elsewhere.calls.fetch.length, 0);
});

test("no signed base to count from raises SIGNER_EXPORT_NO_SIGNED_BASE", async () => {
  const h = exportHistory("export-assert-no-base");
  const r = await assertExport({ root: h.dir, sourceCommit: h.commits.c4, signedRef: null, env: {}, log: quiet });
  assert.deepEqual(r.codes, [CODES.noBase]);
  // A signed head that names only this Source-Commit has no earlier one either.
  h.git(["checkout", "-q", "--orphan", "signed"]);
  h.git(["rm", "-rq", "--cached", "."]);
  h.commit(`signed\n\nSource-Commit: ${h.commits.c4}\n`);
  h.git(["checkout", "-qf", "main"]);
  const r2 = await assertExport({ root: h.dir, sourceCommit: h.commits.c4, signedRef: "signed", env: {}, log: quiet });
  assert.deepEqual(r2.codes, [CODES.noBase]);
});

test("the run's one verdict carries the assertion's code beside a green publish", async () => {
  const h = withSigned();
  const r = await ask(h, { env: { [EXPORT_URL_VAR]: URL_OK }, ...service(stubExport({ root: h.dir, commit: h.commits.c2 })) });
  const { verdict, problems } = composeVerdict({
    check: "signer",
    run: null,
    jobs: [
      { name: "publish", result: "success", status: "green", codes: "", hexes: h.commits.c4 },
      { name: "pages", result: "success", status: "green", codes: "", hexes: "" },
      { name: "export-assert", result: "success", status: r.status, codes: r.codes.join(" "), hexes: r.hexes.join(" ") },
    ],
  });
  assert.deepEqual(problems, []);
  assert.equal(verdict.status, "red");
  assert.deepEqual(verdict.codes, [CODES.stateMismatch]);
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
  assert.match(assertJob, /ref: \$\{\{ needs\.publish\.outputs\.source_commit \}\}/);
  assert.match(assertJob, /node tools\/signer\/export-assert\.mjs --source-commit "\$SOURCE_COMMIT"/);
  assert.match(assertJob, /ASTRA_EXPORT_URL: \$\{\{ vars\.ASTRA_EXPORT_URL \}\}/);
  assert.doesNotMatch(assertJob, /secrets\./, "the export is fetched with a minted token, never a stored secret");
  for (const other of ["pages", "alert-state"]) {
    assert.doesNotMatch(job(other), /export-assert/, `${other} waits for the assertion`);
  }
  const alert = job("alert");
  assert.match(alert, /needs: \[[^\]]*\bexport-assert\b[^\]]*\]/);
  assert.match(alert, /ASTRA_SIGNER_JOBS: publish pages export-assert$/m);
  for (const v of ["RESULT", "STATUS", "CODES", "HEXES"]) assert.match(alert, new RegExp(`EXPORT_ASSERT_${v}: `));
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
