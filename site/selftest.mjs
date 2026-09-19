#!/usr/bin/env node
// The site's own tests. `node site/selftest.mjs`.
//
// The acceptance criterion for task 6.5 is a structural one — *a plugin page
// exists if and only if its index entry does* — and a structural claim that is
// only ever true because nobody has broken it yet is not a structural claim. So
// it is asserted here, in both directions, against a catalogue built for the
// purpose:
//
//   * an entry that is present gets exactly one page;
//   * an entry that is absent gets no page, and a page that existed for it in a
//     previous build is gone rather than stale (the output directory is
//     rebuilt, not merged);
//   * the set of `p/*/` directories equals the set of ids, with no extras.
//
// Plus the things that would be quietly wrong forever: escaping of hostile
// listing text, the absence of an `astra://` link, and the refusal to announce
// a withdrawal that is not in the signed document.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "./build.mjs";
import { markdown, esc, href } from "./lib/html.mjs";
import { checkEntry, buildModerationLog } from "../bot/lib/moderation.mjs";
import { withdrawalsFor } from "./templates/plugin.mjs";

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "astra-site-"));
const scratch = (name) => path.join(tmp, name);

const SITE_DIR = path.dirname(fileURLToPath(import.meta.url));

/** A catalogue with the shape of the real one and none of its data. */
function catalogue(ids, extra = {}) {
  return {
    signatures: [{ key_id: "test-key", sig: "AAAA" }],
    signed: {
      schema: "astra.registry.index/1",
      serial: 7,
      issued_at: "2026-08-11T00:00:00Z",
      expires_at: "2026-09-10T00:00:00Z",
      plugins: ids.map((id) => ({
        id,
        name: `${id} name`,
        version: "1.0.0",
        description: `what ${id} does`,
        author: "Someone",
        license: "MIT",
        capabilities: ["tools"],
        repository_url: `https://github.com/owner/${id}`,
        icon_url: "",
        source: { kind: "github", repo: `owner/${id}` },
        downloads: 0,
        stars: 0,
        updated_at: "2026-08-01T00:00:00Z",
        added_at: "2026-08-01",
        download_url: "",
        platform_downloads: {},
        releases: [
          {
            version: "1.0.0",
            published_at: "2026-08-01T00:00:00Z",
            protocol: 1,
            capabilities: ["tools"],
            permissions: { fire_trigger: { reason: "to run the thing" } },
            release: { kind: "github_release", repo: `owner/${id}`, tag: `${id}-v1.0.0` },
            artifacts: {
              "linux-x64": {
                url: `https://github.com/owner/${id}/releases/download/${id}-v1.0.0/${id}-1.0.0-linux-x64.astraplugin`,
                filename: `${id}-1.0.0-linux-x64.astraplugin`,
                sha256: "a".repeat(64),
                size: 1234,
              },
            },
          },
        ],
        ...extra,
      })),
    },
  };
}

/**
 * @param {string} dir
 * @param {object} indexDoc
 * @param {object|null} [revDoc]
 * @param {object|null} [rootDoc] a `registry/v1/root.json`, when the test cares
 *   whether the trust anchor is provisioned. Omitted means "no root.json in the
 *   deploy tree", which the generator treats exactly like an empty root set.
 */
function buildInto(dir, indexDoc, revDoc, rootDoc) {
  const indexFile = scratch(`${dir}-index.json`);
  fs.writeFileSync(indexFile, JSON.stringify(indexDoc));
  let revFile = null;
  if (revDoc) {
    revFile = scratch(`${dir}-rev.json`);
    fs.writeFileSync(revFile, JSON.stringify(revDoc));
  }
  let registryDir = null;
  if (rootDoc) {
    registryDir = scratch(`${dir}-registry`);
    fs.mkdirSync(registryDir, { recursive: true });
    fs.writeFileSync(path.join(registryDir, "root.json"), JSON.stringify(rootDoc));
  }
  const out = scratch(dir);
  const result = build({ index: indexFile, revocations: revFile, registryDir, out });
  return { out, result };
}

/** A provisioned root set — one active key, one reserve. Public halves only. */
const provisionedRoots = {
  schema: "astra.registry.root/1",
  status: "provisioned",
  roots: [
    { key_id: "astra-root-test-a", role: "active", key: "A".repeat(43) + "=" },
    { key_id: "astra-root-test-a-reserve", role: "reserve", key: "B".repeat(43) + "=" },
  ],
};

const pagesUnder = (out) => {
  const dir = path.join(out, "p");
  return fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
};

console.log("site/selftest.mjs");

// ── the iff, in both directions ─────────────────────────────────────────────

test("a page exists for every entry, and for no id that is not one", () => {
  const ids = ["alpha", "bravo", "charlie"];
  const { out } = buildInto("iff", catalogue(ids));
  assert.deepEqual(pagesUnder(out), ids);
  for (const id of ids) {
    assert.ok(fs.existsSync(path.join(out, "p", id, "index.html")), `${id} has no page`);
  }
  assert.ok(!fs.existsSync(path.join(out, "p", "delta")), "a page exists for an id that is not in the catalogue");
});

test("removing an entry removes its page on the next build", () => {
  const first = buildInto("shrink", catalogue(["alpha", "bravo"]));
  assert.deepEqual(pagesUnder(first.out), ["alpha", "bravo"]);
  // Same output directory, one entry fewer. A generator that merged into the
  // previous tree would leave `bravo` behind, published and unreachable from
  // the catalogue — the exact drift this task exists to make impossible.
  const second = buildInto("shrink", catalogue(["alpha"]));
  assert.deepEqual(pagesUnder(second.out), ["alpha"]);
});

test("the catalogue page links every entry and nothing else", () => {
  const ids = ["alpha", "bravo"];
  const { out } = buildInto("links", catalogue(ids));
  const home = fs.readFileSync(path.join(out, "index.html"), "utf8");
  const linked = [...home.matchAll(/href="p\/([a-z0-9-]+)\//g)].map((m) => m[1]).sort();
  assert.deepEqual([...new Set(linked)], ids);
});

test("an id that is not a safe path component is refused, not written", () => {
  const doc = catalogue(["alpha"]);
  doc.signed.plugins[0].id = "../escape";
  // Keyed on the id and on the refusal, not on the sentence. This read
  // `/not a plugin id/` until the check here stopped re-writing the predicate
  // and started asking `tools/lib/ids.mjs`, which answers with the actual
  // reason — "contains a path separator". The message got better and the test
  // went red: it was keyed on prose, and the property is that the build refuses
  // and names what it refused.
  assert.throws(() => buildInto("evil-id", doc), /refusing to write a page for "\.\.\/escape"/);
  // A second id of the same shape, so this cannot pass on one hard-coded
  // string: a bare `..` is refused too, and for its own reason.
  const dots = catalogue(["alpha"]);
  dots.signed.plugins[0].id = "..";
  assert.throws(() => buildInto("evil-id-2", dots), /refusing to write a page for "\.\."/);
});

// ── escaping ────────────────────────────────────────────────────────────────

test("hostile listing text is escaped everywhere it lands", () => {
  const doc = catalogue(["alpha"]);
  const p = doc.signed.plugins[0];
  p.name = '<script>alert(1)</script>';
  p.description = '"><img src=x onerror=alert(1)>';
  // This payload used to sit on `p.details`, a field the index no longer
  // carries and this site no longer renders. Left there it would have kept
  // passing — a string nothing prints cannot appear raw in the output — and
  // that is an assertion that has quietly stopped asking anything. Moved onto
  // the author string, which IS rendered, on both pages.
  p.author = "</textarea><svg onload=alert(1)>";
  p.releases[0].permissions.fire_trigger.reason = "<b>bold</b>";
  const { out } = buildInto("escape", doc);
  for (const file of ["index.html", path.join("p", "alpha", "index.html")]) {
    const html = fs.readFileSync(path.join(out, file), "utf8");
    // The dangerous part is the angle bracket and the quote, not the word
    // `onerror` — an escaped `&lt;img src=x onerror=alert(1)&gt;` is inert text
    // and still contains that word, so asserting on the word alone would be a
    // test that fails on correct output.
    assert.ok(!html.includes("<script>"), `${file} contains a raw script tag`);
    assert.ok(!html.includes("<img src=x"), `${file} contains a raw img tag`);
    assert.ok(!html.includes("<svg onload"), `${file} contains a raw svg`);
    assert.ok(!html.includes("</textarea>"), `${file} contains a raw closing tag`);
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), `${file} did not escape the name at all`);
  }
  // The author string is on the plugin page and not on the catalogue index —
  // which the first version of this assertion got wrong, and which is exactly
  // why the payload has to land somewhere the test then proves was rendered.
  // Without this line the `</textarea>` assertion above passes for a string
  // that never reached a template.
  const page = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(page.includes("&lt;svg onload"), "the plugin page did not render the escaped author at all");
});

test("href refuses a scheme that is not https", () => {
  assert.equal(href("javascript:alert(1)"), "");
  assert.equal(href("data:text/html,<script>"), "");
  assert.equal(href("http://example.test/"), "");
  assert.equal(href("https://example.test/x"), "https://example.test/x");
  assert.equal(href("../p/alpha/"), "../p/alpha/");
});

test("a listing cannot smuggle markup through an icon or homepage URL", () => {
  const doc = catalogue(["alpha"]);
  doc.signed.plugins[0].icon_url = 'javascript:alert(1)';
  doc.signed.plugins[0].homepage = '" onmouseover="alert(1)';
  const { out } = buildInto("urls", doc);
  const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(!html.includes("javascript:alert"), "a javascript: URL reached an attribute");
  assert.ok(!html.includes('onmouseover="alert'), "an attribute was broken out of");
});

// ── withdrawals ─────────────────────────────────────────────────────────────

const advisory = (over = {}) => ({
  kind: "id",
  value: "alpha",
  id: "ASTRA-2026-0001",
  severity: "critical",
  action: "disable",
  reason: "It shipped a build that reads the config directory and posts it elsewhere.",
  ...over,
});

test("a withdrawal in the signed list is shown on the plugin page and gets an advisory page", () => {
  const rev = { signatures: [{ key_id: "k", sig: "x" }], signed: { schema: "astra.registry.revocations/1", serial: 3, revocations: [advisory()] } };
  const { out } = buildInto("withdrawn", catalogue(["alpha", "bravo"]), rev);
  const alpha = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  const bravo = fs.readFileSync(path.join(out, "p", "bravo", "index.html"), "utf8");
  assert.ok(alpha.includes("Withdrawn"), "the withdrawn plugin is not marked");
  assert.ok(!bravo.includes("Withdrawn"), "an unaffected plugin is marked withdrawn");
  assert.ok(fs.existsSync(path.join(out, "advisory", "ASTRA-2026-0001", "index.html")));
  const page = fs.readFileSync(path.join(out, "advisory", "ASTRA-2026-0001", "index.html"), "utf8");
  assert.ok(page.includes("stopped and will not start again"), "the disable action's user-facing meaning is missing");
});

test("with no withdrawal list, no advisory page is invented", () => {
  const { out } = buildInto("no-rev", catalogue(["alpha"]));
  assert.ok(!fs.existsSync(path.join(out, "advisory")));
});

test("matching follows the daemon's kinds", () => {
  const entry = catalogue(["alpha"]).signed.plugins[0];
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "id", value: "alpha" })]).length, 1);
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "id", value: "alphax" })]).length, 0);
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "id_version", value: "alpha@1.0.0" })]).length, 1);
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "digest", value: "a".repeat(64) })]).length, 1);
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "digest", value: "b".repeat(64) })]).length, 0);
  // An identity or a publisher key names no plugin id, so it cannot be resolved
  // to a page here — the daemon still enforces it.
  assert.equal(withdrawalsFor(entry, [advisory({ kind: "identity", value: "github:owner/alpha" })]).length, 0);
});

// ── the install instruction, which is not unconditional ─────────────────────
//
// A page that prints "search for this id in Astra" under a notice saying the
// entry cannot be installed teaches the reader that this catalogue's prose is
// decorative. These four tests are the reason the section is a function.

test("a staging entry is not told to install itself", () => {
  const { out } = buildInto("staging", catalogue(["alpha"], { staging: true }), null, provisionedRoots);
  const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(html.includes("Not installable"), "the staging notice is missing");
  assert.ok(!/Open Astra, go to/.test(html), "a staging entry carries a step-by-step install instruction");
  assert.ok(/Not yet, and not from here/.test(html), "the install section was not rewritten for staging");
});

test("a blocking withdrawal suppresses the install instruction, a warn does not", () => {
  const sign = (revs) => ({
    signatures: [{ key_id: "k", sig: "x" }],
    signed: { schema: "astra.registry.revocations/1", serial: 3, revocations: revs },
  });
  // `disable` and `block_install` both refuse an install — RevocationAction::
  // blocks_install() is true for everything except `warn`.
  for (const action of ["disable", "block_install"]) {
    const { out } = buildInto(`rev-${action}`, catalogue(["alpha"]), sign([advisory({ action })]), provisionedRoots);
    const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
    assert.ok(!/Open Astra, go to/.test(html), `a ${action} withdrawal still tells the reader to install it`);
    assert.ok(/will refuse to install it/.test(html), `a ${action} withdrawal does not say installs are refused`);
  }
  const { out } = buildInto("rev-warn", catalogue(["alpha"]), sign([advisory({ action: "warn" })]), provisionedRoots);
  const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(/Open Astra, go to/.test(html), "a warn advisory wrongly suppressed the install instruction");
});

test("the digest check is only called 'signed' when the catalogue is signed", () => {
  const unsigned = catalogue(["alpha"]);
  unsigned.signatures = [];
  const { out } = buildInto("unsigned", unsigned, null, provisionedRoots);
  const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(/<strong>unsigned<\/strong>/.test(html), "an unsigned catalogue does not say so in the install section");
  assert.ok(!/signed catalogue/.test(html), "an unsigned catalogue claims a signed one");
});

test("a signed catalogue with no published root does not promise a verified install", () => {
  // The state of this repository today: `registry/v1/root.json` is
  // `"status": "unprovisioned"` with `roots: []`, `PRODUCTION_ROOT_KEYS` is
  // empty, and a shipped daemon fails closed on every signature.
  const unprovisioned = { schema: "astra.registry.root/1", status: "unprovisioned", roots: [] };
  const { out } = buildInto("unanchored", catalogue(["alpha"]), null, unprovisioned);
  const html = fs.readFileSync(path.join(out, "p", "alpha", "index.html"), "utf8");
  assert.ok(!/signed catalogue/.test(html), "a catalogue with no trust anchor claims a verified install");
  assert.ok(/no trust root has been published/.test(html), "the missing anchor is not stated");

  // And with the anchor in place, the plain sentence comes back.
  const anchored = buildInto("anchored", catalogue(["alpha"]), null, provisionedRoots);
  const ok = fs.readFileSync(path.join(anchored.out, "p", "alpha", "index.html"), "utf8");
  assert.ok(/signed catalogue/.test(ok), "a signed, anchored catalogue does not say so");
});

// ── the deep link that must stay absent ─────────────────────────────────────

test("no generated page carries an astra:// link", () => {
  const { out } = buildInto("scheme", catalogue(["alpha"]));
  const walk = (dir) =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? walk(path.join(dir, d.name)) : [path.join(dir, d.name)]));
  for (const file of walk(out)) {
    if (!/\.html$/.test(file)) continue;
    const html = fs.readFileSync(file, "utf8");
    // The words may appear — the plugin page explains at length why the link is
    // absent. An attribute value may not.
    assert.ok(!/(href|src)="astra:/i.test(html), `${path.relative(out, file)} carries an astra:// link`);
  }
});

// ── the moderation log ──────────────────────────────────────────────────────

test("a moderation entry is checked the way an advisory is", () => {
  const ok = { date: "2026-08-11", action: "yank", plugin: "alpha", reason: "The author asked for it." };
  assert.deepEqual(checkEntry(ok), []);
  assert.ok(checkEntry({ ...ok, action: "nope" }).some((e) => /must be one of/.test(e)));
  assert.ok(checkEntry({ ...ok, plugin: "../x" }).some((e) => /not a plugin id/.test(e)));
  assert.ok(checkEntry({ ...ok, reason: "short" }).some((e) => /at least 10/.test(e)));
  assert.ok(checkEntry({ ...ok, reason: `bad‮text that is long enough` }).some((e) => /never reach/.test(e)));
  // A revoke has to name the advisory that carries it; a yank may not.
  assert.ok(checkEntry({ ...ok, action: "revoke" }).some((e) => /must name the advisory/.test(e)));
  assert.ok(checkEntry({ ...ok, advisory: "ASTRA-2026-0001" }).some((e) => /may not name an advisory/.test(e)));
});

test("the log refuses to claim a revocation nobody signed", () => {
  const root = scratch("fake-root");
  fs.mkdirSync(path.join(root, "bot", "moderation"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "bot", "moderation", "2026-08-11-alpha-revoke.json"),
    JSON.stringify({
      date: "2026-08-11",
      action: "revoke",
      plugin: "alpha",
      reason: "It shipped a credential stealer, verified by hand.",
      advisory: "ASTRA-2026-0009",
    }),
  );
  assert.throws(() => buildModerationLog({ root, revocations: [] }), /does not contain that advisory/);
  // …and refuses a mislabelled one: `warn` is a deprecation, not a revocation.
  assert.throws(
    () => buildModerationLog({ root, revocations: [{ id: "ASTRA-2026-0009", action: "warn" }] }),
    /A revoke is block_install or disable/,
  );
  const log = buildModerationLog({ root, revocations: [{ id: "ASTRA-2026-0009", action: "disable" }], revocationsSerial: 4 });
  assert.equal(log.entries.length, 1);
  assert.equal(log.entries[0].backed, true);
  assert.equal(log.revocations_serial, 4);
});

// ── MOD-7: the renderer shows pending and never fails ───────────────────────
//
// The test above is about `bot/lib/moderation.mjs`, which throws, and which is
// right to: `bot/moderation.mjs --check` runs on every pull request and a log
// entry claiming a revocation nobody signed must not be merged. These are about
// the SITE, which must not throw, and the difference is the clock. MOD-3 puts
// the advisory, the log entry and the catalogue edit in one commit; the signed
// withdrawal list carrying that advisory is produced by a later job. In the
// window between, the entry names an advisory the deployed list does not have —
// and the site build is inside the job that publishes the catalogue, so the
// first effect of recording a takedown used to be to stop the deploy carrying
// it, and every deploy after it. MOD-46 is the rule that forbids exactly that.
//
// So the build goes through, out of process, and the row reads `pending`.

/** A repository root holding nothing but the moderation entries given. */
function fakeRoot(name, entries) {
  const root = scratch(name);
  fs.mkdirSync(path.join(root, "bot", "moderation"), { recursive: true });
  for (const [file, body] of Object.entries(entries)) {
    fs.writeFileSync(path.join(root, "bot", "moderation", file), typeof body === "string" ? body : JSON.stringify(body));
  }
  return root;
}

/**
 * Run `node site/build.mjs` as a user would, and return its exit status.
 *
 * Out of process on purpose. "Never fails its build" is a claim about the exit
 * code of a command in a workflow step, and a call to `build()` inside this
 * file can only ever tell us whether a function threw — which is a different
 * sentence, and the one a `try` around the wrong line would keep making.
 */
function runBuild({ root, indexDoc, revDoc, out, extra = [] }) {
  const indexFile = scratch(`${out}-index.json`);
  fs.writeFileSync(indexFile, JSON.stringify(indexDoc));
  const args = ["--index", indexFile, "--out", scratch(out), "--registry-root", root];
  if (revDoc) {
    const revFile = scratch(`${out}-rev.json`);
    fs.writeFileSync(revFile, JSON.stringify(revDoc));
    args.push("--revocations", revFile);
  }
  const r = spawnSync(process.execPath, [path.join(SITE_DIR, "build.mjs"), ...args, ...extra], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, out: scratch(out) };
}

const revokeEntry = {
  date: "2026-08-11",
  action: "revoke",
  plugin: "alpha",
  reason: "It shipped a credential stealer, verified by hand.",
  advisory: "ASTRA-2026-0009",
};

const signedList = (revocations) => ({
  signatures: [{ key_id: "k", sig: "x" }],
  signed: { schema: "astra.registry.revocations/1", serial: 3, revocations },
});

test("a revoke whose advisory the deployed list does not carry builds, and reads pending", () => {
  const root = fakeRoot("pending-root", { "2026-08-11-alpha-revoke.json": revokeEntry });
  const r = runBuild({
    root,
    indexDoc: catalogue(["alpha"]),
    // A withdrawal list that is real, signed and deployed — and does not carry
    // ASTRA-2026-0009, because it has not been signed into one yet.
    revDoc: signedList([]),
    out: "pending",
  });
  assert.equal(r.status, 0, `the build exited ${r.status}\n${r.stderr}`);
  const log = JSON.parse(fs.readFileSync(path.join(r.out, "transparency", "moderation-log.json"), "utf8"));
  assert.equal(log.entries.length, 1, "the entry was dropped instead of being shown as pending");
  assert.equal(log.entries[0].backed, "pending");
  const html = fs.readFileSync(path.join(r.out, "transparency", "index.html"), "utf8");
  assert.match(html, /<span class="badge warn"[^>]*>pending<\/span>/, "the page does not show the row as pending");
  assert.match(html, /you are not protected by a pending row/, "the page does not tell a reader what pending means for them");
});

test("the same entry reads in effect once the deployed list carries the advisory", () => {
  const root = fakeRoot("effect-root", { "2026-08-11-alpha-revoke.json": revokeEntry });
  const r = runBuild({
    root,
    indexDoc: catalogue(["alpha"]),
    revDoc: signedList([advisory({ id: "ASTRA-2026-0009", action: "disable" })]),
    out: "in-effect",
  });
  assert.equal(r.status, 0, `the build exited ${r.status}\n${r.stderr}`);
  const log = JSON.parse(fs.readFileSync(path.join(r.out, "transparency", "moderation-log.json"), "utf8"));
  assert.equal(log.entries[0].backed, true);
  const html = fs.readFileSync(path.join(r.out, "transparency", "index.html"), "utf8");
  assert.match(html, /<span class="badge">in effect<\/span>/);
  assert.ok(!/>pending</.test(html), "an advisory that IS deployed is still shown as pending");
});

test("an advisory deployed with the wrong action is pending, not silently in effect", () => {
  // `warn` is a deprecation. An entry calling it a revoke is either wrong or
  // ahead of the list; either way the page may not say a revoke is in force.
  const root = fakeRoot("mislabel-root", { "2026-08-11-alpha-revoke.json": revokeEntry });
  const r = runBuild({
    root,
    indexDoc: catalogue(["alpha"]),
    revDoc: signedList([advisory({ id: "ASTRA-2026-0009", action: "warn" })]),
    out: "mislabel",
  });
  assert.equal(r.status, 0, `the build exited ${r.status}\n${r.stderr}`);
  const log = JSON.parse(fs.readFileSync(path.join(r.out, "transparency", "moderation-log.json"), "utf8"));
  assert.equal(log.entries[0].backed, "pending");
});

test("a yank stays `false` and an unchecked build stays `null`", () => {
  // The two values that were already right, pinned so that the new third one
  // cannot be introduced by flattening them.
  const yank = { date: "2026-08-12", action: "yank", plugin: "alpha", reason: "The author asked for it." };
  const root = fakeRoot("yank-root", { "2026-08-12-alpha-yank.json": yank, "2026-08-11-alpha-revoke.json": revokeEntry });

  const withList = runBuild({ root, indexDoc: catalogue(["alpha"]), revDoc: signedList([]), out: "yank-listed" });
  assert.equal(withList.status, 0, withList.stderr);
  const a = JSON.parse(fs.readFileSync(path.join(withList.out, "transparency", "moderation-log.json"), "utf8"));
  assert.equal(a.entries.find((e) => e.action === "yank").backed, false);

  const noList = runBuild({ root, indexDoc: catalogue(["alpha"]), out: "yank-unlisted" });
  assert.equal(noList.status, 0, noList.stderr);
  const b = JSON.parse(fs.readFileSync(path.join(noList.out, "transparency", "moderation-log.json"), "utf8"));
  assert.equal(b.entries.find((e) => e.action === "revoke").backed, null);
  assert.equal(b.entries.find((e) => e.action === "yank").backed, false);
});

test("an unreadable moderation source does not stop the catalogue going out", () => {
  // MOD-46, one step out: a broken record of a takedown must not hold up the
  // takedown. `bot/moderation.mjs --check` is where this is fatal, on the pull
  // request, before it can reach main.
  const root = fakeRoot("broken-root", { "2026-08-11-alpha-revoke.json": "{ not json" });
  const r = runBuild({ root, indexDoc: catalogue(["alpha"]), revDoc: signedList([]), out: "broken" });
  assert.equal(r.status, 0, `the build exited ${r.status}\n${r.stderr}`);
  assert.ok(fs.existsSync(path.join(r.out, "p", "alpha", "index.html")), "the catalogue pages were not written");
  const log = JSON.parse(fs.readFileSync(path.join(r.out, "transparency", "moderation-log.json"), "utf8"));
  assert.deepEqual(log.entries, []);
  assert.deepEqual(log.unavailable.sources, ["bot/moderation/2026-08-11-alpha-revoke.json"]);
  const html = fs.readFileSync(path.join(r.out, "transparency", "index.html"), "utf8");
  assert.match(html, /could not read the moderation sources/);
  // The validator's message quotes the entry it refused, and the usual reason
  // to refuse one is that its text must not reach a screen. It goes to the
  // build log, not to the page.
  assert.ok(!/not readable JSON/.test(html), "the validator's message was published");
  assert.match(r.stderr, /not readable JSON/, "the validator's message did not reach the build log either");
});

// ── ROLL-55: the pages that move, and the documents that must not ───────────
//
// At R4b and R9a the plugins service takes over the pages this repository
// generates, one set at a time, and each moved page is replaced here by a
// static redirect. Pages offers no redirect configuration, so the stub is the
// mechanism rather than a fallback for one.
//
// `site/redirects.json` is empty today — RC-R4-1 and RC-R9-1 fill it — so
// these drive the mechanism with synthetic sets. The one test that reads the
// committed file is the last one, and it is about the file being armable.

const REPO = path.resolve(SITE_DIR, "..");

/** Write a redirect document and return its path. */
function redirectsFile(name, sets) {
  const file = scratch(`${name}-redirects.json`);
  fs.writeFileSync(file, JSON.stringify({ schema: "astra.registry.site-redirects/1", sets }));
  return file;
}

function buildWithRedirects(dir, indexDoc, sets, revDoc) {
  const indexFile = scratch(`${dir}-index.json`);
  fs.writeFileSync(indexFile, JSON.stringify(indexDoc));
  let revFile = null;
  if (revDoc) {
    revFile = scratch(`${dir}-rev.json`);
    fs.writeFileSync(revFile, JSON.stringify(revDoc));
  }
  const out = scratch(dir);
  const result = build({ index: indexFile, revocations: revFile, out, redirects: redirectsFile(dir, sets) });
  return { out, result };
}

const R4B = [
  {
    step: "R4b",
    paths: {
      "/": "https://astra.minice.ai/plugins",
      "/search/": "https://astra.minice.ai/plugins",
      "/p/<id>/": "https://astra.minice.ai/plugins/<id>",
    },
  },
];

test("every mapped path is a redirect, and nothing else is", () => {
  const { out, result } = buildWithRedirects("redirect", catalogue(["alpha", "bravo"]), R4B);
  assert.deepEqual(result.redirects, ["index.html", "p/alpha/index.html", "p/bravo/index.html", "search/index.html"]);

  for (const [rel, to] of [
    ["index.html", "https://astra.minice.ai/plugins"],
    ["search/index.html", "https://astra.minice.ai/plugins"],
    ["p/alpha/index.html", "https://astra.minice.ai/plugins/alpha"],
    ["p/bravo/index.html", "https://astra.minice.ai/plugins/bravo"],
  ]) {
    const html = fs.readFileSync(path.join(out, rel), "utf8");
    // Both mechanisms, because they answer to two different readers: the
    // canonical link is the statement that this is the same resource, which a
    // meta refresh does not make, and the refresh is the only thing that moves
    // a browser with no script.
    assert.ok(html.includes(`<link rel="canonical" href="${to}">`), `${rel} has no canonical link`);
    assert.ok(html.includes(`<meta http-equiv="refresh" content="0; url=${to}">`), `${rel} has no meta refresh`);
    // And a visible one, because a meta refresh is the one navigation a reader
    // cannot see coming.
    assert.ok(html.includes(`<a href="${to}">`), `${rel} does not offer the link to a reader`);
    assert.ok(!html.includes("<nav>"), `${rel} carries the nav, whose links are themselves redirects`);
  }

  // A page in no set is untouched. `/policy/` moves at R9a, not at R4b, and a
  // prefix rule or a "redirect everything" flag would have taken it early.
  const policy = fs.readFileSync(path.join(out, "policy", "index.html"), "utf8");
  assert.ok(!/rel="canonical"/.test(policy), "a page outside every set was redirected");
  assert.ok(policy.includes("Rendered from <code>POLICY.md</code>"), "the policy page stopped being the policy page");
});

test("registry/v1/* and the moderation log stay byte-identical", () => {
  // ROLL-55's other half, and the reason the sets are a data file rather than
  // a prefix rule: `/transparency/` moves and
  // `/transparency/moderation-log.json` never does, and they differ by one
  // path component. A daemon follows no redirect — it would read the stub as a
  // catalogue that fails to parse.
  const sets = [{ step: "R9a", paths: { "/transparency/": "https://astra.minice.ai/plugins/_/transparency" } }];
  const rev = { signatures: [{ key_id: "k", sig: "x" }], signed: { schema: "astra.registry.revocations/1", serial: 3, revocations: [advisory()] } };
  const plain = buildInto("bytes-plain", catalogue(["alpha"]), rev);
  const moved = buildWithRedirects("bytes-moved", catalogue(["alpha"]), sets, rev);

  assert.deepEqual(moved.result.redirects, ["transparency/index.html"]);
  const log = path.join("transparency", "moderation-log.json");
  assert.deepEqual(
    fs.readFileSync(path.join(moved.out, log)),
    fs.readFileSync(path.join(plain.out, log)),
    "the machine-readable moderation log changed when its page moved",
  );
  assert.ok(fs.readFileSync(path.join(moved.out, "transparency", "index.html"), "utf8").includes('rel="canonical"'));
});

test("a mapping onto a signed document or a non-page is refused", () => {
  for (const [paths, message] of [
    [{ "/registry/v1/index.json": "https://astra.minice.ai/plugins/index.json" }, /must stay byte-identical \(ROLL-55\)/],
    [{ "/transparency/moderation-log.json": "https://astra.minice.ai/x" }, /must stay byte-identical \(ROLL-55\)/],
    [{ "/assets/site.css": "https://astra.minice.ai/x.css" }, /not a generated page/],
  ]) {
    assert.throws(
      () =>
        build({
          index: (() => {
            const f = scratch("refuse-index.json");
            fs.writeFileSync(f, JSON.stringify(catalogue(["alpha"])));
            return f;
          })(),
          out: scratch("refuse"),
          registryDir: (() => {
            const d = scratch("refuse-registry");
            fs.mkdirSync(d, { recursive: true });
            fs.writeFileSync(path.join(d, "index.json"), "{}");
            return d;
          })(),
          redirects: redirectsFile(`refuse-${Object.keys(paths)[0].replace(/\W+/g, "-")}`, [{ step: "R9a", paths }]),
        }),
      message,
    );
  }
});

test("a mapping the build generated nothing for is refused, and a pattern that matches nothing is not", () => {
  // A literal is a typo: it would sit in the file redirecting nothing, the
  // outside probe would never fetch it, and the old URL would go on serving a
  // page the service has replaced.
  assert.throws(
    () => buildWithRedirects("typo", catalogue(["alpha"]), [{ step: "R9a", paths: { "/plublisher/": "https://astra.minice.ai/x" } }]),
    /generated no such page/,
  );
  // A pattern is not. This catalogue has no advisories, and `/advisory/<id>/`
  // is still the right line to have written.
  const { result } = buildWithRedirects("empty-pattern", catalogue(["alpha"]), [
    { step: "R9a", paths: { "/advisory/<id>/": "https://astra.minice.ai/plugins/_/advisories/<id>" } },
  ]);
  assert.deepEqual(result.redirects, []);
});

test("a redirect target must be an absolute https URL, and may capture only what its path does", () => {
  const cases = [
    [{ "/search/": "http://astra.minice.ai/plugins" }, /absolute https URL/],
    [{ "/search/": "/plugins" }, /absolute https URL/],
    [{ "/search/": "https://astra.minice.ai/plugins/<id>" }, /uses <id>, which the path does not capture/],
  ];
  for (const [paths, message] of cases) {
    assert.throws(() => buildWithRedirects(`bad-${message.source.slice(0, 8).replace(/\W+/g, "")}`, catalogue(["alpha"]), [{ step: "R4b", paths }]), message);
  }
  // And two sets may not both own a page: whichever ran second would silently
  // decide where an old URL points.
  assert.throws(
    () =>
      buildWithRedirects("twice", catalogue(["alpha"]), [
        { step: "R4b", paths: { "/p/<id>/": "https://astra.minice.ai/plugins/<id>" } },
        { step: "R9a", paths: { "/p/alpha/": "https://astra.minice.ai/elsewhere" } },
      ]),
    /already redirected by set R4b/,
  );
});

test("the committed redirects file is armable, and arming it reaches the publish job", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO, "site", "redirects.json"), "utf8"));
  assert.equal(doc.schema, "astra.registry.site-redirects/1");
  assert.deepEqual(doc.sets.map((s) => s.step), ["R4b", "R9a"], "the two steps ROLL-55 names are not both present");

  // THE COUPLING NOTHING ELSE HOLDS. `--redirects` is a flag, and
  // `.github/workflows/build-index.yml` does not pass it. While every set is
  // empty that is invisible and harmless. The moment RC-R4-1 or RC-R9-1 fills
  // one, a set that never reaches the publish job is a takedown of the old
  // URLs that silently did not happen — green CI, right file on `main`, and
  // Pages still serving the pages the service has replaced. So this goes red
  // at exactly that moment and not before.
  const workflow = fs.readFileSync(path.join(REPO, ".github", "workflows", "build-index.yml"), "utf8");
  const calls = workflow.split("node site/build.mjs").length - 1;
  assert.ok(calls > 0, "build-index.yml no longer invokes site/build.mjs, so this check stopped asking anything");

  const armed = doc.sets.filter((s) => Object.keys(s.paths).length);
  if (!armed.length) return;
  const wired = [...workflow.matchAll(/--redirects\s+site\/redirects\.json/g)].length;
  assert.equal(
    wired,
    calls,
    `set(s) ${armed.map((s) => s.step).join(", ")} carry paths, but ${calls - wired} of ${calls} ` +
      "`node site/build.mjs` invocations in .github/workflows/build-index.yml do not pass " +
      "`--redirects site/redirects.json`. Those old URLs would keep serving the page the service replaced.",
  );
});

// ── the markdown subset ─────────────────────────────────────────────────────

test("markdown escapes, and does not invent markup", () => {
  assert.equal(markdown("plain <b>text</b>"), "<p>plain &lt;b&gt;text&lt;/b&gt;</p>");
  assert.ok(markdown("# Heading one").startsWith('<h1 id="heading-one">'));
  assert.ok(markdown("`<script>`").includes("<code>&lt;script&gt;</code>"));
  assert.ok(markdown("[x](javascript:alert(1))").includes("javascript") === false);
  assert.ok(markdown("| a | b |\n|---|---|\n| 1 | 2 |").includes("<table>"));
  assert.ok(markdown("- one\n- two").includes("<li>one</li><li>two</li>"));
  // A number in prose is not a code-span placeholder.
  assert.equal(markdown("waits 24 h, then 6 h"), "<p>waits 24 h, then 6 h</p>");
  assert.equal(esc("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
});

// ── the real catalogue ──────────────────────────────────────────────────────

test("the repository's own committed catalogue builds", () => {
  const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  const out = scratch("real");
  const result = build({
    index: path.join(repoRoot, "registry/v1/index.json"),
    revocations: path.join(repoRoot, "registry/v1/revocations.json"),
    out,
    root: repoRoot,
  });
  const committed = JSON.parse(fs.readFileSync(path.join(repoRoot, "registry/v1/index.json"), "utf8"));
  assert.deepEqual(pagesUnder(out), committed.signed.plugins.map((p) => p.id).sort());
  assert.equal(result.plugins.length, committed.signed.plugins.length);
});

fs.rmSync(tmp, { recursive: true, force: true });

if (failures) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall site tests passed");
