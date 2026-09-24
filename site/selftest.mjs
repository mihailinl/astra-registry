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
import * as successors from "./successors.mjs";

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

/**
 * Every `node site/build.mjs` command in a workflow file, as the lines that
 * make it up: the invocation and each `\`-continued line after it. A flag in a
 * comment, or on the NEXT command, is not a flag this command passes.
 */
function siteBuildCommands(text) {
  const lines = text.split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*#/.test(lines[i]) || !/\bnode site\/build\.mjs\b/.test(lines[i])) continue;
    const cmd = [lines[i]];
    let j = i;
    while (/\\\s*$/.test(lines[j]) && j + 1 < lines.length) cmd.push(lines[++j]);
    out.push({ line: i + 1, text: cmd.join("\n") });
  }
  return out;
}

test("the committed redirects file is armable, and arming it reaches the job that deploys Pages", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(REPO, "site", "redirects.json"), "utf8"));
  assert.equal(doc.schema, "astra.registry.site-redirects/1");
  assert.deepEqual(doc.sets.map((s) => s.step), ["R4b", "R9a"], "the two steps ROLL-55 names are not both present");

  // THE COUPLING NOTHING ELSE HOLDS. `--redirects` is a flag, and a set that
  // never reaches the job that DEPLOYS the site is a takedown of the old URLs
  // that silently did not happen — green CI, the right file on `main`, and
  // Pages still serving the pages the service has replaced.
  //
  // Until RC-R4-1 this read `.github/workflows/build-index.yml` alone and
  // called it "the publish job". It is not: that workflow's site step says of
  // itself "Nothing assembled here is deployed — this tree exists so the page
  // set can be asserted", and the tree Pages serves is built by `sign.yml`'s
  // `pages` job, from `signed`'s bytes. Wiring the flag where this check
  // looked would have left every deployed page unredirected, and the check
  // green. So it now reads EVERY workflow, holds every invocation to the flag
  // unconditionally — with every set empty the flag changes no byte, which the
  // test below holds — and requires that each workflow that deploys Pages is
  // among the invokers, so the check cannot pass by finding nothing.
  const dir = path.join(REPO, ".github", "workflows");
  const files = fs.readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort();
  const invocations = [];
  const deployers = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(dir, f), "utf8");
    for (const c of siteBuildCommands(text)) invocations.push({ file: f, ...c });
    if (/uses:\s*actions\/deploy-pages@/.test(text)) deployers.push(f);
  }
  assert.ok(deployers.length > 0, "no workflow deploys Pages with actions/deploy-pages, so this check stopped asking anything");
  for (const f of deployers) {
    assert.ok(
      invocations.some((c) => c.file === f),
      `${f} deploys Pages and never runs site/build.mjs, so the deployed tree is built somewhere this check does not see`,
    );
  }
  const unwired = invocations.filter((c) => !/(^|\s)--redirects\s+site\/redirects\.json(\s|\\|$)/m.test(c.text));
  assert.deepEqual(
    unwired.map((c) => `${c.file}:${c.line}`),
    [],
    "these `node site/build.mjs` commands do not pass `--redirects site/redirects.json`, so a filled set would " +
      "never reach the pages they build; the deployed ones are " + deployers.join(", "),
  );
});

test("with every set empty, --redirects changes no byte of the site", () => {
  // The claim that makes wiring the flag safe before any set is armed, held
  // here rather than asserted once in a pull request: the same catalogue,
  // built with no flag and with the committed file's two steps emptied, is the
  // same tree file for file and byte for byte.
  const idx = catalogue(["alpha", "bravo"]);
  const rev = { signatures: [{ key_id: "k", sig: "x" }], signed: { schema: "astra.registry.revocations/1", serial: 3, revocations: [advisory()] } };
  const plain = buildInto("empty-plain", idx, rev);
  const empty = buildWithRedirects("empty-wired", idx, [{ step: "R4b", paths: {} }, { step: "R9a", paths: {} }], rev);
  assert.deepEqual(empty.result.redirects, []);
  const tree = (root) => {
    const acc = {};
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) walk(full);
        else acc[path.relative(root, full)] = fs.readFileSync(full).toString("base64");
      }
    };
    walk(root);
    return acc;
  };
  const a = tree(plain.out);
  const b = tree(empty.out);
  assert.ok(Object.keys(a).length > 10, "the plain build wrote almost nothing, so this compared nothing");
  assert.deepEqual(Object.keys(b).sort(), Object.keys(a).sort(), "the empty redirects file changed which files exist");
  for (const k of Object.keys(a)) assert.equal(b[k], a[k], `${k} differs when an empty redirects file is passed`);
});

// ── RC-R4-1: the R4b set, its successors, and the edit that arms it ─────────
//
// `site/successors.mjs` is the arming commit's precondition: it builds the site
// the way `sign.yml`'s `pages` job does, reads each redirected page's canonical
// link, probes those URLs, and writes the set only when every one answers 200
// and ROLL-54's review is named. The canary is RC-R4-1's own: every catalogue
// plugin page redirects, at least the plugin count + 2 pages move, and
// `registry/v1/*` and the moderation log keep their bytes. Asked over the
// COMMITTED catalogue and Table 5-F as the committed token file carries it, so
// it is not vacuous on a tree whose set is still empty — which is today's.

const REAL = {
  index: path.join(REPO, "registry", "v1", "index.json"),
  revocations: path.join(REPO, "registry", "v1", "revocations.json"),
  registryDir: path.join(REPO, "registry", "v1"),
};
const TOKENS = JSON.parse(fs.readFileSync(path.join(REPO, "schema", "contract-tokens-v1.json"), "utf8"));
const COMMITTED_REDIRECTS = JSON.parse(fs.readFileSync(path.join(REPO, "site", "redirects.json"), "utf8"));

test("RC-R4-1 — Table 5-F's R4b set, over the committed catalogue, moves every plugin page and nothing a daemon reads", () => {
  const expected = successors.tableSet(TOKENS, "R4b");
  // What the plan and ROLL-55 say, held against what the token file says: a
  // renamed row or a moved successor is red here, not at the arming commit.
  assert.deepEqual(expected, {
    "/": "https://astra.minice.ai/plugins",
    "/search/": "https://astra.minice.ai/plugins",
    "/p/<id>/": "https://astra.minice.ai/plugins/<id>",
  });
  const doc = successors.onlyStep(successors.withSet(COMMITTED_REDIRECTS, "R4b", expected), "R4b");
  const x = successors.expand({ ...REAL, redirectsDoc: doc, root: REPO });
  assert.ok(x.ids.length > 0, "the committed catalogue has no plugins, so this canary held nothing");
  assert.deepEqual(successors.coverageProblems({ step: "R4b", expected, ...x }), []);
  assert.equal(x.redirected.length, x.ids.length + 2, "the pattern set should move exactly the plugin pages, `/` and `/search/`");
  assert.ok(x.plain.has("registry/v1/index.json"), "the build carried no registry/v1/index.json, so its bytes were compared with nothing");
});

test("RC-R4-1's canary is red on a plugin page left out, a page R4b does not move, and a byte a daemon reads", () => {
  const expected = successors.tableSet(TOKENS, "R4b");
  const ids = JSON.parse(fs.readFileSync(REAL.index, "utf8")).signed.plugins.map((p) => p.id).sort();
  const left = ids[Math.floor(ids.length / 2)];
  const literal = { "/": expected["/"], "/search/": expected["/search/"] };
  for (const id of ids) if (id !== left) literal[`/p/${id}/`] = expected["/p/<id>/"].replace("<id>", id);

  const short = successors.expand({ ...REAL, redirectsDoc: successors.onlyStep(successors.withSet(COMMITTED_REDIRECTS, "R4b", literal), "R4b"), root: REPO });
  const p1 = successors.coverageProblems({ step: "R4b", expected, ...short });
  assert.ok(p1.some((p) => p.startsWith(`p/${left}/index.html is not redirected`)), `the page left out was not named: ${p1.join(" | ")}`);
  assert.ok(p1.some((p) => /the floor is the catalogue/.test(p)), "the floor did not fire on one page short");

  const wide = successors.expand({
    ...REAL,
    redirectsDoc: successors.onlyStep(successors.withSet(COMMITTED_REDIRECTS, "R4b", { ...expected, "/policy/": "https://astra.minice.ai/plugins/_/policy" }), "R4b"),
    root: REPO,
  });
  const p2 = successors.coverageProblems({ step: "R4b", expected, ...wide });
  assert.ok(p2.some((p) => p.startsWith("policy/index.html is redirected")), `a page R9a moves was taken at R4b unnoticed: ${p2.join(" | ")}`);

  const ok = successors.expand({ ...REAL, redirectsDoc: successors.onlyStep(successors.withSet(COMMITTED_REDIRECTS, "R4b", expected), "R4b"), root: REPO });
  const moved = new Map(ok.moved);
  moved.set("registry/v1/index.json", Buffer.from("<!doctype html>"));
  const p3 = successors.coverageProblems({ step: "R4b", expected, ...ok, moved });
  assert.deepEqual(p3, ["registry/v1/index.json changed when R4b's redirects were applied (ROLL-55)"]);
});

test("the committed R4b set is armed only with its evidence, and is armed once R4b's marker is on the tree", () => {
  const common = { tokens: TOKENS, ...REAL, root: REPO };
  // The committed tree, both legs. Today: an empty set and no marker, which is
  // green and asks nothing — so the synthesised cases below are what hold the
  // legs, and this line is what will hold the tree when it changes.
  const marker = fs.existsSync(path.join(REPO, successors.R4B_MARKER));
  assert.deepEqual(successors.armedSetProblems({ doc: COMMITTED_REDIRECTS, markerPresent: marker, ...common }), []);

  const empty = successors.withSet(COMMITTED_REDIRECTS, "R4b", {});
  assert.deepEqual(successors.armedSetProblems({ doc: empty, markerPresent: false, ...common }), []);
  const opened = successors.armedSetProblems({ doc: empty, markerPresent: true, ...common });
  assert.equal(opened.length, 1);
  assert.match(opened[0], /R4b-open\.json is on the tree and set R4b is empty/);

  const expected = successors.tableSet(TOKENS, "R4b");
  const byHand = successors.armedSetProblems({ doc: successors.withSet(COMMITTED_REDIRECTS, "R4b", expected), markerPresent: true, ...common });
  assert.equal(byHand.length, 1, byHand.join(" | "));
  assert.match(byHand[0], /carries paths and no `armed` record/);

  const record = { at: "2026-09-27T00:00:00Z", successors_answered_200: 17, edge_review: "minice docs/plans/…/roll-54.md" };
  assert.deepEqual(successors.armedSetProblems({ doc: successors.withSet(COMMITTED_REDIRECTS, "R4b", expected, { armed: record }), markerPresent: true, ...common }), []);
  const noReview = successors.armedSetProblems({ doc: successors.withSet(COMMITTED_REDIRECTS, "R4b", expected, { armed: { ...record, edge_review: " " } }), markerPresent: true, ...common });
  assert.deepEqual(noReview, ["set R4b's armed.edge_review is empty; ROLL-55 does not redirect before ROLL-54's review is recorded"]);
});

const asyncTests = [];
const atest = (name, fn) => asyncTests.push([name, fn]);

/** A fetch that answers from a table and records what it was asked. */
function fakeFetch(answers) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const a = typeof answers === "function" ? answers(url) : answers[url];
    if (a instanceof Error) throw a;
    const status = typeof a === "number" ? a : a?.status ?? 404;
    const headers = new Map(Object.entries(a?.headers ?? {}));
    return { status, headers: { get: (k) => headers.get(k.toLowerCase()) ?? null } };
  };
  return { impl, calls };
}

atest("the probe asks each successor once, with no credential and no redirect followed, and names what did not answer 200", async () => {
  const f = fakeFetch({
    "https://p.example/a": 200,
    "https://p.example/b": 404,
    "https://p.example/c": { status: 301, headers: { location: "https://p.example/c/" } },
    "https://p.example/d": new Error("getaddrinfo ENOTFOUND"),
  });
  const urls = ["https://p.example/a", "https://p.example/b", "https://p.example/c", "https://p.example/d"];
  const got = await successors.probeTargets(urls, { fetchImpl: f.impl });
  assert.deepEqual(got, [
    { url: "https://p.example/a", status: 200, ok: true },
    { url: "https://p.example/b", status: 404, ok: false },
    { url: "https://p.example/c", status: 301, ok: false, location: "https://p.example/c/" },
    { url: "https://p.example/d", status: null, ok: false, error: "getaddrinfo ENOTFOUND" },
  ]);
  assert.deepEqual(f.calls.map((c) => c.url), urls, "each successor is asked exactly once, in order");
  for (const { init } of f.calls) {
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "manual", "a redirect was followed, so a successor that moves would read as answering");
    assert.equal(init.headers["user-agent"], successors.USER_AGENT);
    const keys = Object.keys(init.headers).map((k) => k.toLowerCase());
    for (const k of ["authorization", "cookie", "proxy-authorization"]) assert.ok(!keys.includes(k), `the probe sent ${k}`);
  }
  assert.equal(successors.USER_AGENT, "astra-registry-lane (+https://github.com/mihailinl/astra-registry)");
});

atest("--arm writes the set only when every successor answers 200 and ROLL-54's review is named, and writes nothing else", async () => {
  const file = scratch("arm-redirects.json");
  const original = fs.readFileSync(path.join(REPO, "site", "redirects.json"));
  // The edit is only one set if the file round-trips: the committed bytes ARE
  // JSON.stringify(doc, null, 2) and a newline, so re-serialising changes
  // nothing but what `arm` changed.
  assert.equal(JSON.stringify(JSON.parse(original.toString("utf8")), null, 2) + "\n", original.toString("utf8"),
    "site/redirects.json no longer round-trips, so --arm would rewrite more than the set it arms");
  const common = { step: "R4b", redirectsFile: file, tokens: TOKENS, ...REAL, root: REPO, now: new Date("2026-09-27T01:02:03.456Z") };
  const reset = () => fs.writeFileSync(file, original);

  reset();
  const all200 = fakeFetch(() => 200);
  const noReview = await successors.arm({ ...common, fetchImpl: all200.impl });
  assert.equal(noReview.armed, false);
  assert.match(noReview.problems[0], /ROLL-54's edge review/);
  assert.equal(all200.calls.length, 0, "it probed before refusing on a missing review");
  assert.ok(fs.readFileSync(file).equals(original), "a refused arm changed the file");

  reset();
  const oneMissing = fakeFetch((url) => (url.endsWith("/json-tools") ? 404 : 200));
  const refused = await successors.arm({ ...common, edgeReview: "recorded", fetchImpl: oneMissing.impl });
  assert.equal(refused.armed, false);
  assert.deepEqual(refused.problems, ["https://astra.minice.ai/plugins/json-tools answered 404; SERVE-84 wants 200 before R4b"]);
  assert.ok(fs.readFileSync(file).equals(original), "an arm with a 404 among its successors changed the file");

  reset();
  const ok = fakeFetch(() => 200);
  const done = await successors.arm({ ...common, edgeReview: "minice docs/plans/2026-09-12-plugins-service/roll-54.md", fetchImpl: ok.impl });
  assert.equal(done.armed, true, done.problems.join(" | "));
  const ids = JSON.parse(fs.readFileSync(REAL.index, "utf8")).signed.plugins.map((p) => p.id);
  assert.equal(ok.calls.length, ids.length + 1, "every plugin successor and the index, each once");
  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  const before = JSON.parse(original.toString("utf8"));
  assert.deepEqual(after.sets[0].paths, successors.tableSet(TOKENS, "R4b"));
  assert.deepEqual(after.sets[0].armed, {
    at: "2026-09-27T01:02:03Z", successors_answered_200: ids.length + 1, edge_review: "minice docs/plans/2026-09-12-plugins-service/roll-54.md",
  });
  // Everything but set R4b's two members is the committed file, unchanged.
  const { paths: _p, armed: _a, ...restAfter } = after.sets[0];
  const { paths: _q, ...restBefore } = before.sets[0];
  assert.deepEqual(restAfter, restBefore);
  assert.deepEqual({ ...after, sets: after.sets.slice(1) }, { ...before, sets: before.sets.slice(1) });
  // And what it wrote passes the committed-set canary, marker or not.
  assert.deepEqual(successors.armedSetProblems({ doc: after, markerPresent: true, tokens: TOKENS, ...REAL, root: REPO }), []);

  const again = await successors.arm({ ...common, edgeReview: "recorded", fetchImpl: ok.impl });
  assert.equal(again.armed, false);
  assert.match(again.problems[0], /already carries paths/);
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

// The async tests, one at a time and in order, so their lines read in place.
for (const [name, fn] of asyncTests) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures++;
    console.error(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
  }
}

fs.rmSync(tmp, { recursive: true, force: true });

if (failures) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall site tests passed");
