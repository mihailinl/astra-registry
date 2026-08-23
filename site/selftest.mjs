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
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
  assert.throws(() => buildInto("evil-id", doc), /not a plugin id/);
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
