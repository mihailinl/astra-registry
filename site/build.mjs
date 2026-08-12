#!/usr/bin/env node
// The website. Static, no framework, no dependency, and generated from the
// signed catalogue in the job that publishes it.
//
//   node site/build.mjs --index dist/registry/v1/index.json --out dist/site \
//        [--revocations dist/registry/v1/revocations.json] \
//        [--registry-dir dist/registry/v1] [--repo owner/name]
//
// ── THE ONE PROPERTY THIS FILE EXISTS FOR ───────────────────────────────────
//
// A plugin page exists **if and only if** the signed catalogue has an entry for
// it. Not "usually", not "after the next sync" — by construction, because there
// is exactly one input and one job.
//
// The alternative shape, and the reason it is not this one: a site that reads
// `plugins/**` and a daemon that reads `registry/v1/index.json` are two
// consumers of two sources that happen to be generated from each other. They
// drift the first time a build fails halfway, and the drift is invisible —
// the site shows a plugin the catalogue does not offer, or offers a version the
// catalogue has yanked, and nothing anywhere is red. So: `--index` takes the
// deploy candidate itself, `--registry-dir` copies those same bytes into the
// published tree, and the page you read and the file your daemon fetches are
// the same file. `.github/workflows/build-index.yml` wires it that way and
// `site/selftest.mjs` asserts the iff in both directions.
//
// ── SAME ORIGIN ─────────────────────────────────────────────────────────────
//
// `/registry/v1/**` is published inside the site tree. `/search/` fetches the
// catalogue with a relative URL and no CORS preflight, and a reader who wants
// to check a digest by hand is reading the same bytes from the same host.
//
// It is also **where the daemon fetches the catalogue** —
// `astra-daemon/src/plugins/registry_client.rs` `DEFAULT_REGISTRY_URL`. That
// pointed at `raw.githubusercontent.com/.../main/registry/v1/index.json`, and
// this comment claimed the two were "byte-identical". They are not, and cannot
// be: the committed file carries `signatures: []` by design, because the key
// that signs the catalogue lives in the `publish` environment and signs the
// DEPLOY CANDIDATE. What is published here is signed; what is in the branch
// never is. A daemon reading the branch copy classified every catalogue
// UNSIGNED and refused it — correctly, having never been sent one that anybody
// had signed.
//
// ── NO astra:// DEEP LINK ───────────────────────────────────────────────────
//
// See the long note at the top of `site/templates/plugin.mjs`. Short version:
// the scheme is already the remote-daemon pairing connection string in three
// places in the Astra tree, so registering it as a browser-reachable protocol
// handler would put a web page one click from "connect this client to that
// daemon". `site/selftest.mjs` fails the build if the string ever appears in a
// generated page outside that explanation.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { REPO_ROOT } from "../tools/lib/sources.mjs";
import { CONSENT_HIGH_RISK } from "../bot/lib/policy.mjs";
import { buildModerationLog } from "../bot/lib/moderation.mjs";
import { loadAdvisories } from "../tools/lib/revocations.mjs";

import { markdown } from "./lib/html.mjs";
import { pluginPage, withdrawalsFor } from "./templates/plugin.mjs";
import { advisoryPage, groupAdvisories } from "./templates/advisory.mjs";
import { homePage, searchPage, publisherPage, publishPage, docPage, transparencyPage, notFoundPage } from "./templates/pages.mjs";

/** The repository this catalogue is served from, for the links that need one. */
const DEFAULT_REPO = "mihailinl/astra-registry";

function parseArgs(argv) {
  const opts = { out: null, index: null, revocations: null, registryDir: null, root: REPO_ROOT, repo: DEFAULT_REPO };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--index") opts.index = path.resolve(argv[++i]);
    else if (a === "--revocations") opts.revocations = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.registryDir = path.resolve(argv[++i]);
    else if (a === "--registry-root") opts.root = path.resolve(argv[++i]);
    else if (a === "--repo") opts.repo = argv[++i];
    else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

function write(out, rel, contents) {
  const file = path.join(out, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return file;
}

function readIfPresent(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * Build the whole site.
 *
 * Exported so `site/selftest.mjs` can drive it against a synthetic catalogue
 * without a shell.
 *
 * @param {{out: string, index: string, revocations?: string|null,
 *          registryDir?: string|null, root?: string, repo?: string}} opts
 * @returns {{pages: string[], plugins: string[], advisories: string[], publishers: string[]}}
 */
export function build(opts) {
  const { out, root = REPO_ROOT, repo = DEFAULT_REPO } = opts;

  const indexDoc = JSON.parse(fs.readFileSync(opts.index, "utf8"));
  const signed = indexDoc.signed;
  if (!signed || !Array.isArray(signed.plugins)) {
    throw new Error(
      `${opts.index} has no \`signed.plugins\`. This generator takes the deploy candidate — the ` +
        "envelope — not a bare catalogue: the serial, the freshness window and the signatures it " +
        "renders all live outside `plugins`.",
    );
  }

  const revDoc = opts.revocations ? JSON.parse(fs.readFileSync(opts.revocations, "utf8")) : null;
  const revocations = revDoc?.signed?.revocations ?? [];

  // The trust anchor, read out of the same deploy tree the index came from.
  //
  // A countersignature on `index.json` is only worth what the chain under it is
  // worth: a daemon believes it because a ROOT key signed the `trust.json` that
  // names the index key, and `PRODUCTION_ROOT_KEYS` is compiled in. Until the
  // ceremony in SECURITY.md §4 runs, `registry/v1/root.json` is
  // `"status": "unprovisioned"` with an empty `roots` and every shipped daemon
  // fails closed on every signature. Pages that would otherwise promise a
  // verified install read this and say so instead.
  //
  // `null` means "no root.json in this tree" — the selftest's synthetic build,
  // and treated exactly like unprovisioned, because a claim nobody can check is
  // not a claim this generator makes.
  const rootDoc = opts.registryDir
    ? JSON.parse(readIfPresent(path.join(opts.registryDir, "root.json")) ?? "null")
    : null;

  const meta = {
    serial: signed.serial,
    issued_at: signed.issued_at ?? null,
    expires_at: signed.expires_at ?? null,
    signatures: indexDoc.signatures ?? [],
    roots: Array.isArray(rootDoc?.roots) ? rootDoc.roots.length : null,
  };

  const entries = [...signed.plugins].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const plugins = new Map(entries.map((e) => [e.id, e]));
  const withdrawnIds = new Set(entries.filter((e) => withdrawalsFor(e, revocations).length).map((e) => e.id));

  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });

  const written = [];
  const w = (rel, contents) => {
    write(out, rel, contents);
    written.push(rel);
  };

  // ── the catalogue, and the pages that are a function of it ───────────────
  w("index.html", homePage(entries, { meta, withdrawnIds }));
  w("search/index.html", searchPage());
  w("publish/index.html", publishPage({ repo }));
  w("404.html", notFoundPage());

  const pluginPages = [];
  for (const entry of entries) {
    // The id is a path component on a user's disk before it is one here, and
    // `tools/validate.mjs` has already refused every id this would not accept.
    // Checked again anyway, because this is the line that turns a string from a
    // JSON file into a directory: an id that reached here containing `..` would
    // write a page outside the output tree.
    if (!/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])$/.test(entry.id)) {
      throw new Error(`refusing to write a page for ${JSON.stringify(entry.id)}: not a plugin id`);
    }
    w(`p/${entry.id}/index.html`, pluginPage(entry, { revocations, meta, highRisk: CONSENT_HIGH_RISK }));
    pluginPages.push(entry.id);
  }

  // ── publishers ───────────────────────────────────────────────────────────
  //
  // A publisher is the owner of the repository a plugin is released from —
  // there are no registry accounts, so there is nothing else it could be.
  const byOwner = new Map();
  for (const entry of entries) {
    const repoName = entry.source?.repo ?? "";
    const owner = repoName.split("/")[0];
    if (!owner || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) continue;
    if (!byOwner.has(owner)) byOwner.set(owner, []);
    byOwner.get(owner).push(entry);
  }
  for (const [owner, owned] of [...byOwner].sort()) {
    w(`publisher/${owner}/index.html`, publisherPage(owner, owned, { withdrawnIds }));
  }

  // ── advisories ───────────────────────────────────────────────────────────
  //
  // Grouped back out of the SIGNED document. An advisory file sitting in
  // `tools/revocations/` that has not been deployed gets no page: the site may
  // not announce a withdrawal that is not in force.
  const { advisories: sourceAdvisories } = loadAdvisories({ root });
  const sources = new Map(sourceAdvisories.map((a) => [a.id, a]));
  const advisories = groupAdvisories(revocations, sources);
  for (const advisory of advisories) {
    if (!/^ASTRA-\d{4}-\d{4,}$/.test(advisory.id)) {
      throw new Error(`refusing to write a page for advisory ${JSON.stringify(advisory.id)}`);
    }
    w(`advisory/${advisory.id}/index.html`, advisoryPage(advisory, { plugins }));
  }

  // ── the transparency log ─────────────────────────────────────────────────
  const log = buildModerationLog({
    root,
    // `null` when there is no withdrawal list to check against, which is what
    // makes `backed` honest rather than assumed.
    revocations: revDoc ? revocations : null,
    revocationsSerial: revDoc?.signed?.serial,
  });
  w("transparency/moderation-log.json", `${JSON.stringify(log, null, 2)}\n`);
  w("transparency/index.html", transparencyPage({ log, advisories, meta, plugins }));

  // ── the repository's own documents, rendered ──────────────────────────────
  const policy = readIfPresent(path.join(root, "POLICY.md"));
  const pubPolicy = readIfPresent(path.join(root, "docs/POLICY.md"));
  w(
    "policy/index.html",
    docPage({
      title: "Policy",
      active: "policy",
      intro: `<p class="thin">Two documents. The first says what may be listed at all; the second says
what happens to a release that got everything right — whether it publishes itself, waits, or waits
for a person. Both are rendered from the repository, so this page cannot state a rule the repository
does not have.</p>`,
      parts: [
        ["POLICY.md", policy ? markdown(policy) : "<p>Not published yet.</p>"],
        ["docs/POLICY.md", pubPolicy ? markdown(pubPolicy) : "<p>Not published yet.</p>"],
      ],
    }),
  );

  const security = readIfPresent(path.join(root, "SECURITY.md"));
  const contact = JSON.parse(readIfPresent(path.join(root, "bot/security-contact.json")) ?? "{}");
  w(
    "security/index.html",
    docPage({
      title: "Security",
      active: "security",
      intro: securityIntro(contact),
      parts: [["SECURITY.md", security ? markdown(security) : "<p>Not published yet.</p>"]],
    }),
  );

  // ── assets, verbatim ─────────────────────────────────────────────────────
  const assets = path.join(path.dirname(fileURLToPath(import.meta.url)), "assets");
  for (const file of fs.readdirSync(assets)) {
    w(`assets/${file}`, fs.readFileSync(path.join(assets, file)));
  }

  // GitHub Pages runs Jekyll over an artifact unless told not to, and Jekyll
  // silently drops files and directories whose names begin with an underscore.
  // Nothing here starts with one today; a plugin id cannot. This is one byte
  // against the day something does.
  w(".nojekyll", "");

  // ── the same bytes, served from the same origin ──────────────────────────
  if (opts.registryDir) {
    for (const file of fs.readdirSync(opts.registryDir)) {
      const src = path.join(opts.registryDir, file);
      if (fs.statSync(src).isFile()) w(`registry/v1/${file}`, fs.readFileSync(src));
    }
  }

  return {
    pages: written,
    plugins: pluginPages,
    advisories: advisories.map((a) => a.id),
    publishers: [...byOwner.keys()].sort(),
  };
}

/**
 * The security page's preamble: the embargoed-report path, and — where it is
 * not provisioned — the fact that it is not.
 *
 * `bot/security-contact.json` carries the mailbox and, once the key exists, its
 * fingerprint and armored public key. Until then this page says so. The
 * repository already does exactly this with the two root key slots, which are
 * empty and which a default build fails closed on; inventing a fingerprint here
 * so the page looks finished would teach a reporter to trust a key nobody holds.
 */
function securityIntro(contact) {
  const mailbox = typeof contact.email === "string" ? contact.email : null;
  const fpr = typeof contact.pgp_fingerprint === "string" && contact.pgp_fingerprint.length ? contact.pgp_fingerprint : null;
  const keyFile = typeof contact.pgp_key_file === "string" && contact.pgp_key_file.length ? contact.pgp_key_file : null;

  const embargo = fpr
    ? `<p><strong>Encrypted, for anything that would let somebody ship code to a user.</strong>
Mail <code>${escapeText(mailbox ?? "")}</code>, encrypted to
<code class="digest">${escapeText(fpr)}</code>${keyFile ? ` — <a href="${escapeText(keyFile)}">public key</a>` : ""}.</p>`
    : `<p class="alert"><strong>There is no PGP key yet.</strong> The mailbox
${mailbox ? `<code>${escapeText(mailbox)}</code>` : "in the repository profile"} exists and is read,
but nothing published here can encrypt to it, so <em>do not send an unencrypted vulnerability report
to it</em>. Use a <a href="${escapeText(contact.advisory_url ?? "")}">private GitHub security
advisory</a> instead: it is end-to-end between you and the maintainer, it needs no key ceremony, and
it is the path this registry can honestly offer today. This paragraph is generated from
<code>bot/security-contact.json</code> and is replaced by the key&rsquo;s fingerprint the moment one
is provisioned — see <code>docs/POLICY.md</code> for what provisioning involves.</p>`;

  return `${embargo}
<p class="thin">Please do not open a public issue for anything that would let someone ship code to a
user. Everything else &mdash; a plugin behaving differently from its description, a name that looks
like impersonation &mdash; is a normal public issue, and those are the reports this registry
actually relies on.</p>`;
}

/** Local escaping for the two strings above; the templates use `esc`. */
function escapeText(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help || !opts.index || !opts.out) {
    console.log(
      "usage: node site/build.mjs --index FILE --out DIR [--revocations FILE] [--registry-dir DIR] [--repo owner/name]",
    );
    return opts.help ? 0 : 2;
  }
  const result = build(opts);
  console.log(
    `wrote ${result.pages.length} file(s) to ${path.relative(process.cwd(), opts.out)}: ` +
      `${result.plugins.length} plugin page(s), ${result.publishers.length} publisher page(s), ` +
      `${result.advisories.length} advisory page(s)`,
  );
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}
