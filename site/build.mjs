#!/usr/bin/env node
// The website. Static, no framework, no dependency, and generated from the
// signed catalogue in the job that publishes it.
//
//   node site/build.mjs --index dist/registry/v1/index.json --out dist/site \
//        [--revocations dist/registry/v1/revocations.json] \
//        [--registry-dir dist/registry/v1] [--redirects site/redirects.json] \
//        [--repo owner/name]
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
import { buildModerationLog, loadEntries, BACKING, SCHEMA } from "../bot/lib/moderation.mjs";
import { loadAdvisories } from "../tools/lib/revocations.mjs";
import { invalidId, unsafePathComponent } from "../tools/lib/ids.mjs";

import { markdown } from "./lib/html.mjs";
import { pluginPage, withdrawalsFor } from "./templates/plugin.mjs";
import { advisoryPage, groupAdvisories } from "./templates/advisory.mjs";
import { homePage, searchPage, publisherPage, publishPage, docPage, transparencyPage, notFoundPage, redirectPage } from "./templates/pages.mjs";

/** The repository this catalogue is served from, for the links that need one. */
const DEFAULT_REPO = "mihailinl/astra-registry";

function parseArgs(argv) {
  const opts = { out: null, index: null, revocations: null, registryDir: null, redirects: null, root: REPO_ROOT, repo: DEFAULT_REPO };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") opts.out = path.resolve(argv[++i]);
    else if (a === "--index") opts.index = path.resolve(argv[++i]);
    else if (a === "--revocations") opts.revocations = path.resolve(argv[++i]);
    else if (a === "--registry-dir") opts.registryDir = path.resolve(argv[++i]);
    else if (a === "--redirects") opts.redirects = path.resolve(argv[++i]);
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
 *          registryDir?: string|null, redirects?: string|null, root?: string,
 *          repo?: string}} opts
 * @returns {{pages: string[], plugins: string[], advisories: string[],
 *            publishers: string[], redirects: string[]}}
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
    // Asked of `tools/lib/ids.mjs` rather than re-written here. The copy that
    // used to sit on this line was correct and was still a second answer to a
    // question with one owner: tighten the predicate there and this line would
    // have gone on admitting what it always did, silently, at the one place
    // that turns a JSON string into a directory name.
    const bad = unsafePathComponent(entry.id) ?? invalidId(entry.id);
    if (bad) {
      throw new Error(`refusing to write a page for ${JSON.stringify(entry.id)}: ${bad}`);
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
  const log = moderationLog({ root, revDoc, revocations });
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

  // ── and, last, the pages that have moved ─────────────────────────────────
  //
  // After everything, including `registry/v1/`, so that a redirect is written
  // over a page that was generated rather than instead of one. The refusals in
  // `applyRedirects` are then about files that demonstrably exist, and "this
  // path was never generated" is a real finding instead of an ordering
  // accident.
  const redirects = opts.redirects ? applyRedirects({ out, file: opts.redirects, written }) : [];

  return {
    pages: written,
    plugins: pluginPages,
    advisories: advisories.map((a) => a.id),
    publishers: [...byOwner.keys()].sort(),
    redirects,
  };
}

// ── ROLL-55: the pages that move, and the documents that must not ───────────
//
// The site is generated from the signed catalogue, and at R4b and R9a its
// pages are replaced one set at a time by the plugins service's own. Pages
// serves this tree and offers no redirect configuration, so a moved page has
// to *be* a page — see `redirectPage` for which two mechanisms it writes and
// for whom.
//
// THE PART THAT IS NOT ABOUT PAGES. `registry/v1/*` and
// `transparency/moderation-log.json` MUST stay byte-identical for as long as
// Pages serves anything (ROLL-55; ROLL-57 keeps the signed documents there
// until R9b). Shipped 0.2.x daemons fetch the catalogue, the withdrawal list
// and the trust documents from this host and derive the sibling URLs by path
// (astra-daemon/src/plugins/registry_client.rs); an HTML stub at one of those
// paths is not a redirect to such a client, it is a catalogue that fails to
// parse — or, worse, a withdrawal list that fails to parse, which is the one
// document whose absence has to be conspicuous. So this function refuses to
// write over anything that is not a generated `.html`, and names ROLL-55 when
// the mapping lands on one of those two.
//
// That refusal is the whole reason the sets are a data file rather than a
// prefix rule: `/transparency/` moves at R9a and
// `/transparency/moderation-log.json` never does, and the two differ by one
// path component.

/** `<id>`, `<owner>` — the only placeholders, on both sides of a mapping. */
const PLACEHOLDER = /<([a-z][a-z0-9_]*)>/g;

/** A target a browser will follow and the outside probe can fetch. */
const ABSOLUTE_HTTPS = /^https:\/\/[^\s"'<>]+$/;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `/` → `index.html`; `/p/<id>/` → `p/<id>/index.html`; `/404.html` → `404.html`. */
function siteFile(sitePath) {
  const rel = sitePath.replace(/^\//, "");
  return rel === "" || rel.endsWith("/") ? `${rel}index.html` : rel;
}

/** A pattern, as a regex over generated files, plus the names it captures. */
function matcher(filePattern) {
  const names = [];
  let source = "";
  let last = 0;
  for (const m of filePattern.matchAll(PLACEHOLDER)) {
    source += escapeRe(filePattern.slice(last, m.index));
    source += "([^/]+)";
    names.push(m[1]);
    last = m.index + m[0].length;
  }
  source += escapeRe(filePattern.slice(last));
  return { re: new RegExp(`^${source}$`), names };
}

/**
 * Replace each mapped page with a redirect. Returns the files rewritten.
 *
 * @param {{out: string, file: string, written: string[]}} ctx
 */
export function applyRedirects({ out, file, written }) {
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  const where = path.basename(file);
  if (doc.schema !== "astra.registry.site-redirects/1") {
    throw new Error(`${where}: schema is ${JSON.stringify(doc.schema)}, not "astra.registry.site-redirects/1"`);
  }
  if (!Array.isArray(doc.sets)) throw new Error(`${where}: \`sets\` must be an array of { step, paths }`);

  const htmlPages = written.filter((rel) => rel.endsWith(".html"));
  const generated = new Set(written);
  /** file → the mapping that claimed it, so two sets cannot both own a page. */
  const claimed = new Map();
  const done = [];

  for (const set of doc.sets) {
    const step = set?.step;
    if (typeof step !== "string" || !/^R[0-9]+[a-z]?$/.test(step)) {
      throw new Error(`${where}: every set needs a \`step\` like "R4b"; got ${JSON.stringify(step)}`);
    }
    if (!set.paths || typeof set.paths !== "object" || Array.isArray(set.paths)) {
      throw new Error(`${where}: set ${step} has no \`paths\` object`);
    }

    for (const [sitePath, target] of Object.entries(set.paths)) {
      const at = `${where}: set ${step}, ${sitePath}`;
      if (!sitePath.startsWith("/")) throw new Error(`${at}: a path must start with "/"`);
      if (typeof target !== "string" || !ABSOLUTE_HTTPS.test(target.replace(PLACEHOLDER, "x"))) {
        throw new Error(
          `${at}: the target must be an absolute https URL, not ${JSON.stringify(target)}. The successor ` +
            "host belongs in one greppable place, and the daily probe fetches these verbatim.",
        );
      }

      const filePattern = siteFile(sitePath);
      const { re, names } = matcher(filePattern);
      for (const m of String(target).matchAll(PLACEHOLDER)) {
        if (!names.includes(m[1])) throw new Error(`${at}: the target uses <${m[1]}>, which the path does not capture`);
      }

      const hits = names.length ? htmlPages.filter((rel) => re.test(rel)) : [filePattern].filter((rel) => generated.has(rel));

      if (!hits.length) {
        if (names.length) {
          // A pattern that matched nothing is legitimate — `/advisory/<id>/`
          // with no advisories deployed is the state this catalogue is in
          // today — so it is a line in the build log rather than a refusal.
          // The direction that protects is the other one, and RC-R9-1's canary
          // holds it: before R9a is requested, every generated HTML path is in
          // a set.
          console.log(`note  ${at}: matched no page in this build`);
          continue;
        }
        // A literal, though, is a typo. `/plublisher/` would sit in the file
        // redirecting nothing, the probe would never fetch it, and the old URL
        // would go on serving a page the service has replaced.
        throw new Error(`${at}: this build generated no such page, so the mapping would do nothing`);
      }

      for (const rel of hits) {
        // Named first, and before the general rule below, so that the two
        // paths ROLL-55 is actually about are refused with ROLL-55's reason
        // rather than with "that is not a page" — which is true, and is not
        // what a reader of this diff needs to know.
        if (rel.startsWith("registry/v1/") || rel === "transparency/moderation-log.json") {
          throw new Error(
            `${at}: ${rel} must stay byte-identical (ROLL-55). It is fetched by daemons and by outside ` +
              "checkers, which follow no redirect and would read an HTML stub as a malformed document.",
          );
        }
        if (!rel.endsWith(".html")) {
          throw new Error(`${at}: refusing to write a redirect over ${rel}, which is not a generated page`);
        }
        const already = claimed.get(rel);
        if (already) throw new Error(`${at}: ${rel} is already redirected by set ${already}`);
        claimed.set(rel, step);

        const values = Object.fromEntries(names.map((n, i) => [n, re.exec(rel)[i + 1]]));
        const to = target.replace(PLACEHOLDER, (_, n) => values[n]);
        if (!ABSOLUTE_HTTPS.test(to)) throw new Error(`${at}: expanded to ${JSON.stringify(to)}, which is not an https URL`);

        const from = `/${rel.replace(/(^|\/)index\.html$/, "$1")}`;
        write(out, rel, redirectPage({ from, to, depth: rel.split("/").length - 1 }));
        done.push(rel);
      }
    }
  }

  return done.sort();
}

/**
 * The moderation log, for a renderer that is not allowed to fail.
 *
 * ── WHY THIS IS NOT `buildModerationLog(…, revocations)` ────────────────────
 *
 * `bot/lib/moderation.mjs` throws when a log entry names an advisory the signed
 * withdrawal list it was handed does not carry. That refusal is right where it
 * lives — `bot/moderation.mjs --check` runs on every pull request, and a log
 * entry claiming a revocation nobody signed must never be merged. It is wrong
 * *here*, and the reason is the clock.
 *
 * A deprecate or a revoke is committed as one commit (MOD-3): the advisory
 * file, the log entry, the catalogue edit. The signed withdrawal list that
 * carries that advisory is produced by a LATER job. So between the commit and
 * the next signing run there is a window in which `bot/moderation/…-revoke.json`
 * names `ASTRA-2026-000N` and the deployed `registry/v1/revocations.json` does
 * not. With the throw wired into the generator, the site build in that window
 * dies — and the site build is in the job that PUBLISHES the catalogue. So the
 * first effect of recording a takedown was to stop the deploy that carries it,
 * and to keep stopping every deploy after it, including the yank or delist
 * somebody files next. That is exactly the shape MOD-46 forbids: a moderation
 * check that delays a moderation action.
 *
 * MOD-7 says what a renderer does instead. It shows a deprecate or a revoke as
 * in effect ONLY once the withdrawal list this host serves carries it, and
 * otherwise shows it as **pending** — never failing its build. That is a
 * stronger claim than the old one, not a weaker one: the old `backed: true`
 * came from a build that would have thrown rather than print `false`, so it was
 * a fact about the build succeeding rather than about the document, and the
 * page could not have told a reader "signed, but not deployed here yet"
 * because that state killed the job.
 *
 * `backed` therefore has four values, and every one of them is a statement
 * about THIS deploy tree:
 *
 *   true        the advisory is in the withdrawal list published beside this
 *               page, with an action that matches (`BACKING`). In effect here.
 *   "pending"   the entry names an advisory, and this tree's withdrawal list
 *               does not carry it — or carries it with a different action.
 *               Recorded, not yet in force on this host.
 *   null        there is no withdrawal list in this tree at all, so nothing was
 *               checked. Unchanged from before.
 *   false       a yank or a delist. It produces no signed document; the
 *               catalogue beside this page IS its effect.
 *
 * ── AND WHY IT ALSO SWALLOWS AN INVALID SOURCE ──────────────────────────────
 *
 * Same argument one step out. `loadEntries` refuses a malformed entry file, and
 * `buildModerationLog` turns that into a throw. On the pull request that is the
 * right answer and `bot/moderation.mjs --check` gives it. In the publish job it
 * would again be a moderation check stopping a catalogue deploy, which is the
 * one thing MOD-46 says it must not do. So the log degrades to "these sources
 * did not load" — loudly, on the page and in the JSON — and the catalogue, the
 * yank and the delist go out.
 *
 * Only the source PATHS are published, never the validator's messages: a
 * message quotes the offending entry's own text, and the reason an entry is
 * refused is often that its text carries something that must not reach a
 * reader's screen. The messages go to the build log.
 *
 * @param {{root: string, revDoc: object|null, revocations: object[]}} ctx
 */
function moderationLog({ root, revDoc, revocations }) {
  // Asked BEFORE the build rather than caught around it, and the difference is
  // the whole point of this function. A `try` here would also swallow the
  // backing throw — the thing this file exists to have removed — and publish an
  // empty log with an "unavailable" notice instead of a pending row, quietly,
  // exit 0. The canary in `site/selftest.mjs` was written against a version
  // that did exactly that: the mutation went red, but on the wrong sentence.
  const { errors } = loadEntries({ root });
  if (errors.length) {
    console.error("WARN  the moderation sources did not load; the log is published empty and says so.");
    for (const e of errors) console.error(`      ${e}`);
    const files = errors.map((e) => e.split(":")[0]).filter((f) => f.startsWith("bot/moderation/"));
    return {
      $comment:
        "GENERATED FILE — DO NOT EDIT. This build could not read bot/moderation/. The entries below " +
        "are NOT the whole log; see `unavailable`.",
      schema: SCHEMA,
      ...(revDoc?.signed?.serial !== undefined ? { revocations_serial: revDoc.signed.serial } : {}),
      unavailable: { sources: [...new Set(files)].sort() },
      entries: [],
    };
  }

  // Built with NO withdrawal list on purpose. `buildModerationLog`'s backing
  // check is the throw this function exists to be rid of, and it only runs when
  // it is handed one; withholding it removes the throw by construction rather
  // than by catching it, which is the difference between "cannot fail here" and
  // "fails silently here". What comes back is every entry with `backed: null`
  // for the ones naming an advisory and `backed: false` for the ones that
  // cannot, and the loop below is the only thing that ever says `true`.
  const log = buildModerationLog({ root, revocationsSerial: revDoc?.signed?.serial });

  if (!revDoc) return log; // `backed: null` — nothing to check against.

  const signedByAdvisory = new Map();
  for (const r of revocations) if (!signedByAdvisory.has(r.id)) signedByAdvisory.set(r.id, r);

  for (const e of log.entries) {
    if (!e.advisory) continue; // yank, delist: `backed: false`, and that is right.
    const signed = signedByAdvisory.get(e.advisory);
    e.backed = signed && BACKING[e.action].includes(signed.action) ? true : "pending";
  }
  return log;
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
      "usage: node site/build.mjs --index FILE --out DIR [--revocations FILE] [--registry-dir DIR]\n" +
        "                          [--redirects site/redirects.json] [--repo owner/name]",
    );
    return opts.help ? 0 : 2;
  }
  const result = build(opts);
  console.log(
    `wrote ${result.pages.length} file(s) to ${path.relative(process.cwd(), opts.out)}: ` +
      `${result.plugins.length} plugin page(s), ${result.publishers.length} publisher page(s), ` +
      `${result.advisories.length} advisory page(s)` +
      (opts.redirects ? `, ${result.redirects.length} of them replaced by a redirect` : ""),
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
