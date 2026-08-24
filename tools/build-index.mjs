#!/usr/bin/env node
// Generates registry/v1/index.json from plugins/**. Nothing else writes it.
//
//   node tools/build-index.mjs            regenerate in place
//   node tools/build-index.mjs --check    fail if the committed file is not
//                                         exactly what this script produces
//   node tools/build-index.mjs --stdout   print, write nothing
//   node tools/build-index.mjs --serial N override the serial
//   node tools/build-index.mjs --registry-dir DIR  generate another tree's index
//
// TWO PROPERTIES THIS FILE EXISTS TO PROTECT
//
// 1. Determinism. Same sources + same serial -> same bytes. No clock read, no
//    map iteration order, no locale collation: keys are sorted by UTF-16 code
//    unit (tools/lib/canonical.mjs), plugins by id, releases by semver. That is
//    what makes `--check` meaningful and what will let a third party in Phase 3
//    reproduce the signed index from the git tree and diff it against ours.
//
// 2. The flat fields are a projection, not a second source. `version`,
//    `platform_downloads` and `download_url` exist because the daemon shipping
//    today reads exactly those (Astra astra-daemon/src/plugins/registry_client.rs);
//    `releases[]` is the real record. They are computed here, in one pass, from
//    the same release object, so they cannot drift the way two hand-kept fields
//    always eventually do.
//
// THE SERIAL. Commit count of `main`, path-limited to plugins/. Never
// read-and-increment a counter file: two PRs merging within the same minute
// both read N and both write N+1, and the second one silently un-bumps the
// first. A commit count cannot do that — it is a property of the history, not
// of a file, so concurrent merges get distinct values by construction. It is
// path-limited so that a commit touching only docs or this generator does not
// move the catalogue's version number, and so a future bot that regenerates and
// commits the index cannot trigger itself in a loop.
//
// ── 3.2: THE ENVELOPE, AND WHY THE GENERATOR STILL READS NO CLOCK ───────────
//
// The catalogue is now `{ "signed": { … }, "signatures": [ … ] }` and the
// signature covers `SHA-256("astra.registry.index/1" ‖ 0x00 ‖ JCS(signed))`.
// This file produces the `signed` member and an EMPTY `signatures` array;
// `bot/sign-index.mjs` stamps the freshness window and signs. The split is not
// tidiness:
//
//   * `issued_at`/`expires_at` are properties of the PUBLICATION, not of the
//     content. If the generator stamped them, a catalogue nobody has changed in
//     31 days would expire itself and every user would see a stale banner over a
//     perfectly current catalogue — which is the freeze attack's symptom
//     produced by nothing but the passage of time.
//   * A generator that reads a clock is a generator whose output cannot be
//     reproduced, and `--check`, the determinism diff in CI, and any third
//     party rebuilding the index from the git tree all depend on it being
//     reproducible.
//
// So: content here, freshness at signing time, and `--check` compares the
// content projection so a signed file and a fresh generation can still be held
// to being the same catalogue.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { stableStringify } from "./lib/canonical.mjs";
import { compareSemver } from "./lib/semver.mjs";
import { loadPublishers, loadSources, REPO_ROOT } from "./lib/sources.mjs";
import { INDEX_SCHEMA } from "../bot/lib/sign.mjs";
import { MAX_README_BYTES, iconDataUri } from "../bot/lib/assets.mjs";

const BANNER =
  "GENERATED FILE — DO NOT EDIT. Source of truth: plugins/<id>/plugin.json and " +
  "plugins/<id>/versions/<semver>.json. Regenerate with `node tools/build-index.mjs`. " +
  "CI (.github/workflows/build-index.yml) fails when this file differs by one byte from " +
  "what the generator produces, so a hand edit is not a shortcut, it is a red build. " +
  "Only the `signed` member is covered by the signatures below; nothing outside it is " +
  "authenticated and nothing may be read out of it.";

const PLATFORM_KEYS_FOR_NOARCH = ["linux-x64", "windows-x64"];

export function resolveSerial({ explicit, root = REPO_ROOT } = {}) {
  if (explicit !== undefined && explicit !== null) return explicit;
  if (process.env.ASTRA_REGISTRY_SERIAL) {
    const n = Number(process.env.ASTRA_REGISTRY_SERIAL);
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new Error(`ASTRA_REGISTRY_SERIAL=${process.env.ASTRA_REGISTRY_SERIAL} is not a non-negative integer`);
    }
    return n;
  }
  try {
    const out = execFileSync("git", ["rev-list", "--count", "HEAD", "--", "plugins"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const committed = Number(out.trim());

    // **Plus the commit that is about to be made.**
    //
    // The count answers "how many commits have touched plugins/", and at the
    // moment `ingest.yml` regenerates the index its own catalogue change is
    // STAGED, not committed — so the honest count for the document being
    // written is one higher than the count of history behind it.
    //
    // Without this, every publish shipped a catalogue carrying the PREVIOUS
    // catalogue's serial, and the follow-up `build-index.yml` run — which
    // counts after the push, so it gets the right number — committed a second
    // time to correct it. Measured on four consecutive publishes: `bb126bd`
    // serial 30 with count 31, corrected by `e4b7c53` to 31; `12b22bb` serial
    // 31 with count 32, corrected by `635d973` to 32.
    //
    // Two different catalogues therefore carried one serial, briefly and while
    // deployed. Nothing reads the serial today — the daemon does not compare
    // it and this repository only asserts `>= 1` — so nothing was exploitable.
    // That is precisely why it was worth fixing: a monotonic counter inside a
    // signed document is the shape of an anti-rollback guarantee, and the first
    // reader to rely on it would have inherited a hole nobody put there on
    // purpose.
    //
    // A dirty `plugins/` means exactly one pending commit, because every writer
    // here commits what it staged. A clean tree adds nothing, so `--check` on a
    // pull request is unchanged.
    const dirty = execFileSync("git", ["status", "--porcelain", "--", "plugins"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return dirty.trim() ? committed + 1 : committed;
  } catch {
    // No git history (a fresh checkout of the files, or the repo before its
    // first commit). 0 is the honest answer and it is deterministic.
    return 0;
  }
}

/** Latest-first, yanked releases removed. */
function listedReleases(plugin) {
  return plugin.versions
    .map((v) => v.doc)
    .filter((d) => d && d.yanked !== true)
    .sort((a, b) => -compareSemver(a.version, b.version));
}

function releaseRecord(doc) {
  const artifacts = {};
  for (const [key, art] of Object.entries(doc.artifacts ?? {})) {
    artifacts[key] = {
      url: art.url,
      filename: art.filename,
      ...(art.sha256 !== undefined ? { sha256: art.sha256 } : {}),
      ...(art.size !== undefined ? { size: art.size } : {}),
    };
  }
  return {
    version: doc.version,
    published_at: doc.published_at,
    ...(doc.protocol !== undefined ? { protocol: doc.protocol } : {}),
    ...(doc.min_astra_version !== undefined ? { min_astra_version: doc.min_astra_version } : {}),
    ...(doc.capabilities !== undefined ? { capabilities: [...doc.capabilities].sort() } : {}),
    ...(doc.permissions !== undefined ? { permissions: doc.permissions } : {}),
    ...(doc.changelog_url !== undefined ? { changelog_url: doc.changelog_url } : {}),
    ...(doc.staging === true ? { staging: true } : {}),
    ...(doc.staging === true && doc.staging_reason ? { staging_reason: doc.staging_reason } : {}),
    // Field by field, and each one only when the source carries it. `repo`/`tag`
    // belong to a github_release and `base_url` to a direct one; writing an
    // absent key as `undefined` would drop out of the JSON silently and take
    // with it the only statement of where these bytes are allowed to come from.
    release: {
      kind: doc.release.kind,
      ...(doc.release.repo !== undefined ? { repo: doc.release.repo } : {}),
      ...(doc.release.tag !== undefined ? { tag: doc.release.tag } : {}),
      ...(doc.release.commit !== undefined ? { commit: doc.release.commit } : {}),
      ...(doc.release.base_url !== undefined ? { base_url: doc.release.base_url } : {}),
    },
    artifacts,
  };
}

/**
 * The compatibility projection. Deliberately refuses to emit a download URL for
 * anything it cannot pin by digest: a client that only understands the flat
 * fields has no way to verify what it downloads, so the only safe thing to hand
 * it is nothing at all.
 */
function flatDownloads(latest) {
  const installable =
    latest.staging !== true &&
    Object.values(latest.artifacts).every((a) => typeof a.sha256 === "string" && typeof a.size === "number");
  if (!installable) return { download_url: "", platform_downloads: {} };

  const platform_downloads = {};
  let download_url = "";
  for (const [key, art] of Object.entries(latest.artifacts)) {
    if (key === "noarch") {
      // §5.2: one artifact for every host. Write it under every supported key
      // so no client has to learn the word "noarch".
      download_url = art.url;
      platform_downloads.noarch = art.url;
      for (const k of PLATFORM_KEYS_FOR_NOARCH) platform_downloads[k] = art.url;
    } else {
      platform_downloads[key] = art.url;
    }
  }
  return { download_url, platform_downloads };
}

/**
 * The two presentation files, read off disk and folded into the entry.
 *
 * They are committed as real files next to `plugin.json` — a reviewer sees the
 * picture and the prose in the pull request — and inlined here so that the
 * shipped catalogue carries them inside the signed envelope. A store that
 * fetched them at render time would leak one request per listing to a host the
 * plugin author chose, and would show unauthenticated bytes beside
 * authenticated ones with nothing marking the difference.
 *
 * Reading a file makes this generator's output depend on the working tree,
 * which it already did for every JSON document here; it stays deterministic
 * because the same tree yields the same bytes. No clock, no network.
 */
function presentation(root, plugin) {
  const dir = path.join(root, "plugins", plugin.dir);
  const p = plugin.doc;
  const out = {};
  const errors = [];
  const bad = (file, message) => errors.push({ file, message });

  if (p.icon) {
    const file = path.join(dir, p.icon);
    if (!fs.existsSync(file)) {
      bad(`plugins/${plugin.dir}/plugin.json`, `names icon ${JSON.stringify(p.icon)}, which is not in the directory`);
    } else {
      out.icon_url = iconDataUri({ name: p.icon, bytes: fs.readFileSync(file) });
    }
  } else if (p.icon_url !== undefined) {
    out.icon_url = p.icon_url;
  } else {
    out.icon_url = "";
  }

  if (p.readme) {
    const file = path.join(dir, p.readme);
    if (!fs.existsSync(file)) {
      bad(`plugins/${plugin.dir}/plugin.json`, `names readme ${JSON.stringify(p.readme)}, which is not in the directory`);
    } else {
      const text = fs.readFileSync(file, "utf8");
      // Bytes: this string is about to be inlined into a signed document whose
      // own ceiling is a byte count. bot/lib/assets.mjs truncates to the same
      // number in the same unit, so anything the bot derived fits here by
      // construction and only a hand-edited file can be over.
      const bytes = Buffer.byteLength(text, "utf8");
      if (bytes > MAX_README_BYTES) {
        bad(`plugins/${plugin.dir}/${p.readme}`, `is ${bytes} bytes, over the ${MAX_README_BYTES} the index allows`);
      } else {
        out.readme = text;
      }
    }
  }

  return { out, errors };
}

/**
 * A card's two strings, in the index's vocabulary.
 *
 * `plugin.json` says `summary` and the index says `description`, because the
 * flat fields have always used the spelling the daemon deserialises. **One
 * function, called for the flat pair and for every locale block**, so the two
 * cannot come to mean different things.
 *
 * The alternative is a field list written out twice, and it has a specific bad
 * ending: `plugin.json`'s `description` is the 4,000-character body and the
 * index's `description` is the 200-character card line. A second copy of this
 * rename that reached for `description` on both sides would put the body under
 * the card's name, in two files, passing every length check on the way.
 *
 * `details` — plugin.json's `description`, copied into the index under a third
 * name — used to be emitted beside these. It is gone: `RegistryPlugin` has no
 * such field, so serde dropped it in every daemon that ever fetched it, and in
 * all ten listings it was byte-identical to `description`, which the store site
 * then rendered as a second paragraph saying the same sentence twice. Deleting
 * it also takes a 4,000-character field out of the site's search haystack,
 * which is the one place a "translation" could have been used as a ranking
 * lever against a reviewer reading a clean English card.
 */
function cardText(doc) {
  return { name: doc.name, description: doc.summary };
}

export function buildIndex({ root = REPO_ROOT, serial } = {}) {
  const { errors, plugins } = loadSources(root);
  const { errors: pubErrors, publishers } = loadPublishers(root);
  errors.push(...pubErrors);
  if (errors.length) {
    const lines = errors.map((e) => `  ${e.file}: ${e.message}`).join("\n");
    throw new Error(`cannot generate the index, the sources do not load:\n${lines}`);
  }

  // Everything a listing can be wrong about is collected and reported together.
  // A bare `throw` out of the middle of the loop stops at the first offender,
  // so a tree with three unrenderable listings takes three runs to diagnose and
  // each run names one file. Collecting them does NOT make the build succeed
  // and must not: a listing silently dropped from a signed catalogue is a
  // plugin that vanishes from every user's store with nothing red anywhere.
  // The build still fails — it just says everything it knows first.
  const entryErrors = [];
  const entries = [];
  for (const plugin of plugins) {
    if (plugin.doc.unlisted === true) continue;
    const releases = listedReleases(plugin);
    if (releases.length === 0) {
      entryErrors.push({
        file: `plugins/${plugin.dir}`,
        message: "every version is yanked or missing; delete the listing or add a release",
      });
      continue;
    }
    const records = releases.map(releaseRecord);
    const latest = records[0];
    const { download_url, platform_downloads } = flatDownloads(latest);
    const p = plugin.doc;

    const pres = presentation(root, plugin);
    if (pres.errors.length) {
      entryErrors.push(...pres.errors);
      continue;
    }

    entries.push({
      id: p.id,
      version: latest.version,
      ...cardText(p),
      ...(p.i18n !== undefined
        ? { i18n: Object.fromEntries(Object.entries(p.i18n).map(([code, block]) => [code, cardText(block)])) }
        : {}),
      ...(p.author?.name !== undefined ? { author: p.author.name } : {}),
      ...(p.author?.url !== undefined ? { author_url: p.author.url } : {}),
      license: p.license,
      capabilities: latest.capabilities ?? [],
      ...(p.categories !== undefined ? { categories: [...p.categories].sort() } : {}),
      ...(p.keywords !== undefined ? { keywords: [...p.keywords].sort() } : {}),
      ...(p.homepage !== undefined ? { homepage: p.homepage } : {}),
      repository_url: `https://github.com/${p.source.repo}`,
      ...pres.out,
      source: {
        kind: p.source.kind,
        repo: p.source.repo,
        ...(p.source.subdirectory !== undefined ? { subdirectory: p.source.subdirectory } : {}),
      },
      // The lookup key only, and only when a reviewed record exists. The
      // display name lives once in `signed.publishers` rather than being
      // copied onto every listing, so a rename is one edit and two entries
      // cannot disagree. An owner with no record emits no key at all: the
      // absence is what a client must read as "no badge", and a client that
      // renders on the field merely being present would badge everybody.
      ...(publishers.has(p.source.repo.split("/")[0].toLowerCase())
        ? { publisher: publishers.get(p.source.repo.split("/")[0].toLowerCase()).doc.owner }
        : {}),
      downloads: 0,
      stars: 0,
      updated_at: latest.published_at,
      added_at: p.added_at,
      ...(latest.staging === true ? { staging: true } : {}),
      download_url,
      platform_downloads,
      releases: records,
    });
  }

  if (entryErrors.length) {
    const lines = entryErrors.map((e) => `  ${e.file}: ${e.message}`).join("\n");
    throw new Error(
      `cannot generate the index, ${entryErrors.length} listing(s) cannot be rendered:\n${lines}`,
    );
  }

  entries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Sorted, so the same sources produce the same bytes whatever order the
  // filesystem handed them back.
  const usedPublishers = {};
  for (const key of [...new Set(entries.map((e) => e.publisher).filter(Boolean))].sort()) {
    const rec = publishers.get(key.toLowerCase()).doc;
    usedPublishers[key] = {
      display_name: rec.display_name,
      // The line a person reads. Carried beside the tier rather than derived
      // from it, because "official" says what kind of claim this is and the
      // reader wanted to know who the publisher IS.
      ...(rec.description_text !== undefined ? { description: rec.description_text } : {}),
      tier: rec.tier,
      verified_at: rec.verified_at,
      ...(rec.last_confirmed_at !== undefined ? { last_confirmed_at: rec.last_confirmed_at } : {}),
    };
  }

  return {
    $comment: BANNER,
    // Empty, and written out rather than omitted: a reader that finds no
    // `signatures` member at all cannot tell "this catalogue is unsigned" from
    // "somebody stripped the signatures". An empty array says the first one.
    signatures: [],
    signed: {
      schema: INDEX_SCHEMA,
      serial: resolveSerial({ explicit: serial, root }),
      plugins: entries,
      // One record per publisher, and only for publishers something in this
      // catalogue actually points at — a record for an owner with no listing
      // would be a claim nobody can reach, and it would make the document
      // depend on files that do not affect it.
      //
      // It lives INSIDE `signed`, so the signature the daemon already checks
      // covers it. A badge is a claim the registry makes; putting it anywhere
      // a signature does not reach would let whoever serves the bytes invent
      // one.
      ...(Object.keys(usedPublishers).length ? { publishers: usedPublishers } : {}),
    },
  };
}

/**
 * The content half of a catalogue: everything the generator is responsible for,
 * with the publication stamp removed.
 *
 * `--check` compares this rather than the whole file so that a signed,
 * timestamped catalogue can still be held to being byte-for-byte the catalogue
 * the sources describe. What is being defended is the highest-value edit
 * anybody with commit access could make — a URL or a digest typed straight into
 * the index — and that edit lands squarely inside this projection.
 */
export function indexContent(doc) {
  const signed = doc?.signed ?? doc ?? {};
  const { issued_at, expires_at, ...content } = signed;
  return content;
}

function parseArgs(argv) {
  const opts = { check: false, stdout: false, serial: undefined, out: null, root: REPO_ROOT };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") opts.check = true;
    else if (a === "--stdout") opts.stdout = true;
    else if (a === "--serial") opts.serial = Number(argv[++i]);
    else if (a === "--out") opts.out = argv[++i];
    // Generate SOMEONE ELSE'S catalogue — a self-hosted or staging tree, the
    // same tree tools/validate.mjs judges with its own --registry-dir. Without
    // this the generator could only ever produce this repository's index, and
    // the documented way to run your own catalogue would have been to fork the
    // generator, which is how two generators start disagreeing.
    else if (a === "--registry-dir") opts.root = path.resolve(argv[++i]);
    else if (a === "--help" || a === "-h") opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log("usage: node tools/build-index.mjs [--check] [--stdout] [--serial N] [--out FILE] [--registry-dir DIR]");
    return 0;
  }
  const outFile = path.resolve(opts.root, opts.out ?? "registry/v1/index.json");

  if (opts.check) {
    if (!fs.existsSync(outFile)) {
      console.error(`FAIL  ${path.relative(opts.root, outFile)} does not exist. Run: node tools/build-index.mjs`);
      return 1;
    }
    const committed = fs.readFileSync(outFile, "utf8");
    // Regenerate at the serial the committed file claims. The serial moves with
    // every listing commit, so comparing it here would fail on every push and
    // teach everyone to ignore this check. What is being checked is that the
    // CONTENT is generated — that nobody hand-edited a URL or a digest into it.
    let parsed;
    try {
      parsed = JSON.parse(committed);
    } catch (e) {
      console.error(`FAIL  ${path.relative(opts.root, outFile)} is not valid JSON: ${e.message}`);
      return 1;
    }
    if (!parsed.signed) {
      console.error(
        `FAIL  ${path.relative(opts.root, outFile)} has no \`signed\` member. Since 3.2 the ` +
          "catalogue is a signed envelope. Regenerate with: node tools/build-index.mjs",
      );
      return 1;
    }
    const claimed = parsed.signed.serial;
    const fresh = buildIndex({ root: opts.root, serial: claimed });
    const regenerated = stableStringify(fresh);

    // Two comparisons, and the second is the one that must always hold. A file
    // that has been through bot/sign-index.mjs carries `issued_at`,
    // `expires_at` and real signatures — none of which a generator reading no
    // clock and holding no key can reproduce. Its CONTENT still has to be
    // exactly what the sources say, and that is where a hand-edited URL or
    // digest would land.
    const stamped = parsed.signed.issued_at !== undefined || (parsed.signatures?.length ?? 0) > 0;
    const committedContent = stableStringify(indexContent(parsed));
    const freshContent = stableStringify(indexContent(fresh));
    if (committedContent === freshContent && (stamped || regenerated === committed)) {
      console.log(
        `ok    ${path.relative(opts.root, outFile)} is ${stamped ? "content-identical" : "byte-identical"} to a ` +
          `fresh generation (serial ${claimed}, ${parsed.signatures?.length ?? 0} signature(s))`,
      );
      return 0;
    }
    console.error(`FAIL  ${path.relative(opts.root, outFile)} is not what the generator produces.`);
    const a = (stamped ? committedContent : committed).split("\n");
    const b = (stamped ? freshContent : regenerated).split("\n");
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] !== b[i]) {
        console.error(`      first difference at line ${i + 1}:`);
        console.error(`      committed:   ${a[i] ?? "<end of file>"}`);
        console.error(`      generated:   ${b[i] ?? "<end of file>"}`);
        break;
      }
    }
    console.error("      Fix by running: node tools/build-index.mjs");
    return 1;
  }

  const text = stableStringify(buildIndex({ root: opts.root, serial: opts.serial }));
  if (opts.stdout) {
    process.stdout.write(text);
    return 0;
  }
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const before = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf8") : null;
  fs.writeFileSync(outFile, text);
  const rel = path.relative(opts.root, outFile);
  console.log(before === text ? `ok    ${rel} unchanged` : `wrote ${rel}`);
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
