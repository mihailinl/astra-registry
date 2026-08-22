// Reads plugins/** into memory. Structure only — no policy, no schema.
// Everything here reports the file it failed on, because "unexpected token }"
// with no path is the reason people stop trusting a tool.

import fs from "node:fs";
import path from "node:path";

import { confusableSkeleton } from "./ids.mjs";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

export function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new Error(`${file}: cannot read (${e.code ?? e.message})`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${file}: not valid JSON — ${e.message}`);
  }
}

/**
 * @param {string} root repo root
 * @returns {{errors: {file: string, message: string}[],
 *            plugins: {dir: string, id: string, file: string, doc: object,
 *                      versions: {file: string, basename: string, doc: object}[]}[]}}
 */
export function loadSources(root = REPO_ROOT) {
  const errors = [];
  const plugins = [];
  const pluginsDir = path.join(root, "plugins");
  if (!fs.existsSync(pluginsDir)) {
    return { errors: [{ file: "plugins/", message: "directory does not exist" }], plugins };
  }

  const dirents = fs.readdirSync(pluginsDir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );

  for (const dirent of dirents) {
    const rel = path.join("plugins", dirent.name);
    if (dirent.isSymbolicLink()) {
      errors.push({ file: rel, message: "is a symlink; plugins/ holds real directories only" });
      continue;
    }
    if (!dirent.isDirectory()) {
      errors.push({ file: rel, message: "is not a directory; plugins/ holds one directory per plugin" });
      continue;
    }

    const manifestFile = path.join(pluginsDir, dirent.name, "plugin.json");
    if (!fs.existsSync(manifestFile)) {
      errors.push({ file: path.join(rel, "plugin.json"), message: "missing" });
      continue;
    }

    let doc;
    try {
      doc = readJson(manifestFile);
    } catch (e) {
      errors.push({ file: path.join(rel, "plugin.json"), message: e.message });
      continue;
    }

    const versions = [];
    const versionsDir = path.join(pluginsDir, dirent.name, "versions");
    if (!fs.existsSync(versionsDir)) {
      errors.push({ file: path.join(rel, "versions/"), message: "missing; a listing with no version has nothing to install" });
    } else {
      const files = fs.readdirSync(versionsDir, { withFileTypes: true }).sort((a, b) =>
        a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
      );
      for (const f of files) {
        const vrel = path.join(rel, "versions", f.name);
        if (!f.isFile()) {
          errors.push({ file: vrel, message: "is not a regular file" });
          continue;
        }
        if (!f.name.endsWith(".json")) {
          errors.push({ file: vrel, message: "is not a .json file" });
          continue;
        }
        try {
          versions.push({
            file: vrel,
            basename: f.name.slice(0, -".json".length),
            doc: readJson(path.join(versionsDir, f.name)),
          });
        } catch (e) {
          errors.push({ file: vrel, message: e.message });
        }
      }
    }

    plugins.push({
      dir: dirent.name,
      id: doc?.id,
      file: path.join(rel, "plugin.json"),
      doc,
      versions,
    });
  }

  return { errors, plugins };
}

export function loadPolicy(root = REPO_ROOT) {
  return {
    limits: readJson(path.join(root, "policy", "limits.json")),
    spdx: readJson(path.join(root, "policy", "spdx-allowlist.json")),
    reserved: readJson(path.join(root, "policy", "reserved-ids.json")),
  };
}

export function loadSchemas(root = REPO_ROOT) {
  return {
    index: readJson(path.join(root, "schema", "index-v1.json")),
    plugin: readJson(path.join(root, "schema", "plugin-v1.json")),
    version: readJson(path.join(root, "schema", "version-v1.json")),
    publisher: readJson(path.join(root, "schema", "publisher-v1.json")),
  };
}

/**
 * Reads `publishers/*.json` into a map keyed by the LOWERCASED owner login —
 * `owner`, plus every login the record's `covers` list says it also speaks for,
 * all pointing at the SAME record object. Use `publisherRecords` when you want
 * each record once rather than each key once.
 *
 * Structure only, like `loadSources` — no policy, no schema, and no clock. The
 * expiry a `verified` record carries is deliberately NOT enforced here: this
 * module feeds a generator whose whole contract is "same sources, same bytes",
 * and a rule that consults the date makes today's index differ from tomorrow's
 * for reasons no diff can show. Expiry is a CHECK (see `expiredPublishers`),
 * which fails loudly and puts a person in front of it, rather than a silent
 * disappearance nobody can date.
 *
 * GitHub logins are case-insensitive, so `mihailinl` and `MihailinL` are one
 * account; keying on the lowercase form is what makes a listing's
 * `source.repo` find its publisher regardless of how either was typed.
 */
export function loadPublishers(root = REPO_ROOT) {
  const dir = path.join(root, "publishers");
  const errors = [];
  const publishers = new Map();
  if (!fs.existsSync(dir)) return { errors, publishers };

  const files = fs.readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const ent of files) {
    const rel = `publishers/${ent.name}`;
    if (ent.isSymbolicLink()) {
      errors.push({ file: rel, message: "is a symlink; publishers/ holds real files only" });
      continue;
    }
    if (!ent.isFile() || !ent.name.endsWith(".json")) continue;
    let doc;
    try {
      doc = readJson(path.join(dir, ent.name));
    } catch (e) {
      errors.push({ file: rel, message: `is not readable JSON — ${e.message}` });
      continue;
    }
    const stem = ent.name.slice(0, -".json".length);
    if (typeof doc?.owner !== "string" || doc.owner.toLowerCase() !== stem.toLowerCase()) {
      // The file name is the key the index is built on, so a record naming a
      // different owner than its file would attach a badge to an account
      // nobody reviewed.
      errors.push({ file: rel, message: `owner ${JSON.stringify(doc?.owner)} does not match the file name` });
      continue;
    }
    // The record's own login, plus every login it says it also speaks for.
    // `covers` exists because the badge is keyed on the owner half of
    // `source.repo` and a person's plugins do not all live under their personal
    // login: `KnlCE`'s reviewed record reached none of their listings, because
    // those live under the `KNICE-TECH` organisation. A second file for the org
    // is NOT the fix — it would carry the same `display_name` and trip
    // `publisherNameCollisions`, correctly, since two records rendering as one
    // word is exactly what that check is for.
    //
    // Every key is claimed the same way and refused the same way, so a
    // `covers` entry cannot quietly take an owner another record already owns,
    // in either direction and whichever file was read first.
    const claims = [doc.owner, ...(Array.isArray(doc.covers) ? doc.covers : [])];
    const taken = claims.map((c) => String(c).toLowerCase()).find((k) => publishers.has(k));
    if (taken !== undefined) {
      const by = publishers.get(taken);
      errors.push({
        file: rel,
        message: taken === doc.owner.toLowerCase() && by.doc.owner.toLowerCase() === taken
          ? `a second record for ${doc.owner}`
          : `claims ${taken}, which ${by.file} already claims`,
      });
      continue;
    }
    const record = { file: rel, doc };
    for (const claim of claims) publishers.set(String(claim).toLowerCase(), record);
  }
  return { errors, publishers };
}

/**
 * The DISTINCT records in a publishers map, once each.
 *
 * The map is keyed by login and a record with `covers` is stored under several,
 * so `publishers.values()` yields the same object more than once. Every caller
 * that reasons about records rather than about keys wants this instead — and
 * one of them, `publisherNameCollisions`, would otherwise compare a record with
 * itself, find its own display name identical to its own display name, and
 * report every multi-login publisher as an impersonation of itself.
 */
export function publisherRecords(publishers) {
  return [...new Set(publishers.values())];
}

/**
 * The records whose evidence has not been confirmed inside its own window.
 *
 * Separate from the loader and from the generator because it is the one part
 * of this that has to know what day it is. A tier granted once and never
 * revisited is a claim about who somebody USED to be; this is what notices.
 */
export function expiredPublishers(publishers, now = new Date()) {
  const today = now.toISOString().slice(0, 10);
  const out = [];
  for (const { file, doc } of publisherRecords(publishers)) {
    if (typeof doc.expires_at === "string" && doc.expires_at < today) {
      out.push({ file, owner: doc.owner, expires_at: doc.expires_at });
    }
  }
  return out;
}

/**
 * Publisher names that a person could not tell apart.
 *
 * The display name is the word a user reads beside a trust mark, so two
 * publishers who render as the same word are an impersonation whether or not
 * anybody intended one. The catalogue already refuses this for plugin NAMES;
 * the argument is stronger here, because a plugin name sits beside a
 * description and a badge sits beside a claim about identity.
 *
 * `confusableSkeleton` and not a fold, and this repository already contains the
 * example that shows why: `KNICE` and `KnlCE` differ by a capital i against a
 * lowercase L. Case folding leaves them distinct — `knice` and `knlce` — and a
 * reader cannot tell them apart in any typeface they are likely to meet. The
 * skeleton collapses both to `knice`, which is the honest answer.
 *
 * A record's OWN login and display name are allowed to collide, and that is not
 * an oversight: `KnlCE` publishing as `KNICE` is one account spelling its own
 * name, which is the case this whole field exists to serve. What is refused is
 * one publisher wearing another's word.
 */
export function publisherNameCollisions(publishers) {
  const out = [];
  const records = publisherRecords(publishers);
  for (let i = 0; i < records.length; i++) {
    for (let j = i + 1; j < records.length; j++) {
      const a = records[i].doc;
      const b = records[j].doc;
      const an = confusableSkeleton(a.display_name ?? "");
      const bn = confusableSkeleton(b.display_name ?? "");
      if (an && an === bn) {
        out.push({ a: a.owner, b: b.owner, why: `both display as ${JSON.stringify(an)} once confusables are folded` });
        continue;
      }
      // Somebody else's LOGIN is also a word users see — in a repository URL,
      // and in this UI as the fallback when a display name is missing.
      if (an && an === confusableSkeleton(b.owner)) {
        out.push({ a: a.owner, b: b.owner, why: `${JSON.stringify(a.display_name)} is confusable with the login ${JSON.stringify(b.owner)}` });
      } else if (bn && bn === confusableSkeleton(a.owner)) {
        out.push({ a: b.owner, b: a.owner, why: `${JSON.stringify(b.display_name)} is confusable with the login ${JSON.stringify(a.owner)}` });
      }
    }
  }
  return out;
}
