// Reads plugins/** into memory. Structure only — no policy, no schema.
// Everything here reports the file it failed on, because "unexpected token }"
// with no path is the reason people stop trusting a tool.

import fs from "node:fs";
import path from "node:path";
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
  };
}
