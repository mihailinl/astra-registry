// A listing's icon and README as content-addressed files beside the catalogue
// (contract 6.28.0 and 6.29.0: BOT-109, TRUST-49; the service's SERVE-115 and
// the client's CLIENT-104 read what this writes).
//
//   "icon":        {"path": "assets/<sha256>.<png|webp|jpg>", "sha256": "<hex>", "size": N, "media_type": "image/png"}
//   "readme_file": {"path": "assets/<sha256>.md",             "sha256": "<hex>", "size": N}
//
// WHY. The catalogue is one signed document every install fetches whole, and
// every client refuses it over 1,048,576 bytes (SERVE-49/50, and the desktop's
// CATALOGUE_MAX_BYTES). Inlined icons and READMEs were most of it. A member
// that names a file by its SHA-256 lets a client fetch the bytes beside the
// index and still hold them to the signature: the digest is inside `signed`.
// The inline `icon_url` and `readme` stay beside the pair until a MAJOR
// version drops them (6.28.0's transition), so an old client reads what it
// read.
//
// ONE MODULE, THREE READERS. `tools/build-index.mjs` derives the members from
// the committed files under plugins/**; `tools/signer/run.mjs` writes the
// named files into the same `signed` commit and refuses a catalogue that names
// one it cannot write as stated (BOT-109); `tools/regenerate-signed.mjs`
// compares a candidate's set of files with the derived one (TRUST-49). Every
// rule below is the plugins service's (minice `plugins-signed/src/assets.rs`,
// `named_assets` and `NamedAsset::verify`), because SERVE-115 refuses the WHOLE
// commit when one named file is missing or is not what its member says: a
// signer that wrote one byte differently would stop the catalogue, the
// withdrawal list and trust.json all at once.
//
// SVG AND ICO HAVE NO PAIR. 6.28.0's path rule names three raster extensions,
// `png`, `webp` and `jpg`, and the service and the client refuse any other.
// A listing whose committed icon is `icon.svg` or `icon.ico` keeps the inline
// `icon_url` alone, which is today's behaviour in every client; the
// contract's "one raster format" for an SVG is the derive step of a later
// change (E_SVG_TEXT, E_SVG_RASTERIZE), not this one.

import { sha256Hex } from "../../bot/lib/assets.mjs";

/** Table 5-A: the largest icon file. Equal to bot/lib/assets.mjs MAX_ICON_BYTES, which no committed icon passes. */
export const ICON_ASSET_MAX_BYTES = 131_072;
/** Table 5-A: the largest README file. Equal to bot/lib/assets.mjs MAX_README_BYTES. */
export const README_ASSET_MAX_BYTES = 16_384;
/** 6.29.0: every distinct file one catalogue names, together. */
export const ASSETS_TOTAL_MAX_BYTES = 33_554_432;

/** Where the files go in a `signed` commit, beside index.json. */
export const ASSETS_DIR = "registry/v1/assets";
/** TRUST-49's grammar for a member's `path`. */
export const ASSET_PATH_RE = /^assets\/([0-9a-f]{64})\.(png|webp|jpg|md)$/;

/** The raster media types a pair may carry, and the extension each is written under. */
export const ICON_ASSET_EXTENSIONS = Object.freeze({ "image/png": "png", "image/webp": "webp", "image/jpeg": "jpg" });
const MEDIA_OF_EXTENSION = Object.freeze({ png: "image/png", webp: "image/webp", jpg: "image/jpeg" });

const KINDS = Object.freeze({
  icon: { member: "icon", cap: ICON_ASSET_MAX_BYTES },
  readme_file: { member: "readme_file", cap: README_ASSET_MAX_BYTES },
});

/**
 * Whether `bytes` are what the extension says: the service's
 * `AssetFormat::is_the_format_of`, byte for byte.
 */
export function isFormat(extension, bytes) {
  const b = Buffer.from(bytes);
  if (extension === "png") return b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (extension === "webp") {
    return b.length >= 12 && b.subarray(0, 4).toString("latin1") === "RIFF" && b.subarray(8, 12).toString("latin1") === "WEBP";
  }
  if (extension === "jpg") return b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  if (extension === "md") {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(b);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * The `icon` member for a committed icon, and the file it names; `null` when
 * the format has no pair (SVG, ICO: see the header).
 *
 * Throws when the bytes cannot be named honestly: over the cap, empty, or not
 * the format the media type says. `tools/validate.mjs` and `checkIcon` refuse
 * all three before a file is committed, so a throw here is a tree that went
 * round them; emitting the pair anyway would make the service refuse the
 * whole `signed` commit (SERVE-115).
 *
 * @param {{media: string, bytes: Buffer}} icon
 * @returns {{member: object, file: {path: string, bytes: Buffer}} | null}
 */
export function iconAsset({ media, bytes }) {
  const ext = ICON_ASSET_EXTENSIONS[media];
  if (!ext) return null;
  if (bytes.length === 0 || bytes.length > ICON_ASSET_MAX_BYTES) {
    throw new Error(`the icon is ${bytes.length} bytes, outside 1..${ICON_ASSET_MAX_BYTES} for an icon file (Table 5-A)`);
  }
  if (!isFormat(ext, bytes)) throw new Error(`the icon does not begin with the ${media} signature`);
  return pair({ ext, bytes, extra: { media_type: media } });
}

/**
 * The `readme_file` member for a README's text, and the file it names; `null`
 * for an empty README, which the service refuses as a zero-byte member.
 *
 * The bytes are the UTF-8 of the text the inline `readme` carries, so the pair
 * and the inline form can never say different things. For a committed file
 * that is valid UTF-8 — every one, `tools/validate.mjs` reads them as text —
 * that is the file's own bytes.
 *
 * @param {string} text
 */
export function readmeAsset(text) {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length === 0) return null;
  if (bytes.length > README_ASSET_MAX_BYTES) {
    throw new Error(`the README is ${bytes.length} bytes, over the ${README_ASSET_MAX_BYTES} for a README file (Table 5-A)`);
  }
  return pair({ ext: "md", bytes, extra: {} });
}

function pair({ ext, bytes, extra }) {
  const sha256 = sha256Hex(bytes);
  const name = `${sha256}.${ext}`;
  return {
    member: { path: `assets/${name}`, sha256, size: bytes.length, ...extra },
    file: { path: `${ASSETS_DIR}/${name}`, bytes: Buffer.from(bytes) },
  };
}

/**
 * The distinct files a catalogue names, in first-named order, and every way
 * its members break the service's rules. The service's `named_assets`: a
 * member of another shape is a problem, never an entry; two listings naming
 * one file with two sizes is a problem; and the total of the distinct sizes
 * is held to ASSETS_TOTAL_MAX_BYTES before any file is read (6.29.0).
 *
 * @param {object} doc  a catalogue, the envelope or its `signed` member
 * @returns {{assets: {listing: string, member: string, name: string, path: string, rel: string,
 *            sha256: string, size: number, ext: string}[], total: number, problems: string[]}}
 */
export function namedAssets(doc) {
  const plugins = (doc?.signed ?? doc)?.plugins;
  const problems = [];
  const byName = new Map();
  for (const listing of Array.isArray(plugins) ? plugins : []) {
    const id = typeof listing?.id === "string" ? listing.id : "(no id)";
    for (const kind of Object.values(KINDS)) {
      if (!listing || !Object.hasOwn(listing, kind.member)) continue;
      const m = listing[kind.member];
      const bad = (why) => problems.push(`listing ${id}: \`${kind.member}\` ${why}`);
      if (m === null || typeof m !== "object" || Array.isArray(m)) {
        bad("is not an object");
        continue;
      }
      if (typeof m.path !== "string" || typeof m.sha256 !== "string" || !Number.isSafeInteger(m.size)) {
        bad("does not carry a string `path`, a string `sha256` and an integer `size`");
        continue;
      }
      const hit = ASSET_PATH_RE.exec(m.path);
      if (!hit) {
        bad(`has the path ${JSON.stringify(m.path)}, which is not assets/<sha256>.<png|webp|jpg|md>`);
        continue;
      }
      const [, hex, ext] = hit;
      if (hex !== m.sha256) {
        bad(`has the path ${JSON.stringify(m.path)}, whose name is not its \`sha256\``);
        continue;
      }
      if (kind.member === "readme_file" && ext !== "md") {
        bad(`has the path ${JSON.stringify(m.path)}, which is not a .md file`);
        continue;
      }
      if (kind.member === "icon") {
        if (ext === "md") {
          bad(`has the path ${JSON.stringify(m.path)}, which is not a picture`);
          continue;
        }
        if (m.media_type !== MEDIA_OF_EXTENSION[ext]) {
          bad(`has the media_type ${JSON.stringify(m.media_type)}, and its path is ${MEDIA_OF_EXTENSION[ext]}`);
          continue;
        }
      }
      if (m.size < 1 || m.size > kind.cap) {
        bad(`states ${m.size} bytes, outside 1..${kind.cap} for this member`);
        continue;
      }
      const name = `${hex}.${ext}`;
      const first = byName.get(name);
      if (first && first.size !== m.size) {
        bad(`says ${name} is ${m.size} bytes, and listing ${first.listing} says it is ${first.size}`);
        continue;
      }
      if (!first) {
        byName.set(name, { listing: id, member: kind.member, name, path: m.path, rel: `${ASSETS_DIR}/${name}`, sha256: hex, size: m.size, ext });
      }
    }
  }
  const assets = [...byName.values()];
  const total = assets.reduce((n, a) => n + a.size, 0);
  if (total > ASSETS_TOTAL_MAX_BYTES) {
    problems.push(
      `the catalogue names ${assets.length} distinct asset files of ${total} bytes together, over the ` +
      `${ASSETS_TOTAL_MAX_BYTES} one catalogue may name (contract 6.29.0)`,
    );
  }
  return { assets, total, problems };
}

/**
 * Why `bytes` are not the file `asset` names, or `null` when they are: the
 * service's `NamedAsset::verify` — length, then digest, then content.
 */
export function assetMismatch(asset, bytes) {
  if (!bytes) return `${asset.rel} (\`${asset.member}\` of ${asset.listing}) has no bytes to write`;
  if (bytes.length !== asset.size) {
    return `${asset.rel} (\`${asset.member}\` of ${asset.listing}) is ${bytes.length} bytes and its member says ${asset.size}`;
  }
  if (sha256Hex(bytes) !== asset.sha256) return `${asset.rel} (\`${asset.member}\` of ${asset.listing}) does not digest to its name`;
  if (!isFormat(asset.ext, bytes)) {
    return `${asset.rel} (\`${asset.member}\` of ${asset.listing}) is not ${asset.ext === "md" ? "valid UTF-8" : MEDIA_OF_EXTENSION[asset.ext]}`;
  }
  return null;
}

/**
 * The files one catalogue names, as they go into a `signed` commit: exactly
 * the named set, each held to its member. `lookup(asset)` answers the bytes
 * from wherever the caller has them (the generator's own output, or the
 * `signed` head a carried catalogue was published with), or `null`.
 *
 * @returns {{files: Record<string, Buffer>, total: number, count: number, problems: string[]}}
 */
export function assetFilesFor(doc, lookup) {
  const { assets, total, problems } = namedAssets(doc);
  const files = {};
  if (problems.length) return { files, total, count: assets.length, problems };
  for (const asset of assets) {
    const bytes = lookup(asset);
    const why = assetMismatch(asset, bytes);
    if (why) problems.push(why);
    else files[asset.rel] = Buffer.from(bytes);
  }
  return { files, total, count: assets.length, problems };
}
