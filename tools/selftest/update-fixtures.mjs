// Everything the two update modules both need, in one place because it is one
// tool. Splitting a 639-line section across two files is only honest if the
// fixtures are shared rather than copied: two counters would give both halves an
// `update-x-1.json`, and `assertRefused`'s "it wrote <out>" check would start
// reading another test's leftovers.
//
// `updateSeq` is the only mutable state here and is reached through `nextSeq()`,
// because `++` on an imported binding is a TypeError.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { REPO_ROOT } from "../lib/sources.mjs";
import { loadTestRoot } from "../testkeys/regenerate.mjs";
import {
  UPDATE_SCHEMA, publicKeyFromBase64, rfc3339, signEnvelope, verifyEnvelope,
} from "../../bot/lib/sign.mjs";
import { assert, assertEqual, tmp } from "./harness.mjs";
import { ROOT_A_KEY_ID, ROOT_B_KEY_ID, TRUST_ROOT_A, sandboxWithRoot, testRootPem } from "./fixtures.mjs";

export const UPDATE_SIGNER = loadTestRoot(ROOT_A_KEY_ID);
export const UPDATE_SIGNER_PUB = [{ key_id: UPDATE_SIGNER.key_id, publicKey: publicKeyFromBase64(UPDATE_SIGNER.publicKeyB64) }];
export const TRUST_ROOT_B = testRootPem(ROOT_B_KEY_ID);
export const DAY_MS = 86400 * 1000;
export const PRODUCTION_ROOTS = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "registry", "v1", "root.json"), "utf8"))
  .roots.map((r) => ({ key_id: r.key_id, publicKey: publicKeyFromBase64(r.public_key) }));

let updateSeq = 0;
/** The next temp-path number. One counter for both halves of the update section. */
export function nextSeq() {
  return ++updateSeq;
}
export const readText = (f) => fs.readFileSync(f, "utf8");
export const pretty = (doc) => `${JSON.stringify(doc, null, 2)}\n`;
export const hoursFromNow = (h) => rfc3339(new Date(Date.now() + h * 3600 * 1000));

export function updateTmp(stem) {
  return path.join(tmp, `update-${stem}-${nextSeq()}.json`);
}
export function writeUpdateText(text) {
  const f = updateTmp("doc");
  fs.writeFileSync(f, text);
  return f;
}
export const writeUpdateDoc = (doc) => writeUpdateText(pretty(doc));

/** A release record, where the signer looks for them: `<dir>/releases/<version>/manifest.json`. */
export function writeRecord(dir, doc) {
  const rel = path.join("releases", doc.signed.latest.version, "manifest.json");
  fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), pretty(doc));
  return rel;
}

/**
 * A fresh copy of the tool whose root.json publishes test root A as the active
 * root and test root B as the reserve, holding exactly these release records.
 */
export function updateSandbox(records = []) {
  const dir = sandboxWithRoot(`update-${nextSeq()}`, TRUST_ROOT_A.keyId, TRUST_ROOT_A.publicKey, [
    { key_id: TRUST_ROOT_B.keyId, role: "reserve", algorithm: "ed25519", public_key: TRUST_ROOT_B.publicKey },
  ]);
  for (const doc of records) writeRecord(dir, doc);
  return dir;
}

/** Run the signer in `cwd`; never throws, returns what it said. */
export function updateSigner(args, cwd) {
  const r = spawnSync("node", ["tools/sign-update-manifest.mjs", ...args], { cwd, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** A refusal: exit 1, `expect` in what it said, and `out` (when given) never written. */
export function assertRefused(r, expect, out, name) {
  assertEqual(r.status, 1, `${name}: exit status\n  stdout: ${r.stdout.slice(-400)}\n  stderr: ${r.stderr.slice(-400)}`);
  assert(r.stderr.includes(expect), `${name}: expected ${JSON.stringify(expect)} in:\n${r.stderr}`);
  if (out) assert(!fs.existsSync(out), `${name}: it wrote ${out}`);
}

/**
 * A document signed by test root A. The notes are hostile to a re-serialiser
 * (Cyrillic, a non-BMP emoji, a quote, a backslash); there are two artefacts;
 * and `repo` is a nested member this script does not model, after `latest`.
 * `mutate` runs BEFORE signing, so what it changes is covered by the signature.
 */
export function updateDoc({ version = "0.2.5", signedAt = hoursFromNow(-1), expires = hoursFromNow(5 * 24), mutate } = {}, signer = UPDATE_SIGNER) {
  const signed = {
    schema: UPDATE_SCHEMA,
    channel: "stable",
    signedAt,
    expires,
    min_supported_version: "0.2.4",
    latest: {
      version,
      releasedAt: "2026-09-08T19:02:05Z",
      placeholder: false,
      notes: {
        en: "Signing in is sturdier.\n\nA quote \" and a backslash \\ survive.",
        ru: "Вход стал надёжнее.",
        uk: "Вхід став надійнішим. 🚀",
      },
      artifacts: [
        {
          platform: "windows-x64",
          kind: "installer",
          filename: `Astra-Installer-${version}.exe`,
          sizeBytes: 88118552,
          sha256: "95c2a19ced2721ce4a08b215aabe0a2970301f57605b5d7279e2f4b2f183229b",
        },
        {
          platform: "windows-x64",
          kind: "portable",
          filename: `Astra-Installer-${version}.exe`,
          sizeBytes: 0,
          sha256: "0".repeat(64),
        },
      ],
    },
    repo: {
      base_url: "https://pkg.minice.ai/astra",
      formats: ["deb", "rpm", "arch"],
      signing: { fingerprint: "AB CD", subkeys: [{ id: 1, expires: null }, { id: 2, expires: "2029-01-01" }] },
    },
  };
  mutate?.(signed);
  return signEnvelope({ domain: UPDATE_SCHEMA, signed, signers: [{ key_id: signer.key_id, privateKey: signer.privateKey }] });
}

/** Everything but the two dates and the signatures, as the file carries it. */
export function bytesButDates(text) {
  const end = text.indexOf('\n  "signatures": [');
  assert(end > 0, "no signatures block where a pretty-printed manifest puts it");
  const head = text.slice(0, end);
  const DATES = /^ {4}"(signedAt|expires)": "[^"]*",\n/gm;
  assertEqual((head.match(DATES) ?? []).length, 2, "the two top-level dates, where a pretty-printed manifest puts them");
  return head.replace(DATES, "");
}

/** The same document with `latest.version` written twice; JSON.parse keeps the second, the signed one. */
export function withDuplicateVersion(doc) {
  const text = pretty(doc);
  const line = `\n      "version": "${doc.signed.latest.version}",`;
  assert(text.includes(line), "no version line to duplicate");
  const out = text.replace(line, `\n      "version": "9.9.9",${line}`);
  assert(verifyEnvelope(JSON.parse(out), UPDATE_SCHEMA, UPDATE_SIGNER_PUB).ok, "premise: it still verifies leniently");
  return out;
}

/** The same document with the signature's "=" padding stripped; Node's lenient decoder still reads it. */
export function withUnpaddedSignature(doc) {
  const copy = structuredClone(doc);
  copy.signatures[0].sig = copy.signatures[0].sig.replace(/=+$/, "");
  assert(copy.signatures[0].sig !== doc.signatures[0].sig, "premise: the signature had padding to strip");
  assert(verifyEnvelope(copy, UPDATE_SCHEMA, UPDATE_SIGNER_PUB).ok, "premise: Node's lenient decoder still verifies it");
  return pretty(copy);
}

export const UPDATE_NOTES_EN = path.join(tmp, "update-notes.en.txt");
fs.writeFileSync(UPDATE_NOTES_EN, "Plain text, as the client renders it.\n");

/** An artefact on disk named for `version`; its size and digest are what the signer computes. */
export function artefactFile(version) {
  const dir = path.join(tmp, `update-artefact-${nextSeq()}`);
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, `Astra-Installer-${version}.exe`);
  fs.writeFileSync(f, "not really an installer");
  return f;
}
export const freshArgs = (version = "0.2.6", notesEn = UPDATE_NOTES_EN) =>
  ["--root-key", TRUST_ROOT_A.file, "--artifact", artefactFile(version), "--notes-en", notesEn];
