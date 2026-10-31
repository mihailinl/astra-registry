#!/usr/bin/env node
//
// What a pull request does to the owner's passkey pin, as an alarm verdict
// (operator-acts-by-passkey design §2.3, review finding 4).
//
//   node tools/passkey-pins.mjs --base bot/lib/operator-passkeys.json \
//                               --head head-pin.json --out verdict.json
//
// `.github/workflows/passkey-pins.yml` runs this on `pull_request_target`,
// from main's checkout, over the head's pin fetched through the API as a file
// of bytes: the head's JSON is DATA here, parsed and never run. Each key the
// head adds, and each key whose status it moves, is named by its kid and by
// the fingerprint the owner's act page showed him at enrolment (the first 16
// hex of SHA-256 over its SPKI), so he compares the two on his own phone
// before he acknowledges the tree. The registry's own channel carries it;
// minice relays nothing here.
//
// The verdict's grammar is the channel's (bot/lib/alert-verdict.mjs): codes,
// ids and hex. A kid is a lowercase id, so it rides in `ids`.

import fs from "node:fs";

import { VERDICT_SCHEMA, runUrl, verdictProblems } from "../bot/lib/alert-verdict.mjs";
import { KID_RE, keyFingerprint, pinProblems } from "../bot/lib/operator-act.mjs";

/** The head's pin, at most this many bytes. */
export const MAX_PIN_BYTES = 256 * 1024;


/**
 * The verdict for a head pin against the base pin. `headText` is the head's
 * bytes as text; nothing in it is executed, and a value of the wrong shape is
 * a refusal code, never an exception.
 */
export function pinVerdict({ base, headText, run = null }) {
  const codes = new Set();
  const ids = new Set();
  const hexes = new Set();
  const notes = [];
  let head = null;
  if (typeof headText !== "string" || Buffer.byteLength(headText, "utf8") > MAX_PIN_BYTES) {
    codes.add("PASSKEY_PIN_UNREADABLE");
    notes.push(`the head's pin is absent or over ${MAX_PIN_BYTES} bytes`);
  } else {
    try {
      head = JSON.parse(headText);
    } catch (e) {
      codes.add("PASSKEY_PIN_UNREADABLE");
      notes.push(`the head's pin is not JSON: ${e.message}`);
    }
  }
  if (head) {
    const before = new Map((Array.isArray(base?.keys) ? base.keys : []).map((k) => [k?.kid, k]));
    const keys = Array.isArray(head.keys) ? head.keys : [];
    const name = (k) => {
      if (typeof k?.kid === "string" && KID_RE.test(k.kid)) ids.add(k.kid);
      try {
        hexes.add(keyFingerprint(k?.public_key).replace(/ /g, ""));
      } catch {
        /* a key with no readable public key is refused by pinProblems below */
      }
    };
    for (const k of keys) {
      const old = before.get(k?.kid);
      if (!old) {
        codes.add("PASSKEY_PIN_KEY_ADDED");
        name(k);
        notes.push(`added ${k?.kid} (${k?.status}), fingerprint ${(() => { try { return keyFingerprint(k?.public_key); } catch { return "?"; } })()}`);
      } else if (old.status !== k.status) {
        codes.add("PASSKEY_PIN_KEY_STATUS");
        name(k);
        notes.push(`${k.kid}: ${old.status} → ${k.status}`);
      }
    }
    for (const kid of before.keys()) {
      if (!keys.some((k) => k?.kid === kid)) {
        codes.add("PASSKEY_PIN_KEY_REMOVED");
        notes.push(`removed ${kid}`);
      }
    }
    const problems = pinProblems(head, { base });
    if (problems.length) {
      codes.add("PASSKEY_PIN_REFUSED");
      notes.push(...problems.map((p) => `refused: ${p}`));
    }
  }
  const list = (s, n = 40) => [...s].sort().slice(0, n);
  const verdict = {
    schema: VERDICT_SCHEMA,
    check: "passkey-pins",
    status: codes.size ? "red" : "green",
    ...(codes.size ? { codes: list(codes) } : {}),
    ...(ids.size ? { ids: list(ids) } : {}),
    ...(hexes.size ? { hexes: list(hexes) } : {}),
    ...(run ? { run } : {}),
  };
  const problems = verdictProblems(verdict);
  if (problems.length) throw new Error(`the pin verdict may not be sent: ${problems.join("; ")}`);
  return { verdict, notes };
}

const arg = (argv, name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

export function main(argv = process.argv.slice(2), { env = process.env, log = console } = {}) {
  const base = JSON.parse(fs.readFileSync(arg(argv, "--base") ?? "bot/lib/operator-passkeys.json", "utf8"));
  const headFile = arg(argv, "--head");
  let headText = null;
  try {
    if (headFile && fs.statSync(headFile).size <= MAX_PIN_BYTES) headText = fs.readFileSync(headFile, "utf8");
  } catch {
    headText = null;
  }
  const { verdict, notes } = pinVerdict({ base, headText, run: runUrl(env) });
  for (const n of notes) log.log(`note  ${n}`);
  fs.writeFileSync(arg(argv, "--out") ?? "verdict.json", `${JSON.stringify(verdict)}\n`);
  log.log(`ok    ${verdict.status}: ${(verdict.codes ?? []).join(" ") || "no key added or moved"}`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main());
