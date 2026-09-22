// §0.7's time, held to one statement in every reader (contract 0.34.0).
//
// **What 0.34.0 says.** *Every time names a real UTC instant, and a seconds
// field of 60 is not admissible* — for every time on the wire, where 0.31.0
// said it of the migration-notice marker's two times alone. `2026-02-30` and
// hour `24` were already not RFC 3339 date-times; second 60 is the one
// departure from RFC 3339, and every party refuses it wherever it reads a time.
//
// **What this repository did until then**, measured before the change (ops
// `dev/server-registry-contract-pending.md` item 10): `parseTime`, the cutover
// preflight and the marker's schema refused second 60; fifteen date-time
// patterns in nine schemas and ten code sites in six modules admitted it, with
// hour 24, minute 60 and day 32 besides — so one committed deadline record was refused
// by `tools/validate.mjs` and accepted by the plugins service, and a decision
// record's `Decided-At:` trailer was admitted by the writer and would have been
// refused by this repository's own `parseTime`.
//
// **What this module asks, each question its own test, because each can break
// without the others:**
//
//   * the GRAMMAR: `tools/lib/time.mjs` refuses what §0.7 refuses and admits a
//     real time, with and without a fraction;
//   * the SCHEMAS: every date-time pattern under `schema/` is that module's,
//     byte for byte, and refuses second 60 through the validator the gates
//     run — a schema added with a laxer pattern is red here by name;
//   * the READERS: every code reader of a §0.7 time refuses second 60, hour 24,
//     minute 60 and `2026-02-30`, and admits a real time — driven, not read;
//   * the SPELLINGS: no module in the readers' reach spells a time's grammar
//     for itself, except `bot/lib/alert-checks.mjs`'s one copy, which every
//     alert job's sparse checkout forces and which is held here to the
//     module's pattern byte for byte.
//
// It imports only modules inside TRUST-31's set. `tools/cutover-preflight.mjs`
// is a reader too and is outside the set, so it is READ as bytes for the
// spelling test and never imported: an import from this directory, which the
// publish path runs, would make a desk tool an input to every publication.

import fs from "node:fs";
import path from "node:path";

import { REPO_ROOT } from "../lib/sources.mjs";
import { validate } from "../lib/jsonschema.mjs";
import {
  TIME_PATTERN, TIME_FRACTION_PATTERN, isTime, isTimeWithFraction,
} from "../lib/time.mjs";
import { checkBaselineMarker } from "../validate.mjs";
import { recordPath, refuseUncomposableAuthorAction, trailerLine } from "../../bot/lib/decisions.mjs";
import { wholeSeconds } from "../../bot/lib/compile-decision.mjs";
import { composeRecords, refuseUncomposable as baselineMembers, markerProblems } from "../../bot/baseline.mjs";
import { refuseUncomposable as exportMembers } from "../../bot/export-issues.mjs";
import { isArmedAt } from "../../bot/lib/alert-checks.mjs";
import { parseTime } from "../../bot/lib/listing-state.mjs";
import { test, assert, tmp } from "./harness.mjs";

const GOOD = "2026-09-22T23:59:59Z";
/** What §0.7 refuses, each for its own reason. The first is the one 0.34.0 is about. */
const BAD = {
  "second 60": "2026-06-30T23:59:60Z",
  "hour 24": "2026-09-22T24:00:00Z",
  "minute 60": "2026-09-22T23:60:00Z",
  "day 32": "2026-01-32T00:00:00Z",
  "month 13": "2026-13-01T00:00:00Z",
  "a day its month does not have": "2026-02-30T00:00:00Z",
};
/** What a pattern alone can refuse; the last of BAD needs a calendar. */
const PATTERN_BAD = Object.fromEntries(Object.entries(BAD).filter(([k]) => k !== "a day its month does not have"));

/** The date-time `pattern`s of one schema, each with the node that carries it. */
function timePatterns(doc) {
  const out = [];
  const walk = (node, at) => {
    if (!node || typeof node !== "object") return;
    if (typeof node.pattern === "string" && /T/.test(node.pattern) && /:/.test(node.pattern)) {
      out.push({ at, node });
    }
    for (const [k, v] of Object.entries(node)) walk(v, `${at}/${k}`);
  };
  walk(doc, "");
  return out;
}

/** Each reader, as a function that throws or returns false on a refusal. */
function readers() {
  const refused = (fn) => (v) => {
    try {
      const r = fn(v);
      return r === false;
    } catch {
      return true;
    }
  };
  const baselineMarkerRefuses = (v) => {
    const dir = fs.mkdtempSync(path.join(tmp, "times-baseline-"));
    fs.mkdirSync(path.join(dir, "log"));
    fs.writeFileSync(path.join(dir, "log", "baseline.json"), JSON.stringify({
      schema: "astra.registry.baseline/1", written_at: v, source_commit: "a".repeat(40),
      version_count: 1, record_count: 1,
    }));
    const errors = [];
    const report = { errors, note() {}, error(where, message) { errors.push({ where, message }); } };
    checkBaselineMarker([], { root: dir, report });
    return errors.some((e) => /written_at/.test(e.message));
  };
  return {
    "tools/lib/time.mjs isTime": (v) => !isTime(v),
    "tools/lib/time.mjs isTimeWithFraction": (v) => !isTimeWithFraction(v),
    "bot/lib/decisions.mjs recordPath (the record's path)": refused((v) => recordPath({ decision_id: "a".repeat(32), decided_at: v })),
    "bot/lib/decisions.mjs trailerLine (`Decided-At:`)": refused((v) => trailerLine("Decided-At", v)),
    // The author-action grammar refuses a record missing its other members as
    // well, so only a refusal OF `decided_at` counts as this reader refusing.
    "bot/lib/decisions.mjs the author-action `decided_at` grammar": (v) => {
      try {
        refuseUncomposableAuthorAction({ decided_at: v });
        return false;
      } catch (e) {
        return /`decided_at` does not match/.test(e.message);
      }
    },
    "bot/lib/compile-decision.mjs wholeSeconds (the service's `decided_at`)": refused((v) => wholeSeconds(v)),
    "bot/lib/compile-decision.mjs wholeSeconds, with a fraction": refused((v) => wholeSeconds(v.replace(/Z$/, ".5Z"))),
    "bot/baseline.mjs `decided_at`": refused((v) => baselineMembers({ decided_at: v })),
    "bot/baseline.mjs composeRecords (a version file's `published_at`)": refused((v) => composeRecords([{
      plugin_id: "demo", version: "1.0.0", repo: "owner/name", tag: "v1.0.0", commit: "a".repeat(40),
      fingerprint: "b".repeat(16), repository_id: "123", repository_owner_id: "456",
    }], new Map([["demo@1.0.0", v]]))),
    "bot/baseline.mjs the marker's `written_at`": (v) => markerProblems({ written_at: v }).some((p) => /written_at/.test(p)),
    "bot/export-issues.mjs `decided_at`": refused((v) => exportMembers({ decided_at: v })),
    "bot/lib/alert-checks.mjs `armed_at`": (v) => !isArmedAt(v),
    "bot/lib/listing-state.mjs parseTime (deadline, cutover, `now`)": refused((v) => parseTime(v, "the value")),
    "tools/validate.mjs the baseline marker's `written_at`": baselineMarkerRefuses,
  };
}

/** The files a §0.7 time reader lives in, read as bytes. */
function readerFiles() {
  const listed = [];
  const walk = (rel) => {
    const abs = path.join(REPO_ROOT, rel);
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      const r = path.posix.join(rel, e.name);
      if (e.isDirectory()) walk(r);
      else if (e.name.endsWith(".mjs")) listed.push(r);
    }
  };
  for (const dir of ["bot/lib", "bot/policy", "tools/lib"]) walk(dir);
  for (const e of fs.readdirSync(path.join(REPO_ROOT, "bot"))) if (e.endsWith(".mjs")) listed.push(`bot/${e}`);
  listed.push("tools/validate.mjs", "tools/build-index.mjs", "tools/build-revocations.mjs", "tools/cutover-preflight.mjs");
  return listed.sort();
}

/** A time grammar spelled in source: an `HH:MM` of digit classes, in a regex or a pattern string. */
const SPELLING = /\\d\{2\}:\\d\{2\}|\[0-9\]\{2\}:\[0-9\]\{2\}|\[0-5\]\[0-9\]:\[0-5\]\[0-9\]|\\d\\d:\\d\\d|\[0-9\]\[0-9\]:\[0-9\]\[0-9\]/;

/** Every line of `text` that spells one. */
function spellings(text) {
  return text.split("\n").map((line, i) => ({ line: i + 1, text: line })).filter((l) => SPELLING.test(l.text));
}

export async function run() {
  console.log("\n§0.7's time, one statement in every reader (contract 0.34.0)");

  await test("tools/lib/time.mjs refuses what §0.7 refuses, and admits a real time", () => {
    assert(isTime(GOOD) && isTimeWithFraction(GOOD) && isTimeWithFraction("2026-09-22T23:59:59.25Z"),
      "a real time was refused");
    assert(!isTime("2026-09-22T23:59:59.25Z"), "isTime admitted a fraction, and §0.7 times are whole seconds");
    for (const [why, v] of Object.entries(BAD)) {
      assert(!isTime(v), `isTime admitted ${why}: ${v}`);
      assert(!isTimeWithFraction(v), `isTimeWithFraction admitted ${why}: ${v}`);
      assert(!isTimeWithFraction(v.replace(/Z$/, ".5Z")), `isTimeWithFraction admitted ${why} with a fraction`);
    }
    for (const v of [null, undefined, 20260922, "", "2026-09-22", "2026-09-22T23:59:59+00:00", "2026-09-22t23:59:59z"]) {
      assert(!isTime(v), `isTime admitted ${JSON.stringify(v)}`);
    }
  });

  await test("every date-time pattern under schema/ is §0.7's, byte for byte, and the validator refuses second 60 by it", () => {
    const files = fs.readdirSync(path.join(REPO_ROOT, "schema")).filter((f) => f.endsWith(".json")).sort();
    const found = [];
    const wrong = [];
    for (const f of files) {
      const doc = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "schema", f), "utf8"));
      for (const { at, node } of timePatterns(doc)) {
        found.push(`${f}${at}`);
        if (node.pattern !== TIME_PATTERN && node.pattern !== TIME_FRACTION_PATTERN) {
          wrong.push(`${f}${at}: ${node.pattern}`);
          continue;
        }
        const sub = { type: "string", pattern: node.pattern };
        assert(validate(sub, GOOD, "$").length === 0, `${f}${at} refused a real time through the validator`);
        for (const [why, v] of Object.entries(PATTERN_BAD)) {
          assert(validate(sub, v, "$").length > 0, `${f}${at} admitted ${why} (${v}) through the validator`);
        }
      }
    }
    assert(!wrong.length, `date-time patterns that are not tools/lib/time.mjs's: ${wrong.join("; ")}. §0.7 is one ` +
      "grammar; a laxer copy admits second 60 where every other reader refuses it (contract 0.34.0)");
    // 17 on 2026-09-22: fifteen in nine schemas made strict by 0.34.0, and the
    // marker's two from 0.31.0. The floor is below that and not equal to it,
    // so a schema that legitimately loses a time does not go red here.
    assert(found.length >= 12, `found ${found.length} date-time pattern(s) under schema/; this is a broken walk, ` +
      "not a registry with fewer times");
    // The walk is aimed: the pattern 0.34.0 replaced, put back into a copy of
    // one schema, is found and is not §0.7's.
    const lax = { properties: { t: { type: "string", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$" } } };
    const hit = timePatterns(lax);
    assert(hit.length === 1 && hit[0].node.pattern !== TIME_PATTERN, "the walk did not find a lax pattern put in front of it");
    assert(validate(hit[0].node, BAD["second 60"], "$").length === 0,
      "the pattern 0.34.0 replaced refuses second 60 here, so the assertions above prove nothing about it");
  });

  await test("every reader of a §0.7 time refuses second 60, hour 24, minute 60 and a day its month lacks", () => {
    const all = readers();
    assert(Object.keys(all).length >= 14, `only ${Object.keys(all).length} readers are driven`);
    const wrong = [];
    for (const [name, refuses] of Object.entries(all)) {
      if (refuses(GOOD)) wrong.push(`${name} refused a real time, ${GOOD}`);
      for (const [why, v] of Object.entries(BAD)) {
        if (!refuses(v)) wrong.push(`${name} admitted ${why} (${v})`);
      }
    }
    assert(!wrong.length, wrong.join("; "));
  });

  await test("no reader spells a time's grammar for itself, but for the one copy a sparse checkout forces", () => {
    const files = readerFiles();
    assert(files.length >= 60, `read ${files.length} reader file(s); this is a broken walk`);
    const found = [];
    for (const rel of files) {
      if (rel === "tools/lib/time.mjs") continue;
      for (const l of spellings(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"))) found.push({ rel, ...l });
    }
    const copy = found.filter((f) => f.rel === "bot/lib/alert-checks.mjs");
    const other = found.filter((f) => f.rel !== "bot/lib/alert-checks.mjs");
    assert(!other.length, `a reader spells a time's grammar for itself: ${other.map((f) => `${f.rel}:${f.line}`).join(", ")}. ` +
      "Import `isTime` or `TIME_RE` from tools/lib/time.mjs: §0.7 is one grammar, and until 0.34.0 each private " +
      "copy of it was a laxer one");
    assert(copy.length === 1, `bot/lib/alert-checks.mjs spells a time ${copy.length} time(s); it is allowed one copy`);
    const literal = /\/(\^[^/]+\$)\//.exec(copy[0].text);
    assert(literal && literal[1] === TIME_PATTERN,
      `bot/lib/alert-checks.mjs's copy is not tools/lib/time.mjs's TIME_PATTERN, byte for byte: ${copy[0].text.trim()}`);
    // Aimed: the spelling 0.34.0 removed from six readers is found.
    assert(spellings("const DATE_RE = /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/;").length === 1,
      "the scan does not see the lax spelling it exists to refuse");
  });
}
