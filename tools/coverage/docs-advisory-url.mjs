#!/usr/bin/env node
// MOD-13's precondition: the withdrawal documentation teaches no advisory URL
// that this registry does not serve (registry plan M-T1.3).
//
//     node tools/coverage/docs-advisory-url.mjs [--repo <dir>] [--report <file>]
//
// ── WHAT WENT WRONG, AND WHERE IT WOULD HAVE SHOWN UP ───────────────────────
//
// `tools/revocations/README.md` is the only page that says how to write an
// advisory, and its worked example carried
//
//     "advisory_url": "https://github.com/<owner>/astra-registry/security/advisories/ASTRA-2026-0001"
//
// which could not have worked for two separate reasons. GitHub numbers its
// advisories `GHSA-xxxx-xxxx-xxxx` and this repository numbers its own
// `ASTRA-YYYY-NNNN`, so that path is a 404 by construction; and MOD-13 gives
// the field one value — the base the registry compiles, plus the id — set by
// the bot and ignored wherever a decision supplies its own. An operator
// writing the first real advisory copies the block above, and the URL they
// copy is the one line of the withdrawal a **user** sees: the daemon shows it
// on the screen that says their plugin has been disabled.
//
// Nothing would have caught it. `checkAdvisory` accepts any `https://` string,
// because refusing hosts is RC-R1-6's job and naming the base is M-T3.9's, and
// neither of those reads a Markdown file. A wrong URL in a document is not a
// broken build; it is a correct build of the wrong thing.
//
// ── WHAT THIS RULE ASSERTS, AND WHAT IT DELIBERATELY DOES NOT ───────────────
//
// Three legs, and each one is a regression somebody could plausibly make:
//
//   1. an `advisory_url` VALUE anywhere in the document that is not under
//      MOD-13's base. Restoring the old example trips this, and so does any
//      other host somebody reaches for;
//   2. a `github.com` or `github.io` URL that is advisory-shaped — its path
//      names an advisory, or it sits on a line that names `advisory_url`.
//      This is the leg that still fires if the field is renamed or the value
//      is shown in prose rather than in JSON;
//   3. the document mentioning `advisory_url` at all. A rule whose subject can
//      be deleted is a rule that goes green by deletion, and the sentence
//      telling an operator to OMIT the field is the other half of M-T1.3.
//
// It does NOT flag every github.com link. A link to a repository, a workflow
// run or an issue has business being in this document, and a canary that goes
// red for one of those is a canary whose repair is to delete the canary.
//
// **Knowing the base and documenting the base are two different acts.** This
// rule knows it from the contract (MOD-13); M-T3.9 is what writes it into the
// README, and this rule is already green for the document M-T3.9 will leave
// behind.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./rules.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..", "..");

export const RULE = "docs-advisory-url";

/** The one document M-T1.3 is about. */
export const DOC = "tools/revocations/README.md";

/**
 * MOD-13's compiled base: `advisory_url` is this plus the advisory id, set by
 * the bot, and every other value is somebody's guess. Recorded in contract
 * §7.2 (MOD-13) when OPEN-MBE-15 closed; M-T3.9 is the task that teaches it to
 * `tools/lib/revocations.mjs` and to the README.
 */
export const ADVISORY_BASE = "https://astra.minice.ai/plugins/_/advisories/";

/** Any absolute URL, with trailing Markdown and JSON punctuation left behind. */
const URL_RE = /https?:\/\/[^\s"'`<>()[\]{},]+/g;

/** `advisory_url` in JSON, in a table, in prose — the key, then its URL. */
const VALUE_RE = /advisory_url\W{0,4}\s*(https?:\/\/[^\s"'`<>()[\]{},]+)/gi;

const trimTail = (u) => u.replace(/[.,;:]+$/, "");

/** Is this a host whose advisories are not ours to serve? */
export function isGithubHost(url) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return host === "github.com" || host.endsWith(".github.com") ||
    host === "github.io" || host.endsWith(".github.io");
}

/** Does this URL read as an advisory page rather than as an ordinary link? */
export function looksLikeAdvisory(url) {
  let pathname;
  try {
    pathname = new URL(url).pathname;
  } catch {
    return false;
  }
  return /\/advisor(y|ies)\b/i.test(pathname) || /ASTRA-\d{4}-\d{3,}/.test(pathname) || /GHSA-/i.test(pathname);
}

/**
 * @param {string} repo repository root
 * @returns {{status: "green"|"red", codes: string[], ids: string[], hexes: string[], detail: string[]}}
 */
export function run(repo, { doc = DOC } = {}) {
  const file = path.join(repo, doc);
  if (!fs.existsSync(file)) {
    return {
      status: "red",
      codes: ["MOD_13_DOCS_ABSENT"], ids: [], hexes: [],
      detail: [
        `${doc} is not in the tree. It is the only page that says how to write an advisory, and this rule is ` +
        "the only thing watching what it says about `advisory_url`; a moved document is a rule that passes " +
        "about nothing",
      ],
    };
  }

  const lines = fs.readFileSync(file, "utf8").split("\n");
  const codes = [];
  const detail = [];

  let mentions = 0;
  lines.forEach((line, i) => {
    const at = `${doc}:${i + 1}`;
    if (/advisory_url/i.test(line)) mentions++;

    for (const m of line.matchAll(VALUE_RE)) {
      const url = trimTail(m[1]);
      if (url.startsWith(ADVISORY_BASE)) continue;
      codes.push("MOD_13_DOCS_ADVISORY_EXAMPLE");
      detail.push(
        `${at} shows advisory_url = ${url}, which is not under MOD-13's compiled base. The bot sets that field ` +
        "from the base plus the id and ignores any value a decision carries, so a worked example naming another " +
        "host is an example whose only reader is the operator writing the first advisory by hand",
      );
    }

    for (const raw of line.match(URL_RE) ?? []) {
      const url = trimTail(raw);
      if (!isGithubHost(url)) continue;
      if (!looksLikeAdvisory(url) && !/advisory_url/i.test(line)) continue;
      codes.push("MOD_13_DOCS_GITHUB_ADVISORY");
      detail.push(
        `${at} names ${url}: a GitHub advisory URL in the one document that says how to write a withdrawal. ` +
        "GitHub numbers advisories GHSA-xxxx-xxxx-xxxx and this repository numbers them ASTRA-YYYY-NNNN, so " +
        "an id of ours under /security/advisories/ is a 404 — shown to a user on the screen that says their " +
        "plugin has been disabled",
      );
    }
  });

  if (mentions === 0) {
    codes.push("MOD_13_DOCS_SILENT");
    detail.push(
      `${doc} no longer mentions advisory_url anywhere. The field is optional and M-T1.3's sentence is the one ` +
      "that tells an operator to omit it; with the sentence gone this rule would be green about a document " +
      "that has stopped saying anything",
    );
  }

  if (codes.length === 0) {
    detail.push(
      `${doc} names no advisory URL this registry does not serve, and still tells an operator what to do with ` +
      "the field (" + mentions + " mention(s))",
    );
  }
  return { status: codes.length ? "red" : "green", codes, ids: [], hexes: [], detail };
}

function main(argv) {
  const args = { repo: DEFAULT_REPO, report: process.env.ASTRA_COVERAGE_FINDINGS };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--repo") args.repo = path.resolve(argv[++i]);
    else if (argv[i] === "--report") args.report = argv[++i];
    else { console.error(`FAIL  unknown argument ${JSON.stringify(argv[i])}`); return 2; }
  }
  report(RULE, run(args.repo), args.report);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
