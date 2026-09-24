#!/usr/bin/env node
// PRIV-2's published check: nothing personal is composed into git.
//
//     node tools/priv-scan.mjs                     the walk, from this file's own commit
//     node tools/priv-scan.mjs --from <sha>        from somewhere else, for evidence
//     node tools/priv-scan.mjs --repo <dir>        a fixture clone
//
// PRIV-2 forbids Minice subject ids, e-mails, Telegram ids, account names, IPs,
// report and appeal text, reporter identity, moderator notes and logins, tokens
// and publisher-to-account links from anything the bot, the signer, an operator
// or the service COMPOSES for git, a signed document or a commit message. Its
// Check is "an id-shape canary over composed files and commit bodies, outside
// signing jobs", and four things already rely on it existing — M-T3.8's PRIV-10
// canary, M-T1.7b's lint, MOD-46's registered list and ROLL-44's R1 row — while
// nothing built it. B-T2.2 refuses at composition time and never reads `main`,
// a hand-written operator commit or a commit body.
//
// ── THE SCAN THE PLAN ASKED FOR IS NOT THE SCAN THAT CAN BE BUILT ───────────
//
// The registry plan's M-T1.5 says this file flags, among other shapes, "the
// Minice subject-id shape, `^[A-Za-z0-9_-]{1,64}$`". It does not, and it must
// not, and the reason is arithmetic rather than taste.
//
// That pattern matches a Minice subject id. It also matches a plugin id, a
// GitHub login, a semver, a refusal code, a branch name, a filename stem and
// **80% of the whitespace-separated tokens in this repository's last hundred
// commit messages** — 23,556 of 29,462, counted on 2026-09-19. A canary that
// flags twenty-three thousand tokens is a canary that is red on its first run
// and switched off on its second, and the requirement it was standing in for
// is then enforced by nothing at all, with a green tick over it.
//
// M-T3.8's lane met the same pattern from the other side and wrote down the
// answer, which this file takes: **an allowlist, not a scan for bad shapes.**
// `bot/export-issues.mjs` (astra-registry b9ccdc5) says it in one sentence —
// "asking 'does this value look personal' of a value that could be anything is
// a question with no safe answer; asking 'is this value a semver' of a member
// that may only ever be a semver is a question with one."
//
// So the subject-id shape is enforced **by position**. Every composed document
// kind below declares the members it may carry. A member nobody declared is
// refused whatever it holds, which is exactly where a subject id would land —
// `subject`, `account_id`, `minice_user` — and no value that IS declared can be
// one, because every declared member is a repository coordinate, a fixed
// vocabulary word, a hex digest, a date or a MOD-41 reason, all of which PRIV-2
// permits by name. A subject id has nowhere to be.
//
// **A commit body has no members, so the position rule cannot reach it**, and
// the shape rule cannot look for `^[A-Za-z0-9_-]{1,64}$` there either. That is
// a real hole and it is stated rather than papered over: a Minice subject id
// pasted into a commit message is not caught by this file. What catches it is
// B-T2.2 refusing to compose one and review refusing to merge one. If that is
// not enough, the answer is a narrower shape from minice-be — a prefix, a
// length, a checksum — and not a wider regex here.
//
// ── THE SHAPES THAT ARE SCANNED, AND WHAT EACH ONE COSTS ────────────────────
//
// Four, chosen because each one is nearly always what it looks like:
//
//   e-mail address     `a@b.c`, minus three exemptions below
//   `@handle`          at a value's start or after whitespace
//   Telegram id        a `-100…` chat id, a `t.me/` or `tg://` link, or ANY
//                      value under a member whose name says Telegram
//   UUID               outside the `submission_id` and `service_decision_id`
//                      members, which DEC-7 says hold one
//
// The exemptions are three, each principled and each narrow:
//
//   **git's own authorship trailers** — `Co-authored-by:`, `Signed-off-by:`
//   and their siblings. 51 of the 53 addresses in this repository's last sixty
//   commit messages are `Co-Authored-By: … <noreply@anthropic.com>` and one
//   more is the owner's in the same trailer. They are not composed content:
//   the forge writes them, `git commit --author` puts the same address in the
//   commit header where no scan of the MESSAGE can see it anyway, and a rule
//   that flagged them would be red on every commit this repository will ever
//   receive. That is the whole difference between a check and a nuisance.
//
//   **reserved names** — the TLDs `.example`, `.invalid`, `.test`,
//   `.localhost` (RFC 2606 §2, RFC 6761) **and the domains `example.com`,
//   `example.net`, `example.org` (RFC 2606 §3)**, subdomains included. These
//   are addresses that cannot belong to a person by construction.
//   `1@evil.example` is in a commit body here, as a test vector in a sentence
//   about a host parser, and it is not a leak. §3 was cited in this comment
//   and missing from the code until 2026-09-20, when the first commit body to
//   quote `someone@example.com` — recording what a new guard printed when it
//   was watched red — turned `main` red.
//
//   **role addresses (MOD-45)** — PRIV-2 permits them by name, by two rules.
//   A role LOCAL PART (`security`, `abuse`, `noreply` and the rest of
//   RFC 2142), which needs no file; and, in this walk only, whatever address
//   `bot/security-contact.json` publishes — read from that file rather than
//   typed here, so the exemption and the published address cannot drift
//   apart. The file's `email` is empty on purpose until the mailbox exists
//   (POLICY.md §12 is where the address will be published), so today the
//   second rule exempts nothing. **The decision writer applies the first rule
//   and never the second**: a file outside TRUST-31's hashed set must not
//   decide what a bot run writes into a public record (dev/couplings.md entry
//   104). The rules themselves live in `tools/lib/priv-rules.mjs`, which reads
//   no file; this module keeps the one read, and `run` is its only caller.
//
// ── CLEARING A RED ONE ──────────────────────────────────────────────────────
//
// History is not rewritten to clear a canary. `tools/coverage/priv-scan-exempt.json`
// carries one entry per cleared finding, each naming the commit, the place and
// a reason — and **an exemption that matches nothing fails**, so the file
// cannot quietly accumulate entries for findings that no longer exist and
// cannot be used to pre-authorise a shape nobody has seen yet.
//
// ── IT GATES NOTHING, AND NO SIGNING JOB RUNS IT (MOD-46) ───────────────────
//
// It runs in `moderation-coverage.yml`'s `check` job and nowhere else.
// M-T1.7b's lint names this file by path for exactly that reason. And no bot
// run imports it: what it shares with the decision writer is
// `tools/lib/priv-rules.mjs`, and `bot/tests/code-paths.test.mjs`'s walk is
// what would say so if a bot module started importing this file again.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./coverage/rules.mjs";
import {
  blobAt, changedPaths, commitMeta, commitsAfter, historyCount, introducingCommit, isShallow,
  mergeOwnChanges, mergesAfter,
} from "./coverage/git.mjs";
import { DOCUMENT_MEMBERS, EMAIL_RE, scanDocument, shapeFindings } from "./lib/priv-rules.mjs";

// Re-exported so that what this canary applies stays importable under the name
// its tests and its readers already use. The definitions are in
// `tools/lib/priv-rules.mjs`.
export { DOCUMENT_MEMBERS, scanDocument, shapeFindings };

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, "..");

export const SELF_PATH = "tools/priv-scan.mjs";
export const RULE = "priv-scan";
export const EXEMPT_FILE = "tools/coverage/priv-scan-exempt.json";

// 228 commits reachable on 2026-09-19. The same floor, for the same reason, as
// `tools/moderation-coverage.mjs`: it is not a claim about history, it is the
// check that `fetch-depth: 0` is still on the job.
//
// **The commits SCANNED at landing are zero**, and the plan asks for that
// number as the floor. Zero is not a floor, and a floor of zero written down
// as if it were one is worse than none — so the number recorded here is the
// one that can go wrong: a walk that returns nothing because the checkout was
// truncated is caught, and a walk that returns nothing because this file
// landed an hour ago is reported as "0 commits in range", in the run log,
// where it is the truth.
export const HISTORY_FLOOR = 228;

// ── what counts as composed ─────────────────────────────────────────────────

const COMPOSED = [
  { re: /^log\/decisions\/.*\.json$/, kind: "decision" },
  { re: /^log\/cutover\.json$/, kind: "cutover" },
  { re: /^log\/signed-wake-ack\.json$/, kind: "signed-wake-ack" },
  { re: /^log\/.*\.json$/, kind: null },               // log/** with no declared kind
  { re: /^plugins\/[^/]+\/identity\.json$/, kind: "identity" },
  { re: /^state\/alerts\/[^/]+\.json$/, kind: "alert-record" },
  { re: /^state\/deny\/[^/]+\.json$/, kind: "deny-record" },
  { re: /^state\/queue\/[^/]+\.json$/, kind: "queue-entry" },
  { re: /^state\/queue\/.*$/, kind: null },            // anything else under the queue
  { re: /^bot\/moderation\/[^/]+\.json$/, kind: "moderation-entry" },
];

/** @returns {{composed: boolean, kind: string|null}} */
export function classify(p) {
  for (const { re, kind } of COMPOSED) if (re.test(p)) return { composed: true, kind };
  return { composed: false, kind: null };
}

/** Git's authorship block. The forge writes these; PRIV-2's "composes" does not reach them. */
export const AUTHORSHIP_TRAILERS = [
  "co-authored-by", "signed-off-by", "reported-by", "reviewed-by", "acked-by",
  "tested-by", "suggested-by", "helped-by", "cc",
];

/**
 * The published role addresses PRIV-2 permits (MOD-45), read rather than typed.
 *
 * **This walk's, and nobody else's.** `run` is the only caller. The decision
 * writer used to import this too, which made a file outside TRUST-31's hashed
 * set an input to what the bot writes into a public record: an address added
 * to `bot/security-contact.json` stopped being refused on the moderation
 * run's path (dev/couplings.md entry 104). Keep it out of every module a bot
 * run imports — `bot/tests/code-paths.test.mjs`'s leg (c) fails, naming this
 * file's read, the day one does.
 */
export function roleAddresses(repo) {
  const out = new Set();
  const file = path.join(repo, "bot", "security-contact.json");
  if (!fs.existsSync(file)) return out;
  try {
    const found = JSON.stringify(JSON.parse(fs.readFileSync(file, "utf8"))).match(EMAIL_RE) ?? [];
    for (const a of found) out.add(a.toLowerCase());
  } catch { /* an unreadable contact file exempts nothing, which is the safe direction */ }
  return out;
}

/** Strip git's authorship trailers before a message is scanned. */
export function withoutAuthorship(message) {
  return message.split("\n")
    .filter((line) => {
      const m = /^([A-Za-z-]+):\s/.exec(line);
      return !(m && AUTHORSHIP_TRAILERS.includes(m[1].toLowerCase()));
    })
    .join("\n");
}

// ── exemptions ──────────────────────────────────────────────────────────────

/** `{commit, where, code, reason}` entries. An entry matching nothing fails. */
export function loadExemptions(repo) {
  const file = path.join(repo, EXEMPT_FILE);
  if (!fs.existsSync(file)) return [];
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(value.exemptions) ? value.exemptions : [];
  } catch {
    return [];
  }
}

const matchesExemption = (e, finding) =>
  finding.sha.startsWith(e.commit) && e.where === finding.where && e.code === finding.code;

// ── the walk ────────────────────────────────────────────────────────────────

export function run(repo, { from, historyFloor = HISTORY_FLOOR } = {}) {
  const codes = [];
  const hexes = [];
  const detail = [];

  if (isShallow(repo)) {
    return {
      status: "red",
      codes: ["PRIV_SHALLOW_CHECKOUT"],
      ids: [], hexes: [],
      detail: ["this checkout is shallow; the job that runs this rule needs `fetch-depth: 0`, and a walk " +
        "over the commits that happened to be fetched is green about every commit it never saw"],
    };
  }
  const reachable = historyCount(repo);
  if (reachable < historyFloor) {
    return {
      status: "red",
      codes: ["PRIV_HISTORY_FLOOR"],
      ids: [], hexes: [],
      detail: [`git rev-list --count HEAD is ${reachable} and there were ${historyFloor} on 2026-09-19`],
    };
  }

  const start = from ?? introducingCommit(SELF_PATH, repo);
  if (!start) {
    return {
      status: "red",
      codes: ["PRIV_NO_INTRODUCING_COMMIT"],
      ids: [], hexes: [],
      detail: [`git knows no commit that added ${SELF_PATH}, so the walk has no start and judged nothing`],
    };
  }

  const roles = roleAddresses(repo);
  const shas = commitsAfter(start, repo);
  const merges = mergesAfter(start, repo);
  const findings = [];
  let documents = 0;
  let mergeDocuments = 0;
  let mergesWithOwnChanges = 0;

  const scanMessage = (sha) => {
    const meta = commitMeta(sha, repo);
    for (const f of shapeFindings(withoutAuthorship(meta.message), { roles })) {
      findings.push({ sha, where: "commit-message", code: f.code, what: f.what });
    }
  };

  for (const sha of shas) {
    scanMessage(sha);
    for (const { status, path: p } of changedPaths(sha, repo)) {
      if (status === "D") continue;
      const { composed, kind } = classify(p);
      if (!composed) continue;
      documents++;
      for (const f of documentFindings(blobAt(sha, p, repo), p, kind, roles)) findings.push({ sha, where: p, ...f });
    }
  }

  // ── what a merge's own resolution wrote (gap 93) ─────────────────────────
  //
  // `commitsAfter` is right to leave merges out — a merge's first-parent diff
  // is the branch again — and wrong to be the only walk: an address typed
  // while resolving a conflict is in no side's commit, so it was in no walk.
  // A merge is judged on the paths its resolution changed (`mergeOwnChanges`,
  // remerge semantics), and on each one reports only what NO parent's copy of
  // that document already had. That subtraction is what keeps a conflict
  // resolved by keeping both sides — which changes the file relative to the
  // conflicted remerge, and so is in `changes` — from reporting the side's
  // finding a second time under the merge's SHA, where the side's exemption
  // entry would not match it.
  //
  // **And its message.** A commit message is composed content whoever wrote
  // it: `git merge -m`, a lane's "Merge origin/main into …" body and the
  // pull-request title GitHub puts in its own merge message are all typed by
  // somebody, and until gap 93 this walk read none of them.
  for (const sha of merges) {
    scanMessage(sha);
    const own = mergeOwnChanges(sha, repo);
    if (!own.judged) {
      findings.push({
        sha, where: "merge", code: "E_PRIV_MERGE_NOT_JUDGED",
        what: `a merge of ${own.parents.length} parents has no two-sided remerge, so what its own resolution ` +
          "wrote was not scanned; an octopus merge is not a clean one because this walk could not read it",
      });
      continue;
    }
    if (own.changes.length) mergesWithOwnChanges++;
    for (const { status, path: p } of own.changes) {
      if (status === "D") continue;
      const { composed, kind } = classify(p);
      if (!composed) continue;
      mergeDocuments++;
      const inherited = new Set();
      for (const parent of own.parents) {
        const before = blobAt(parent, p, repo);
        if (before === null) continue;
        for (const f of documentFindings(before, p, kind, roles)) inherited.add(JSON.stringify([f.code, f.what]));
      }
      for (const f of documentFindings(blobAt(sha, p, repo), p, kind, roles)) {
        if (inherited.has(JSON.stringify([f.code, f.what]))) continue;
        findings.push({ sha, where: p, ...f });
      }
    }
  }

  const exemptions = loadExemptions(repo);
  const used = new Set();
  const live = [];
  for (const f of findings) {
    const i = exemptions.findIndex((e) => matchesExemption(e, f));
    if (i >= 0) { used.add(i); continue; }
    live.push(f);
  }
  // An exemption matching nothing fails. Without this the file is a place to
  // pre-authorise a shape nobody has seen, and a place where the entry for a
  // finding that has since been fixed lives on, exempting the next one.
  exemptions.forEach((e, i) => {
    if (used.has(i)) return;
    codes.push("PRIV_EXEMPTION_MATCHES_NOTHING");
    detail.push(
      `${EXEMPT_FILE} exempts ${e.code} at ${e.where} in ${String(e.commit).slice(0, 12)} and this walk ` +
      "found no such finding; an exemption that matches nothing is an exemption for something else",
    );
  });

  for (const f of live) {
    codes.push(f.code);
    hexes.push(f.sha);
    detail.push(`${f.sha.slice(0, 12)} ${f.where}: ${f.what}`);
  }
  detail.push(
    `walk: ${shas.length} commit(s) after ${start.slice(0, 12)}, ${documents} composed document(s), ` +
    `${roles.size} exempt role address(es), ${exemptions.length} exemption(s)`,
  );
  detail.push(
    `merges: ${merges.length} merge(s) in range, messages scanned; ${mergesWithOwnChanges} whose own ` +
    `resolution changed a path, ${mergeDocuments} composed document(s) among those changes`,
  );
  return { status: codes.length ? "red" : "green", codes, ids: [], hexes, detail };
}

/**
 * The findings one composed document yields, without a SHA or a place — the
 * commit walk and the merge walk both attach those.
 *
 * @param {string|null} raw the blob, or null when the path is absent
 * @returns {{code: string, what: string}[]}
 */
function documentFindings(raw, p, kind, roles) {
  if (raw === null) return [];
  if (kind === null) {
    return [{
      code: "E_PRIV_UNDECLARED_DOCUMENT",
      what: `${p} is under a composed path and no kind in tools/priv-scan.mjs declares its members; ` +
        "declare it there, with the requirement that fixes each member, in the commit that introduces it",
    }];
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch (e) {
    return [{ code: "E_PRIV_UNREADABLE", what: String(e.message) }];
  }
  return scanDocument(value, kind, roles);
}

function parseArgs(argv) {
  const args = { repo: DEFAULT_REPO, report: process.env.ASTRA_COVERAGE_FINDINGS };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") args.repo = path.resolve(argv[++i]);
    else if (a === "--from") args.from = argv[++i];
    else if (a === "--report") args.report = argv[++i];
    else if (a === "--history-floor") args.historyFloor = Number(argv[++i]);
    else { console.error(`FAIL  unknown argument ${JSON.stringify(a)}`); return null; }
  }
  return args;
}

function main(argv) {
  const args = parseArgs(argv);
  if (!args) return 2;
  report(RULE, run(args.repo, args), args.report);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
