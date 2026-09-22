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
//   **role addresses (MOD-45)** — PRIV-2 permits them by name, and
//   `security@minice.ai` is published in `bot/security-contact.json` and in
//   POLICY.md §12. Read from that file rather than typed here, so the
//   exemption and the published address cannot drift apart.
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
// M-T1.7b's lint names this file by path for exactly that reason.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { report } from "./coverage/rules.mjs";
import {
  blobAt, changedPaths, commitMeta, commitsAfter, historyCount, introducingCommit, isShallow,
  mergeOwnChanges, mergesAfter,
} from "./coverage/git.mjs";

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

/**
 * Every composed document kind, and the TOP-LEVEL members it may carry.
 *
 * Top-level only, said plainly. A nested object — `artifact_digests` keyed by
 * filename, say — has member names this table cannot know, so nested values
 * get the shape rules and not the position rule. The position rule is where a
 * subject id is caught, so a composed document that nests one inside an object
 * is a document this file passes. Nothing here nests today; the day something
 * does, that kind needs its own nested table rather than a looser top level.
 */
export const DOCUMENT_MEMBERS = {
  // MOD-33, as `bot/moderation/README.md` documents it, plus M-T1.6's
  // additions so that task lands green rather than turning this red.
  //
  // `$comment` is here because five entries on `main` carry one and this table
  // did not. It was not caught when they landed: `c16be2d` added them, and
  // `a7495ed` — which built this scan — starts its walk at its own commit, so
  // the rule was green about a tree it had never looked at. Its commit message
  // claims "green over all 213 commits"; run from the root today it is red on
  // exactly those five, and it was red on the day it was written.
  //
  // **The cost was not the red run; it was WHEN the red run arrives.** Nothing
  // fails until somebody next edits one of those five files — and the most
  // likely reason to edit a retroactive moderation entry is to correct it,
  // which is the worst moment to meet an unrelated refusal you did not cause.
  // A trap laid for whoever touches the file next is the shape this repository
  // spent 2026-09-19 pulling out of a plan three at a time.
  //
  // Declaring it is not a loosening. An undeclared member is skipped by the
  // value scan entirely — `continue`, below — so `$comment` free text was the
  // one place in a composed document where an address could sit unread.
  // Declared, it is walked like every other member: the shapes apply.
  "moderation-entry": {
    members: ["$comment", "date", "action", "plugin", "versions", "reason", "advisory", "appeal",
      "category", "reverses", "appeal_of", "outcome", "service_decision_id", "declared_interest"],
    uuidOk: ["service_decision_id"],
    handleOk: [],
    source: "contract MOD-33; bot/moderation/README.md; M-T1.6; `$comment` per bot/moderation/*.json on main",
  },
  // DEC-7 (contract §2), whose own sentence is "with only these members". The
  // author-action record's members are a subset of these, so one table serves
  // both.
  decision: {
    members: ["schema", "decision_id", "submission_id", "decided_at", "actor", "moderator", "trigger",
      "plugin_id", "version", "repo", "repository_id", "repository_owner_id", "tag", "commit",
      "artifact_digests", "fingerprint", "state", "reasons", "category", "appeal_of", "outcome",
      "declared_interest", "publish_after", "run", "advisory"],
    uuidOk: ["submission_id", "service_decision_id"],
    // DEC-7 carries a moderator HANDLE, which PRIV-2 permits in that member
    // and in no other. A handle anywhere else is a moderator's name in a place
    // nobody will think to look for one.
    handleOk: ["moderator"],
    source: "contract DEC-7",
  },
  identity: {
    members: ["schema", "plugin_id", "repository_id", "repository_owner_id", "repo", "token_hash"],
    uuidOk: [],
    handleOk: [],
    source: "contract ID-15 (`astra.registry.identity/1`), which says `exactly these required members`",
  },
  "alert-record": {
    members: ["schema", "fingerprint", "event", "approval_decided_at", "delivered_at", "run"],
    uuidOk: [],
    handleOk: [],
    source: "contract TRUST-14; registry plan RC-R1-4",
  },
  "deny-record": {
    members: ["schema", "fingerprint", "run", "at"],
    uuidOk: [],
    handleOk: [],
    source: "contract TRUST-33 (`astra.registry.deny/1`); registry plan M-T3.5",
  },
  cutover: {
    members: ["schema", "cutover_at"],
    uuidOk: [],
    handleOk: [],
    source: "registry plan M-T6.2, commit B",
  },
  // Read off the tree rather than out of a document, because this one exists
  // and the others do not: `git log -p -- 'state/queue/*'` over 228 commits
  // gives exactly these fifteen members and exactly three values that have
  // ever been in `submitter` — `github-actions[bot]`, `mihailinl` and
  // `teletemagame-dev`. All three are GitHub logins, and PRIV-2 permits
  // "logins in existing fields" by name, which is what these are.
  "queue-entry": {
    members: ["$comment", "id", "version", "repo", "tag", "submitter", "queued_at", "publish_after",
      "delay_hours", "reason", "artifact_digests", "approved_by", "approved_at", "approved_for", "issue"],
    uuidOk: [],
    handleOk: ["submitter", "approved_by", "approved_for"],
    source: "BOT-33's publication queue, as `bot/publish-apply.mjs` writes it",
  },
};

// ── the shapes ──────────────────────────────────────────────────────────────

// The lookbehind is not decoration. This repository's publication queue names
// its files `<plugin-id>@<semver>.json`, so every commit that queues a release
// carries `state/queue/dice-roller@0.1.2.json` in its message — and the naive
// address pattern reads `dice-roller@0.1.2.json` as a mailbox at the domain
// `0.1.2.json`. That was the ONLY finding this rule produced over all 228
// commits on 2026-09-19, which is to say: the whole of its output, on the tree
// it was written for, was one filename. A canary whose every alarm is a
// filename is a canary nobody reads twice.
//
// Two guards, both narrow. The match may not begin inside a path or an
// identifier, which is what `state/queue/…` is; and the final label may not be
// a file extension or all digits, which is what `.json` and `0.1.2` are.
const EMAIL_RE = /(?<![A-Za-z0-9._%+/-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/** Final labels that are a file, not a top-level domain. */
const NOT_A_TLD = new Set([
  "json", "md", "mjs", "cjs", "js", "ts", "txt", "yaml", "yml", "toml", "lock",
  "zip", "tar", "gz", "png", "jpg", "svg", "rs", "py", "sh", "html", "css", "pem", "sig",
]);

function looksLikeAFile(address) {
  const tld = address.split(".").pop().toLowerCase();
  if (NOT_A_TLD.has(tld)) return true;
  const domain = address.slice(address.lastIndexOf("@") + 1);
  return domain.split(".").some((label) => /^\d+$/.test(label));
}
const HANDLE_RE = /(?:^|\s)(@[A-Za-z0-9](?:[A-Za-z0-9_-]{1,38}))/g;
const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;
// A Telegram supergroup or channel id, a t.me link and a tg: URI. A Telegram
// USER id is a bare integer and there is no shape that separates one from a
// run number, a byte count or a year; the member-name rule below is what
// covers that, and this comment is the statement that a bare integer is not
// covered anywhere else.
const TELEGRAM_RE = /(?:\B-100\d{9,12}\b|\bt\.me\/[A-Za-z0-9_+/-]+|\btg:\/\/\S+)/g;
const TELEGRAM_MEMBER_RE = /telegram|chat_id/i;

/** RFC 2606 §2 and RFC 6761: top-level domains that cannot belong to a person. */
const RESERVED_TLDS = [".example", ".invalid", ".test", ".localhost"];

/**
 * RFC 2606 **§3**, which the comment at the top of this file cites and the
 * code did not implement: `example.com`, `example.net` and `example.org` are
 * reserved for documentation exactly as the four TLDs above are, and are the
 * addresses a person actually writes when they need a fake one.
 *
 * It was the omission rather than the rule that was wrong, and the way it
 * surfaced says why it matters: the first commit body in this repository to
 * quote an example address did so to record a **watched-red** run — the
 * evidence that a new guard fires — and the privacy scan went red on `main`
 * about it. A rule whose failure mode is punishing the one habit this estate
 * most wants (write down what the check printed when you broke it) is a rule
 * on its way to being switched off.
 *
 * Subdomains count: `a@mail.example.com` is no more a person's address than
 * `a@example.com`. Matched on the registrable domain, not by `endsWith` on
 * the whole address, so `a@notexample.com` is still a finding.
 */
const RESERVED_DOMAINS = ["example.com", "example.net", "example.org"];

function reservedDomain(host) {
  return RESERVED_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`));
}

/**
 * A role address is a mailbox that is a FUNCTION rather than a person, and
 * that is what PRIV-2 permits when it says "role addresses (MOD-45)". The set
 * is RFC 2142's, plus the five this estate actually uses.
 *
 * Defined by the local part rather than by a list of addresses, because the
 * address this project will publish does not exist yet:
 * `bot/security-contact.json` carries `"email": ""` on purpose until the
 * mailbox is registered and delivery is proved, and M-T6.2's cutover commit
 * writes `security@minice.ai` into POLICY.md §12 on a day nothing here would
 * have known about. A rule keyed to the file alone would go red on that
 * commit, in the alarm channel, about the address of the alarm.
 */
const ROLE_LOCAL_PARTS = new Set([
  "postmaster", "hostmaster", "webmaster", "abuse", "noc", "security",
  "usenet", "news", "uucp", "ftp", "info", "marketing", "sales", "support",
  "noreply", "no-reply", "privacy", "legal", "contact",
]);

/** Git's authorship block. The forge writes these; PRIV-2's "composes" does not reach them. */
export const AUTHORSHIP_TRAILERS = [
  "co-authored-by", "signed-off-by", "reported-by", "reviewed-by", "acked-by",
  "tested-by", "suggested-by", "helped-by", "cc",
];

/** The published role addresses PRIV-2 permits (MOD-45), read rather than typed. */
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

function addressExempt(address, roles) {
  const lower = address.toLowerCase();
  if (roles.has(lower)) return true;
  if (RESERVED_TLDS.some((tld) => lower.endsWith(tld))) return true;
  if (reservedDomain(lower.split("@").pop() ?? "")) return true;
  if (ROLE_LOCAL_PARTS.has(lower.split("@")[0])) return true;
  return looksLikeAFile(lower);
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

/**
 * The shape rules over one string.
 *
 * @param {string} text
 * @param {{roles: Set<string>, member?: string, uuidOk?: boolean, handleOk?: boolean}} ctx
 * @returns {{code: string, what: string}[]}
 */
export function shapeFindings(text, ctx) {
  const out = [];
  for (const a of text.match(EMAIL_RE) ?? []) {
    if (!addressExempt(a, ctx.roles)) out.push({ code: "E_PRIV_EMAIL", what: a });
  }
  if (!ctx.handleOk) {
    for (const m of text.matchAll(HANDLE_RE)) out.push({ code: "E_PRIV_HANDLE", what: m[1] });
  }
  for (const t of text.match(TELEGRAM_RE) ?? []) out.push({ code: "E_PRIV_TELEGRAM", what: t });
  if (ctx.member && TELEGRAM_MEMBER_RE.test(ctx.member)) {
    out.push({ code: "E_PRIV_TELEGRAM", what: `member \`${ctx.member}\`` });
  }
  if (!ctx.uuidOk) {
    for (const u of text.match(UUID_RE) ?? []) out.push({ code: "E_PRIV_UUID", what: u });
  }
  return out;
}

/** Walk a parsed document, applying the position rule at the top and the shapes everywhere. */
export function scanDocument(value, kind, roles) {
  const found = [];
  const table = kind ? DOCUMENT_MEMBERS[kind] : null;
  if (kind && !table) {
    return [{ code: "E_PRIV_UNKNOWN_KIND", what: `${kind} has no entry in DOCUMENT_MEMBERS` }];
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    // A composed document that is not an object has no members to check, so
    // only the shapes apply. Saying nothing here would be a silent pass.
    for (const f of shapeFindings(String(value), { roles })) found.push(f);
    return found;
  }
  for (const [member, v] of Object.entries(value)) {
    if (table && !table.members.includes(member)) {
      found.push({
        code: "E_PRIV_UNDECLARED_MEMBER",
        what: `\`${member}\` is not a member ${kind} may carry (${table.source}); PRIV-2's subject-id rule ` +
          "is enforced by position, so a member nobody declared is refused whatever it holds",
      });
      continue;
    }
    const ctx = {
      roles,
      member,
      uuidOk: !!table?.uuidOk.includes(member),
      handleOk: !!table?.handleOk.includes(member),
    };
    walkValue(v, ctx, found, member);
  }
  return found;
}

function walkValue(v, ctx, found, where) {
  if (typeof v === "string") {
    for (const f of shapeFindings(v, ctx)) found.push({ ...f, what: `${where}: ${f.what}` });
    return;
  }
  if (Array.isArray(v)) { v.forEach((e, i) => walkValue(e, ctx, found, `${where}[${i}]`)); return; }
  if (v && typeof v === "object") {
    for (const [k, e] of Object.entries(v)) {
      // Nested member names are not in the position table (see DOCUMENT_MEMBERS).
      // A nested name that says Telegram is still caught, because that rule is
      // about the name and not about the table.
      const nctx = TELEGRAM_MEMBER_RE.test(k) ? { ...ctx, member: k } : ctx;
      walkValue(e, nctx, found, `${where}.${k}`);
    }
  }
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
