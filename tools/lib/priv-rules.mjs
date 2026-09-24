// PRIV-2's rules as a function of the value and nothing else: the member
// table, the four shapes and their exemptions, which `tools/priv-scan.mjs`
// applies to history and `bot/lib/decisions.mjs` applies to a decision record
// before it is written. `tools/priv-scan.mjs`'s header is where each rule is
// argued; this file is where it lives. **It reads no file**, and that is the
// reason it is a file of its own.
//
// ── WHY THE RULES LEFT THE CANARY ───────────────────────────────────────────
//
// They lived in `tools/priv-scan.mjs`, and the decision writer imported them
// from there together with `roleAddresses`, which reads
// `bot/security-contact.json` and exempts every address that file contains. So
// the bot's own refusal — `writeDecisionRecord` → `refusePrivate` →
// `privacyFindings`, on the moderation run's path — depended on a file
// TRUST-31's hashed set does not name. Measured on 2026-09-22: a private
// address in a decision's `reasons` was `E_PRIV_EMAIL` with the committed file
// and passed once the same address was added to it. A registry writer could
// have widened what a bot run writes into a public decision record, for ever
// (DEC-7: git never forgets), without the bot going back to shadow
// (dev/couplings.md entry 104).
//
// The file bought the decision writer nothing. Its `email` is empty, and was
// in both versions it has ever had; the address it says it will carry is a
// `security@` mailbox, which `ROLE_LOCAL_PARTS` below already exempts by its
// local part. That was measured before anything moved, not argued: identical
// findings with and without the file for every string it has ever held, and
// for every role local part written into it as its `email`.
//
// So the rules moved here, under `tools/lib/`, which TRUST-31 already hashes as
// a directory, and the decision writer takes them from here and passes no
// published roles. The canary still reads the file for its own walk — MOD-45's
// "read rather than typed" is its rule, and it holds there unchanged — and the
// canary is no longer a module any bot run imports. Two checks hold that:
// `bot/tests/decisions.test.mjs` from the outside (an address added to the
// contact file is still refused on the writer's path), and
// `bot/tests/code-paths.test.mjs`'s leg (c) from the inside (a data file a
// reachable module names is in the set or declared outside it, and the
// contact file is neither).
//
// **Nothing here may read a file.** An address this module exempts is exempt
// because of what it IS — a reserved name, a role mailbox, a filename — never
// because a repository file says so. `roles` is a parameter so that the
// canary, and only the canary, can pass the published ones.

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
  // RC-R2-3 commit (ii)'s precondition: the one answer the release desk read
  // from SERVE-94's wake hint before `sign.yml` may send it. Declared here
  // before the document exists, so that the commit which records it is the
  // one-line flip plus the record and nothing else. The member list is also the
  // record's closed member set: `tools/selftest/repo-rules.mjs` reads it from
  // here rather than keeping a second copy.
  "signed-wake-ack": {
    members: ["schema", "method", "url", "status", "body", "read_at", "read_from"],
    uuidOk: [],
    handleOk: [],
    source: "registry plan RC-R2-3 commit (ii); contract SERVE-94 and §4.2's `astra.plugins.wake-ack/1`",
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
export const EMAIL_RE = /(?<![A-Za-z0-9._%+/-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

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

function addressExempt(address, roles) {
  const lower = address.toLowerCase();
  if (roles.has(lower)) return true;
  if (RESERVED_TLDS.some((tld) => lower.endsWith(tld))) return true;
  if (reservedDomain(lower.split("@").pop() ?? "")) return true;
  if (ROLE_LOCAL_PARTS.has(lower.split("@")[0])) return true;
  return looksLikeAFile(lower);
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
