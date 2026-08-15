// Does the person asking for this listing control the repository it names?
//
// The registry has to answer this once, at the first listing, and again whenever
// the repository changes. Everything after that is pinned: the daemon carries a
// TOFU pin to `identity.repo`, so once a plugin is listed from `you/thing`, an
// impostor cannot take it over by convincing this bot of anything — they would
// have to convince every installed copy, which is not a thing the registry can
// do (PRODUCTION_PLAN §5.5).
//
// ── what this check is actually for ─────────────────────────────────────────
//
// The build attestation already binds the bytes to a repository, and the
// listing is already pinned to that repository. What ownership adds is the one
// thing neither of those says: **that the person asking for the listing
// controls that repository** — so a stranger cannot list somebody else's plugin
// and become the account through which its updates reach Astra users. Every
// line below is in service of that sentence and nothing else.
//
// ── the file is the proof. it is not a fallback ────────────────────────────
//
// `.well-known/astra-plugin-owner`, on the default branch, one login per line.
//
// It used to be second in a list of three and was mentioned to authors only in
// the remedy text *after* a refusal — and that ordering was wrong in the
// strongest way an ordering can be wrong: **the other two cannot fire for an
// honest first submission**, so every correct author was guaranteed one refusal
// before being told the thing that works. Both halves of that were settled by a
// production run against `astra-registry#13` and `#14` (2026-08-14), where
// every cryptographic check passed and only this one failed:
//
//   * `GET /repos/{o}/{r}/collaborators/{u}/permission` answered **403** — the
//     bot's `GITHUB_TOKEN` belongs to `astra-registry`, and GitHub answers that
//     endpoint only for a caller that already has access to the repository
//     being asked about. A token from another repository is told *nothing*,
//     which is not the same fact as *no*;
//   * the release was published by **`@github-actions[bot]`**, because the
//     documented `plugin-release.yml` is what creates the Release. Our own CI
//     defeats our own fallback, for everyone, permanently.
//
// So the file is what the author is asked for first, on the submission form,
// before a run ever happens. It costs one commit and no CI.
//
// **Be honest about what it proves.** It proves that *somebody who can write to
// that repository's default branch vouches for this login*. It is a proof of
// write access, not of legal ownership, not of authorship, and not of identity.
// Two properties make that enough here:
//
//   1. a stranger cannot get a commit onto somebody else's default branch, and
//      a stranger is exactly what this check exists to stop;
//   2. it is read **live**, on every run, from the default branch — so removing
//      a login from the file stops that login opening a new listing request or
//      passing a `/recheck`, which is the thing a one-time challenge-nonce
//      commit can never do. It does **not** reach an already-listed plugin:
//      later releases are proved against the account that published the release
//      (see arm 3 below), and the listing is pinned to the repository anyway.
//
// Its residual risk is stated rather than hidden: a contributor can open a pull
// request that adds their own login, and a maintainer who merges without
// reading has vouched for them. That is a real hole, and the registry cannot
// close it, because the same distracted merge could change the release workflow
// or the plugin's source — anyone who can land commits on the default branch is
// already the plugin's update path.
//
// ── the collaborator endpoint: an opportunistic fast path ──────────────────
//
// Tried first, because it costs one request and asks the author for nothing. It
// is a *shortcut*, not the proof: for a third-party repository it answers 403
// essentially always, and that must be read as **"the bot cannot see"**.
//
// A 403 is not evidence about the submitter, it is not a failed check, and it
// is never printed as one. The refusal a stranger reads must not contain a line
// that looks like GitHub denied them something, when what happened is that
// GitHub declined to talk to us.
//
// **A 200 is different, and a 200 is final in both directions.** GitHub answers
// only for a caller that can already see the repository, and when it does
// answer it is answering the exact question, about the exact person. `admin` or
// `maintain` grants. Anything else — `write`, `triage`, and the `read`/`none` a
// non-collaborator gets — is an explicit statement that this login is not a
// maintainer of this repository, and it ends the run. That distinction is the
// one the ranking used to lack: an answered `write` fell through and could be
// overridden by a file a contributor had added in a pull request, or by a
// release published before the account was removed. The owner file speaks where
// GitHub will not; it does not overrule GitHub where it will.
//
// ── release author: kept, demoted, and silent where it cannot fire ─────────
//
// The account that published the release being listed. It was the third arm of
// three, and on the **first-listing** path it is inert: the documented workflow
// publishes releases as `@github-actions[bot]`, so it cannot match a human
// submitter, and a release a human published by hand carries no attestation
// from the pinned reusable workflow and is refused two checks later anyway. On
// that path it contributed nothing except a third line in a refusal message,
// naming a fact the author cannot change. It no longer appears there.
//
// It is **not deleted**, because it is load-bearing somewhere else. On the
// re-listing paths — a `/release` ping and the cron backstop —
// `resolveSubmitter` (`bot/lib/notify.mjs`) sets the submitter to the release's
// own author, so this is the only arm that can answer, and every zero-touch
// release of every already-listed plugin goes through it. Worth saying plainly:
// on that path the arm is *circular* — the release author is checked against
// the release author — and the security comes from somewhere else entirely,
// namely that a ping may only name a repository that is **already listed** and
// already pinned to that repository's identity. The age cap below is what keeps
// the circularity from also being permanent.
//
// Ranked, tried in order, and the winning method is recorded in the listing's
// audit trail so "how did this get in" always has an answer.

const API = "https://api.github.com";

/** The one path this registry reads an ownership claim from. */
export const OWNER_FILE = ".well-known/astra-plugin-owner";

function headers(token) {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-registry-bot",
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/**
 * `GET /repos/{o}/{r}/collaborators/{u}/permission`, and what its answer means.
 *
 * Extracted because there are now two questions in this repository that hang on
 * this one endpoint and must not answer it differently: *does this submitter
 * control the repository they are listing* (below), and *may this commenter
 * approve a held release* (`bot/lib/maintainer.mjs`). One caller reading
 * `role_name` and another reading `permission` is exactly how a `maintain`
 * collaborator ends up trusted by one path and refused by the other.
 *
 * The distinction the two callers share, and the reason this returns
 * `answered` rather than a boolean: **"GitHub said no" and "GitHub would not
 * say" are different facts.** A 200 is an answer in both directions. A 403 or a
 * 404 means the caller cannot see the endpoint, which is evidence of nothing.
 * What each caller *does* with a missing answer differs — one falls back to the
 * repository's own owner file, the other refuses outright — and that is their
 * decision to make, not this function's.
 *
 * Verified against the live API on 2026-08-13, against this registry itself:
 * for a **public** repository the endpoint answers 200 `role_name: "read"` for
 * an account that is not a collaborator at all (`octocat`), and 200
 * `role_name: "admin"` for the owner. So "not a collaborator" arrives here as
 * an answered denial rather than as a 404, and the callers can rely on the
 * distinction meaning what it says.
 *
 * Verified against a real Actions run on 2026-08-14, for a **third-party**
 * repository (`Rel0d1x/command-intent-guard`, from `astra-registry#13`/`#14`):
 * **403**. That is the case that matters in production and it is the case for
 * every repository this registry does not own, which is what makes the path
 * below a shortcut that rarely fires rather than a check that usually answers.
 *
 * @returns {Promise<{answered: boolean, role: string|null, outcome: string}>}
 */
export async function collaboratorRole(repo, login, opts = {}) {
  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const url = `${API}/repos/${repo}/collaborators/${encodeURIComponent(login)}/permission`;
    const res = await doFetch(url, { headers: headers(opts.token) });
    if (res.ok) {
      const body = await res.json();
      // `role_name` is the fine-grained role (`admin`, `maintain`, `write`, …);
      // `permission` is the coarse legacy field, where `maintain` reports as
      // `write`. Read the fine one and fall back, so a `maintain` collaborator
      // is not silently demoted by an old field name.
      const role = String(body.role_name ?? body.permission ?? "").toLowerCase() || "none";
      return { answered: true, role, outcome: `role is \`${role}\`` };
    }
    if (res.status === 403 || res.status === 404) {
      // Worded as a fact about the bot, deliberately. This string can reach an
      // author, and a bare "403" printed beside their name reads as a denial.
      return {
        answered: false,
        role: null,
        outcome: `HTTP ${res.status} — GitHub does not disclose this repository's collaborators to the bot`,
      };
    }
    return { answered: false, role: null, outcome: `HTTP ${res.status} — no answer` };
  } catch (e) {
    return { answered: false, role: null, outcome: `request failed: ${e.message}` };
  }
}

/** The two roles that count as control of a repository, in either question. */
export const CONTROL_ROLES = ["admin", "maintain"];

/**
 * The strength order the methods are reported in.
 *
 * Strength is not the same as primacy. `well-known` is the proof this registry
 * *asks* for, because it is the only one of the three an honest author can act
 * on; `collaborator-permission` still outranks it, because GitHub answering
 * directly about a person is a stronger statement than a file, and
 * `release-author` sits below both for the reasons in the header.
 */
export const METHOD_STRENGTH = {
  "collaborator-permission": 3,
  "well-known": 2,
  "release-author": 1,
};

/**
 * How stale a release may be and still stand as proof its publisher has access.
 *
 * Ninety days is the shape of the claim rather than a security parameter: the
 * point is that the fact expires at all, so an account removed from an
 * organisation stops being able to list on the strength of what it did before
 * it was removed.
 */
export const RELEASE_AUTHOR_MAX_AGE_DAYS = 90;

/** Age of a release in days, or null when there is no usable date. */
function releaseAgeDays(publishedAt, now) {
  if (!publishedAt) return null;
  const t = Date.parse(publishedAt);
  if (!Number.isFinite(t)) return null;
  return (now.getTime() - t) / 86_400_000;
}

/** GitHub's login charset, for the one place a stranger's file is echoed back. */
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

/**
 * Read `.well-known/astra-plugin-owner` off the default branch, now.
 *
 * The file belongs to a stranger, so it is capped before it is parsed, and
 * every login echoed back into a public comment is re-checked against the
 * charset it claims to be. `#` starts a comment, a leading `@` is forgiven,
 * blank lines are ignored, and the comparison is case-insensitive because
 * GitHub logins are.
 *
 * The contents API is asked for the raw body, and no ref is passed, so what is
 * read is the **default branch as it stands right now**: delete a login, and the
 * next run that consults this file stops accepting it. That is the whole of the
 * revocation story on the paths that consult it — a first listing and a
 * `/recheck`. The ping and cron paths do not reach here, because
 * `resolveSubmitter` makes the submitter the release's own author.
 *
 * **`transient` is the difference between "you did not do it" and "we could not
 * look".** A 404 is an answer: the file is not on that branch. A rate-limited
 * or blocked read is not an answer at all, and telling an author to commit a
 * file they committed last week — because the bot happened to run inside an
 * exhausted rate-limit window — is the worst message this module can produce.
 * Note which status means what: a **private** repository is hidden by GitHub
 * and comes back **404**, not 403, so it is diagnosed with the missing-file
 * case; 403 here means an exhausted primary limit, a blocked repository, or a
 * token that may not read this one, and 429 is the secondary limit.
 *
 * @returns {Promise<{found: boolean, transient: boolean, logins: string[], outcome: string}>}
 */
export async function readOwnerFile(repo, opts = {}) {
  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const url = `${API}/repos/${repo}/contents/${OWNER_FILE}`;
    const res = await doFetch(url, {
      headers: { ...headers(opts.token), Accept: "application/vnd.github.raw+json" },
    });
    if (res.status === 404) {
      return {
        found: false,
        transient: false,
        logins: [],
        outcome: `there is no \`${OWNER_FILE}\` on that branch (HTTP 404)`,
      };
    }
    if (!res.ok) {
      const remaining = res.headers?.get?.("x-ratelimit-remaining");
      const rateLimited = res.status === 429 || (res.status === 403 && remaining === "0");
      return {
        found: false,
        transient: rateLimited,
        logins: [],
        outcome: rateLimited
          ? `the bot ran out of GitHub API requests before it could read the file (HTTP ${res.status})`
          : `the file could not be read (HTTP ${res.status})`,
      };
    }
    const text = await res.text();
    const logins = text
      .slice(0, 4096)
      .split("\n")
      .map((l) => l.split("#")[0].trim().replace(/^@/, ""))
      .filter(Boolean)
      .slice(0, 64);
    return { found: true, transient: false, logins, outcome: `the file lists ${logins.length} login(s)` };
  } catch (e) {
    // The request never completed, so nothing was learnt about the file.
    return { found: false, transient: true, logins: [], outcome: `the file could not be read: ${e.message}` };
  }
}

/**
 * The one sentence that tells an author what to create.
 *
 * Exported and used by the refusal below, so the message a stranger reads and
 * the fixed `remedy` in `bot/lib/codes.mjs` cannot drift into naming two
 * different paths. `bot/tests/ingest.test.mjs` asserts the form's confirmation
 * quotes the same path.
 */
export function ownerFileInstruction(repo, login) {
  return (
    `**Commit \`${OWNER_FILE}\` on ${repo}'s default branch containing one line — \`${login}\` — ` +
    "then comment `/recheck` here.** One commit, no CI, nothing to install."
  );
}

/**
 * @param {{repo: string, login: string, releaseAuthor?: string|null,
 *          releasePublishedAt?: string|null, now?: Date,
 *          token?: string, fetchImpl?: typeof fetch}} opts
 * @returns {Promise<{ok: boolean, method: string|null, detail: string, tried: {method: string, outcome: string}[]}>}
 */
export async function proveOwnership(opts) {
  const { repo, login, releaseAuthor = null, releasePublishedAt = null } = opts;
  const now = opts.now ?? new Date();
  const token = opts.token ?? process.env.GITHUB_TOKEN;
  const doFetch = opts.fetchImpl ?? fetch;
  const tried = [];

  if (!login) {
    return { ok: false, method: null, detail: "no submitter login was supplied", tried };
  }

  // 1 ── the fast path: ask GitHub who has admin or maintain.
  //
  // Free for the author, and worth one request on the chance it answers. For a
  // repository this registry cannot see it will not answer, and that is the
  // normal case rather than a problem with the submission.
  const asked = await collaboratorRole(repo, login, { token, fetchImpl: doFetch });
  tried.push({ method: "collaborator-permission", outcome: asked.outcome });

  if (asked.answered && CONTROL_ROLES.includes(asked.role)) {
    return {
      ok: true,
      method: "collaborator-permission",
      detail: `GitHub reports @${login} has \`${asked.role}\` on ${repo}`,
      tried,
    };
  }
  if (asked.answered) {
    // **A 200 is a denial, and a denial ends it.** The owner file exists for
    // the case where GitHub will not say; it is not a second opinion on an
    // answer GitHub gave, about this person, on this repository, just now.
    return {
      ok: false,
      method: null,
      detail:
        `**Ask someone with \`admin\` or \`maintain\` on ${repo} to open this request instead**, ` +
        "or have them give you one of those roles, then comment `/recheck`.\n" +
        `GitHub reports @${login} has \`${asked.role}\` on ${repo}, which is neither. A ` +
        `\`${OWNER_FILE}\` file does not override this: GitHub answered the question directly, ` +
        "about you, on this repository, and the file only speaks where GitHub will not.",
      tried,
    };
  }

  // 2 ── the proof: the repository's own owner file, read live.
  const file = await readOwnerFile(repo, { token, fetchImpl: doFetch });
  const wanted = login.toLowerCase();
  if (file.found && file.logins.some((l) => l.toLowerCase() === wanted)) {
    tried.push({ method: "well-known", outcome: `names @${login}` });
    return {
      ok: true,
      method: "well-known",
      detail:
        `\`${OWNER_FILE}\` on ${repo}'s default branch names @${login} — a statement by somebody ` +
        "who can write to that branch, read live on this run",
      tried,
    };
  }
  tried.push({ method: "well-known", outcome: file.outcome });

  // 3 ── the release's own author.
  //
  // Only ever consulted when the submitter *is* that account, which on the
  // first-listing path is structurally impossible (`plugin-release.yml`
  // publishes as `@github-actions[bot]`) and on the ping/backstop path is
  // guaranteed by `resolveSubmitter`. When it cannot apply it is recorded in
  // `tried` and then kept out of the author's way: a third failure line about
  // who pressed a button in CI is noise in a message whose job is to name one
  // fix.
  let staleRelease = null;
  if (releaseAuthor && releaseAuthor.toLowerCase() === wanted) {
    const ageDays = releaseAgeDays(releasePublishedAt, now);
    if (ageDays === null) {
      tried.push({ method: "release-author", outcome: "matches, but the release carries no publication date" });
    } else if (ageDays > RELEASE_AUTHOR_MAX_AGE_DAYS) {
      staleRelease =
        `You published this release ${Math.round(ageDays)} days ago, which is past the ` +
        `${RELEASE_AUTHOR_MAX_AGE_DAYS}-day limit on that standing as evidence of current access.`;
      tried.push({
        method: "release-author",
        outcome: `matches, but the release is ${Math.round(ageDays)} days old (limit ${RELEASE_AUTHOR_MAX_AGE_DAYS})`,
      });
    } else {
      tried.push({ method: "release-author", outcome: `matches, published ${Math.round(ageDays)} day(s) ago` });
      return {
        ok: true,
        method: "release-author",
        detail:
          `@${login} published the release being listed ${Math.round(ageDays)} day(s) ago, which ` +
          `required push access to ${repo} at that moment. GitHub would not say who has ` +
          "`admin` or `maintain` now.",
        tried,
      };
    }
  } else {
    tried.push({
      method: "release-author",
      outcome: releaseAuthor
        ? `not applicable: the release was published by @${releaseAuthor}`
        : "not applicable: the release names no author",
    });
  }

  // ── the refusal, which leads with the fix ─────────────────────────────────
  //
  // One instruction, first, with the exact path and the exact line; then what
  // the bot actually saw, in a form the author can act on. The 403 the fast
  // path returns for every third-party repository is deliberately **not** in
  // this list: it is a fact about this bot's token, and printing it beside a
  // submitter's name reads as an accusation. It stays in `tried`, which is the
  // audit trail, not the comment.
  //
  // The one case where the instruction is wrong is the one where the bot never
  // got an answer — a rate-limited or failed read. "Commit the file" is then
  // an instruction its author has already followed, so it is replaced rather
  // than decorated.
  const named = file.found ? file.logins.filter((l) => LOGIN_RE.test(l)).slice(0, 8) : [];
  const unanswered = !file.found && file.transient;
  const lines = [
    unanswered
      ? `**The bot could not read \`${OWNER_FILE}\` on ${repo} this run** — ${file.outcome}. ` +
        "That is a fault on this side and says nothing about your submission. If you have " +
        `already committed the file, comment \`/recheck\` and it will be read again; if you ` +
        `have not, commit it with \`${login}\` on a line of its own first.`
      : ownerFileInstruction(repo, login),
  ];
  if (unanswered) {
    // `file.outcome` is already in the line above.
  } else if (file.found) {
    lines.push(
      named.length
        ? `The file is there but does not name you: it lists ${named.map((l) => `\`${l}\``).join(", ")}. ` +
          "Add `" + login + "` on a line of its own — a typo in one of those is the usual cause."
        : "The file is there, but the bot could not read a login out of it. One login per line and " +
          "nothing else; `#` starts a comment.",
    );
  } else {
    lines.push(`Right now ${file.outcome}.`);
  }
  if (staleRelease) lines.push(staleRelease);
  lines.push(
    "This is the proof the registry asks for, and for almost every repository it is the only one " +
      "available: GitHub does not tell a stranger's token who has `admin` on your repository, so " +
      "the bot cannot look you up. That is a limit of the bot's token and says nothing about you " +
      "— this check is only about who is asking, not about your release.",
  );

  return { ok: false, method: null, detail: lines.join("\n"), tried };
}
