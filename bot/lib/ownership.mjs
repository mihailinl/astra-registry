// Does the person asking for this listing control the repository it names?
//
// The registry has to answer this once, at the first listing, and again whenever
// the repository changes. Everything after that is pinned: the daemon carries a
// TOFU pin to `identity.repo`, so once a plugin is listed from `you/thing`, an
// impostor cannot take it over by convincing this bot of anything — they would
// have to convince every installed copy, which is not a thing the registry can
// do (PRODUCTION_PLAN §5.5).
//
// ── why not a challenge file as the primary ─────────────────────────────────
//
// The usual pattern is "commit `astra-verify-<nonce>` to your default branch".
// It proves that at some moment somebody could write to that branch. It does not
// prove they still can, it survives the author being removed from the
// organisation, and it is a file a contributor can add in a pull request that a
// distracted maintainer merges. Asking GitHub who has admin or maintain **now**
// is both stronger and one API call, with nothing for the author to do.
//
// ── the three ways, and exactly what each proves ────────────────────────────
//
//   1. COLLABORATOR PERMISSION — `GET /repos/{o}/{r}/collaborators/{u}/permission`
//      returning `admin` or `maintain`. The strongest answer available and the
//      one PRODUCTION_PLAN task 3.3 specifies. GitHub only answers it for a
//      caller that itself has admin visibility on the repository, so in practice
//      it works when the registry's GitHub App is installed on the repo. When it
//      is not, GitHub returns 403/404 — which is *not* evidence of anything, and
//      is treated as "no answer", never as "no".
//
//      **A 200 is final, in both directions.** This is the fix for the thing
//      that made the ranking meaningless: the three methods used to be tried in
//      sequence with no distinction between "GitHub did not answer" and "GitHub
//      answered no". A 200 carrying `role_name: "write"` — an explicit statement
//      that the login is NOT admin or maintain — was written into `tried` and
//      then overridden by method 2 or 3. So a contributor with push access, or
//      an ex-collaborator GitHub reports as `none`, could still be granted by a
//      file they added in a pull request or by a release they published before
//      they were removed. Only 403/404, another status, or a network error may
//      fall through now, because only those mean nobody answered.
//
//   2. `.well-known/astra-plugin-owner` on the default branch, one login per
//      line. The org-repo fallback the plan names. Proves that somebody with
//      push access to the default branch asserts this login — read live, so a
//      person removed from the org stops being an owner as soon as the file is
//      updated, but not before.
//
//   3. RELEASE AUTHOR — the account that published the release being listed.
//      Publishing a release requires push access, and this is the release whose
//      bytes are being listed, so it is the narrowest possible statement: "the
//      person asking is the person who published these exact bytes." Weaker
//      than 1 (push is not maintain) and accepted for the same reason 2 is:
//      refusing every submission from an organisation that has not installed an
//      app would make third-party publishing theoretical.
//
//      **Capped, because it is a permanent historical fact.** "@x published a
//      release last March" stays true forever, including after @x is removed
//      from the organisation — which is precisely what the section above rejects
//      a challenge file for. So it is accepted only when the release was
//      published inside [`RELEASE_AUTHOR_MAX_AGE_DAYS`], which turns it from "at
//      some point they had access" into "they had access recently", and only
//      when method 1 gave no answer at all.
//
// Ranked, tried in order, and the winning method is recorded in the listing's
// audit trail so "how did this get in" always has an answer.

const API = "https://api.github.com";

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
 * What each caller *does* with a missing answer differs — one falls back to
 * weaker proofs, the other refuses outright — and that is their decision to
 * make, not this function's.
 *
 * Verified against the live API on 2026-08-13, against this registry itself:
 * for a **public** repository the endpoint answers 200 `role_name: "read"` for
 * an account that is not a collaborator at all (`octocat`), and 200
 * `role_name: "admin"` for the owner. So "not a collaborator" arrives here as
 * an answered denial rather than as a 404, and the callers can rely on the
 * distinction meaning what it says.
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
      return { answered: false, role: null, outcome: `HTTP ${res.status} — not visible to the bot` };
    }
    return { answered: false, role: null, outcome: `HTTP ${res.status}` };
  } catch (e) {
    return { answered: false, role: null, outcome: `request failed: ${e.message}` };
  }
}

/** The two roles that count as control of a repository, in either question. */
export const CONTROL_ROLES = ["admin", "maintain"];

/** The strength order the methods are reported in. */
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

  // 1 ── ask GitHub who has admin or maintain.
  const asked = await collaboratorRole(repo, login, { token, fetchImpl: doFetch });
  let githubAnswered = false;
  if (asked.answered && CONTROL_ROLES.includes(asked.role)) {
    tried.push({ method: "collaborator-permission", outcome: asked.role });
    return {
      ok: true,
      method: "collaborator-permission",
      detail: `GitHub reports @${login} has \`${asked.role}\` on ${repo}`,
      tried,
    };
  }
  if (asked.answered) {
    // **A 200 is a denial, and a denial ends it.** The fallbacks exist for the
    // case where GitHub will not say; they are not a second opinion on an
    // answer GitHub gave.
    githubAnswered = true;
    tried.push({ method: "collaborator-permission", outcome: asked.outcome });
    return {
      ok: false,
      method: null,
      detail:
        `GitHub reports @${login} has \`${asked.role}\` on ${repo}, which is neither ` +
        "`admin` nor `maintain`. That is an answer, not a missing one, so the weaker checks " +
        "(`.well-known/astra-plugin-owner`, release author) are not consulted — neither of them " +
        "can outrank what GitHub just said.",
      tried,
    };
  }
  // No answer, not a denial: this endpoint is only fully visible to a caller
  // with admin on the repository. Reading it as "no" would refuse every
  // organisation that has not installed the registry's app.
  tried.push({ method: "collaborator-permission", outcome: asked.outcome });

  // 2 ── the file, on the default branch, read now.
  try {
    const url = `${API}/repos/${repo}/contents/.well-known/astra-plugin-owner`;
    const res = await doFetch(url, { headers: { ...headers(token), Accept: "application/vnd.github.raw+json" } });
    if (res.ok) {
      const text = await res.text();
      // Capped before parsing: this is a stranger's file and the only thing
      // wanted out of it is a short list of logins.
      const logins = text
        .slice(0, 4096)
        .split("\n")
        .map((l) => l.split("#")[0].trim().replace(/^@/, "").toLowerCase())
        .filter(Boolean);
      if (logins.includes(login.toLowerCase())) {
        tried.push({ method: "well-known", outcome: "lists the submitter" });
        return {
          ok: true,
          method: "well-known",
          detail: `\`.well-known/astra-plugin-owner\` on ${repo}'s default branch lists @${login}`,
          tried,
        };
      }
      tried.push({ method: "well-known", outcome: `present, lists ${logins.length} login(s), not @${login}` });
    } else {
      tried.push({ method: "well-known", outcome: `HTTP ${res.status}` });
    }
  } catch (e) {
    tried.push({ method: "well-known", outcome: `request failed: ${e.message}` });
  }

  // 3 ── who published the release whose bytes are being listed.
  if (releaseAuthor && releaseAuthor.toLowerCase() === login.toLowerCase()) {
    // `githubAnswered` is unreachable here today — a 200 returns above — but it
    // is asserted rather than assumed, so a later edit that softens the return
    // does not silently re-open the override.
    if (githubAnswered) {
      tried.push({ method: "release-author", outcome: "not consulted: GitHub already answered" });
    } else {
      const ageDays = releaseAgeDays(releasePublishedAt, now);
      if (ageDays === null) {
        tried.push({ method: "release-author", outcome: "matches, but the release carries no publication date" });
      } else if (ageDays > RELEASE_AUTHOR_MAX_AGE_DAYS) {
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
    }
  } else {
    tried.push({
      method: "release-author",
      outcome: releaseAuthor ? `the release was published by @${releaseAuthor}` : "unknown",
    });
  }

  return {
    ok: false,
    method: null,
    detail:
      `nothing proves @${login} controls ${repo}. ` +
      tried.map((t) => `${t.method}: ${t.outcome}`).join("; "),
    tried,
  };
}
