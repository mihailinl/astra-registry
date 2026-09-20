// The GitHub reads the bot needs, and nothing else.
//
// Every one is unauthenticated-capable: a public release is public. A token,
// when GITHUB_TOKEN is set, buys rate limit and nothing more — the bot never
// needs write access to anything, which is deliberate. A registry bot that can
// push is a registry bot whose compromise is a supply-chain event.
//
// ── the by-id reads (registry plan B-T1.3; BOT-21, ID-22, ID-63, MIG-31) ───
//
// The second half of this file reads GitHub **by repository id**, not by name.
// A name is a string its owner can give away: `astra-chess` was released from
// `KNICE-TECH/astra-chess`, the organisation renamed itself to `MINICE-AI`,
// and the old login became registrable by anybody. An id cannot be handed to a
// stranger, so it is the anchor every identity comparison uses and a name is
// only ever a label printed beside one.
//
// **Three answers, never two.** `found`, `not_found` and `transient`. A caller
// maps `transient` to `W_GITHUB_RATE_LIMITED` and waits; it must never map it
// to absence, because "GitHub did not answer" and "the thing is not there" are
// the two facts a rate limit is most likely to make look identical — and the
// second one ends a listing.
//
// **Measured against the live API on 2026-09-19** (unauthenticated, one
// request each), because every endpoint shape below is otherwise a claim:
//
//   * `GET /repositories/{id}` → 200, and `/repositories/{id}/commits/{sha}`,
//     `/repositories/{id}/contents/{path}?ref=`, `/repositories/{id}/commits?
//     sha=&path=`, `/repositories/{id}/commits/{sha}/pulls` and
//     `/repositories/{id}/actions/runs/{run_id}` all answer 200 too. The
//     by-id form is not documented for every sub-path; it works, and it is
//     what these functions use, so nothing here has to spend a name lookup to
//     ask a question about an id.
//   * a renamed repository answers `GET /repos/KNICE-TECH/astra-chess` with
//     **301 and `location: https://api.github.com/repositories/1343092393`** —
//     the id is in the redirect itself, and the followed body gives
//     `full_name: MINICE-AI/astra-chess`. That is how `fetchRepositoryIds`
//     learns the current name of a listing whose `source.repo` is stale, and
//     it is also why the redirect is followed HERE rather than left to
//     `fetch`: the bot has to be able to say that a rename happened.
//
// **A network failure was not measured** and its signature is not asserted
// anywhere in this file (B-T1.2 could not induce one through gh's own flags).
// Anything that is not an HTTP answer is `transient` by construction — a
// thrown request is a read that did not happen.

const API = "https://api.github.com";

function headers() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-registry-bot",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/**
 * Headers for a RELEASE ASSET, which carry no token — deliberately.
 *
 * `github.com/<repo>/releases/download/<tag>/<file>` is a redirect to a
 * PRE-SIGNED URL on `objects.githubusercontent.com`, and that host refuses a
 * request that also carries an `Authorization` header:
 *
 *     anonymous HEAD  -> 200
 *     same HEAD + Bearer -> 401
 *
 * `fetch(…, { redirect: "follow" })` carries request headers across the hop, so
 * attaching a token to the github.com URL attaches it to the signed one. Every
 * asset came back `E_ASSET_HEAD_FAILED: HTTP 401`, and since the digest cannot
 * be computed without the bytes, no plugin could be listed at all.
 *
 * The code this replaces was guarding the opposite risk — do not leak the token
 * to a host that is not GitHub — and kept the header for `github.com` for
 * exactly that reason. The leak it prevented is real; it just also has to not
 * send the token to the GitHub host that will not take it.
 *
 * Sending nothing settles both. A listed repository is public by policy
 * (POLICY.md §1), so its assets need no credential, and a token that is never
 * attached cannot travel down a redirect chain. Rate limit is unaffected: the
 * release API call above still authenticates, and asset hosts do not share the
 * API's budget.
 */
function assetHeaders() {
  return { "User-Agent": "astra-registry-bot" };
}

/** @returns {Promise<{tag_name: string, html_url: string, published_at: string, target_commitish: string, assets: {name: string, size: number, browser_download_url: string}[]}>} */
export async function fetchRelease(repo, tag) {
  const url = `${API}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
  const res = await fetch(url, { headers: headers() });
  if (res.status === 404) {
    throw new Error(`no release tagged ${tag} in ${repo} (404)`);
  }
  if (!res.ok) {
    throw new Error(`GitHub returned HTTP ${res.status} for ${url}`);
  }
  return res.json();
}

/**
 * Download a release asset.
 *
 * The URL is the one recorded in the LISTING, not one discovered from the API
 * response: the listing's URL is what a user's daemon will fetch, so it is the
 * one whose bytes have to be checked. Capped, because an unbounded download
 * driven by a stranger's release is a denial-of-service primitive.
 *
 * The token goes to GitHub or nowhere. `headers()` attaches
 * `Authorization: Bearer $GITHUB_TOKEN` whenever the environment has one, and
 * the URL here comes out of a LISTING — a string a submitter wrote. A listing
 * can now name a non-GitHub origin (`release.kind: "direct"`, for a self-hosted
 * or staging catalogue), so an unconditional header would mail the bot's
 * credential to whatever host a pull request typed. Exact host match, never a
 * suffix: `evil-github.com` and `github.com.attacker.net` both fail it.
 */
/**
 * Ask about an asset without fetching it.
 *
 * Two things worth knowing before a byte is spent: what the origin claims the
 * size is (so a 4 GB "plugin" is refused for the cost of one request rather
 * than one download), and where the redirect chain ends up — GitHub serves
 * release assets from `objects.githubusercontent.com`, and a chain that leaves
 * that namespace is a chain that leaves the repository the listing pins.
 *
 * Every hop is required to be https. `fetch` will happily follow an
 * https→http downgrade, and the daemon's own download policy refuses one; a
 * registry that verified bytes fetched over a downgrade would be verifying
 * bytes a user's machine will never accept.
 *
 * @param {string} url
 * @param {typeof fetch} [fetchImpl]
 */
export async function headAsset(url, fetchImpl = fetch) {
  const res = await fetchImpl(url, { method: "HEAD", headers: assetHeaders(), redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status} for HEAD ${url}`);
  if (!String(res.url || url).startsWith("https://")) {
    throw new Error(`the redirect chain left https: ${res.url}`);
  }
  return {
    size: Number(res.headers.get("content-length") ?? "0"),
    finalUrl: res.url || url,
    etag: res.headers.get("etag"),
  };
}

export async function downloadAsset(url, maxBytes, fetchImpl = fetch) {
  const res = await fetchImpl(url, { headers: assetHeaders(), redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  if (!res.url.startsWith("https://")) throw new Error(`redirected off https: ${res.url}`);
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error(`asset declares ${declared} bytes, over the ${maxBytes} cap`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error(`asset is ${buf.length} bytes, over the ${maxBytes} cap`);
  return buf;
}

// ── the by-id reads ─────────────────────────────────────────────────────────

const BASE10_RE = /^[0-9]+$/;

/**
 * One GitHub read, classified.
 *
 * `status` is `found`, `not_found` or `transient`, and `reason` says which
 * evidence produced it, so an alert names something a person can check.
 *
 * A 403 or 429 is `transient` whether or not it carries rate-limit headers.
 * The two shapes are told apart in `reason` — the plan names "403 with
 * rate-limit headers" — but neither is ever absence: a repository the bot may
 * not read and a repository that does not exist are different facts, and
 * calling the first one absence is how a rate limit deletes a listing.
 *
 * @param {string} url
 * @param {{fetchImpl?: typeof fetch, accept?: string, maxHops?: number}} opts
 * @returns {Promise<{status: string, reason: string, res?: object, raw?: string,
 *   parsed?: any, url?: string, redirected?: boolean, location?: string|null}>}
 */
async function read(url, { fetchImpl = fetch, accept = null, maxHops = 3 } = {}) {
  let current = url;
  let redirected = false;
  let location = null;

  for (let hop = 0; hop <= maxHops; hop++) {
    let res;
    try {
      const h = headers();
      if (accept) h.Accept = accept;
      // `manual`, so that a rename is something this file OBSERVES rather than
      // something `fetch` quietly smooths over. A caller has to be able to say
      // "the name you gave me is not the name GitHub uses now".
      res = await fetchImpl(current, { headers: h, redirect: "manual" });
    } catch (e) {
      return { status: "transient", reason: `the request did not complete: ${e.message}`, url: current };
    }

    if (res.status === 301 || res.status === 302 || res.status === 307 || res.status === 308) {
      location = res.headers?.get?.("location") ?? null;
      if (!location) {
        return { status: "transient", reason: `HTTP ${res.status} with no Location`, url: current, res };
      }
      if (!location.startsWith(`${API}/`)) {
        // A redirect off api.github.com is not a redirect this bot follows.
        return { status: "transient", reason: `HTTP ${res.status} left the API host: ${location}`, url: current, res };
      }
      current = location;
      redirected = true;
      continue;
    }

    if (res.status === 404) {
      return { status: "not_found", reason: "HTTP 404", url: current, res, redirected, location };
    }
    if (res.status === 403 || res.status === 429) {
      const remaining = res.headers?.get?.("x-ratelimit-remaining");
      const retry = res.headers?.get?.("retry-after");
      const limited = remaining === "0" || retry !== null;
      return {
        status: "transient",
        reason: limited
          ? `HTTP ${res.status} with rate-limit headers (x-ratelimit-remaining ${remaining ?? "-"}, retry-after ${retry ?? "-"})`
          : `HTTP ${res.status} without rate-limit headers — refused, which is not absence`,
        url: current, res, redirected, location,
      };
    }
    if (res.status >= 500) {
      return { status: "transient", reason: `HTTP ${res.status}`, url: current, res, redirected, location };
    }
    if (!res.ok) {
      return { status: "transient", reason: `unexpected HTTP ${res.status}`, url: current, res, redirected, location };
    }

    const raw = await res.text();
    if (accept && !accept.includes("json")) {
      return { status: "found", reason: `HTTP ${res.status}`, raw, url: current, res, redirected, location };
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      // A 200 whose body is not the shape we know is not a fact about the
      // world. Waiting is the only safe reading of it.
      return { status: "transient", reason: `HTTP 200 with a body that is not JSON: ${e.message}`, url: current, res };
    }
    return { status: "found", reason: `HTTP ${res.status}`, raw, parsed, url: current, res, redirected, location };
  }
  return { status: "transient", reason: `more than ${maxHops} redirects`, url: current };
}

/**
 * A base-10 id read out of the RAW body, not out of `JSON.parse`'s number.
 *
 * `JSON.parse('{"id":9007199254740993}')` yields `9007199254740992`, and
 * `String()` on that produces digits that name a different repository while
 * looking exactly as trustworthy. Ids past 2^53 are not hypothetical for a
 * platform that has been minting them for eighteen years, and SCOPE-5 makes
 * every id a base-10 STRING for this reason. So the digits come from the text
 * and the parse is used only for structure; when the two disagree, the text
 * wins and `precision_lost` says so.
 *
 * @param {string} raw the response body
 * @param {{after?: string}} opts `after` scopes the search past a key, which
 *   is how the owner's id is told from the repository's.
 */
export function idDigits(raw, { after = null } = {}) {
  let text = raw;
  if (after) {
    const i = raw.indexOf(after);
    if (i < 0) return null;
    text = raw.slice(i + after.length);
  }
  const m = /"id"\s*:\s*(\d+)/.exec(text);
  return m ? m[1] : null;
}

function idField(raw, parsedValue, { after = null } = {}) {
  const digits = idDigits(raw, { after });
  if (digits === null) return { id: null, precision_lost: false };
  const fromParse = typeof parsedValue === "number" ? String(parsedValue) : null;
  return { id: digits, precision_lost: fromParse !== null && fromParse !== digits };
}

/**
 * The ids of a repository named by `owner/name`, following a rename.
 *
 * This is BOT-21's anchor: the id of the repository the assets came from. The
 * name is returned beside it as a LABEL — `full_name` is what GitHub calls the
 * repository today, which is not necessarily what the listing or the
 * certificate calls it. (`astra-chess`: certificate `.12` says
 * `KNICE-TECH/astra-chess`, id `1343092393`, and GitHub answers
 * `MINICE-AI/astra-chess` for that id.)
 *
 * @param {string} fullName `owner/name`
 * @returns {Promise<{status: string, reason: string, id: string|null,
 *   owner_id: string|null, full_name: string|null, renamed: boolean}>}
 */
export async function fetchRepositoryIds(fullName, { fetchImpl = fetch } = {}) {
  const answer = await read(`${API}/repos/${fullName}`, { fetchImpl });
  if (answer.status !== "found") {
    return { status: answer.status, reason: answer.reason, id: null, owner_id: null, full_name: null, renamed: false };
  }
  const repo = idField(answer.raw, answer.parsed?.id);
  const owner = idField(answer.raw, answer.parsed?.owner?.id, { after: '"owner"' });
  const full = typeof answer.parsed?.full_name === "string" ? answer.parsed.full_name : null;
  if (!repo.id || !owner.id || !full) {
    return {
      status: "transient",
      reason: "HTTP 200 without an id, an owner id or a full_name — not a shape this bot can read",
      id: null, owner_id: null, full_name: null, renamed: false,
    };
  }
  return {
    status: "found",
    reason: answer.reason + (repo.precision_lost || owner.precision_lost
      ? "; the id exceeded 2^53 and was taken from the response text rather than from JSON.parse"
      : ""),
    id: repo.id,
    owner_id: owner.id,
    full_name: full,
    // Either GitHub redirected us, or it answered under a different name.
    renamed: Boolean(answer.redirected) || full.toLowerCase() !== fullName.toLowerCase(),
  };
}

/** Is `sha` a commit of the repository with this id? (ID-22's precondition.) */
export async function commitInRepository(repositoryId, sha, { fetchImpl = fetch } = {}) {
  if (!BASE10_RE.test(String(repositoryId))) {
    return { status: "transient", reason: `${JSON.stringify(repositoryId)} is not a repository id` };
  }
  const answer = await read(`${API}/repositories/${repositoryId}/commits/${sha}`, { fetchImpl });
  return { status: answer.status, reason: answer.reason, sha: answer.status === "found" ? sha : null };
}

/**
 * A file at one commit, raw, by repository id (ID-22: at the ATTESTED commit,
 * never at the default branch — deleting a line from `main` ends nothing).
 */
export async function fileAtCommit(repositoryId, sha, filePath, { fetchImpl = fetch } = {}) {
  if (!BASE10_RE.test(String(repositoryId))) {
    return { status: "transient", reason: `${JSON.stringify(repositoryId)} is not a repository id`, content: null };
  }
  const url = `${API}/repositories/${repositoryId}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}` +
    `?ref=${encodeURIComponent(sha)}`;
  const answer = await read(url, { fetchImpl, accept: "application/vnd.github.raw" });
  return { status: answer.status, reason: answer.reason, content: answer.status === "found" ? answer.raw : null };
}

/**
 * The account that started a workflow run, for MIG-31's comparison with `.17`.
 *
 * The run is named by `.21`'s URI, which carries the repository's NAME; the
 * id form (`/repositories/{id}/actions/runs/{run_id}`) answers too and is
 * used whenever the caller has an id, so the read is anchored to the same
 * thing every other identity read is.
 */
export async function workflowRun(repo, runId, { fetchImpl = fetch } = {}) {
  const base = BASE10_RE.test(String(repo)) ? `${API}/repositories/${repo}` : `${API}/repos/${repo}`;
  const answer = await read(`${base}/actions/runs/${runId}`, { fetchImpl });
  if (answer.status !== "found") {
    return { status: answer.status, reason: answer.reason, triggering_actor_id: null };
  }
  const actor = idField(answer.raw, answer.parsed?.triggering_actor?.id, { after: '"triggering_actor"' });
  if (!actor.id) {
    return { status: "transient", reason: "HTTP 200 with no triggering_actor id", triggering_actor_id: null };
  }
  return { status: "found", reason: answer.reason, triggering_actor_id: actor.id };
}

/**
 * The newest commit touching `filePath` up to `sha` — ID-63's first field.
 *
 * `found` with a null commit is a real answer: the path has no history up to
 * that commit. It is NOT `not_found`, which is reserved for the repository or
 * the ref being absent, because the two lead to different decisions.
 */
export async function lastCommitTouching(repositoryId, sha, filePath, { fetchImpl = fetch } = {}) {
  if (!BASE10_RE.test(String(repositoryId))) {
    return { status: "transient", reason: `${JSON.stringify(repositoryId)} is not a repository id`, commit: null };
  }
  const url = `${API}/repositories/${repositoryId}/commits` +
    `?sha=${encodeURIComponent(sha)}&path=${encodeURIComponent(filePath)}&per_page=1`;
  const answer = await read(url, { fetchImpl });
  if (answer.status !== "found") return { status: answer.status, reason: answer.reason, commit: null };
  const list = Array.isArray(answer.parsed) ? answer.parsed : [];
  return {
    status: "found",
    reason: answer.reason,
    commit: typeof list[0]?.sha === "string" ? list[0].sha : null,
  };
}

/**
 * Does GitHub tie this commit to a pull request? — ID-63's second field.
 *
 * `pull_request: false` is an answer; `transient` is not one. A caller that
 * reported "no pull request" after a rate-limited read would be recording, in
 * a decision record that outlives everybody, the absence of something it never
 * looked for.
 */
export async function pullsForCommit(repositoryId, sha, { fetchImpl = fetch } = {}) {
  if (!BASE10_RE.test(String(repositoryId))) {
    return { status: "transient", reason: `${JSON.stringify(repositoryId)} is not a repository id`, pulls: null };
  }
  const answer = await read(
    `${API}/repositories/${repositoryId}/commits/${sha}/pulls`,
    { fetchImpl, accept: "application/vnd.github+json" },
  );
  if (answer.status !== "found") return { status: answer.status, reason: answer.reason, pulls: null };
  const list = Array.isArray(answer.parsed) ? answer.parsed : [];
  return {
    status: "found",
    reason: answer.reason,
    pulls: list.map((p) => p?.number).filter((n) => Number.isInteger(n)),
  };
}
