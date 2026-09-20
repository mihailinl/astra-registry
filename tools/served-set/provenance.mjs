// SERVE-90's fallback: proving that every commit on `signed` was pushed by a
// signer run, when a ruleset cannot say so (registry plan RC-R1-5, RC-R0-2(c)).
//
// **A `Run:` trailer is a line of text.** Anybody who can push to `signed` can
// copy the trailers off a real commit — Source-Commit, Run, Signer, all four —
// onto a commit of their own, and every document in it can be a real signed
// document lifted from the branch's own history. Nothing in D2's shape
// distinguishes that from a signer run. So the trailer is a POINTER and the
// proof is what it points at:
//
//   1. the run is a run of `.github/workflows/sign.yml`, in this repository,
//      from `main`, on an event that can legitimately start the signer;
//   2. it carries the artifact `signed-commit-<this commit's sha>`, which only
//      a run that had already made this commit could have uploaded (D2's
//      receipt). This is the step a copied trailer cannot pass: the artifact
//      names the commit, so a trailer copied from another commit's run points
//      at a run holding somebody else's receipt;
//   3. the Source-Commit it claims is one that run could have read — equal to
//      or a descendant of the run's own `head_sha`;
//   4. that Source-Commit is reachable from `main`, so the bytes were signed
//      over a tree that exists in public history and not over a branch that
//      was deleted afterwards;
//   5. no other `signed` commit cites the same run. One run makes at most one
//      commit; two commits naming one run means one of them was made by
//      something else.
//
// ── the two scopes, which are not the same scope ───────────────────────────
//
// Checks 1 to 4 run over the commits RC-R1-5 names: every `signed` commit
// younger than 7 days, and always the head. Check 5 is over the WHOLE branch,
// and that difference is the check. A forged commit's cheapest disguise is a
// run URL copied from a commit outside the window — old enough that nothing
// re-examines it, real enough to resolve. Scoping the duplicate check to the
// window would have made the older half of the branch a supply of valid-looking
// trailers.
//
// ── what the 7 days are about ──────────────────────────────────────────────
//
// Artifacts expire. A receipt for a commit made a year ago is gone, and a
// check that demanded one would be permanently red about history nobody can
// re-attest. The head is always checked because the head is what is served:
// if it is old enough for its receipt to have expired, the signer has been
// dead for months and red is the right answer — the message says so rather
// than blaming the receipt.

import { finding, verdict } from "./report.mjs";
import { gitMaybe, gitText } from "../signer/git.mjs";
// One string, two questions, and they fail in opposite ways — which is the
// whole argument for one string. Here it decides whether a run is the signer's;
// in main-vs-signed.mjs its presence on `main` is what arms the missing-branch
// failure. Kept separately, a signer that lands at another path would make
// this one refuse every commit LOUDLY and make that one wait for ever
// SILENTLY, and the silent half is the one nobody would go looking for.
import { SIGNER_WORKFLOW } from "./main-vs-signed.mjs";

/** RC-R1-5's window: every `signed` commit younger than this, and always the head. */
export const PROVENANCE_WINDOW_DAYS = 7;

/**
 * The events that can legitimately start the signer (D1's triggers).
 *
 * `workflow_run` is here because the signer runs on the completion of every
 * committing workflow. What is NOT here is the point: `pull_request`,
 * `issue_comment`, `repository_dispatch` — anything a stranger or a fork can
 * cause — and `dynamic`, which is what GitHub reports for a run started by
 * something else's API call.
 */
export const SIGNER_EVENTS = ["push", "workflow_run", "schedule", "workflow_dispatch"];

/** `https://github.com/<owner>/<repo>/actions/runs/<id>`, with an optional job suffix. */
const RUN_URL_RE =
  /^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100})\/actions\/runs\/([0-9]{1,20})(?:\/job\/[0-9]{1,20})?$/;

/** @returns {{repo: string, run_id: string}|null} */
export function parseRunUrl(url) {
  const m = RUN_URL_RE.exec(String(url ?? "").trim());
  return m ? { repo: m[1], run_id: m[2] } : null;
}

/**
 * D2's receipt, by name.
 *
 * One function so the signer, this check and anybody reading a run's artifact
 * list spell it one way. A check looking for `signed-commit-<sha>` while the
 * signer uploaded `signed_commit_<sha>` is a check that fails every run, is
 * read as noise, and is switched off.
 */
export const receiptName = (sha) => `signed-commit-${sha}`;

/**
 * The trailers of one commit message.
 *
 * The LAST occurrence of each key wins, because trailers live at the end and a
 * commit subject is free text that can contain a colon. This is not a security
 * boundary — nothing below trusts a trailer, it only follows it — so a message
 * that confuses the parse costs its author a red run and nothing else.
 */
export function trailersOf(body) {
  const out = {};
  for (const line of String(body).split("\n")) {
    const m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]*(\S.*)$/.exec(line.trim());
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

// ASCII unit and record separators, written as escapes: neither can appear
// in a sha or an RFC 3339 time, and a commit message carrying one would only
// split its own trailers. A newline delimiter would be wrong here — the body
// IS newlines.
const UNIT = "\u001f";
const RECORD = "\u001e";

/**
 * Every commit on `signed`, newest first, with its trailers.
 *
 * @param {{root: string, ref: string, limit?: number}} opts
 */
export function signedCommits({ root, ref, limit = 2000 }) {
  const out = gitText(["log", `--max-count=${limit}`, `--format=%H${UNIT}%cI${UNIT}%B${RECORD}`, ref], { root });
  return out
    .split(RECORD)
    .map((r) => r.trim())
    .filter(Boolean)
    .map((record) => {
      const [sha, committed_at, ...rest] = record.split(UNIT);
      return { sha: sha.trim(), committed_at: committed_at.trim(), trailers: trailersOf(rest.join(UNIT)) };
    });
}

/**
 * SERVE-90's decision, over facts and nothing else.
 *
 * @param {object} o
 * Every input is a value, the API answers included: `runs` is a Map that
 * `check.mjs` has already filled in. This function makes no call and awaits
 * nothing, so the suite can put a forged branch in front of it without a
 * server, which is the only way the five canaries below can be watched
 * failing at all.
 *
 * @param {object} o
 * @param {object[]} o.commits    from signedCommits, newest first, the WHOLE branch
 * @param {string} o.repo         `owner/name` of this repository
 * @param {Map<string, object>} o.runs  run id → `{ok, path, head_branch, event, head_sha, artifacts}`
 * @param {(sha: string) => boolean} o.reachableFromMain
 * @param {(ancestor: string, descendant: string) => boolean} o.descendsFrom
 * @param {string} o.now
 * @param {number} [o.windowDays]
 */
export function provenance({
  commits,
  repo,
  runs,
  reachableFromMain,
  descendsFrom,
  now,
  windowDays = PROVENANCE_WINDOW_DAYS,
}) {
  const findings = [];
  const notes = [];
  const hexes = [];

  if (!commits.length) return verdict({ findings, notes: ["`signed` has no commits"], hexes });

  // Check 5's index, over the whole branch. Built first, and from every commit,
  // for the reason in the header.
  const citedBy = new Map();
  for (const c of commits) {
    const ref = parseRunUrl(c.trailers.Run);
    if (!ref) continue;
    const key = `${ref.repo}#${ref.run_id}`;
    if (!citedBy.has(key)) citedBy.set(key, []);
    citedBy.get(key).push(c.sha);
  }

  const cutoff = Date.parse(now) - windowDays * 86400 * 1000;
  const inScope = commits.filter((c, i) => i === 0 || Date.parse(c.committed_at) >= cutoff);
  notes.push(
    `${inScope.length} of ${commits.length} \`signed\` commits are in scope: the head, and every commit younger ` +
    `than ${windowDays} days`,
  );

  for (const commit of inScope) {
    const short = commit.sha.slice(0, 12);
    hexes.push(commit.sha);

    const ref = parseRunUrl(commit.trailers.Run);
    if (!ref) {
      findings.push(finding(
        "SERVE_90_NO_RUN_TRAILER",
        `\`signed\` commit ${short} carries no usable \`Run:\` trailer (${JSON.stringify(commit.trailers.Run ?? null)}). ` +
        `Only a signer run may write this branch (D1), and a commit that does not say which run made it cannot be ` +
        `shown to be one.`,
      ));
      continue;
    }
    if (ref.repo !== repo) {
      findings.push(finding(
        "SERVE_90_RUN_NOT_A_SIGNER_RUN",
        `\`signed\` commit ${short} cites a run in ${ref.repo}, not in ${repo}. A run in another repository — a ` +
        `fork's, most cheaply — proves nothing about who wrote here.`,
      ));
      continue;
    }

    const duplicates = (citedBy.get(`${ref.repo}#${ref.run_id}`) ?? []).filter((s) => s !== commit.sha);
    if (duplicates.length) {
      findings.push(finding(
        "SERVE_90_RUN_CITED_TWICE",
        `\`signed\` commit ${short} cites run ${ref.run_id}, and so does ${duplicates.map((s) => s.slice(0, 12)).join(", ")}. ` +
        `One run makes at most one commit, so at least one of these was made by something that is not a signer run.`,
      ));
      // Not `continue`: a copied trailer should also fail the receipt check
      // below, and a reader who sees only one of the two findings learns less
      // about which commit is the forged one.
    }

    const run = runs?.get(ref.run_id);
    if (!run?.ok) {
      findings.push(finding(
        "SERVE_90_RUN_NOT_A_SIGNER_RUN",
        `\`signed\` commit ${short} cites run ${ref.run_id} and it could not be read: ${run?.error ?? "no answer"}. ` +
        `A trailer pointing at a run that does not exist is a trailer somebody typed.`,
      ));
      continue;
    }
    const wrong = [];
    if (run.path !== SIGNER_WORKFLOW) wrong.push(`it is a run of ${run.path}, not ${SIGNER_WORKFLOW}`);
    if (run.head_branch !== "main") wrong.push(`its head_branch is ${JSON.stringify(run.head_branch)}, not "main"`);
    if (!SIGNER_EVENTS.includes(run.event)) {
      wrong.push(`its event is ${JSON.stringify(run.event)}, which is not one the signer runs on (${SIGNER_EVENTS.join(", ")})`);
    }
    if (wrong.length) {
      findings.push(finding(
        "SERVE_90_RUN_NOT_A_SIGNER_RUN",
        `\`signed\` commit ${short} cites run ${ref.run_id} and ${wrong.join("; ")}.`,
      ));
      continue;
    }

    const receipt = receiptName(commit.sha);
    if (!run.artifacts?.includes(receipt)) {
      findings.push(finding(
        "SERVE_90_NO_RECEIPT",
        `run ${ref.run_id} carries no artifact ${receipt}, so it did not make \`signed\` commit ${short} ` +
        `(it holds: ${run.artifacts?.join(", ") || "nothing"}). A \`Run:\` trailer can be copied onto a ` +
        `hand-pushed commit; the receipt names the commit and cannot. If this commit is older than the ` +
        `repository's artifact retention, the receipt has expired — which for the head means the signer has not ` +
        `run in months.`,
      ));
      continue;
    }

    const source = commit.trailers["Source-Commit"];
    if (!/^[0-9a-f]{40}$/.test(String(source ?? ""))) {
      findings.push(finding(
        "SERVE_90_SOURCE_COMMIT_UNREACHABLE",
        `\`signed\` commit ${short} has no 40-hex \`Source-Commit\` trailer (${JSON.stringify(source ?? null)}), ` +
        `so there is no tree its documents can be said to have been signed over.`,
      ));
      continue;
    }
    if (!(source === run.head_sha || descendsFrom(run.head_sha, source))) {
      findings.push(finding(
        "SERVE_90_SOURCE_COMMIT_NOT_DESCENDANT",
        `\`signed\` commit ${short} claims Source-Commit ${source.slice(0, 12)}, which is neither run ` +
        `${ref.run_id}'s own head ${String(run.head_sha).slice(0, 12)} nor a descendant of it. That run could not ` +
        `have read the tree this commit says it signed.`,
      ));
      continue;
    }
    if (!reachableFromMain(source)) {
      findings.push(finding(
        "SERVE_90_SOURCE_COMMIT_UNREACHABLE",
        `\`signed\` commit ${short} claims Source-Commit ${source.slice(0, 12)}, which is not reachable from ` +
        `\`main\`. The bytes served to every client were signed over a tree that is not in public history.`,
      ));
    }
  }

  return verdict({ findings, notes, hexes });
}

/**
 * Which runs `provenance` will ask about, so `check.mjs` can resolve them
 * before calling it. The same scope rule, in one place, rather than a second
 * copy of "the head and every commit younger than 7 days" that can drift from
 * the first.
 */
export function runsInScope({ commits, repo, now, windowDays = PROVENANCE_WINDOW_DAYS }) {
  const cutoff = Date.parse(now) - windowDays * 86400 * 1000;
  const ids = new Set();
  commits
    .filter((c, i) => i === 0 || Date.parse(c.committed_at) >= cutoff)
    .forEach((c) => {
      const ref = parseRunUrl(c.trailers.Run);
      if (ref && ref.repo === repo) ids.add(ref.run_id);
    });
  return [...ids];
}

/** `git merge-base --is-ancestor`, as a predicate rather than an exit status. */
export function gitAncestry({ root }) {
  const isAncestor = (ancestor, descendant) =>
    gitMaybe(["merge-base", "--is-ancestor", ancestor, descendant], { root }).ok;
  return {
    descendsFrom: (ancestor, descendant) => ancestor !== descendant && isAncestor(ancestor, descendant),
    reachableFrom: (sha, ref) => isAncestor(sha, ref),
  };
}

/**
 * The Actions API, as the one thing `provenance` cannot decide for itself.
 *
 * Two calls per run, memoised, because a branch with twenty commits in the
 * window would otherwise ask about the same run twenty times. A failure is an
 * answer — `{ok: false}` with the reason — and never an exception: one
 * unreachable run must not stop the other nineteen commits being checked.
 *
 * @param {{repo: string, token: string, api?: string, fetchImpl?: typeof fetch}} opts
 */
export function actionsRunLookup({ repo, token, api = "https://api.github.com", fetchImpl = fetch }) {
  const cache = new Map();
  const get = async (url) => {
    const res = await fetchImpl(url, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "astra-registry-served-set",
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url.replace(api, "")}`);
    return res.json();
  };
  return async function lookupRun(runId) {
    if (cache.has(runId)) return cache.get(runId);
    let answer;
    try {
      const run = await get(`${api}/repos/${repo}/actions/runs/${runId}`);
      const arts = await get(`${api}/repos/${repo}/actions/runs/${runId}/artifacts?per_page=100`);
      answer = {
        ok: true,
        path: run.path,
        head_branch: run.head_branch,
        event: run.event,
        head_sha: run.head_sha,
        artifacts: (arts.artifacts ?? []).map((a) => a.name),
      };
    } catch (e) {
      answer = { ok: false, error: String(e?.message ?? e) };
    }
    cache.set(runId, answer);
    return answer;
  };
}
