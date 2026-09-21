// One bot OIDC token, minted for one call, masked before anything can print it.
//
//     node bot/lib/oidc.mjs --claims     print what OPEN-OPS-13 measures
//
// Registry plan B-T2.5 (BOT-3, BOT-20, DEC-4); contract ID-33, ID-34, §2.5.
// Nothing here is wired into a workflow yet: `plugins-ingest.yml`'s `claim`
// step still exits 1 naming this task, and it goes live at R3 (B-T5.1). This
// module is written dark so that the step, when it lands, is three lines.
//
// ── the three rules, and why each one is here rather than in the caller ────
//
// **One token per call (BOT-3).** Contract ID-33 refuses a `jti` the service
// has already seen, so a token is a single use. That makes "mint once per run
// and reuse" not a shortcut but a self-inflicted `replay`, which BOT-63 turns
// into a failed run with an operator alert. `mintToken` therefore takes no
// cache and offers no way to hold a token: every call to it is a round trip to
// the Actions token endpoint, and `bot/lib/service.mjs` calls it once per
// ATTEMPT, not once per call — a retry that re-sent the first attempt's token
// would be refused as the replay it is.
//
// **The mask precedes first use.** The runner's logs are public. `::add-mask::`
// is emitted the instant the token is in this process, BEFORE the claim checks
// below, because a claim check that throws would otherwise print a stack trace
// through a log the token has not been registered with yet. The test pins the
// ORDER — mask line, then the first request carrying an `Authorization` header
// — rather than the presence of the line, because presence is what a masked-
// too-late token also has.
//
// **It refuses to run outside `environment: plugins-service`.** GitHub exposes
// no environment name to a step, so the refusal cannot be a read of the
// runner's environment — it is a read of the TOKEN, whose `environment` claim
// carries the deployment environment the job declared. That is the same fact
// contract ID-34 pins at the far end, checked here before the token leaves this
// function rather than after it has been spent on a call the service will
// refuse. `aud` is checked the same way and for the same reason.
//
// Neither check is a verification. This process does not hold GitHub's keys and
// is not the party ID-34 addresses; it is reading a token it just minted for
// itself, to catch a job that was moved out of its environment or a caller that
// asked for the wrong audience. The service verifies. If these two ever
// disagree with it, the service's answer is the one that counts.

import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

/**
 * The bot audience, compiled in.
 *
 * Contract ID-34 and the token file's `audience:bot` entry. It is an opaque
 * string that does not move if the service API base moves, which is why it is
 * written here as a literal and not derived from `service.mjs`'s base — the two
 * look like the same string with a suffix and are two decisions.
 * `bot/tests/service.test.mjs` compares this value with the token file.
 */
export const BOT_AUDIENCE = "https://api.minice.ai/plugins/v1/bot";

/** The deployment environment a bot token may be minted in (contract ID-34). */
export const ENVIRONMENT = "plugins-service";

/** The two claims this side can check about its own token before spending it. */
export const PINNED_CLAIMS = Object.freeze({ aud: BOT_AUDIENCE, environment: ENVIRONMENT });

const MINT_TIMEOUT_MS = 20_000;

/**
 * The Actions token endpoint, as the runner hands it over.
 *
 * Both variables exist only in a job that declares `id-token: write`
 * (registry plan ID-38). Their absence is not a skip: a bot call that
 * proceeded without a token would reach the service unauthenticated, be
 * refused, and read in the log as a service fault.
 */
export const REQUEST_URL_VAR = "ACTIONS_ID_TOKEN_REQUEST_URL";
export const REQUEST_TOKEN_VAR = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/** @returns {string[]} one sentence per reason this job cannot mint a token */
export function mintProblems(env = process.env) {
  const problems = [];
  for (const name of [REQUEST_URL_VAR, REQUEST_TOKEN_VAR]) {
    const value = env[name];
    if (typeof value !== "string" || value.trim() === "") {
      problems.push(
        `${name} is not set in this job. The Actions token endpoint is exposed only to a job that declares ` +
        "`id-token: write` and names environment `plugins-service` (registry plan ID-38, BOT-1). Without it " +
        "there is no bot token, and a call made anyway reaches the service unauthenticated",
      );
    }
  }
  return problems;
}

/**
 * The payload of a JWT, decoded and not verified.
 *
 * Base64url with no padding, which `Buffer.from(…, "base64url")` handles, and
 * a payload that is not an object is a token this side will not reason about.
 */
export function decodeClaims(token) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) throw new Error(`the token has ${parts.length} dot-separated parts, not 3`);
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch (e) {
    throw new Error(`the token's payload is not JSON: ${String(e.message ?? e)}`);
  }
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("the token's payload is not a JSON object");
  }
  return claims;
}

/**
 * @returns {string[]} one sentence per pinned claim this token does not carry
 *
 * Exact equality, never a prefix or a `startsWith`: an audience that merely
 * begins with the bot audience is a different audience, and contract ID-34
 * says `aud` is exact.
 */
export function claimProblems(claims) {
  const problems = [];
  for (const [name, want] of Object.entries(PINNED_CLAIMS)) {
    const got = claims?.[name];
    if (got !== want) {
      problems.push(
        `the token's \`${name}\` is ${JSON.stringify(got ?? null)} and this bot only ever calls with ` +
        `${JSON.stringify(want)} (contract ID-34). ` +
        (name === "environment"
          ? "A job that mints a bot token runs in environment `plugins-service`; this one did not, and the " +
            "service would refuse the call with `token_refused`"
          : "The audience is compiled in and a call with any other is refused"),
      );
    }
  }
  return problems;
}

/**
 * Mint one bot OIDC token.
 *
 * The mask is emitted before the claim checks on purpose; see the header.
 * Nothing about the token is returned on failure — not a prefix, not a length
 * — because an error string is the one place a secret reliably escapes.
 *
 * @returns {Promise<{token: string, claims: object}>}
 */
export async function mintToken({
  env = process.env,
  fetchImpl = fetch,
  audience = BOT_AUDIENCE,
  log = console,
} = {}) {
  const problems = mintProblems(env);
  if (problems.length) throw new Error(problems.join("\n"));

  const url = `${env[REQUEST_URL_VAR]}&audience=${encodeURIComponent(audience)}`;
  let res;
  try {
    res = await fetchImpl(url, {
      headers: {
        Authorization: `Bearer ${env[REQUEST_TOKEN_VAR]}`,
        Accept: "application/json; api-version=2.0",
        "User-Agent": "astra-registry-bot",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(MINT_TIMEOUT_MS),
    });
  } catch (e) {
    throw new Error(`the Actions token endpoint could not be reached: ${String(e.message ?? e)}`);
  }
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`the Actions token endpoint answered HTTP ${res.status}, a redirect, which is never followed`);
  }
  if (!res.ok) throw new Error(`the Actions token endpoint answered HTTP ${res.status}`);

  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error("the Actions token endpoint answered 2xx with something that is not JSON");
  }
  const token = body?.value;
  if (typeof token !== "string" || token === "") {
    throw new Error("the Actions token endpoint answered 2xx with no `value`");
  }

  // Before anything else can print, throw or log.
  log.log(`::add-mask::${token}`);

  const claims = decodeClaims(token);
  const bad = claimProblems(claims);
  if (bad.length) throw new Error(bad.join("\n"));
  return { token, claims };
}

/**
 * OPEN-OPS-13's bot-token measurement, as a line a person can read out of a
 * public run log.
 *
 * `job_workflow_ref`, `run_id` and `run_attempt` with their JSON types —
 * contract §0.7 records the format from this measurement, and the expectation
 * on record is "canonical base-10 digit strings, like the ids", which only a
 * printed `typeof` can confirm or refute. `jti` appears as a 16-hex SHA-256
 * prefix and never as itself: ID-33's replay refusal keys on it, so a printed
 * `jti` is a printed replay key, and what the measurement needs of it is only
 * whether it differs across `run_attempt`, which a hash answers.
 *
 * The token never appears. Neither does any claim not named here.
 */
export function claimsReport(claims) {
  const jti = claims?.jti;
  const rows = [];
  for (const name of ["job_workflow_ref", "run_id", "run_attempt"]) {
    const value = claims?.[name];
    rows.push(`${name} = ${JSON.stringify(value ?? null)} (${value === undefined ? "absent" : typeof value})`);
  }
  rows.push(
    typeof jti === "string" && jti !== ""
      ? `jti sha256:${crypto.createHash("sha256").update(jti).digest("hex").slice(0, 16)} (${typeof jti})`
      : `jti = ${JSON.stringify(jti ?? null)} (${jti === undefined ? "absent" : typeof jti})`,
  );
  return rows;
}

/** `--claims`: mint one token and print only what `claimsReport` names. */
export async function runClaims({ env = process.env, fetchImpl = fetch, log = console } = {}) {
  const { claims } = await mintToken({ env, fetchImpl, log });
  for (const row of claimsReport(claims)) log.log(`claim ${row}`);
  return claims;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const mode = process.argv[2];
  if (mode !== "--claims") {
    console.error("usage: node bot/lib/oidc.mjs --claims");
    process.exit(2);
  }
  runClaims().catch((e) => {
    console.error(`FAIL  ${String(e.message ?? e)}`);
    process.exit(1);
  });
}
