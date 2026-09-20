// SERVE-39's Pages half: what a client is actually served, against what
// `signed` says it should be — and D5's latch, which decides which of the two
// withdrawal lists that is (registry plan RC-R1-5).
//
// ── the three documents, and the fourth ─────────────────────────────────────
//
// `index.json`, `trust.json` and `root.json` are always `signed`'s head. The
// withdrawal list is the one that depends on the latch, and it is the one that
// can hurt a client that is already running:
//
//   * before the latch, Pages serves main's UNSIGNED list and every shipped
//     0.2.x daemon stays `NotEnforced`. The failure to watch for is a list
//     that VERIFIES appearing early — those clients arm themselves on it, and
//     seven days after their last accepted fetch they block installs. Arming
//     is one-way in the field, so this has no grace period: by the time it is
//     thirty minutes old the clients that saw it have armed and cannot be
//     un-armed by anything this estate does;
//   * from the latch, Pages must serve `signed`'s list, and an unsigned or
//     stale one is those same clients' 7-day fuse burning down.
//
// The latch is read with `armingState` from `tools/signer/pages.mjs` and not
// re-derived here. Three readers have to agree about when it closed — the
// `pages` job that deploys, this check, and RC-R1-7's probe — and three
// readings of "is the flag there" is three chances to read it differently. In
// particular this is why the check does not look at `policy/` in the tree: the
// latch is a question about HISTORY, and a revert of the flag commit changes
// nothing in the field.
//
// ── one clock ──────────────────────────────────────────────────────────────
//
// SERVE-39's window is measured from the `signed` commit, which is exactly the
// right clock here and needs none of SERVE-85's care: the thing being compared
// IS that commit's bytes, so the commit that created the difference is the
// commit the window starts at.
//
// ── the Pages address is a constant ────────────────────────────────────────
//
// Not an input, not an environment variable, not a workflow input. A check
// whose target can be set by the thing it is checking is a check that can be
// pointed at a copy that agrees with it, and the whole value of this one is
// that it reads what a stranger's daemon reads. The override below exists for
// the suite and is never read from the environment.

// REVOCATIONS_SCHEMA and no other domain: a signature made over one domain
// must not verify under another, so passing the wrong one here would report
// "does not verify" about a list that verifies perfectly — reading early
// arming as correctness.
import { REVOCATIONS_SCHEMA, verifyEnvelope } from "../../bot/lib/sign.mjs";
import { delegatedVerifierKeys } from "../signer/key-window.mjs";
import { SIGNED_FILES } from "../signer/plan.mjs";
import { GRACE_MINUTES, finding, minutesSince, verdict, withinGrace } from "./report.mjs";

/** What a shipped daemon fetches. README's "The URL Astra fetches", minus the file. */
export const PAGES_BASE = "https://mihailinl.github.io/astra-registry/";

const FETCH_TIMEOUT_MS = 20_000;

/**
 * The documents Pages is compared on, in the order a reader thinks about them.
 *
 * `index` leaves this list at R9a and not before: RC-R9-1 retires the
 * catalogue from Pages, and its own canary is that this check drops
 * `index.json` only once the R9a marker exists — watched there by deploying an
 * index after it. Until then a catalogue on Pages that is not `signed`'s is a
 * split view, which is the thing SERVE-39 is for.
 */
export const ALWAYS_COMPARED = ["index", "trust", "root"];

/**
 * Fetch the four documents Pages serves.
 *
 * `cache: "no-store"` and the two headers are asked for rather than relied on:
 * Pages sits behind a CDN that purges on deploy, and the 30-minute window
 * absorbs what is left. What must not happen is this job holding a response
 * from its own previous run, which `no-store` does settle.
 *
 * @param {{base?: string, fetchImpl?: typeof fetch}} opts
 */
export async function fetchServed({ base = PAGES_BASE, fetchImpl = fetch } = {}) {
  const served = {};
  for (const [name, rel] of Object.entries(SIGNED_FILES)) {
    const url = new URL(rel, base).toString();
    try {
      const res = await fetchImpl(url, {
        cache: "no-store",
        headers: { "Cache-Control": "no-cache", Pragma: "no-cache", "User-Agent": "astra-registry-served-set" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) {
        served[name] = { ok: false, url, status: res.status, body: null, error: `HTTP ${res.status}` };
        continue;
      }
      served[name] = { ok: true, url, status: res.status, body: await res.text(), error: null };
    } catch (e) {
      served[name] = { ok: false, url, status: null, body: null, error: String(e?.message ?? e) };
    }
  }
  return served;
}

/** The keys a client could verify a list with: everything either trust.json delegates. */
export function verifierKeys({ head, served }) {
  const keys = new Map();
  const add = (text) => {
    if (typeof text !== "string") return;
    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      return;
    }
    try {
      for (const k of delegatedVerifierKeys(doc)) keys.set(k.key_id, k);
    } catch {
      // A trust.json with an unusable key in it is root-delegation.mjs's
      // subject, not this one's. What matters here is only whether SOME key
      // would have verified the list a client was served.
    }
  };
  add(head?.bytes?.trust);
  add(served?.trust?.body);
  return [...keys.values()];
}

/**
 * SERVE-39's decision, over facts and nothing else.
 *
 * @param {object} o
 * @param {object} o.head           from fetchSignedHead
 * @param {string|null} o.headClock the `signed` head's committer time, RFC 3339
 * @param {object} o.served         from fetchServed
 * @param {{armed: boolean, latch_commit: string|null}} o.arming
 * @param {boolean} o.signerWorkflowPresent
 * @param {string} o.now
 * @param {number} [o.graceMinutes]
 * @param {string[]} [o.compared]
 */
export function serve39({
  head,
  headClock,
  served,
  arming,
  signerWorkflowPresent,
  now,
  graceMinutes = GRACE_MINUTES,
  compared = ALWAYS_COMPARED,
}) {
  const findings = [];
  const waiting = [];
  const notes = [];
  const hexes = [];

  if (!head?.present) {
    if (!signerWorkflowPresent) {
      waiting.push(
        "there is no `signed` branch and no .github/workflows/sign.yml on main to create one, so what Pages " +
        "serves has nothing to be compared with yet (registry plan D1, RC-R1-2). The heartbeat below still posts.",
      );
      return verdict({ findings, waiting, hexes, notes });
    }
    findings.push(finding(
      "SERVE_39_NO_SIGNED_BRANCH",
      "sign.yml is on main and there is no `signed` branch, so Pages is serving bytes that nothing publishes " +
      "and nothing can be compared with.",
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  hexes.push(head.sha);
  const age = minutesSince(headClock, now);
  const excused = withinGrace(headClock, now, graceMinutes);
  notes.push(
    `\`signed\`@${head.sha.slice(0, 12)} committed ${headClock}, ${age === null ? "an unreadable time" : `${age.toFixed(1)} minutes`} ago; ` +
    `the latch is ${arming?.armed ? `closed at ${String(arming.latch_commit).slice(0, 12)}` : "open"}`,
  );

  for (const name of compared) {
    const rel = SIGNED_FILES[name];
    const want = head.bytes?.[name];
    const got = served?.[name];
    if (typeof want !== "string") {
      findings.push(finding(
        "SERVE_39_SIGNED_INCOMPLETE",
        `\`signed\`@${head.sha.slice(0, 12)} has no ${rel}; a published commit missing one of D2's four files is ` +
        `a commit no client can be served from.`,
      ));
      continue;
    }
    if (!got?.ok) {
      findings.push(finding(
        "SERVE_39_PAGES_UNREACHABLE",
        `${got?.url ?? rel} could not be read: ${got?.error ?? "no answer"}. Every daemon that refreshes now gets ` +
        `the same answer.`,
      ));
      continue;
    }
    if (got.body === want) continue;
    if (excused) {
      notes.push(`${rel} on Pages is not \`signed\`'s yet, ${age?.toFixed(1)} minutes in; the deploy has ${graceMinutes}`);
      continue;
    }
    findings.push(finding(
      "SERVE_39_DOCUMENT_DRIFT",
      `Pages serves a ${rel} that is not \`signed\`@${head.sha.slice(0, 12)}'s, ${age === null ? "at an unreadable time" : `${age.toFixed(0)} minutes`} ` +
      `after that commit (served ${got.body.length} bytes, \`signed\` holds ${want.length}). A split view between ` +
      `the branch and the deployment is what SERVE-39 exists to find.`,
    ));
  }

  // ── the fourth document: the latch ────────────────────────────────────────
  const servedList = served?.revocations;
  if (!servedList?.ok) {
    findings.push(finding(
      "SERVE_39_PAGES_UNREACHABLE",
      `${servedList?.url ?? SIGNED_FILES.revocations} could not be read: ${servedList?.error ?? "no answer"}. ` +
      `An armed client that cannot fetch the list blocks installs seven days after its last accepted one.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }

  if (!arming?.armed) {
    const keys = verifierKeys({ head, served });
    let doc = null;
    try {
      doc = JSON.parse(servedList.body);
    } catch {
      // An unparseable list before the latch is main's unsigned file being
      // mangled somewhere, which the drift check above cannot see because the
      // list is not compared before the latch. It is not early arming — no
      // client arms on bytes it cannot parse — so it is reported as itself.
      findings.push(finding(
        "SERVE_39_LIST_UNPARSEABLE",
        `Pages serves a ${SIGNED_FILES.revocations} that is not JSON. Before the latch it should be main's ` +
        `committed unsigned list, exactly as today.`,
      ));
      return verdict({ findings, waiting, hexes, notes });
    }
    const check = verifyEnvelope(doc, REVOCATIONS_SCHEMA, keys);
    if (check.ok) {
      // No grace, deliberately. Every other finding here is "this will be
      // wrong if it lasts"; this one is "a client that fetched in the last
      // fifteen minutes has already armed, and nothing can un-arm it".
      findings.push(finding(
        "SERVE_39_EARLY_ARMING",
        `Pages serves a withdrawal list that verifies under delegated key ${check.key_id}, and ` +
        `${SIGNED_FILES.revocations}'s arming flag has never been added on main. Every 0.2.x daemon that ` +
        `fetches this arms itself and blocks installs seven days after its last accepted list — one way, in the ` +
        `field, whatever this repository does next (D5, ROLL-14).`,
      ));
    } else {
      notes.push(`the list Pages serves does not verify (${check.reason}), which before the latch is correct`);
    }
    return verdict({ findings, waiting, hexes, notes });
  }

  const want = head.bytes?.revocations;
  if (typeof want !== "string") {
    findings.push(finding(
      "SERVE_39_SIGNED_INCOMPLETE",
      `the latch is closed and \`signed\`@${head.sha.slice(0, 12)} has no ${SIGNED_FILES.revocations}.`,
    ));
    return verdict({ findings, waiting, hexes, notes });
  }
  if (servedList.body === want) {
    notes.push(`the latch is closed and Pages serves \`signed\`'s list, byte for byte`);
    return verdict({ findings, waiting, hexes, notes });
  }
  if (excused) {
    notes.push(`the list on Pages is not \`signed\`'s yet, ${age?.toFixed(1)} minutes in; the deploy has ${graceMinutes}`);
    return verdict({ findings, waiting, hexes, notes });
  }
  findings.push(finding(
    "SERVE_39_DISARMING",
    `the latch closed at ${String(arming.latch_commit).slice(0, 12)} and Pages serves a ${SIGNED_FILES.revocations} ` +
    `that is not \`signed\`@${head.sha.slice(0, 12)}'s, ${age === null ? "at an unreadable time" : `${age.toFixed(0)} minutes`} ` +
    `after that commit. Armed clients do not disarm: they keep the last list they accepted and block installs ` +
    `seven days later.`,
  ));
  return verdict({ findings, waiting, hexes, notes });
}
