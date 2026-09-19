// The section of the comment an author reads.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19.

import path from "node:path";

import {
  CLEAN_RELEASES_FOR_TRUSTED,
  CONSENT_HIGH_RISK,
  DELAY_HOURS,
  HIGH_RISK,
  POLICY_CODES,
  REVIEW_SLA_HOURS,
  TRUSTED_DELAY_HOURS,
  policyCodeDef,
} from "./constants.mjs";
import { queueFile } from "./queue.mjs";

const GLYPH = { error: "❌", review: "🧑‍⚖️", warn: "⚠️", pass: "✅", note: "ℹ️" };

/**
 * The policy half of the issue comment, appended to the checks' half.
 *
 * Two things it must always answer, because they are the two questions every
 * author actually has: *is it going to publish*, and *when*. A comment that
 * lists nine green checks and does not say "live in 24 hours" has answered
 * neither.
 */
export function renderPolicySection(decision, derived) {
  const id = derived?.plugin?.id ?? "";
  const version = derived?.version?.version ?? "";
  const lines = ["", "---", "", "## Publication"];

  const headline = {
    refuse: "**Not published.** A check above failed; the policy never got a say.",
    review: `**Held for a maintainer.** Nothing is wrong with \`${id} ${version}\` — the decision below is not the bot's to make. The SLA is ${REVIEW_SLA_HOURS} h, by ${decision.sla_deadline}.`,
    delay: `**Publishing itself at ${decision.publish_after}.** \`${id} ${version}\` passed every check; it waits out the publication delay and then goes live with nobody touching it.`,
    publish: `**Published.** \`${id} ${version}\` is live; no human was involved and none was needed.`,
  }[decision.outcome];
  lines.push("", headline, "");

  // A cleared hold still appears in the table below, and it must: the record of
  // what was held is the point. But its remedy ("nothing to do but wait") is
  // now false, so the approval is stated first and the remedies are suppressed.
  //
  // On the refuse path there was no hold, and claiming one was cleared is worse
  // than saying nothing. `decide()` records `approved_by` there deliberately —
  // the maintainer did type the command, and a record that omitted it could not
  // be reconciled with the thread — but rendering the two sentences back to
  // back ("a check failed, the policy never got a say" / "a maintainer cleared
  // the hold") reads to the author as the bot contradicting itself, or as the
  // approval having been lost. So the refusal gets its own line, and it says
  // what actually became of the command.
  // The line a maintainer copies, on the comment they are reading when they
  // decide. It is generated rather than described because the fingerprint in it
  // is the whole binding: an instruction that says "type /approve" cannot be
  // checked against anything later, and one that says "type this exact line"
  // can. `decision.repo` and `decision.tag` come from the run, never from the
  // issue body — that body is the thing the binding exists to stop trusting.
  if (decision.outcome === "review" && decision.fingerprint && decision.repo && decision.tag) {
    lines.push(
      "**A maintainer clears this hold with exactly this line:**",
      "",
      "```",
      `/approve ${decision.repo}@${decision.tag} ${decision.fingerprint}`,
      "```",
      "",
      "**Or clear it and publish immediately, without the delay:**",
      "",
      "```",
      `/publish ${decision.repo}@${decision.tag} ${decision.fingerprint}`,
      "```",
      "",
      `\`${decision.fingerprint}\` names this submission: the repository, the tag, \`${id} ${version}\`, ` +
      `and the ${decision.artifact_digests.length || "no"} artifact digest(s) hashed in this run. ` +
      "If the release changes before the line is typed, the approval is refused and this comment is " +
      "posted again with a new one — an approval applies to what somebody read, or to nothing.",
      "",
    );
  }

  // An approval that named something else. Stated before the table, because it
  // is the answer to "I typed the command, why is this still held".
  if (decision.approval_refused) {
    const r = decision.approval_refused;
    lines.push(
      `**@${r.by}'s \`/approve\` was refused.** It named ` +
      (r.for ? `\`${r.for}\`` : "no submission at all") +
      `, and this run is \`${decision.fingerprint ?? "not a listing"}\`. It cleared nothing, and ` +
      "it changed nothing about the outcome above: the command was typed at " +
      `${r.at}, and what it approved is not what is here.`,
      "",
    );
  }

  if (decision.approved_by && decision.outcome !== "refuse") {
    lines.push(
      `A maintainer cleared the hold: **@${decision.approved_by}**, at ${decision.approved_at}. ` +
      "Nothing was carried over from the run that raised it — every check in this comment ran " +
      "again, from scratch, against the release as it is right now.",
      "",
    );
  } else if (decision.approved_by) {
    lines.push(
      `**@${decision.approved_by}** typed \`/approve\` at ${decision.approved_at}. It was recorded ` +
      "and it changed nothing, because a failed check is not a decision an approval can clear — " +
      "nothing was held here for it to clear. Fix what the table below names and push a new " +
      "release, and a maintainer approves the hold *that* release raises: an approval is recorded " +
      "against the digests of the bytes it applied to, and these are not those bytes.",
      "",
    );
  }

  lines.push("| | code | detail |", "|---|---|---|");
  for (const r of decision.reasons) {
    lines.push(`| ${GLYPH[r.level] ?? "•"} | \`${r.code}\` | ${String(r.message).replace(/\|/g, "\\|")} |`);
  }
  lines.push("");

  const actionable = decision.reasons.filter(
    (r) => (r.level === "review" && !decision.approved_by) || r.level === "warn",
  );
  if (actionable.length) {
    const seen = new Set();
    for (const r of actionable) {
      if (seen.has(r.code)) continue;
      seen.add(r.code);
      const def = policyCodeDef(r.code);
      lines.push(`**\`${r.code}\` — ${def.title}.** ${def.remedy}`, "");
    }
  }

  if (decision.outcome === "delay") {
    lines.push(
      `<sub>The delay is ${decision.queue_entry?.delay_hours ?? DELAY_HOURS} h and the waiting release is \`${decision.queue_entry ? queueFile(id, version) : "queue/"}\` in this repository — visible, auditable, and cancellable by deleting the file. ` +
        "If you did not publish this release, say so on this issue now: the delay exists for exactly that, " +
        "and it is the only defence this registry has against a compromised author account (PRODUCTION_PLAN §5.5).</sub>",
      "",
    );
    // The line a maintainer needs at the moment they decide not to wait. It was
    // absent, and the waiver was documented as "edit publish_after" — a commit,
    // from a machine with a checkout. Somebody reading this comment on a phone
    // had to know a command existed, and then guess its arguments from the
    // `/approve` line above. A command nobody can find is half a command.
    if (decision.repo && decision.tag && decision.fingerprint) {
      lines.push(
        "**A maintainer publishes it now with exactly this line:**",
        "",
        "```",
        `/publish ${decision.repo}@${decision.tag} ${decision.fingerprint}`,
        "```",
        "",
        "<sub>It waives the wait and nothing else — every check above runs again, from scratch, " +
        "before anything is published, and the shortened window is recorded here where the author " +
        "reads it.</sub>",
        "",
      );
    }
  }
  lines.push(`<sub>Why this outcome and not another: \`docs/POLICY.md\`. The rules are ${HIGH_RISK.length} high-risk names, ${REVIEW_SLA_HOURS} h for the three events that need a person, and ${DELAY_HOURS} h (${TRUSTED_DELAY_HOURS} h after ${CLEAN_RELEASES_FOR_TRUSTED} clean releases) for everything else that is not routine.</sub>`);
  return lines.join("\n");
}
