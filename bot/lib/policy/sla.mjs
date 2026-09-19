// The review queue, said out loud on every run.
//
// Split out of `bot/lib/policy.mjs` on 2026-09-19.

import { REVIEW_SLA_HOURS, SLA_BREACH_HOURS } from "./constants.mjs";
import { HOUR_MS } from "./time.mjs";

// ── the SLA, made visible ───────────────────────────────────────────────────

/**
 * What the review queue looks like right now.
 *
 * Printed by the cron job on every run. The point is not the number; it is that
 * a breach is *loud*. The policy's own escape hatch — widen auto-publish rather
 * than let the queue rot — only gets exercised if somebody can see that the
 * queue is rotting, and a maintainer who has to go and look never does.
 *
 * @param {{number: number, title: string, created_at: string}[]} openIssues
 */
export function slaReport(openIssues, now = new Date()) {
  const items = (openIssues ?? []).map((i) => ({
    number: i.number,
    title: i.title,
    age_hours: Math.floor((now.getTime() - new Date(i.created_at).getTime()) / HOUR_MS),
  }));
  const late = items.filter((i) => i.age_hours > REVIEW_SLA_HOURS);
  const breached = items.filter((i) => i.age_hours > SLA_BREACH_HOURS);
  return {
    open: items.length,
    late: late.length,
    breached: breached.length,
    oldest_hours: items.reduce((m, i) => Math.max(m, i.age_hours), 0),
    items: items.sort((a, b) => b.age_hours - a.age_hours),
    verdict:
      breached.length > 0
        ? `${breached.length} listing(s) past ${SLA_BREACH_HOURS} h. POLICY.md §Review says what to do about that, and it is not "review harder".`
        : late.length > 0
          ? `${late.length} listing(s) past the ${REVIEW_SLA_HOURS} h SLA.`
          : "within SLA",
  };
}

// ── the comment ─────────────────────────────────────────────────────────────
