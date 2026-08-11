// `/advisory/<ASTRA-YYYY-NNNN>/` — one page per advisory in the signed
// withdrawal list, and the four escalating actions explained in one place.
//
// PRODUCTION_PLAN task 6.6. The id format is `ASTRA-YYYY-NNNN`, enforced at the
// source by `tools/lib/revocations.mjs`'s `ADVISORY_ID` regex — an advisory
// whose file name and `id` disagree does not load, so the URL below is stable
// for as long as the advisory exists, which is what a stable id is for.
//
// ── WHAT THIS PAGE MAY SAY ──────────────────────────────────────────────────
//
// Only what the SIGNED document says. The generator is handed
// `dist/revocations.json` — the same bytes `.github/workflows/revoke.yml` signs
// and deploys — and an advisory that is not in it gets no page, however many
// files sit in `tools/revocations/`. The prose comes from the advisory source
// beside the generator; the *effect* comes from the signed entry. If the two
// ever disagreed, the signed entry is the one a user's daemon acts on, so it is
// the one this page reports.
//
// ── THE FOUR ACTIONS, AND WHY THEY ARE THESE FOUR ───────────────────────────
//
// Task 6.6 asks for four escalating actions. They are not four new mechanisms:
// each is a thing the code already does, and the escalation is the order of
// how much they take away from somebody who already installed.
//
//   yank      `"yanked": true` on a version file. `tools/build-index.mjs:103`
//             filters it out of the catalogue. Nothing reaches an installed
//             copy — this is the author's "do not use this one", not a control.
//   delist    `"unlisted": true` on plugin.json. `tools/build-index.mjs:179`
//             drops the whole plugin from the catalogue. Again: nothing
//             reaches an installed copy.
//   deprecate An advisory with `"action": "warn"`. The daemon badges the
//             plugin and notifies; `RevocationAction::blocks_install()` in
//             astra-daemon/src/plugins/trust.rs is false for `warn` and only
//             for `warn`, so installs are still allowed.
//   revoke    An advisory with `"action": "block_install"` (refuse new installs
//             and updates, leave a running copy alone) or `"disable"` (refuse
//             installs AND stop what is already there —
//             `RevocationAction::stops_installed()` is true only for this one).
//
// The first two are catalogue edits and reach nobody's machine. The last two
// are signed statements that do. Saying which is which, on the page a user
// lands on, is the entire job.

import { esc, href, page } from "../lib/html.mjs";
import { ACTION_MEANING } from "./plugin.mjs";

/** The escalation, in order, with what each costs a user who already installed. */
export const ACTIONS = [
  {
    name: "Yank",
    how: '<code>"yanked": true</code> on a version file',
    installed: "Nothing. The version leaves the catalogue; a copy already installed keeps running and is not badged.",
    signed: "No — a catalogue edit.",
  },
  {
    name: "Delist",
    how: '<code>"unlisted": true</code> on <code>plugin.json</code>',
    installed: "Nothing. The whole plugin leaves the catalogue. Installed copies keep running and stop being offered updates.",
    signed: "No — a catalogue edit.",
  },
  {
    name: "Deprecate",
    how: 'an advisory with <code>"action": "warn"</code>',
    installed: ACTION_MEANING.warn,
    signed: "Yes — in <code>revocations.json</code>, re-signed at least every 7 days.",
  },
  {
    name: "Revoke",
    how: 'an advisory with <code>"action": "block_install"</code> or <code>"disable"</code>',
    installed: `${ACTION_MEANING.block_install} With <code>disable</code>: ${ACTION_MEANING.disable.toLowerCase()}`,
    signed: "Yes — in <code>revocations.json</code>, re-signed at least every 7 days.",
  },
];

export function escalationTable() {
  return `<div class="scroll"><table>
<thead><tr><th>Action</th><th>How it is expressed</th><th>Signed?</th><th>What it does to a copy you already installed</th></tr></thead>
<tbody>${ACTIONS.map(
    (a) => `<tr><td><strong>${esc(a.name)}</strong></td><td>${a.how}</td><td>${a.signed}</td><td>${a.installed}</td></tr>`,
  ).join("")}</tbody>
</table></div>`;
}

/**
 * One advisory page.
 *
 * @param {{id: string, severity: string, action: string, reason: string,
 *          advisory_url?: string, published?: string,
 *          entries: object[]}} advisory  grouped out of the signed document
 * @param {{plugins: Map<string, object>}} ctx
 */
export function advisoryPage(advisory, ctx) {
  const affected = [...new Set(advisory.entries.map((e) => pluginIdOf(e)).filter(Boolean))];

  const entryRows = advisory.entries
    .map(
      (e) => `<tr>
  <td><code>${esc(e.kind)}</code></td>
  <td class="digest"><code>${esc(e.value)}</code></td>
  <td>${
    e.versions
      ? esc(
          `${e.versions.introduced ?? "the first version"} up to but not including ${
            e.versions.fixed ?? "every later version"
          }`,
        )
      : '<span class="thin">every version this key names</span>'
  }</td>
</tr>`,
    )
    .join("");

  const body = `
<article>
<h1>${esc(advisory.id)}</h1>
<p class="thin">${esc(advisory.published ?? "")} &middot; severity <strong>${esc(advisory.severity)}</strong>
&middot; action <code>${esc(advisory.action)}</code></p>

<div class="alert danger">
<p>${esc(advisory.reason)}</p>
<p><strong>If you have this installed:</strong> ${esc(ACTION_MEANING[advisory.action] ?? "")}</p>
</div>

${advisory.advisory_url ? `<p><a href="${href(advisory.advisory_url)}">Full write-up</a></p>` : ""}

${
  affected.length
    ? `<h2>Plugins named</h2><ul>${affected
        .map((id) =>
          ctx.plugins.has(id)
            ? `<li><a href="../../p/${esc(id)}/">${esc(ctx.plugins.get(id).name)}</a> <code>${esc(id)}</code></li>`
            : `<li><code>${esc(id)}</code> <span class="thin">— no longer listed</span></li>`,
        )
        .join("")}</ul>`
    : ""
}

<h2>What is withdrawn, exactly</h2>
<p class="thin">One row per key the advisory names. A user&rsquo;s daemon matches on the first row
that applies and shows that row&rsquo;s reason, so each one stands on its own.</p>
<div class="scroll"><table>
<thead><tr><th>Keyed on</th><th>Value</th><th>Versions</th></tr></thead>
<tbody>${entryRows}</tbody></table></div>

<h2>How this reaches a machine</h2>
<p>Astra fetches <a href="../../registry/v1/revocations.json">registry/v1/revocations.json</a>
alongside the catalogue and checks it at install, at start, and on every refresh. The document
carries a <strong>seven-day</strong> expiry against the catalogue&rsquo;s thirty
(<code>REVOCATION_MAX_AGE_DAYS</code> and <code>CATALOG_MAX_AGE_DAYS</code> in
<code>astra-daemon/src/plugins/trust.rs</code>), and it is re-signed on a schedule even when nothing
has changed &mdash; past that window Astra blocks new installs outright rather than assuming the
list it has is current.</p>

<h2>The four actions</h2>
${escalationTable()}

<h2>If you think this is wrong</h2>
<p>Appeal it. The template and what happens next are in
<a href="../../policy/#10-appeals">the policy</a>; an advisory withdrawn in error is undone by
publishing a higher serial without it, which is deliberately possible.</p>
</article>
`;

  return page({
    title: `${advisory.id} — Astra plugin registry`,
    description: advisory.reason,
    depth: 2,
    active: "transparency",
    body,
  });
}

/** The plugin id an entry names, where it names one at all. */
export function pluginIdOf(entry) {
  if (entry.kind === "id" || entry.kind === "version_range") return entry.value;
  if (entry.kind === "id_version") {
    const cut = String(entry.value).lastIndexOf("@");
    return cut === -1 ? null : String(entry.value).slice(0, cut);
  }
  return null;
}

/** Group a flat signed withdrawal list back into the advisories it came from. */
export function groupAdvisories(revocations, sources = new Map()) {
  const byId = new Map();
  for (const r of revocations ?? []) {
    if (!byId.has(r.id)) {
      byId.set(r.id, {
        id: r.id,
        severity: r.severity,
        action: r.action,
        reason: r.reason,
        advisory_url: r.advisory_url,
        published: sources.get(r.id)?.published,
        entries: [],
      });
    }
    byId.get(r.id).entries.push(r);
  }
  return [...byId.values()].sort((a, b) => (a.id < b.id ? 1 : -1));
}
