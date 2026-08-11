// Every page that is not a plugin page and not an advisory page.
//
// `/`, `/search/`, `/publisher/<owner>/`, `/publish/`, `/policy/`, `/security/`
// and `/transparency/`.
//
// TWO OF THESE RENDER MARKDOWN OUT OF THE REPOSITORY rather than restating it:
// `/policy/` is POLICY.md and docs/POLICY.md, `/security/` is SECURITY.md. The
// alternative — a hand-written page saying roughly the same thing — is two
// policies, and the second one is wrong within a month. This way a policy
// change is one commit and the site cannot claim a rule the repository does not
// have.

import { esc, href, page } from "../lib/html.mjs";
import { escalationTable } from "./advisory.mjs";

/** One card, on the home page and on a publisher page. */
function card(entry, { depth, withdrawn }) {
  const up = "../".repeat(depth);
  return `<a class="card" href="${esc(up)}p/${esc(entry.id)}/">
  ${entry.icon_url ? `<img class="icon" src="${href(entry.icon_url)}" alt="" width="40" height="40">` : '<span class="icon blank"></span>'}
  <span class="card-body">
    <strong>${esc(entry.name)}</strong>
    <code>${esc(entry.id)}</code>
    <span class="thin">${esc(entry.description)}</span>
    <span class="badges">${entry.staging ? '<span class="badge warn">staging</span>' : ""}${
      withdrawn ? '<span class="badge danger">withdrawn</span>' : ""
    }${(entry.capabilities ?? []).map((c) => `<span class="tag">${esc(c)}</span>`).join("")}</span>
  </span>
</a>`;
}

export function homePage(entries, { meta, withdrawnIds }) {
  const body = `
<section class="hero">
<h1>Astra plugins</h1>
<p>Every plugin Astra will install, and the catalogue it installs them from. The list below is
generated from <a href="registry/v1/index.json">the catalogue file</a> in the job that published
it, so a page here exists exactly when an entry there does.</p>
<p class="thin">Serial <code>${esc(meta.serial)}</code>${
    meta.issued_at ? ` &middot; issued <code>${esc(meta.issued_at)}</code>` : ""
  }${meta.expires_at ? ` &middot; expires <code>${esc(meta.expires_at)}</code>` : ""} &middot;
${esc(entries.length)} plugin${entries.length === 1 ? "" : "s"} &middot;
<a href="search/">search</a></p>
${
  meta.signatures.length === 0
    ? `<p class="alert">This catalogue carries <strong>no signature</strong>. That is what a build
outside <code>main</code> looks like, and Astra will refuse it. Do not install from it.</p>`
    : ""
}
</section>

<section class="grid">
${entries.map((e) => card(e, { depth: 0, withdrawn: withdrawnIds.has(e.id) })).join("\n")}
</section>

<section>
<h2>Before you install anything</h2>
<p>Astra checks that a plugin&rsquo;s bytes are the bytes its author&rsquo;s CI built and released,
and that nobody swapped them on the way to you. It does not check what the code does.
<strong>A plugin runs as a native program with your full user account access</strong> &mdash; there
is no sandbox, and this site will not imply there is one.</p>
<p>What that buys you and what it does not is in <a href="policy/">the policy</a> and
<a href="security/">the security model</a>; what has been withdrawn, and why, is in
<a href="transparency/">the transparency log</a>.</p>
</section>
`;
  return page({ title: "Astra plugin registry", description: "The signed catalogue of Astra plugins.", depth: 0, active: "catalogue", body });
}

export function searchPage() {
  const body = `
<h1>Search</h1>
<p class="thin">Runs in your browser against
<a href="../registry/v1/index.json">registry/v1/index.json</a> &mdash; the same signed file Astra
reads. Nothing is sent anywhere, and there is no server-side index that could disagree with the
catalogue.</p>
<input id="q" type="search" placeholder="name, id, keyword, capability&hellip;" autocomplete="off" autofocus>
<p id="status" class="thin">Loading the catalogue&hellip;</p>
<div id="results" class="grid"></div>
`;
  return page({ title: "Search — Astra plugin registry", description: "Search the Astra plugin catalogue.", depth: 1, active: "search", body, script: "search.js" });
}

export function publisherPage(owner, entries, { withdrawnIds }) {
  const body = `
<h1>${esc(owner)}</h1>
<p class="thin"><a href="${href(`https://github.com/${owner}`)}">github.com/${esc(owner)}</a> &middot;
${esc(entries.length)} listed plugin${entries.length === 1 ? "" : "s"}</p>

<section class="grid">
${entries.map((e) => card(e, { depth: 2, withdrawn: withdrawnIds.has(e.id) })).join("\n")}
</section>

<section>
<h2>What &ldquo;publisher&rdquo; means here</h2>
<p>It means the GitHub account or organisation that owns the repository each plugin is built and
released from. There are no registry accounts, no passwords and nothing to sign in to: the identity
is the repository, and control of it is proved against GitHub every time a release is ingested.</p>
<p>Astra pins that identity on first install. A later release from a <em>different</em> repository
is not a routine update &mdash; it is an identity change, one of the three events that stop and wait
for a person (<a href="../../policy/#3-the-three-events-that-need-a-person">policy</a>). What the app
can honestly say about a subsequent release is &ldquo;same author as before&rdquo;, and that is what
it says.</p>
</section>
`;
  return page({ title: `${owner} — Astra plugin registry`, description: `Plugins published from github.com/${owner}.`, depth: 2, active: "catalogue", body });
}

/**
 * `/publish/` — the one path.
 *
 * Every command named here was read out of AstraPlugins
 * `astra-plugin-cli/src/main.rs`: `init-ci` (with `--ref`, `--linux-packages`,
 * `--offline`), `publish` (with `--dry-run`, `--notify`, `--repo`, `--tag`,
 * `--print-url`), `check`, `build`, `verify`, `test`. There is no `login`,
 * because there is nothing to log in to.
 */
export function publishPage({ repo }) {
  const body = `
<h1>Publish a plugin</h1>
<p>One path, and it is the same path for the first release and the hundredth. You never upload a
file here and you never hold a credential for this repository.</p>

<h2>1. Let CI build and attest it</h2>
<pre><code>astra-plugin init-ci</code></pre>
<p>Writes a workflow into your repository that calls Astra&rsquo;s reusable release workflow, pinned
by commit SHA. Pushing a tag then builds your plugin on GitHub-hosted runners and asks GitHub to
attest the result &mdash; a statement, signed by GitHub, that <em>this file</em> came out of
<em>that workflow</em> at <em>that commit</em>.</p>
<p class="thin">The pin is a commit, never a tag: a mutable <code>@v1</code> is a workflow whose
contents can change after you read them. <code>--ref</code> pins a different one on purpose,
<code>--offline</code> keeps whatever pin the file already has.</p>

<h2>2. Push a tag</h2>
<pre><code>git tag my-plugin-v0.2.0 &amp;&amp; git push --tags</code></pre>
<p>The release workflow builds every target, verifies the bundle it just built, and publishes it as
a GitHub Release asset in <em>your</em> repository. The bytes users install are the bytes on your
release page; this registry never hosts them, and never gets a copy to swap.</p>

<h2>3. Ask to be listed &mdash; once, ever</h2>
<p>Open a listing issue with two fields: your repository and the tag.
<a href="${href(`https://github.com/${repo}/issues/new?template=plugin-listing.yml`)}">The form is
here.</a> A bot downloads the release asset, checks the attestation against a root-signed allowlist
of build workflows, parses the manifest with the daemon&rsquo;s own parser, and either lists it or
tells you exactly which check failed and in which file.</p>
<p>You can rehearse all of that before you open anything:</p>
<pre><code>astra-plugin publish --dry-run</code></pre>
<p>It runs every check the registry runs that can be run locally, and names the ones only the
registry can run.</p>

<h2>4. Every release after that</h2>
<p>Push a tag. That is the whole step. This registry finds out three ways &mdash; a ping from
<code>astra-plugin publish --notify</code>, a <code>/release v0.2.0</code> comment on your listing
issue, or a daily poll of your <code>releases.atom</code> with <code>If-None-Match</code> as a
backstop &mdash; and all three end in the same verification from scratch. None of them is a claim
the registry believes; they are all just a request to go and look.</p>
<p>A routine release publishes itself with nobody in the loop. Exactly three things stop and wait
for a person, and one thing adds a delay; <a href="../policy/">the policy</a> says which, how long,
and what happens when the queue runs late.</p>

<h2>What you are signing up for</h2>
<ul>
<li>Your artifacts stay on your GitHub Releases. This catalogue stores a URL, a SHA-256 and a size.</li>
<li>A version file is <strong>immutable once merged</strong>. Fixing a release means publishing a
new version, never editing a digest.</li>
<li>You can yank a version or delist the plugin at any time, and asking for removal needs no reason.</li>
<li>Nothing you declare is enforced by this registry at run time &mdash; the daemon enforces it.
Declaring honestly is how the consent sheet in front of your users stays accurate.</li>
</ul>

<h2>Running your own catalogue</h2>
<p>Nothing above is privileged. <code>plugins.registry_url</code> is ordinary configuration in
Astra, the generators take <code>--registry-dir</code>, and the daemon&rsquo;s verification path
contains no hostname check &mdash; it believes a catalogue because a root key signed the trust
document that names the key that signed it, not because of where it was fetched from. Point it at
your own tree and the same tooling works.</p>
`;
  return page({ title: "Publish — Astra plugin registry", description: "How a plugin gets built, attested, released and listed.", depth: 1, active: "publish", body });
}

/** A repository document, rendered. `parts` is [heading, html] pairs. */
export function docPage({ title, active, intro, parts, depth = 1 }) {
  const body = `
<h1>${esc(title)}</h1>
${intro}
${parts.map(([source, html]) => `<section class="doc"><p class="thin">Rendered from <code>${esc(source)}</code>.</p>\n${html}</section>`).join("\n<hr>\n")}
`;
  return page({ title: `${title} — Astra plugin registry`, description: `${title} for the Astra plugin registry.`, depth, active, body });
}

/**
 * `/transparency/` — the moderation log, and what is not in it.
 *
 * @param {{log: object, advisories: object[], meta: object, plugins: Map<string, object>}} ctx
 */
export function transparencyPage({ log, advisories, meta, plugins }) {
  const rows = log.entries
    .map((e) => {
      const linked = plugins.has(e.plugin)
        ? `<a href="../p/${esc(e.plugin)}/">${esc(e.plugin)}</a>`
        : `<code>${esc(e.plugin)}</code>`;
      return `<tr>
  <td>${esc(e.date)}</td>
  <td><span class="badge ${e.action === "revoke" ? "danger" : e.action === "deprecate" ? "warn" : ""}">${esc(e.action)}</span></td>
  <td>${linked}${e.versions?.length ? ` <span class="thin">${esc(e.versions.join(", "))}</span>` : ""}</td>
  <td>${esc(e.reason)}</td>
  <td>${e.advisory ? `<a href="../advisory/${esc(e.advisory)}/">${esc(e.advisory)}</a>` : ""}${
    e.appeal ? ` <a href="${href(e.appeal)}">appeal</a>` : ""
  }</td>
</tr>`;
    })
    .join("");

  const body = `
<h1>Transparency</h1>
<p>Every moderation action this registry has taken, what it means for somebody who already
installed the plugin, and &mdash; because a log that only shows what happened is half a log &mdash;
what this registry cannot tell you.</p>
<p class="thin">Machine-readable: <a href="moderation-log.json">moderation-log.json</a>. Catalogue
serial <code>${esc(meta.serial)}</code>${meta.expires_at ? `, expires <code>${esc(meta.expires_at)}</code>` : ""}.
Signed withdrawal list: <a href="../registry/v1/revocations.json">revocations.json</a>${
    log.revocations_serial !== undefined ? `, serial <code>${esc(log.revocations_serial)}</code>` : ""
  }.</p>

<h2>The four actions</h2>
${escalationTable()}

<h2>The log</h2>
${
  log.entries.length
    ? `<div class="scroll"><table>
<thead><tr><th>Date</th><th>Action</th><th>Plugin</th><th>Reason</th><th>Links</th></tr></thead>
<tbody>${rows}</tbody></table></div>`
    : `<p class="thin">Empty. No plugin has been yanked, delisted, deprecated or revoked. That is a
statement about this catalogue&rsquo;s age, not about its rigour &mdash; it has never had to.</p>`
}

<h2>Advisories</h2>
${
  advisories.length
    ? `<ul>${advisories
        .map(
          (a) =>
            `<li><a href="../advisory/${esc(a.id)}/">${esc(a.id)}</a> &middot; ${esc(a.severity)} &middot;
<code>${esc(a.action)}</code> &mdash; ${esc(a.reason)}</li>`,
        )
        .join("")}</ul>`
    : `<p class="thin">None published. Advisory ids are <code>ASTRA-YYYY-NNNN</code> and are stable
for as long as the advisory exists; the id, the file name and the signed entry are checked against
each other by <code>tools/lib/revocations.mjs</code>, so a published id cannot be silently reused.</p>`
}

<h2>What this log does not contain</h2>
<ul>
<li><strong>Submissions that were refused before they were ever listed.</strong> They are in the
issue tracker, publicly, with the failing check named &mdash; but a refusal is not a moderation
action against a listed plugin, and mixing the two would make the count meaningless.</li>
<li><strong>Reports we received and did not act on.</strong> Publishing those would publish an
accusation the registry did not substantiate.</li>
<li><strong>Anything about installed copies.</strong> This registry has no telemetry, receives no
install pings, and cannot tell you how many people are running a withdrawn version. The download
counts in the catalogue are <code>0</code> because nothing counts them.</li>
</ul>

<h2>How to make something appear here</h2>
<p>Open an issue with the plugin id and what you observed. Behaviour reports beat every heuristic
this registry has, and they are the mechanism it actually relies on. For anything that would let
somebody ship code to a user, use the embargoed path on the <a href="../security/">security
page</a> instead of a public issue.</p>
`;
  return page({ title: "Transparency — Astra plugin registry", description: "Every moderation action this registry has taken.", depth: 1, active: "transparency", body });
}

export function notFoundPage() {
  const body = `
<h1>Not here</h1>
<p>If you were looking for a plugin page: one exists for every entry in
<a href="registry/v1/index.json">the catalogue file</a> and for nothing else. A plugin that was
delisted or yanked loses its page at the next catalogue build &mdash; the record of why stays in
<a href="transparency/">the transparency log</a> and in this repository&rsquo;s git history.</p>
<p><a href="search/">Search the catalogue</a>.</p>
`;
  return page({ title: "Not found — Astra plugin registry", description: "", depth: 0, active: "catalogue", body });
}
