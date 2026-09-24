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

import { esc, href, page, upTo } from "../lib/html.mjs";
import { escalationTable } from "./advisory.mjs";

/**
 * A page that has moved, written over the page that used to be there.
 *
 * ── WHY A PAGE AND NOT A 301 ────────────────────────────────────────────────
 *
 * GitHub Pages serves this tree and has no redirect configuration of any kind,
 * so the only thing that can stand at an old URL is a document. ROLL-55 names
 * the two mechanisms and this writes both, because they answer to two different
 * readers and neither covers the other:
 *
 *   `<link rel="canonical">`   a crawler, an archive, anything that already
 *                              holds the old URL. It is the statement that the
 *                              successor is the same resource, which a meta
 *                              refresh alone does not make.
 *   `<meta http-equiv="refresh" content="0; url=…">`
 *                              a person. It is the only thing that moves a
 *                              browser without JavaScript, and this site ships
 *                              no script it does not need.
 *
 * And a visible link under both, because a meta refresh is the one navigation
 * a reader cannot see coming and cannot undo with Back — the stub says where it
 * is sending them and lets them not go.
 *
 * ── NO NAV ──────────────────────────────────────────────────────────────────
 *
 * Deliberately not built on `page()`. The shell's nav links to `/`, `/search/`,
 * `/policy/` and the rest, and at R9a every one of those is itself a stub: a
 * reader who clicked the nav to escape a redirect would be redirected again,
 * from a page that exists only to say it is gone. The stylesheet is kept — the
 * assets are still written — so the stub does not look like a broken deploy.
 *
 * @param {{from: string, to: string, depth: number}} ctx `from` is the site
 *   path this file stands at, for the reader; `to` is an absolute https URL.
 */
export function redirectPage({ from, to, depth }) {
  const up = upTo(depth);
  const url = esc(to);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Moved — Astra plugin registry</title>
<link rel="canonical" href="${url}">
<meta http-equiv="refresh" content="0; url=${url}">
<meta name="description" content="${esc(from)} has moved to ${url}.">
<link rel="stylesheet" href="${esc(up)}assets/site.css">
</head>
<body>
<main>
<h1>This page has moved</h1>
<p><code>${esc(from)}</code> is now <a href="${url}">${url}</a>, and your browser is being sent
there. If it is not, follow the link.</p>
<p class="thin">The page you asked for was generated from this registry&rsquo;s signed catalogue and
is now served by the plugins service instead. The signed documents themselves have
<strong>not</strong> moved and are not redirected &mdash;
<a href="${esc(up)}registry/v1/index.json">the catalogue</a>, the withdrawal list and the trust
documents are still the same bytes at the same URLs here, which is what a daemon and an outside
checker fetch.</p>
</main>
</body>
</html>
`;
}

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
released from. This registry has no accounts of its own, and nothing here to sign in to: the
identity is the repository, and control of it is proved against GitHub every time a release is
ingested. <em>Amended 2026-09-24:</em> binding a repository to its listing also needs a Minice account
holding <code>astraUser</code>, at astra.minice.ai. That account is told about each release, and it
is never shown on this page.</p>
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
<p>Since the cutover (ROLL-33) a listing is requested in Minice&rsquo;s panel, not through an issue
here. Sign in at <a href="${href("https://astra.minice.ai/plugins")}">astra.minice.ai/plugins</a> with
a Minice account holding <code>astraUser</code>, mint a binding token for your repository, commit the
line it shows you &mdash; <code>astra-binding: &lt;token&gt;</code> &mdash; into
<code>.well-known/astra-plugin-owner</code> on the commit you tag, and submit the repository and the
tag. A bot downloads the release asset, checks the attestation against a root-signed allowlist of
build workflows, parses the manifest with the daemon&rsquo;s own parser, and either lists it or tells
you exactly which check failed and in which file, by a notice to your account.</p>
<p>You can rehearse all of that before you submit anything:</p>
<pre><code>astra-plugin publish --dry-run</code></pre>
<p>It runs every check the registry runs that can be run locally, and names the ones only the
registry can run.</p>

<h2>4. Every release after that</h2>
<p>Push a tag with your listing&rsquo;s tag prefix, on a commit that carries your binding line. That
is the whole step. This registry polls your release feed every 30 minutes and takes a new release up
at its next run, every 10 minutes, and verifies it from scratch. A tag is a request to go and look,
never a claim the registry believes.</p>
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
 * One log entry's `backed`, said in words a reader can act on.
 *
 * MOD-7: a deprecate or a revoke is "in effect" on a host only once the
 * withdrawal list THAT host serves carries it; otherwise it is pending. The
 * distinction is not bookkeeping — a pending revoke is a decision that has been
 * taken and recorded, and a daemon fetching from this host will not act on it
 * until the next signed list goes out. Printing "revoked" for both states would
 * tell a reader their machine is protected when it is not yet.
 *
 * The four values are `site/build.mjs`'s `moderationLog`; see the note there.
 */
function effectCell(entry) {
  if (entry.backed === true) {
    return `<span class="badge">in effect</span>`;
  }
  if (entry.backed === "pending") {
    return `<span class="badge warn" title="Recorded here, and not yet carried by the withdrawal list published beside this page.">pending</span>`;
  }
  if (entry.backed === null) {
    return `<span class="badge" title="This build was given no withdrawal list, so nothing was checked.">unchecked</span>`;
  }
  // `false` — a yank or a delist. It produces no signed document at all, so
  // there is nothing to be pending on: the catalogue beside this page is the
  // effect.
  return `<span class="thin" title="A catalogue edit. It produces no signed document; the catalogue published beside this page is the effect.">catalogue</span>`;
}

/**
 * `/transparency/` — the moderation log, and what is not in it.
 *
 * @param {{log: object, advisories: object[], meta: object, plugins: Map<string, object>}} ctx
 */
export function transparencyPage({ log, advisories, meta, plugins }) {
  const anyPending = log.entries.some((e) => e.backed === "pending");
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
  <td>${effectCell(e)}</td>
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
  log.unavailable
    ? `<p class="alert"><strong>This build could not read the moderation sources, so the log below is
empty and is not the whole log.</strong> The files that failed to load are
${log.unavailable.sources.length ? log.unavailable.sources.map((s) => `<code>${esc(s)}</code>`).join(", ") : "in <code>bot/moderation/</code>"}.
The catalogue and the withdrawal list beside this page are unaffected and are in force: a broken
record of a takedown must never hold up the takedown. The validator&rsquo;s own messages are in the
build log rather than here, because a message quotes the text of the entry it refused and the usual
reason to refuse an entry is that its text must not reach a reader&rsquo;s screen.</p>`
    : ""
}
${
  log.entries.length
    ? `<div class="scroll"><table>
<thead><tr><th>Date</th><th>Action</th><th>Plugin</th><th>Reason</th><th>Effect here</th><th>Links</th></tr></thead>
<tbody>${rows}</tbody></table></div>
<p class="thin"><strong>&ldquo;Effect here&rdquo; is about this host, not about the decision.</strong>
A deprecate or a revoke is carried by <a href="../registry/v1/revocations.json">the signed withdrawal
list</a>, and it reads <em>in effect</em> only once the list published beside this page carries it
with a matching action &mdash; which is the moment a daemon fetching from here starts acting on it.
<em>Pending</em> means the decision is recorded and the list this host serves does not carry it yet;
that is a real state with a real duration, usually until the next publish, and the page says so
rather than failing to build. A yank and a delist produce no signed document, so they read
<em>catalogue</em>: the catalogue beside this page is their effect.</p>${
        anyPending
          ? `\n<p class="alert">Something in this log is <strong>pending</strong>. If you are reading
this to decide whether you are protected: you are not protected by a pending row. Check
<a href="../registry/v1/revocations.json">revocations.json</a> yourself &mdash; it is the document
your machine acts on, and it is the one that decides.</p>`
          : ""
      }`
    : log.unavailable
      ? ""
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
<li><strong>Submissions that were refused before they were ever listed.</strong> Since the cutover
they are public in the decision log (<code>log/decisions/</code>), with the failing check named, and
never as issues &mdash; but a refusal is not a moderation action against a listed plugin, and mixing
the two would make the count meaningless.</li>
<li><strong>Reports we received and did not act on.</strong> Publishing those would publish an
accusation the registry did not substantiate.</li>
<li><strong>Anything about installed copies.</strong> This registry has no telemetry, receives no
install pings, and cannot tell you how many people are running a withdrawn version. The download
counts in the catalogue are <code>0</code> because nothing counts them.</li>
</ul>

<h2>How to make something appear here</h2>
<p>Report it on Minice's report page, at
<a href="${href("https://astra.minice.ai/plugins/_/report")}">astra.minice.ai/plugins/_/report</a>,
or from the plugin's page in the panel, which opens it with the plugin chosen. Sign in as an Astra
owner, and give the version and what you observed. Since the cutover (ROLL-33) an issue on this
repository reaches nobody. Behaviour reports beat every heuristic this registry has, and they are
the mechanism it actually relies on. For anything that would let somebody ship code to a user, use
the path on the <a href="../security/">security page</a> instead.</p>
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
