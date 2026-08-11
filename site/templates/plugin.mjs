// `/p/<id>/` — one page per catalogue entry, and one only if the entry exists.
//
// EVERY FACT ON THIS PAGE COMES OUT OF THE SIGNED INDEX RECORD that was
// deployed in the same job, plus the signed withdrawal list deployed beside it.
// There is no second database, no scrape, and no live fetch: the generator is
// handed `dist/index.json` — the exact bytes that become
// `registry/v1/index.json` — and cannot render a plugin that is not in it or
// omit one that is. That is the whole point of task 6.5, and it is the reason
// the build and the deploy are one job rather than two.
//
// ── the deep link that is deliberately absent ───────────────────────────────
//
// If you came here looking for an `astra://install/<id>` button: it is not
// missing, it was refused, and this is where the reason lives.
//
// `astra://` is ALREADY IN USE, and not by the plugin system. It is the scheme
// of a remote-daemon pairing connection string — `astra://<host>:<port>` —
// built in three places in the Astra tree:
//
//     astra-rs/astra-ui/src/pages/Oobe/OobePage.tsx:5123
//     astra-rs/astra-ui/src/pages/Settings/SettingsPage.tsx:740
//     astra-rs/astra-tui/src/main.rs:1751
//
// (Verified by reading those three lines; each builds `astra://${addr}:${port}`
// for a client that is about to connect to a daemon.)
//
// Registering `astra://` as an OS protocol handler so a web page could hand the
// app an install request would therefore do two things at once. It would create
// a grammar collision — `astra://install/dice-roller` and
// `astra://192.168.1.4:9000` would arrive at the same parser and one of them
// has to lose — and, worse, it would turn a family of handlers that includes
// "connect this client to that daemon" into something any web page in any
// browser can invoke with a click. That is a remote attack surface bolted onto
// a pairing mechanism, bought in exchange for saving a user one paste of a
// plugin id into a search box that already exists in the app.
//
// So the install instruction on this page — when there is one at all; see
// `installBlock`, which withholds it for a staging or withdrawn entry — is:
// open Astra, search the id. It costs nothing and it removes the surface
// entirely. If a future contributor wants the deep link back, the argument that
// has to be answered first is the pairing-scheme collision above, not the
// convenience.

import { esc, href, page } from "../lib/html.mjs";

/** Bytes, in the unit a person reads. */
export function humanSize(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Which withdrawal entries, if any, cover this plugin.
 *
 * Matched the way `astra-daemon/src/plugins/trust.rs` matches them, on the
 * kinds that name a plugin rather than a byte sequence — `id`, `id_version`,
 * `version_range` — plus `digest` against the artifact digests this record
 * carries. The daemon is the authority on the match; this is the page saying
 * out loud what the daemon will already have decided, so that a user reading
 * the catalogue and a user opening the app are not told different things.
 */
export function withdrawalsFor(entry, revocations) {
  const hits = [];
  const digests = new Set();
  for (const rel of entry.releases ?? []) {
    for (const art of Object.values(rel.artifacts ?? {})) {
      if (art.sha256) digests.add(String(art.sha256).toLowerCase());
    }
  }
  for (const r of revocations ?? []) {
    const value = String(r.value ?? "");
    if (r.kind === "id" && value === entry.id) hits.push(r);
    else if (r.kind === "version_range" && value === entry.id) hits.push(r);
    else if (r.kind === "id_version" && value.slice(0, value.lastIndexOf("@")) === entry.id) hits.push(r);
    else if ((r.kind === "digest" || r.kind === "binary") && digests.has(value.toLowerCase())) hits.push(r);
  }
  return hits;
}

/** What a withdrawal action means for somebody who already installed. */
export const ACTION_MEANING = {
  // Verified against `RevocationAction` in astra-daemon/src/plugins/trust.rs:
  // `blocks_install()` is true for everything except `warn`, and
  // `stops_installed()` is true only for `disable`.
  block_install: "New installs and updates are refused. A copy already installed keeps running.",
  disable: "New installs are refused, and a copy already installed is stopped and will not start again.",
  warn: "Astra badges it and tells you. Nothing is blocked and nothing is stopped.",
};

function badge(text, kind) {
  return `<span class="badge ${esc(kind)}">${esc(text)}</span>`;
}

function permissionRows(release, highRisk) {
  const perms = release.permissions ?? {};
  const names = Object.keys(perms).sort();
  if (names.length === 0) return "";
  const rows = names
    .map((name) => {
      const p = perms[name] ?? {};
      const extra = [
        Array.isArray(p.types) && p.types.length ? `events: ${p.types.join(", ")}` : "",
        Array.isArray(p.scopes) && p.scopes.length ? `scopes: ${p.scopes.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join(" · ");
      return `<tr>
  <td><code>${esc(name)}</code>${highRisk.includes(name) ? ` ${badge("high risk", "warn")}` : ""}</td>
  <td>${p.reason ? `<span class="quoted">The author says: ${esc(p.reason)}</span>` : '<span class="thin">no reason given</span>'}
      ${extra ? `<div class="thin">${esc(extra)}</div>` : ""}</td>
</tr>`;
    })
    .join("");
  return `<h3>Permissions this version asks for</h3>
<p class="thin">The words Astra puts in front of you at install time come from a table shipped
inside the app, keyed by these ids. What the registry carries — and what is reproduced here — is
the id and the author's own one-line reason, which is why it is quoted rather than stated.</p>
<div class="scroll"><table><thead><tr><th>Permission</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function artifactRows(release) {
  const keys = Object.keys(release.artifacts ?? {}).sort();
  return keys
    .map((key) => {
      const a = release.artifacts[key];
      return `<tr>
  <td><code>${esc(key)}</code></td>
  <td>${a.url ? `<a href="${href(a.url)}">${esc(a.filename)}</a>` : esc(a.filename)}</td>
  <td>${esc(humanSize(a.size))}</td>
  <td class="digest">${a.sha256 ? `<code>${esc(a.sha256)}</code>` : '<span class="thin">none — unverifiable, and therefore uninstallable</span>'}</td>
</tr>`;
    })
    .join("");
}

/**
 * The provenance panel, and the block under it that never collapses.
 *
 * The field list is PRODUCTION_PLAN §4.2's, minus every row this document
 * cannot honestly fill. The index record carries no attestation certificate
 * identity, no Rekor index and no workflow run id — the bot checks those at
 * ingest (`bot/lib/attestation.mjs`) and does not write them into the
 * catalogue — so they are absent here rather than invented. What is present is
 * exactly what a reader can re-derive from the signed bytes.
 */
function provenance(entry, release, meta) {
  const rel = release.release ?? {};
  const repo = rel.repo ?? entry.source?.repo ?? "";
  const rows = [
    ["Publisher", repo ? `<a href="${href(`https://github.com/${repo}`)}">github.com/${esc(repo)}</a>` : "&mdash;"],
    [
      "Source",
      [rel.tag ? `tag <code>${esc(rel.tag)}</code>` : "", rel.commit ? `commit <code>${esc(rel.commit)}</code>` : ""]
        .filter(Boolean)
        .join(" · ") || "&mdash;",
    ],
    ["Release kind", `<code>${esc(rel.kind ?? "unknown")}</code>`],
    [
      "Countersignature",
      meta.signatures.length
        ? `registry key <code>${esc(meta.signatures.map((s) => s.key_id).join(", "))}</code> · index serial <code>${esc(meta.serial)}</code>` +
          (meta.expires_at ? ` · this catalogue expires <code>${esc(meta.expires_at)}</code>` : "")
        : `<strong>none.</strong> These bytes were generated without a signing key, which happens on a
           pull request and on a fork. A catalogue in that state is for inspection, not for install.`,
    ],
  ];

  return `<h3>Provenance</h3>
<div class="scroll"><table class="kv"><tbody>${rows
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`)
    .join("")}</tbody></table></div>

<div class="does-not-prove">
<p>This proves the file came from that repository&rsquo;s automated build of that commit, and that
Astra listed it. It does not prove the code is safe, and it does not prove the author&rsquo;s GitHub
account was not compromised. <strong>Plugins run as normal programs with your user account&rsquo;s
full privileges.</strong></p>
</div>`;
}

/**
 * The one-liner, and it is a real one.
 *
 * `astra-plugin verify <file>` exists — AstraPlugins `astra-plugin-cli/src/main.rs`
 * declares `Verify { file }` and `commands/verify.rs` prints `artifact sha256`
 * over the whole file, which is the same number the `sha256` column above
 * carries and the same one the attestation covers. `gh attestation verify` with
 * `--repo` is the invocation `bot/lib/attestation.mjs:176` makes on every
 * ingest, so a reader running it is running the registry's own check.
 *
 * `--signer-workflow` is on the bot's command line and is NOT on this one: the
 * value is the reusable workflow pinned by commit in root-signed `trust.json`,
 * and a reader who has not read `trust.json` cannot supply it. Omitting it makes
 * the reader's check strictly weaker than the registry's, so the caption says
 * so rather than letting the shorter command imply parity.
 */
function verifyBlock(entry, release) {
  const rel = release.release ?? {};
  const first = Object.keys(release.artifacts ?? {}).sort()[0];
  const art = first ? release.artifacts[first] : null;
  if (!art?.url) return "";
  const repo = rel.repo ?? entry.source?.repo ?? "";

  // No digest means no pin, and a "verify it yourself" block whose first step
  // is "compare against nothing" would be theatre. Say what is missing instead.
  if (!art.sha256) {
    return `<h3>Verify it yourself</h3>
<p class="alert">Not yet. This entry carries <strong>no SHA-256</strong>, because the release it
names does not exist — there is nothing to download and nothing to compare. Astra refuses to install
an entry in this state, and so should you. When the release is published the digest lands here, in
the attestation, and in what the daemon hashes: one number in three places.</p>`;
  }
  const cmd = [
    `curl -fL -o ${art.filename} \\`,
    `  ${art.url}`,
    ``,
    `# 1. the bytes are the bytes this catalogue pinned`,
    `sha256sum ${art.filename}`,
    `#    expect ${art.sha256}`,
    ``,
    `# 2. the bundle is well-formed, and its own digests agree`,
    `astra-plugin verify ${art.filename}`,
    ...(repo
      ? [
          ``,
          `# 3. GitHub attests that this file came out of a build in that repository`,
          `gh attestation verify ${art.filename} --repo ${repo}`,
        ]
      : []),
  ].join("\n");

  return `<h3>Verify it yourself</h3>
<pre class="copy"><code>${esc(cmd)}</code></pre>
<p class="thin">Step 3 is weaker than the check this registry ran before listing: the bot also
passes <code>--signer-workflow</code>, pinned by commit SHA in the root-signed
<code>trust.json</code>, so that &ldquo;some workflow in that repository built it&rdquo; becomes
&ldquo;the reusable workflow we allow built it&rdquo;. Without that flag a build produced by any
workflow in the repository passes.</p>`;
}

/**
 * The install section, which refuses to give an install instruction for
 * something that cannot be installed.
 *
 * There are three states and the page has to tell them apart, because the
 * failure mode of not telling them apart is a reader following a step-by-step
 * instruction, finding nothing, and concluding the catalogue is fiction.
 *
 *  1. **staging** — `entry.staging`, the same flag the alert above reads. No
 *     release artifact exists, so there is no digest, so the daemon refuses it
 *     by construction. Every entry in this catalogue is in this state today.
 *  2. **withdrawn with a blocking action** — anything but `warn`. Matches
 *     `RevocationAction::blocks_install()` in
 *     `astra-daemon/src/plugins/trust.rs`, which is true for every action
 *     except `warn` (and an action a build does not recognise disables).
 *  3. **installable** — and even then, what the digest check is *anchored to*
 *     depends on `meta.signatures` and `meta.roots`. An unsigned catalogue is a
 *     pull-request or fork build. A signed one whose root set is empty is a
 *     catalogue no shipped daemon will believe, because `PRODUCTION_ROOT_KEYS`
 *     is empty until the ceremony runs (SECURITY.md §4) and the daemon fails
 *     closed. Neither is a state in which to promise a verified install.
 *
 * The `astra://` paragraph is not conditional: it is a design decision about
 * this page and it holds in every state.
 */
function installBlock(entry, meta, hits) {
  const noLink = `<p class="thin">There is no install button on this page and no <code>astra://</code> link, on
purpose. That scheme already carries remote-daemon pairing addresses in Astra&rsquo;s own UI and
TUI, and registering it as a browser-reachable protocol handler would put a web page one click away
from a handler family that includes &ldquo;connect this client to that daemon&rdquo;. Typing an id
into a search box costs nothing and removes the surface.</p>`;

  if (entry.staging) {
    return `<h2>Installing it</h2>
<p>Not yet, and not from here. This entry is staging: there are no bytes to pin, so there is
nothing for Astra to download and nothing to check a digest against &mdash; searching for
<code>${esc(entry.id)}</code> in the app will not find it. Once the author publishes a GitHub
Release and this listing carries a digest, installing it becomes: open Astra, go to
<strong>Plugins</strong>, search that id.</p>
${noLink}`;
  }

  const blocking = hits.filter((h) => h.action !== "warn");
  if (blocking.length) {
    return `<h2>Installing it</h2>
<p>This plugin has been withdrawn &mdash; see the notice at the top of this page &mdash; and Astra
will refuse to install it. No instruction is given here for getting around that.</p>
${noLink}`;
  }

  // What the digest is checked against, said at the strength it actually has.
  const anchored = meta.signatures.length > 0 && meta.roots > 0;
  const check = anchored
    ? `checks the SHA-256 against the signed catalogue before anything is unpacked`
    : meta.signatures.length > 0
      ? `checks the SHA-256 against this catalogue before anything is unpacked &mdash; though no
         Astra can verify who signed this catalogue yet: no trust root has been published, so a
         shipped daemon fails closed on the signature rather than accepting it (SECURITY.md &sect;4)`
      : `would check the SHA-256 against the catalogue before unpacking anything &mdash; but these
         pages were generated from an <strong>unsigned</strong> catalogue, which happens on a pull
         request and on a fork. A catalogue in that state is for inspection, not for install`;

  return `<h2>Install it</h2>
<p>Open Astra, go to <strong>Plugins</strong>, and search for <code>${esc(entry.id)}</code>.
Astra downloads it from the author&rsquo;s GitHub Release, ${check}, and shows you what it is
asking for before it starts.</p>
${noLink}`;
}

/** The full page. */
export function pluginPage(entry, { revocations = [], meta, highRisk = [] }) {
  const releases = entry.releases ?? [];
  const latest = releases[0] ?? {};
  const hits = withdrawalsFor(entry, revocations);

  const withdrawal = hits.length
    ? `<div class="alert danger">
<h2>Withdrawn</h2>
${hits
  .map(
    (h) => `<p><strong>${esc(h.id)}</strong> &middot; ${esc(h.severity)} &middot;
<code>${esc(h.action)}</code><br>${esc(h.reason)}<br>
<span class="thin">${esc(ACTION_MEANING[h.action] ?? "")}</span>
${h.advisory_url ? ` <a href="${href(h.advisory_url)}">Advisory</a>` : ""}
<a href="../../advisory/${esc(h.id)}/">Details</a></p>`,
  )
  .join("")}
</div>`
    : "";

  const staging = entry.staging
    ? `<div class="alert">
<h2>Not installable</h2>
<p>This entry is <strong>staging</strong>: no release artifact exists yet, so there is no digest to
pin and Astra will refuse to install it. It is listed so the catalogue&rsquo;s shape can be reviewed
before any bytes exist, and <code>tools/validate.mjs</code> only tolerates it behind an explicit
<code>--allow-staging</code>.</p>
${latest.staging_reason ? `<p class="thin">${esc(latest.staging_reason)}</p>` : ""}
</div>`
    : "";

  const meta1 = [
    entry.author
      ? entry.author_url
        ? `<a href="${href(entry.author_url)}">${esc(entry.author)}</a>`
        : esc(entry.author)
      : "",
    esc(entry.license),
    `<a href="${href(entry.repository_url)}">${esc(entry.source?.repo ?? "source")}</a>`,
    entry.homepage ? `<a href="${href(entry.homepage)}">homepage</a>` : "",
  ]
    .filter(Boolean)
    .join(" &middot; ");

  const releaseSections = releases
    .map(
      (r) => `<section class="release">
<h3>${esc(r.version)} ${r.staging ? badge("staging", "warn") : ""}</h3>
<p class="thin">published ${esc(r.published_at)}${r.protocol !== undefined ? ` &middot; protocol ${esc(r.protocol)}` : ""}${
        r.min_astra_version ? ` &middot; needs Astra ${esc(r.min_astra_version)} or newer` : ""
      }${r.capabilities?.length ? ` &middot; capabilities: ${esc(r.capabilities.join(", "))}` : ""}</p>
<div class="scroll"><table><thead><tr><th>Target</th><th>File</th><th>Size</th><th>SHA-256</th></tr></thead>
<tbody>${artifactRows(r)}</tbody></table></div>
${permissionRows(r, highRisk)}
</section>`,
    )
    .join("");

  const body = `
<article>
<header class="plugin">
  ${entry.icon_url ? `<img class="icon" src="${href(entry.icon_url)}" alt="" width="64" height="64">` : ""}
  <div>
    <h1>${esc(entry.name)}</h1>
    <p class="id"><code>${esc(entry.id)}</code> &middot; ${esc(entry.version)}</p>
    <p class="thin">${meta1}</p>
  </div>
</header>

${withdrawal}
${staging}

<p class="summary">${esc(entry.description)}</p>
${entry.details ? `<p>${esc(entry.details)}</p>` : ""}

${
  entry.keywords?.length || entry.categories?.length
    ? `<p class="tags">${[...(entry.categories ?? []), ...(entry.keywords ?? [])]
        .map((k) => `<span class="tag">${esc(k)}</span>`)
        .join("")}</p>`
    : ""
}

${installBlock(entry, meta, hits)}

<h2>Releases</h2>
${releaseSections}

<h2>Where these bytes come from</h2>
${provenance(entry, latest, meta)}
${verifyBlock(entry, latest)}
</article>
`;

  return page({
    title: `${entry.name} — Astra plugin registry`,
    description: entry.description,
    depth: 2,
    active: "",
    body,
  });
}
