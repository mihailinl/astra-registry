// Escaping, the page shell, and a deliberately small Markdown subset.
//
// Three rules this file exists to hold.
//
// 1. EVERY string that reaches a page goes through `esc`. Almost all of them
//    come from a listing somebody else wrote — a name, a summary, a keyword, a
//    withdrawal reason. `tools/lib/ids.mjs`'s `unsafeDisplayText` already keeps
//    bidi overrides and zero-width joiners out of those fields, and that is a
//    *content* rule; this is the *encoding* rule, and a static site generator
//    that relies on the content rule for its escaping has one bug between a
//    stranger and script execution on the registry's own origin.
//
// 2. NO framework, and no dependency. This repository has none anywhere else,
//    on purpose (see .github/workflows/build-index.yml), and a site generator
//    that needed `npm ci` would be a site generator that cannot be rebuilt on
//    the day a package registry is down — which is the day a withdrawal notice
//    most needs republishing.
//
// 3. EVERY link is RELATIVE. GitHub Pages for this repository serves from
//    `https://<owner>.github.io/astra-registry/`, a base path, and a root-
//    relative `/p/dice-roller/` would 404 there while working perfectly in a
//    local preview. Relative links also make the whole tree work from a
//    `file://` checkout, which is how it gets reviewed.

/** HTML-escape. Applied to every interpolated value without exception. */
export function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Escape a value that lands in an `href`.
 *
 * `esc` is not enough on its own: `javascript:alert(1)` contains no character
 * `esc` touches. Listings carry `homepage`, `icon_url` and artifact URLs, all
 * written by a stranger, and `tools/validate.mjs` requires https for the ones
 * it knows about — this refuses anything else a second time, at the point of
 * use, because a scheme check that lives only in the validator protects only
 * the documents the validator has seen.
 */
export function href(url) {
  const s = String(url ?? "").trim();
  if (!/^https:\/\//i.test(s) && !/^(\.|[a-z0-9-]+\/|#|mailto:)/i.test(s)) return "";
  return esc(s);
}

/** `a/b/c` -> `../../` — how many hops back to the site root. */
export function upTo(depth) {
  return depth === 0 ? "" : "../".repeat(depth);
}

/**
 * The page shell.
 *
 * One stylesheet, no script except where a page asks for one, and a `<meta
 * name="robots">` that is deliberately absent: a catalogue that does not want
 * to be indexed is a catalogue nobody can find, and everything here is public
 * by construction.
 */
export function page({ title, description, depth = 0, body, script = "", active = "" }) {
  const up = upTo(depth);
  // `active` is a key, not a path, so that a page with no nav entry of its own
  // — a plugin page, a publisher page — can pass "" and highlight nothing,
  // rather than accidentally matching the catalogue's empty path.
  const nav = [
    ["catalogue", "", "Catalogue"],
    ["search", "search/", "Search"],
    ["publish", "publish/", "Publish"],
    ["policy", "policy/", "Policy"],
    ["security", "security/", "Security"],
    ["transparency", "transparency/", "Transparency"],
  ]
    .map(
      ([key, path, label]) =>
        `<a href="${esc(up + path)}"${active === key ? ' aria-current="page"' : ""}>${esc(label)}</a>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description ?? "")}">
<link rel="stylesheet" href="${esc(up)}assets/site.css">
</head>
<body>
<header class="site">
  <a class="brand" href="${esc(up)}">Astra plugin registry</a>
  <nav>${nav}</nav>
</header>
<main>
${body}
</main>
<footer class="site">
  <p><strong>A listed plugin runs as a native program with your full user account access.</strong>
  Being in this catalogue is not a safety review and not an endorsement.</p>
  <p class="thin">Generated from the catalogue this site was published with &mdash;
  <a href="${esc(up)}registry/v1/index.json">registry/v1/index.json</a>.
  A page exists here if and only if that file has an entry for it.
  Whether that file is signed, and by what, is on each plugin&rsquo;s page.</p>
</footer>
${script ? `<script src="${esc(up)}assets/${esc(script)}"></script>` : ""}
</body>
</html>
`;
}

// ── the Markdown subset ─────────────────────────────────────────────────────
//
// WHY RENDER MARKDOWN AT ALL, rather than hand-writing /policy/ and /security/
// as templates: because then there would be two policies. The repository's
// POLICY.md, docs/POLICY.md and SECURITY.md are the documents the maintainer
// edits and reviewers read in a diff; a second copy in a template is a copy that
// is wrong within a month. So the site renders those files, and the site cannot
// state a rule the repository does not.
//
// WHAT IS SUPPORTED, and nothing else: ATX headings, paragraphs, GFM tables,
// `-`/`*` and `1.` lists, fenced code, blockquotes, `---` rules, and the inline
// set (`code`, **bold**, *italic*, links). Anything outside that renders as its
// own literal text rather than as markup — a renderer that guesses is a
// renderer that eventually guesses an unescaped `<script>` into the page.

function inline(text) {
  // Code spans first, and their contents are removed from the string before any
  // other rule runs: `**` inside backticks is two asterisks, not emphasis.
  //
  // The placeholder is delimited by NUL, which `esc` leaves alone and which a
  // source document cannot contain. A placeholder made of ordinary characters
  // — ` 0 `, say — would be substituted back out of any prose that happened to
  // contain that number.
  const spans = [];
  let s = String(text).replace(/`([^`]+)`/g, (_, code) => {
    spans.push(`<code>${esc(code)}</code>`);
    return `\u0000${spans.length - 1}\u0000`;
  });

  s = esc(s);
  // [label](url) — the URL goes through `href`, so a `javascript:` link in a
  // document renders as a link to nowhere rather than as a working one.
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, url) => {
    const safe = href(url);
    return safe ? `<a href="${safe}">${label}</a>` : label;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>");
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => spans[Number(i)]);
}

/** Split a table row on `|`, leaving pipes inside code spans alone. */
function cells(row) {
  const out = [];
  let cur = "";
  let inCode = false;
  for (const ch of row.trim().replace(/^\||\|$/g, "")) {
    if (ch === "`") inCode = !inCode;
    if (ch === "|" && !inCode) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out.map((c) => c.trim());
}

/**
 * Render the subset above.
 *
 * @param {string} md
 * @returns {string} HTML
 */
export function markdown(md) {
  const lines = String(md).replace(/\r\n/g, "\n").split("\n");
  const out = [];
  let para = [];

  const flush = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("```")) {
      flush();
      const lang = line.slice(3).trim();
      const buf = [];
      for (i++; i < lines.length && !lines[i].startsWith("```"); i++) buf.push(lines[i]);
      out.push(`<pre${lang ? ` data-lang="${esc(lang)}"` : ""}><code>${esc(buf.join("\n"))}</code></pre>`);
      continue;
    }

    if (/^\s*$/.test(line)) {
      flush();
      continue;
    }

    if (/^---+\s*$/.test(line)) {
      flush();
      out.push("<hr>");
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length;
      const text = inline(heading[2]);
      // A stable anchor, so docs/POLICY.md can be deep-linked from the app and
      // from an issue comment. Derived from the heading text, which is what a
      // reader would guess.
      const id = heading[2]
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
      out.push(`<h${level} id="${esc(id)}">${text}</h${level}>`);
      continue;
    }

    // A GFM table: a header row, a delimiter row, then body rows.
    if (line.includes("|") && /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(lines[i + 1] ?? "")) {
      flush();
      const head = cells(line);
      i++;
      const rows = [];
      while (i + 1 < lines.length && lines[i + 1].includes("|")) {
        rows.push(cells(lines[++i]));
      }
      out.push(
        `<div class="scroll"><table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>` +
          `<tbody>${rows
            .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`)
            .join("")}</tbody></table></div>`,
      );
      continue;
    }

    const quote = /^>\s?(.*)$/.exec(line);
    if (quote) {
      flush();
      const buf = [quote[1]];
      while (i + 1 < lines.length && /^>\s?/.test(lines[i + 1])) buf.push(lines[++i].replace(/^>\s?/, ""));
      out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`);
      continue;
    }

    const item = /^\s*([-*]|\d+\.)\s+(.*)$/.exec(line);
    if (item) {
      flush();
      const ordered = !/^[-*]$/.test(item[1]);
      const items = [item[2]];
      while (i + 1 < lines.length) {
        const next = /^\s*([-*]|\d+\.)\s+(.*)$/.exec(lines[i + 1]);
        if (next && /^[-*]$/.test(next[1]) !== ordered) {
          items.push(next[2]);
          i++;
        } else if (/^\s{2,}\S/.test(lines[i + 1] ?? "")) {
          // A continuation line, indented under its bullet.
          items[items.length - 1] += ` ${lines[++i].trim()}`;
        } else break;
      }
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</${tag}>`);
      continue;
    }

    para.push(line.trim());
  }
  flush();
  return out.join("\n");
}
