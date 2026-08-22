// The icon and the README, lifted out of a bundle the attestation already covers.
//
// These are the two files a plugin author writes for a HUMAN rather than for the
// daemon, and until now the registry threw them away: `icon_url` was retyped by
// hand into plugin.json and the README was not carried at all, so Astra's store
// showed a wall of identical grey cards with one line of text each.
//
// Both come out of the bundle, which means both are covered by the build
// attestation — the same reason §3.5 derives every other listing field from
// there rather than from a form. Nobody types a URL, so nobody can type a URL
// pointing somewhere the bundle does not.
//
// ── the part that needs care ────────────────────────────────────────────────
//
// Everything here is a STRANGER'S CONTENT that Astra will render in its own
// window. That is a different risk from the rest of the bundle: the binary is
// executed behind a consent sheet the user reads, while an icon and a README
// are shown to a user who has not agreed to anything yet — they are what the
// user reads in order to decide. So they are sanitised at derive time, on the
// registry's machine, and what reaches a user is the sanitised copy.
//
// Defence in depth, not defence in one place: `react-markdown` ignores raw HTML
// by default and `<img>` does not execute scripts in an SVG. Both of those are
// true today, neither is written down anywhere Astra's UI can enforce, and a
// future maintainer adding `rehype-raw` for a legitimate reason should not be
// able to turn a catalogue listing into script execution. So the bytes are
// cleaned here as well.

/**
 * The icon formats, in the order they are preferred when a bundle ships more
 * than one, with the media type each is inlined under and the signature each
 * has to actually begin with.
 *
 * PNG first because it is lossless and has an alpha channel, which is what a
 * card icon wants; WebP next for the same reasons; SVG after those because it
 * scales best but is the one format that is also a document; JPEG below them
 * because it has no transparency and puts ringing artefacts around flat art;
 * ICO last. ICO is a Windows multi-resolution container — Chromium renders it,
 * so it works, but it is a favicon format and nothing about a store card wants
 * one. It is accepted so that an author who has one is not stuck.
 *
 * `magic` is `null` for SVG alone, which is text and is checked by parsing
 * rather than by a prefix.
 */
export const ICON_FORMATS = [
  { name: "icon.png", media: "image/png", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { name: "icon.webp", media: "image/webp", magic: [0x52, 0x49, 0x46, 0x46], also: { at: 8, bytes: [0x57, 0x45, 0x42, 0x50] } },
  { name: "icon.svg", media: "image/svg+xml", magic: null },
  { name: "icon.jpg", media: "image/jpeg", magic: [0xff, 0xd8, 0xff] },
  { name: "icon.jpeg", media: "image/jpeg", magic: [0xff, 0xd8, 0xff] },
  { name: "icon.ico", media: "image/x-icon", magic: [0x00, 0x00, 0x01, 0x00] },
];

/** Icon filenames the packer ships, in the order they are preferred. */
export const ICON_NAMES = ICON_FORMATS.map((f) => f.name);
export const README_NAME = "README.md";

/**
 * 128 KiB.
 *
 * A store card draws this at somewhere around 48–64 CSS pixels, so the honest
 * size is single-digit kilobytes and every icon in the catalogue today is under
 * 3 KB. The cap is set well above that because the file an author actually has
 * is usually whatever their designer exported — a 512×512 PNG straight out of
 * Figma — and refusing that over a number they did not choose is a bad first
 * experience for a decorative file. It still bounds the index: this is inlined,
 * so the cap is also the per-listing cost of carrying it.
 */
export const MAX_ICON_BYTES = 128 * 1024;
/**
 * 16 KiB of markdown — several screens of prose. See the contract note on when
 * this moves out of the index.
 *
 * BYTES, measured as UTF-8, because bytes are the thing being bounded: this
 * markdown is inlined into `registry/v1/index.json`, one signed document every
 * install fetches whole, and the ceiling that document is held to is a byte
 * count.
 *
 * It used to be compared against `text.length`, which is neither bytes nor
 * characters but UTF-16 code units. A Chinese character is one unit and three
 * bytes, so 16,384 units of Chinese is 49,152 bytes and passed. Every README in
 * the catalogue is close enough to ASCII for the two numbers to look like the
 * same number, which is why nothing noticed — until `sub-models-for-astra`,
 * whose committed README was 16,289 units and 16,390 bytes: six bytes over the
 * budget its own truncation notice said it was inside. It was the truncator
 * below that produced it.
 */
export const MAX_README_BYTES = 16 * 1024;

/**
 * Image hosts a README may point at.
 *
 * Not an anti-malware measure — it is a PRIVACY one. Every remote image in a
 * rendered README is a request from the user's machine, made before they have
 * installed anything, carrying their IP to whoever the author named. A badge
 * service or an analytics pixel dressed as a screenshot would turn opening the
 * store into an announcement to a dozen third parties.
 *
 * GitHub's own asset hosts are allowed because the listing already points at
 * GitHub for the download, so no NEW party learns anything. Everything else is
 * dropped to its alt text rather than rejected: an author should not have a
 * listing refused over a build badge.
 */
export const ALLOWED_IMAGE_HOSTS = new Set([
  "raw.githubusercontent.com",
  "user-images.githubusercontent.com",
  "camo.githubusercontent.com",
  "github.com",
]);

/**
 * The SVG constructs that make an image a program.
 *
 * `<img src="…svg">` is a "secure static mode" in every browser engine — no
 * script, no external fetch — so on today's rendering path none of these can
 * fire. They are refused anyway because that guarantee belongs to the *call
 * site*, and the call site is in another repository: an SVG inlined into a
 * stylesheet, dropped into `dangerouslySetInnerHTML`, or opened in a preview
 * tab loses it silently. An icon has no legitimate reason to contain any of
 * this, so refusing costs an honest author nothing.
 */
const SVG_HAZARDS = [
  [/<script[\s>]/i, "a <script> element"],
  [/<foreignObject[\s>]/i, "a <foreignObject> element"],
  [/<!ENTITY/i, "an entity declaration (XXE)"],
  [/\son[a-z]+\s*=/i, "an inline event handler"],
  [/javascript:/i, "a javascript: URL"],
  [/<use\b[^>]*\bhref\s*=\s*["']?https?:/i, "an external <use> reference"],
  [/<image\b[^>]*href\s*=\s*["']?https?:/i, "an external <image> reference"],
];

/**
 * Pick the icon out of a bundle's file list.
 *
 * A raster format wins over SVG when both are present. Not a judgement about
 * which looks better — it is that a raster image has no execution semantics at
 * all, so the common case never rests on the SVG hardening below being
 * complete.
 *
 * @param {{name: string, bytes: Buffer}[]} files
 * @returns {{name: string, bytes: Buffer}|null}
 */
export function pickIcon(files) {
  for (const want of ICON_NAMES) {
    const hit = files.find((f) => f.name === want);
    if (hit) return hit;
  }
  return null;
}

/** The format record for a filename, or null if it is not an icon name at all. */
function formatOf(name) {
  return ICON_FORMATS.find((f) => f.name === name) ?? null;
}

/**
 * Is this actually the image its filename claims?
 *
 * A `.png` that is really an SVG would be written to the registry, inlined with
 * an `image/png` media type, and then sniffed as SVG by the renderer — which is
 * how a "PNG" comes to hold a script. Checked by content, never by extension.
 *
 * @param {{name: string, bytes: Buffer}} icon
 * @returns {{level: string, code: string, message: string}[]}
 */
export function checkIcon(icon) {
  const findings = [];
  const err = (message) => findings.push({ level: "error", code: "E_ICON_UNUSABLE", message });

  if (icon.bytes.length === 0) {
    err(`${icon.name} is empty`);
    return findings;
  }
  if (icon.bytes.length > MAX_ICON_BYTES) {
    err(`${icon.name} is ${icon.bytes.length} bytes, over the ${MAX_ICON_BYTES}-byte cap for an icon`);
  }

  const format = formatOf(icon.name);
  if (!format) {
    err(`${icon.name} is not one of ${ICON_NAMES.join(", ")}`);
    return findings;
  }

  if (format.magic) {
    // By CONTENT, never by extension. A file named .png that is really an SVG
    // would be written to the registry, inlined under an `image/png` media type
    // and then sniffed back as SVG by the renderer — which is how a "PNG" comes
    // to hold a script.
    const starts = (at, bytes) => icon.bytes.subarray(at, at + bytes.length).equals(Buffer.from(bytes));
    if (!starts(0, format.magic) || (format.also && !starts(format.also.at, format.also.bytes))) {
      err(`${icon.name} does not begin with the ${format.media} signature, whatever its name says`);
    }
    return findings;
  }

  // SVG: text, so it is read as text.
  const raw = icon.bytes.toString("utf8");
  if (!/<svg[\s>]/i.test(raw)) {
    err(`${icon.name} contains no <svg> element`);
    return findings;
  }
  // Comments out FIRST. An XML comment is inert — no parser has ever executed
  // one — so scanning it can only produce false refusals, and it produced one
  // immediately: `astra-plugin new` scaffolds an icon whose header comment
  // tells the author "no <script>, no <foreignObject>", and the very act of
  // documenting the rule tripped it. An honest icon must not be refused for
  // quoting the rule it obeys.
  //
  // This loses nothing. Hiding a live element inside a comment is not a way to
  // execute it; it is a way to not execute it.
  const text = raw.replace(/<!--[\s\S]*?-->/g, " ");
  for (const [re, what] of SVG_HAZARDS) {
    if (re.test(text)) {
      err(`${icon.name} contains ${what}; an icon must be a picture, not a program`);
    }
  }
  return findings;
}

/**
 * `data:` URI for the index, so the store renders with no network request.
 * @param {{name: string, bytes: Buffer}} icon
 */
export function iconDataUri(icon) {
  const format = formatOf(icon.name);
  if (!format) throw new Error(`${icon.name} is not an icon filename`);
  return `data:${format.media};base64,${icon.bytes.toString("base64")}`;
}

/** Fenced-code tracking, so nothing below rewrites an example someone is documenting. */
function* linesOutsideFences(text) {
  let fence = null;
  for (const line of text.split("\n")) {
    const m = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (fence) {
      if (m && line.trimStart().startsWith(fence)) fence = null;
      yield { line, inFence: true };
      continue;
    }
    if (m) {
      fence = m[1];
      yield { line, inFence: true };
      continue;
    }
    yield { line, inFence: false };
  }
}

/** Strip HTML tags, leaving their text. Never inside a fence, never inside inline code. */
function stripHtml(text) {
  const out = [];
  let stripped = 0;
  for (const { line, inFence } of linesOutsideFences(text)) {
    if (inFence) {
      out.push(line);
      continue;
    }
    // Split on inline-code spans and only rewrite what is between them.
    const parts = line.split(/(`+[^`]*`+)/);
    const rebuilt = parts.map((part) => {
      if (part.startsWith("`")) return part;
      return part.replace(/<\/?[a-zA-Z][^>]*>/g, () => {
        stripped += 1;
        return "";
      });
    });
    out.push(rebuilt.join(""));
  }
  return { text: out.join("\n"), stripped };
}

/** Resolve one image URL, or return null to drop the image. */
function resolveImageUrl(raw, { repo, commit }) {
  const url = raw.trim();
  if (url === "") return null;

  if (/^https:\/\//i.test(url)) {
    let host;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }
    return ALLOWED_IMAGE_HOSTS.has(host) ? url : null;
  }
  // Any other scheme — http:, data:, javascript:, mailto: — is dropped rather
  // than downgraded. `data:` in particular is how a 4 MB image arrives inside a
  // 16 KB budget.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) return null;
  if (url.startsWith("//")) return null;
  if (url.startsWith("#")) return null;

  // Relative, so it names a file in the author's repository at the commit this
  // release was built from. Pinning to the commit rather than to a branch is
  // what stops the picture changing after a human approved the listing.
  if (!commit) return null;
  const clean = url.replace(/^\.\//, "").replace(/^\//, "");
  if (clean.split("/").includes("..")) return null;
  const encoded = clean.split("/").map(encodeURIComponent).join("/");
  return `https://raw.githubusercontent.com/${repo}/${commit}/${encoded}`;
}

/**
 * The longest prefix of `text` that fits in `budget` UTF-8 bytes.
 *
 * `Buffer.prototype.write` stops on a code-point boundary — it will not emit a
 * partial UTF-8 sequence, and a surrogate pair is one code point of four bytes,
 * so it is all or nothing. That is the property this function exists for.
 * Slicing the string instead measures UTF-16 units and can cut a character in
 * half; see the note at the cap below for what a half character costs.
 *
 * Exported for one reason: whether a cut lands between the halves of a
 * surrogate pair depends on the exact budget, and the budget here depends on
 * the length of a repository name. A test that goes through `rewriteReadme`
 * therefore proves the property for one arithmetic accident and not for the
 * next one — which is what it did, until the mutation that reverts this
 * function to `text.slice` was run and the test stayed green.
 */
export function cutToBytes(text, budget) {
  if (budget <= 0) return "";
  if (Buffer.byteLength(text, "utf8") <= budget) return text;
  const buf = Buffer.alloc(budget);
  const written = buf.write(text, 0, budget, "utf8");
  return buf.toString("utf8", 0, written);
}

/**
 * The README as it will be stored and rendered.
 *
 * Raw HTML out, images resolved against the attested commit or dropped to their
 * alt text, and a hard cap. Returns the rewritten markdown plus findings that
 * describe every change made — an author is told what happened to their file
 * rather than discovering it in the store.
 *
 * @param {string} source
 * @param {{repo: string, commit: string|null}} at
 * @returns {{markdown: string, findings: {level: string, code: string, message: string}[]}}
 */
export function rewriteReadme(source, { repo, commit }) {
  const findings = [];
  const note = (message) => findings.push({ level: "note", code: "N_README_REWRITTEN", message });

  // Normalise line endings first: a CRLF file would otherwise keep a stray \r
  // at the end of every line and render with ragged spacing.
  let text = source.replace(/\r\n?/g, "\n");

  const html = stripHtml(text);
  text = html.text;
  if (html.stripped > 0) {
    note(`${html.stripped} HTML tag(s) removed — the store renders markdown only`);
  }

  let dropped = 0;
  let pinned = 0;
  const rewriteInline = (line) =>
    line.replace(/!\[([^\]]*)\]\(\s*(<[^>]*>|[^\s)]+)([^)]*)\)/g, (whole, alt, target, tail) => {
      const bare = target.startsWith("<") ? target.slice(1, -1) : target;
      const resolved = resolveImageUrl(bare, { repo, commit });
      if (resolved === null) {
        dropped += 1;
        return alt ? `*${alt}*` : "";
      }
      if (resolved !== bare) pinned += 1;
      return `![${alt}](${resolved}${tail})`;
    });

  const rewritten = [];
  for (const { line, inFence } of linesOutsideFences(text)) {
    if (inFence) {
      rewritten.push(line);
      continue;
    }
    // Reference-style definitions: `[label]: url "title"`.
    const ref = /^(\s{0,3}\[[^\]]+\]:\s*)(\S+)(.*)$/.exec(line);
    if (ref) {
      const resolved = resolveImageUrl(ref[2], { repo, commit });
      // A definition can be a link target as well as an image target, and this
      // cannot tell them apart. Keep it when it resolves; leave it alone when it
      // does not, because dropping it would break ordinary links too.
      if (resolved !== null && resolved !== ref[2]) {
        pinned += 1;
        rewritten.push(`${ref[1]}${resolved}${ref[3]}`);
        continue;
      }
      rewritten.push(line);
      continue;
    }
    rewritten.push(rewriteInline(line));
  }
  text = rewritten.join("\n");

  if (pinned > 0) {
    note(`${pinned} image(s) pinned to ${repo}@${(commit ?? "").slice(0, 12)}`);
  }
  if (dropped > 0) {
    note(`${dropped} image(s) dropped — only GitHub's own asset hosts are rendered, so the store makes no request to a third party`);
  }

  text = `${text.replace(/\n{3,}/g, "\n\n").trim()}\n`;

  // The cap, and the two things the old cut got wrong.
  //
  // It reserved 200 UTF-16 units for a footer whose real cost is bytes, so its
  // own output could come out over the cap that produced it — which is what
  // happened to `sub-models-for-astra`. The reserve is now the footer's actual
  // byte length, so the result is inside the cap by construction.
  //
  // And its fallback path, `cut.slice(0, cut.length)` when the prose holds no
  // newline, is a raw UTF-16 cut that can land between the halves of a
  // surrogate pair. That leaves a lone surrogate in a string that
  // `tools/build-index.mjs` inlines into the signed catalogue, which
  // `serde_json` then refuses whole. `cutToBytes` cannot do that: it writes
  // whole code points or nothing.
  if (Buffer.byteLength(text, "utf8") > MAX_README_BYTES) {
    const footer =
      `\n\n---\n\n*This README was truncated. [Read the rest on GitHub](https://github.com/${repo}).*\n`;
    const budget = Math.max(0, MAX_README_BYTES - Buffer.byteLength(footer, "utf8"));
    const cut = cutToBytes(text, budget);
    const atLine = cut.lastIndexOf("\n");
    text = `${(atLine > 0 ? cut.slice(0, atLine) : cut).trimEnd()}${footer}`;
    note(`README truncated to ${MAX_README_BYTES} bytes`);
  }

  return { markdown: text, findings };
}
