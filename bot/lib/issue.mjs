// The two facts, out of an issue body.
//
// GitHub renders an issue FORM into markdown before anyone — human or bot —
// ever sees it: each field becomes `### <label>` followed by the value, and an
// unfilled optional field becomes the literal `_No response_`. There is no
// structured payload, so this is the parse.
//
// It is deliberately tiny, and everything it produces is treated as a
// stranger's text: `bot/ingest.mjs` matches the repository against
// `^owner/name$` and the tag against a conservative charset before either
// reaches a URL or an argument list. Nothing here is trusted, and nothing here
// is the only thing standing between a submitter and a shell.
//
// It also reads the confirmations, because a checkbox that is required by the
// template and never read is a checkbox that means nothing. What they buy is
// small and worth stating: the submitter has asserted ownership *in writing*,
// which is not evidence but is the difference between a mistake and a lie.

const FIELD_LABELS = {
  repo: ["source repository"],
  tag: ["release tag carrying the .astraplugin assets", "release tag"],
  why: ["what does it do, and why should it be listed?"],
};

/**
 * @param {string} body the issue body, as GitHub renders a form
 * @returns {{repo: string|null, tag: string|null, why: string|null,
 *            confirmations: {label: string, checked: boolean}[]}}
 */
export function parseIssueForm(body) {
  const text = String(body ?? "").replace(/\r\n/g, "\n");
  /** @type {Map<string, string>} */
  const sections = new Map();
  let current = null;
  const buffer = [];
  const flush = () => {
    if (current !== null) sections.set(current, buffer.join("\n").trim());
    buffer.length = 0;
  };
  for (const line of text.split("\n")) {
    const heading = /^#{1,6}\s+(.+?)\s*$/.exec(line);
    if (heading) {
      flush();
      current = heading[1].trim().toLowerCase();
      continue;
    }
    if (current !== null) buffer.push(line);
  }
  flush();

  const pick = (names) => {
    for (const n of names) {
      const v = sections.get(n);
      // An unfilled optional field is this exact string, and reading it as a
      // value would send `_No response_` to the GitHub API as a tag.
      if (v && v !== "_No response_") return v;
    }
    return null;
  };

  // Single-line fields: take the first line and strip the decorations people
  // add without thinking — a leading `@`, backticks, a trailing slash, and the
  // full URL when somebody pastes the address bar instead of the name.
  const oneLine = (v) => {
    if (!v) return null;
    let s = v.split("\n")[0].trim().replace(/^`+|`+$/g, "").trim();
    s = s.replace(/^@/, "").replace(/^https?:\/\/github\.com\//i, "");
    s = s.replace(/\/+$/, "").replace(/\.git$/, "").replace(/\/+$/, "");
    return s || null;
  };

  const confirmations = [...text.matchAll(/^\s*-\s*\[( |x|X)\]\s*(.+?)\s*$/gm)].map((m) => ({
    checked: m[1].toLowerCase() === "x",
    label: m[2],
  }));

  return {
    repo: oneLine(pick(FIELD_LABELS.repo)),
    tag: oneLine(pick(FIELD_LABELS.tag)),
    why: pick(FIELD_LABELS.why),
    confirmations,
  };
}

/**
 * `/recheck` in a comment, and nothing else.
 *
 * Case-insensitive, must be the whole first line, so a sentence that merely
 * mentions the command does not run it. Anyone may say it — the bot verifies
 * everything from scratch every time, so the worst a stranger can do by
 * spamming it is make the registry re-check a listing that is already pinned to
 * a repository identity (PRODUCTION_PLAN task 3.4 makes the same argument for
 * the release ping).
 */
export function isRecheckCommand(comment) {
  return /^\s*\/recheck\s*$/i.test(String(comment ?? "").split("\n")[0] ?? "");
}
