// ROLL-63's deadline watch, as a pure judgement over dates (registry plan
// M-T5.4). `tools/deadline-watch.mjs` gathers the inputs — the tree, the
// markers' history, the clock, the banner — and this decides.
//
// ── WHAT IT ALARMS ON ──────────────────────────────────────────────────────
//
//   (a) round 2 cannot give MIG-2's 60 days any more: the deadline is under
//       60 days away and no round-2 marker is on `main`, or the round-2
//       marker's `sent_at` is under 60 days before the deadline.
//   (b) the deadline is under 30 days away and `log/cutover.json` is not on
//       `main` — MIG-29 keeps it at least 30 days after cutover.
//   (c) the deadline is under 14 days away and no round-3 marker is on
//       `main`, or round 3's `sent_at` is under 14 days before it (MIG-13).
//   guard n22: a marker's `cutover_planned_at` moved EARLIER while its
//       `sent_at` stayed the same. An earlier date is a new round 2 with a new
//       `sent_at`; the same `sent_at` means the procedure was done wrong, and
//       every clock that counts from it counts from a date the authors were
//       never given notice of.
//   guard n28: a marker on `main` announces a cutover date the authoritative
//       one (the highest `round` present) does not.
//   banner: the listing banner MIG-13 names says something the records do
//       not, read from the hooks contract 2.7.0 publishes on the page: its
//       `cutover-planned` date is not the authoritative marker's (or is there
//       before any marker carries one, or missing once one does), its
//       `binding-deadline` is not `policy/binding-deadline.json`'s, or its
//       round is not the highest marker's; or it carries a hook twice, which
//       makes it ambiguous. minice-be's banner took its date from an owner-set
//       knob and not from the marker, so a re-send could move the marker and
//       leave the banner behind, silently on both sides.
//
// **It reads `sent_at`, never a commit's date.** A re-send that re-commits
// round 2's marker with a later cutover keeps its `sent_at`, and (a) keyed on
// the commit would count 60 days from the re-commit and fire about a round
// the authors already had.
//
// **No deadline is a state, not a finding** (BOT-72): there is nothing to
// count down to, and the watch says so. The two guards still run, because a
// marker announcing a superseded date is wrong whether or not a deadline has
// been committed.
//
// **It never waits.** It compares the clock it is handed with dates; a
// fixture clock is a `now` argument.

import { isTime } from "./time.mjs";
import { authoritative } from "./migration-notice.mjs";

const DAY_MS = 86_400_000;

export const ROUND2_DAYS = 60;
export const CUTOVER_DAYS = 30;
export const ROUND3_DAYS = 14;

/** The check this watch reports as, in `bot/lib/alert-checks.mjs`. */
export const CHECK = "deadline-watch";

/** The fixed codes a verdict may carry (bot/lib/alert-verdict.mjs: no sentences). */
export const CODES = Object.freeze({
  round2: "DEADLINE_ROUND2_UNFIT",
  cutover: "DEADLINE_NO_CUTOVER",
  round3: "DEADLINE_ROUND3_UNFIT",
  earlier: "MARKER_EARLIER_SAME_SENT_AT",
  superseded: "MARKER_DATE_SUPERSEDED",
  unreadable: "MARKER_UNREADABLE",
  bannerDiffers: "BANNER_DATE_DIFFERS",
  bannerDeadline: "BANNER_DEADLINE_DIFFERS",
  bannerRound: "BANNER_ROUND_DIFFERS",
  bannerAmbiguous: "BANNER_HOOKS_AMBIGUOUS",
  bannerUnreachable: "BANNER_UNREACHABLE",
});

const days = (ms) => (ms / DAY_MS).toFixed(1);

/**
 * Guard n22 over one marker file's history, oldest first.
 *
 * Among the versions that share the CURRENT version's `sent_at` — the ones
 * that record this send — the announced date may only have stayed or moved
 * later. The current date being earlier than any of them is n22's wrong turn.
 * A version with a different `sent_at` is a different send (a new round 2),
 * and is not compared: that is the procedure done right.
 *
 * @param history {{sent_at?: string, cutover_planned_at?: string}[]}
 * @returns {string|null} the finding, or null
 */
export function earlierWithSameSentAt(file, history) {
  const readable = history.filter((v) => v && isTime(v.sent_at));
  if (!readable.length) return null;
  const now = readable[readable.length - 1];
  if (!isTime(now.cutover_planned_at)) return null;
  const same = readable.filter((v) => v.sent_at === now.sent_at && isTime(v.cutover_planned_at));
  const latest = same.reduce((a, v) => (Date.parse(v.cutover_planned_at) > Date.parse(a.cutover_planned_at) ? v : a), same[0]);
  if (Date.parse(now.cutover_planned_at) < Date.parse(latest.cutover_planned_at)) {
    return `${file} announced ${latest.cutover_planned_at} and now announces the EARLIER ${now.cutover_planned_at} ` +
      `under the same sent_at ${now.sent_at}. An earlier cutover is a new round 2 with its own sent_at (MIG-13, n22); ` +
      "kept, it leaves every clock counting from a notice of a date that is not the one arriving";
  }
  return null;
}

// ── MIG-13's HOOKS, READ WITHOUT A DOM (contract 2.7.0) ───────────────────
//
// Until 2.7.0 MIG-13 gave the page no form for its dates, so this module
// searched the HTML for the date's text. That passed a page that showed the
// date anywhere — an old round's sentence, the flight payload a Next.js page
// sends in a <script> — and would have alarmed on one that formatted it.
// 2.7.0 publishes the form, and this reads it and nothing else: a start tag
// whose `data-astra` is the hook's name, found by a tokenizer that knows where
// HTML has no tags — comments, the raw text of <script>, <style>, <textarea>,
// <title> and their kin, and the inside of another attribute's quoted value.
// No DOM library: the repository has none, and this needs start tags and
// their attributes, not a tree. What it does not do is check that the two
// <time> hooks sit INSIDE the banner's element; that needs a tree, and a hook
// of either name appearing twice anywhere is already refused.

/** The `data-astra` values MIG-13 publishes on `/plugins/<id>` (contract 2.7.0). */
export const HOOKS = Object.freeze({
  banner: "migration-banner",
  cutover: "cutover-planned",
  deadline: "binding-deadline",
});

/**
 * Elements whose content HTML does not parse as markup: WHATWG's RAWTEXT and
 * RCDATA elements. `noscript` is not among them, because the reader MIG-13
 * names has no JavaScript, and to that reader its content is markup.
 */
const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes"]);

const isSpace = (c) => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f";
const isAlpha = (c) => c !== undefined && /[A-Za-z]/.test(c);

/** The character references an attribute value may carry: numeric, and the five XML names. */
const decode = (v) =>
  v.replace(/&(?:#([0-9]{1,7})|#[xX]([0-9A-Fa-f]{1,6})|(amp|lt|gt|quot|apos));/g, (all, dec, hex, name) => {
    if (name) return { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" }[name];
    const cp = dec !== undefined ? Number(dec) : parseInt(hex, 16);
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : all;
  });

/**
 * Every start tag in `html`, in document order, each with its attributes
 * (names lower-cased, the first of a repeated name kept, values decoded), as
 * WHATWG's tokenizer reads them for the parts a server-rendered page uses. A
 * tag the document ends inside is dropped, as HTML drops it.
 *
 * @returns {{name: string, attrs: Map<string, string>}[]}
 */
export function startTags(html) {
  const n = html.length;
  const tags = [];
  /** From just past a tag's name: its attributes and the index past its `>`, or null at the end of the document. */
  const attributes = (j) => {
    const attrs = new Map();
    for (;;) {
      while (j < n && (isSpace(html[j]) || html[j] === "/")) j++;
      if (j >= n) return null;
      if (html[j] === ">") return [attrs, j + 1];
      let k = j + 1; // a name's first character may even be `=`
      while (k < n && !isSpace(html[k]) && html[k] !== "/" && html[k] !== ">" && html[k] !== "=") k++;
      const name = html.slice(j, k).toLowerCase();
      j = k;
      while (j < n && isSpace(html[j])) j++;
      let value = "";
      if (html[j] === "=") {
        j++;
        while (j < n && isSpace(html[j])) j++;
        const q = html[j];
        if (q === '"' || q === "'") {
          const close = html.indexOf(q, j + 1);
          if (close === -1) return null;
          value = html.slice(j + 1, close);
          j = close + 1;
        } else {
          k = j;
          while (k < n && !isSpace(html[k]) && html[k] !== ">") k++;
          value = html.slice(j, k);
          j = k;
        }
      }
      if (!attrs.has(name)) attrs.set(name, decode(value));
    }
  };
  const nameEnd = (k) => {
    while (k < n && !isSpace(html[k]) && html[k] !== "/" && html[k] !== ">") k++;
    return k;
  };

  let i = 0;
  while (i < n) {
    i = html.indexOf("<", i);
    if (i === -1) break;
    if (html.startsWith("<!--", i)) {
      // `<!-->` and `<!--->` are empty comments; any other runs to `-->`.
      if (html.startsWith(">", i + 4)) i += 5;
      else if (html.startsWith("->", i + 4)) i += 6;
      else {
        const close = html.indexOf("-->", i + 4);
        i = close === -1 ? n : close + 3;
      }
      continue;
    }
    const c = html[i + 1];
    if (c === "!" || c === "?") {
      // A doctype, a CDATA section outside SVG and MathML, a processing
      // instruction: each runs to the next `>`, and none is a tag.
      const close = html.indexOf(">", i + 2);
      i = close === -1 ? n : close + 1;
      continue;
    }
    if (c === "/") {
      if (isAlpha(html[i + 2])) {
        // An end tag. Its attributes are parsed, so that a quoted `>` does not
        // end it early, and dropped: an end tag carries none.
        const r = attributes(nameEnd(i + 2));
        i = r ? r[1] : n;
      } else {
        const close = html.indexOf(">", i + 2);
        i = close === -1 ? n : close + 1;
      }
      continue;
    }
    if (!isAlpha(c)) {
      i += 1; // a `<` in text
      continue;
    }
    const k = nameEnd(i + 1);
    const name = html.slice(i + 1, k).toLowerCase();
    const r = attributes(k);
    if (!r) break;
    tags.push({ name, attrs: r[0] });
    i = r[1];
    if (name === "plaintext") break;
    if (RAW_TEXT.has(name)) {
      // Its text runs to the first `</name` followed by a space, `/` or `>`.
      const close = new RegExp(`</${name}[\\t\\n\\f\\r />]`, "gi");
      close.lastIndex = i;
      const m = close.exec(html);
      i = m ? m.index : n;
    }
  }
  return tags;
}

/**
 * MIG-13's hooks as a page carries them (contract 2.7.0).
 *
 * `round`, `cutover` and `deadline` are the values as served, verbatim, or
 * null where the page draws no hook — which MIG-13 says is how the page shows
 * an absent, null or non-§0.7 value. `problems` are the ways the page is
 * ambiguous: a hook of one name on two elements, the banner twice, or a date
 * hook on an element that is no <time>. A page with a problem is not
 * compared: which of two hooks it means is exactly what it does not say.
 *
 * @param {string|null} body
 * @returns {{problems: string[], banners: number, round: string|null, cutover: string|null, deadline: string|null}}
 */
export function bannerHooks(body) {
  const tags = startTags(typeof body === "string" ? body : "");
  const problems = [];
  const carrying = (hook) => tags.filter((t) => t.attrs.get("data-astra") === hook);
  const banners = carrying(HOOKS.banner);
  if (banners.length > 1) {
    problems.push(`${banners.length} elements carry data-astra="${HOOKS.banner}", and MIG-13 has one banner`);
  }
  const time = (hook) => {
    const found = carrying(hook);
    const others = found.filter((t) => t.name !== "time");
    if (others.length) {
      problems.push(`data-astra="${hook}" is on <${others.map((t) => t.name).join(">, <")}>, and MIG-13's hook is a <time>`);
    }
    if (found.length > 1) {
      problems.push(`${found.length} elements carry data-astra="${hook}", so the page does not say which date it means`);
    }
    return found.length === 1 && !others.length ? (found[0].attrs.get("datetime") ?? "") : null;
  };
  return {
    problems,
    banners: banners.length,
    round: banners.length === 1 ? (banners[0].attrs.get("data-astra-round") ?? null) : null,
    cutover: time(HOOKS.cutover),
    deadline: time(HOOKS.deadline),
  };
}

/**
 * @param {{
 *   deadline: string|null,        policy/binding-deadline.json's value, or null
 *   cutoverOnMain: boolean,       log/cutover.json is on the tree
 *   markers: object[],            tools/lib/migration-notice.mjs readMarkers()
 *   histories: Record<string, object[]>,  each marker file's versions, oldest first
 *   now: string,                  the clock, a §0.7 time
 *   banner: {id: string, url: string, status: number|null, body: string|null}|null,
 *   r4bOpen: boolean,             R4b's registry marker is on the tree; a caller
 *                                 that does not say gets the loud reading of a 404
 * }} input
 * @returns {{status: "red"|"green", codes: string[], ids: string[], detail: string[]}}
 */
export function judge({ deadline, cutoverOnMain, markers, histories = {}, now, banner = null, r4bOpen = true }) {
  const codes = [];
  const ids = [];
  const detail = [];
  const add = (code, line) => { codes.push(code); detail.push(`${code}: ${line}`); };
  if (!isTime(now)) throw new Error(`the clock ${JSON.stringify(now)} is not a §0.7 time`);
  const nowMs = Date.parse(now);

  const { marker: top, problems } = authoritative(markers);
  for (const p of problems) add(CODES.unreadable, p);
  const readable = problems.length ? [] : markers;
  const round = (n) => readable.find((m) => m.doc.round === n) ?? null;

  // The guards first: they are about the markers, deadline or not.
  for (const m of readable) {
    const finding = earlierWithSameSentAt(m.file, histories[m.file] ?? [m.doc]);
    if (finding) add(CODES.earlier, finding);
  }
  const announced = top && top.doc.round >= 2 ? top.doc.cutover_planned_at : null;
  if (announced) {
    detail.push(`authoritative marker: ${top.file} (round ${top.doc.round}), announcing ${announced}`);
    for (const m of readable.filter((x) => x.doc.round >= 2 && x.doc.cutover_planned_at !== announced)) {
      add(CODES.superseded, `${m.file} announces ${m.doc.cutover_planned_at} and the authoritative round ` +
        `${top.doc.round} announces ${announced}; re-commit it (MIG-13, n28)`);
    }
  } else {
    detail.push(top ? `authoritative marker: ${top.file} (round ${top.doc.round}), which carries no date` : "no migration-notice marker on this tree");
  }

  if (deadline === null) {
    detail.push("no binding deadline is committed, so (a), (b) and (c) have nothing to count down to (BOT-72)");
  } else {
    if (!isTime(deadline)) throw new Error(`the deadline ${JSON.stringify(deadline)} is not a §0.7 time`);
    const dl = Date.parse(deadline);
    const away = dl - nowMs;
    detail.push(`deadline ${deadline}, ${days(away)} day(s) away at ${now}`);

    const two = round(2);
    if (!two && away < ROUND2_DAYS * DAY_MS) {
      add(CODES.round2, `the deadline is ${days(away)} day(s) away and no round-2 marker is on main; MIG-2 keeps it at ` +
        `least ${ROUND2_DAYS} days after round 2`);
    } else if (two && dl - Date.parse(two.doc.sent_at) < ROUND2_DAYS * DAY_MS) {
      add(CODES.round2, `round 2 was sent at ${two.doc.sent_at}, ${days(dl - Date.parse(two.doc.sent_at))} day(s) before ` +
        `the deadline, and MIG-2 keeps it at least ${ROUND2_DAYS}`);
    }
    if (!cutoverOnMain && away < CUTOVER_DAYS * DAY_MS) {
      add(CODES.cutover, `the deadline is ${days(away)} day(s) away and log/cutover.json is not on main; MIG-29 keeps ` +
        `it at least ${CUTOVER_DAYS} days after cutover — the owner moves it later (never earlier)`);
    }
    const three = round(3);
    if (!three && away < ROUND3_DAYS * DAY_MS) {
      add(CODES.round3, `the deadline is ${days(away)} day(s) away and no round-3 marker is on main; MIG-13 sends round ` +
        `3 at least ${ROUND3_DAYS} days before it`);
    } else if (three && dl - Date.parse(three.doc.sent_at) < ROUND3_DAYS * DAY_MS) {
      add(CODES.round3, `round 3 was sent at ${three.doc.sent_at}, ${days(dl - Date.parse(three.doc.sent_at))} day(s) ` +
        `before the deadline, and MIG-13 sends it at least ${ROUND3_DAYS} before`);
    }
  }

  // The banner, by MIG-13's hooks (contract 2.7.0). Every hook has something
  // to be held to from the moment its record exists: `binding-deadline` from
  // the deadline's commit (before R4b), `data-astra-round` from round 1, and
  // `cutover-planned` from round 2 — before which its ABSENCE is the check,
  // because a date on the banner then comes from somewhere other than a marker.
  if (banner) {
    const flag = (code, line) => {
      add(code, line);
      if (!ids.includes(banner.id)) ids.push(banner.id);
    };
    const url = banner.url;
    if (banner.status === 404 && r4bOpen === false) {
      // MIG-13 since 2.7.0: until R4b opens, the plugins zone is dark and a 404
      // is the zone not being open yet. Only a 404, and only before R4b.
      detail.push(`${url} answered 404 before R4b opened: the plugins zone is not open yet, which MIG-13 reads as no ` +
        "mismatch, so the banner was not compared");
    } else if (banner.status !== 200) {
      flag(CODES.bannerUnreachable, `${url} answered ${banner.status ?? "nothing"}${banner.status === 404 ? " after R4b opened" : ""}; ` +
        "MIG-13's banner is one of the two ways a round reaches an author, and a page that does not load tells nobody");
    } else {
      const page = bannerHooks(banner.body);
      for (const p of page.problems) flag(CODES.bannerAmbiguous, `${url}: ${p}`);
      const quote = (v) => (v === null ? "none" : JSON.stringify(v));
      if (page.problems.length) {
        detail.push(`${url}'s hooks do not read as one answer, so nothing on it was compared`);
      } else {
        if (problems.length) {
          detail.push("the markers cannot be ordered (MARKER_UNREADABLE above), so the banner's round and cutover date " +
            "were not compared against a guess");
        } else {
          const round = top ? String(top.doc.round) : null;
          if (page.round !== round) {
            flag(CODES.bannerRound, `${url} serves round ${quote(page.round)}` +
              `${page.banners === 0 ? ` (it has no data-astra="${HOOKS.banner}" element)` : ""} and the highest marker on this ` +
              `tree is ${top ? `round ${round} (${top.file})` : "none"}; the banner's round is that marker's (Table 5-G, migration.round)`);
          }
          if (announced && page.cutover === null) {
            flag(CODES.bannerDiffers, `${url} carries no cutover-planned hook, and the authoritative marker ${top.file} ` +
              `announces ${announced}; MIG-13 draws no hook only while no marker carries a date, so the page is not reading ` +
              "the marker, or is serving a Source-Commit from before its round");
          } else if (announced && page.cutover !== announced) {
            flag(CODES.bannerDiffers, `${url} serves cutover-planned ${quote(page.cutover)} and the authoritative marker ` +
              `${top.file} announces ${announced}; MIG-13's hook carries the marker's date verbatim`);
          } else if (!announced && page.cutover !== null) {
            flag(CODES.bannerDiffers, `${url} serves cutover-planned ${quote(page.cutover)} and no marker carries a date ` +
              `(${top ? `the highest is round ${top.doc.round}` : "none is on this tree"}); until round 2's MIG-13's banner shows ` +
              "none, so this date comes from somewhere other than a marker");
          } else if (announced) {
            detail.push(`${url} serves cutover-planned ${announced}, the announced date`);
          }
        }
        if (page.deadline !== deadline) {
          flag(CODES.bannerDeadline, deadline === null
            ? `${url} serves binding-deadline ${quote(page.deadline)} and policy/binding-deadline.json is not on this tree`
            : page.deadline === null
              ? `${url} carries no binding-deadline hook, and policy/binding-deadline.json commits ${deadline}; MIG-13 ` +
                "draws none only while that record is absent"
              : `${url} serves binding-deadline ${quote(page.deadline)} and policy/binding-deadline.json commits ${deadline}`);
        } else if (deadline !== null) {
          detail.push(`${url} serves binding-deadline ${deadline}, the committed deadline`);
        }
      }
    }
  } else if (markers.length || deadline !== null) {
    detail.push("the banner was not read this run");
  }

  return { status: codes.length ? "red" : "green", codes, ids, detail };
}
