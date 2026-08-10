// Is this name already taken, or dressed up as someone else's?
//
// The store shows a card: an icon, a display name, an author string. A user
// deciding whether to install `dice-roIler` has that and nothing else, so the
// registry is the only place the question can be asked at all.
//
// Four rules, in increasing order of how sure the bot is:
//
//   1. EXACT COLLISION AFTER FOLDING -> reject. Two listings that render to the
//      same string cannot both exist; there is no version of the store where
//      both cards are honest.
//   2. TRADEMARK -> reject. Not a legal judgement — a rule about what a card
//      claims. See bot/policy/trademarks.json for exactly how narrow it is.
//   3. DAMERAU-LEVENSHTEIN <= 1 -> hand to a human. `dice-roller` and
//      `dice-rollers` are one edit apart and so are a great many honest names.
//   4. DISPLAY NAME EQUAL BAR CASE/WHITESPACE/LOOKALIKE SCRIPT -> hand to a
//      human. Ids are unique by construction; the names beside them are not.
//      "Equal" INCLUDES byte-identical: an exactly equal name is trivially
//      equal bar case and whitespace, and it is the strongest collision there
//      is, not an exception to the rule.
//   5. A DISPLAY NAME MIXING ALPHABETS -> hand to a human. The id charset is
//      `[a-z0-9-]`, so a Cyrillic id is impossible; the display name is
//      unconstrained prose and it is what the card renders.
//
// The folding itself is `tools/lib/ids.mjs`, imported rather than copied: the
// registry's CI validator applies rule 1 across the whole catalogue on every
// pull request, and a bot that folded differently would accept at ingest what
// CI rejects at merge, or the reverse.
//
// **This is a heuristic and docs/BOT-CHECKS.md says so in those words.** It
// catches accidents and lazy impersonation. Someone willing to read the fold
// table and pick a name outside it gets past all four rules, arrives in the
// store, and is dealt with by reports and revocation — which is a slower answer
// and the only honest one.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  confusableSkeleton,
  editDistance,
  foldId,
  foldLookalikeScripts,
  scriptsUsed,
} from "../../tools/lib/ids.mjs";

const BOT_DIR = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

export function loadTrademarks(dir = BOT_DIR) {
  return JSON.parse(fs.readFileSync(path.join(dir, "policy", "trademarks.json"), "utf8"));
}

/**
 * A display name folded for comparison: NFKC, Cyrillic/Greek lookalikes mapped
 * to the Latin letters they are drawn as, case-folded, every run of whitespace
 * collapsed, ends trimmed.
 *
 * Deliberately NOT `foldId`. An id is one token and DIGIT folding is
 * appropriate there; a display name is prose, and folding `0`→`o` inside it
 * would collide "Mp3 Tools" with "Mpo Tools". The rule the plan states for
 * names is narrow on purpose: **case or whitespace only.**
 *
 * The one thing added to that narrowness is
 * [`foldLookalikeScripts`](../../tools/lib/ids.mjs), and it is not a widening
 * of the same kind. NFKC unifies compatibility variants of the same character;
 * it does not touch two different characters that happen to be drawn
 * identically. `Dіce Roller` — U+0456 CYRILLIC SMALL LETTER
 * BYELORUSSIAN-UKRAINIAN I for the ASCII `i` — used to fold to `dіce roller`,
 * compare unequal to `dice roller`, produce no finding at all, and publish
 * unattended with a card pixel-identical to the plugin it was copying.
 * `unsafeDisplayText` did not catch it either: it rejects invisible characters,
 * and a homoglyph is not invisible, it is the opposite.
 *
 * The map holds only unambiguous shapes, so a name written entirely in Cyrillic
 * or Greek still folds to itself.
 */
export function foldDisplayName(name) {
  return foldLookalikeScripts(String(name))
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The leading token of a display name, folded the way ids are, so
 * `Spotify Controller`, `spotify-controller` and `SPOTIFY controller` are one
 * answer.
 */
function leadingToken(name) {
  const first = foldDisplayName(name).split(" ")[0] ?? "";
  return confusableSkeleton(first);
}

/**
 * Trademark rule. Returns a sentence, or null.
 *
 * @param {{id: string, name: string, repoOwner: string}} candidate
 * @param {object} trademarks bot/policy/trademarks.json
 */
export function trademarkClaim(candidate, trademarks) {
  const { id, name, repoOwner } = candidate;
  if (Object.hasOwn(trademarks.allow_ids ?? {}, id)) return null;

  const owner = String(repoOwner ?? "").toLowerCase();
  const permitted = (mark) =>
    (trademarks.allow_repo_owners?.[mark] ?? []).some((o) => String(o).toLowerCase() === owner);

  // A **skeleton**, not `foldId`. `foldId`'s table is single-valued — `1`→`l`
  // and nothing maps `1`→`i` — so `Sp0tify Controller` was caught (`0`→`o`) and
  // the neighbouring `Spot1fy Controller` folded to `spotlfy` and matched no
  // mark at all. The table caught one digit substitution and missed the one next
  // to it on the keyboard. A skeleton collapses every spelling of a shape to one
  // symbol, so there is no neighbour left to miss. It is used HERE and not in
  // the collision rule above because the marks list is short and curated, while
  // collision is an outright rejection across the whole catalogue.
  const foldedId = confusableSkeleton(id);
  for (const mark of trademarks.marks) {
    if (permitted(mark)) continue;
    const m = confusableSkeleton(mark);
    // The id IS the mark, or LEADS with it. Anywhere else it is a description
    // and passes: `music-for-spotify` and `notes-sync-notion` say which service
    // they talk to, which is exactly what an honest third-party plugin does.
    // `spotify-controller` is the impersonation, because the leading token is
    // what a store card reads as the publisher.
    const parts = String(id).toLowerCase().split("-").map(confusableSkeleton);
    const idClaims = foldedId === m || parts[0] === m;
    if (idClaims) {
      return `the id "${id}" is, or begins with, the mark "${mark}"`;
    }
    if (leadingToken(name) === m) {
      return `the display name "${name}" begins with the mark "${mark}"`;
    }
  }
  return null;
}

/**
 * Compare one candidate against everything already listed.
 *
 * @param {{id: string, name: string, repoOwner: string}} candidate
 * @param {{id: string, name: string}[]} existing every OTHER listing
 * @param {{flagDistance: number, trademarks: object}} opts
 * @returns {{level: "error"|"review", code: string, message: string}[]}
 */
export function checkNames(candidate, existing, opts) {
  const out = [];
  const others = existing.filter((e) => e.id !== candidate.id);

  const mine = foldId(candidate.id);
  for (const other of others) {
    if (foldId(other.id) === mine) {
      out.push({
        level: "error",
        code: "E_TYPOSQUAT_COLLISION",
        message:
          `"${candidate.id}" folds to the same string as the listed "${other.id}" ` +
          `(both become "${mine}" after NFKC, case folding, hyphen stripping and confusable folding)`,
      });
    }
  }

  const claim = trademarkClaim(candidate, opts.trademarks);
  if (claim) {
    out.push({
      level: "error",
      code: "E_TRADEMARK",
      message: `${claim}. Name the plugin for what it does; say which service it talks to in the summary.`,
    });
  }

  // Near-misses, once each, against the closest listing rather than every one:
  // a comment listing eleven names one edit away is a comment nobody reads.
  let nearest = null;
  for (const other of others) {
    const d = editDistance(mine, foldId(other.id));
    if (d > 0 && d <= opts.flagDistance && (nearest === null || d < nearest.d)) {
      nearest = { d, id: other.id };
    }
  }
  if (nearest) {
    out.push({
      level: "review",
      code: "R_TYPOSQUAT_NEAR",
      message: `"${candidate.id}" is ${nearest.d} edit(s) from the listed "${nearest.id}"`,
    });
  }

  // A display name that draws its Latin letters out of two alphabets at once.
  // Checked before the collision rule because it stands on its own: it is a
  // finding even when nothing else is listed under that name yet, since the
  // name it is aimed at may be listed tomorrow.
  const scripts = scriptsUsed(candidate.name);
  if (scripts.length > 1) {
    out.push({
      level: "review",
      code: "R_DISPLAY_NAME_MIXED_SCRIPT",
      message:
        `the display name "${candidate.name}" mixes ${scripts.join(" and ")} letters. ` +
        "A name written in one alphabet is ordinary; one that borrows a single letter from " +
        "another is how a card is made to render as a name it does not contain.",
    });
  }

  const myName = foldDisplayName(candidate.name);
  for (const other of others) {
    if (!other.name) continue;
    // **No `other.name !== candidate.name` clause.** It used to be here, and it
    // excluded the byte-identical case — so the STRONGEST collision produced no
    // finding while every weaker variant was held for a human. A plugin could
    // repaint its store card as a popular plugin's, exactly, unattended, and
    // only the clumsy lowercase version was caught. An identical display name on
    // two different ids is at least as much a human decision as a case variant.
    if (foldDisplayName(other.name) === myName) {
      out.push({
        level: "review",
        code: "R_DISPLAY_NAME_COLLISION",
        message:
          `the display name "${candidate.name}" matches "${other.name}" (listed as "${other.id}") ` +
          "once case, whitespace and lookalike letters are ignored",
      });
    }
  }

  return out;
}
