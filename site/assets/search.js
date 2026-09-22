// Client-side search over the signed catalogue.
//
// It fetches `../registry/v1/index.json` — the same file Astra reads, served
// from this origin because the site build copies the deploy candidate into the
// published tree. There is deliberately no generated search index: a second
// document describing the first is a document that can disagree with it, and
// "the site said it was there" is a bug report nobody can act on.
//
// No framework and no innerHTML. Every value here came out of a listing a
// stranger wrote; `document.createTextNode` cannot be tricked into markup, and
// a 60-line search box is not worth a sanitiser nobody audits.

(function () {
  "use strict";

  var q = document.getElementById("q");
  var status = document.getElementById("status");
  var results = document.getElementById("results");
  var entries = [];

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.appendChild(document.createTextNode(String(text)));
    return node;
  }

  function card(e) {
    var a = el("a", "card");
    a.href = "../p/" + encodeURIComponent(e.id) + "/";

    if (e.icon_url && /^https:\/\//i.test(e.icon_url)) {
      var img = el("img", "icon");
      img.src = e.icon_url;
      img.alt = "";
      img.width = 40;
      img.height = 40;
      a.appendChild(img);
    } else {
      a.appendChild(el("span", "icon blank"));
    }

    var body = el("span", "card-body");
    body.appendChild(el("strong", null, e.name));
    body.appendChild(el("code", null, e.id));
    body.appendChild(el("span", "thin", e.description || ""));

    var badges = el("span", "badges");
    if (e.staging) badges.appendChild(el("span", "badge warn", "staging"));
    (e.capabilities || []).forEach(function (c) {
      badges.appendChild(el("span", "tag", c));
    });
    body.appendChild(badges);

    a.appendChild(body);
    return a;
  }

  // `e.details` used to be in here. It was the listing's 4,000-character body,
  // copied into the index under a third name, byte-identical to `description`
  // in every listing that ever carried it, and read by nothing in the daemon.
  // It is gone from the index, and it is worth knowing why it is not coming
  // back in another form: a long free-text field inside the search filter is a
  // ranking lever the listing's own author operates. Ninety lines of a
  // competitor's name in a "translation" would match every query, in nine
  // languages, while the human who approved the listing read a clean English
  // card. What is searched here is the card: the id, the name, the one-line
  // summary, and the keywords a curator wrote.
  //
  // Those seven fields are all flat English, and the flat fields ARE the
  // English — `en` is not a key in `i18n`, see that member's `$comment` in
  // `schema/index-v1.json`. The other nine locales are already in the document
  // this file fetches, two short strings each, and nothing here reads them:
  // not this filter, not `card()` above. That is the state. It is not a
  // decision — nobody has been asked.
  //
  // The daemon was asked, and answered the other way in writing.
  // `RegistryClient::browse` in
  // `astra-rs/astra-daemon/src/plugins/registry_client.rs` ORs
  // `p.i18n.values()` — name and description, and explicitly not `details` —
  // into the same filter, under a doc comment headed "Selecting one language
  // and SEARCHING all of them is deliberate": the card shows what the user
  // reads, the filter must not. So the app and this page disagree about what
  // is findable, and the disagreement is live rather than hypothetical. In
  // `registry/v1/index.json` at serial 52, 5 of 16 listings carry `i18n` (six
  // records, `ru` and `uk`), and `voice-text-input` publishes a Russian name
  // sharing no character with `Voice Text Input`. Every haystack this function
  // builds is ASCII but for one em dash. That listing is findable in Astra by
  // its own name and findable here only in English (counted 2026-09-22).
  //
  // Two things would have to be true before `i18n` joins the list, and neither
  // is this file's to settle:
  //
  //   * the `details` argument above, re-run against a bounded field. It was
  //     about unbounded author-operated text; these are 64 and 200 characters
  //     per locale by schema, nine locales, each record checked at ingest by
  //     `bot/lib/locales.mjs`. Bounded is not the same as answered.
  //   * a result card that can say why it matched. `browse` can: it takes a
  //     `language` and renders that locale's card beside the hit. This page has
  //     no reader-language signal at all — the shell in `site/lib/html.mjs`
  //     writes `<html lang="en">` for every page — so a match found in Russian
  //     would draw an English card containing none of the query.
  function haystack(e) {
    return [e.id, e.name, e.description, (e.keywords || []).join(" "), (e.categories || []).join(" "), (e.capabilities || []).join(" "), e.author]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  }

  function render() {
    var terms = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    var hits = entries.filter(function (e) {
      return terms.every(function (t) {
        return e._h.indexOf(t) !== -1;
      });
    });

    while (results.firstChild) results.removeChild(results.firstChild);
    hits.forEach(function (e) {
      results.appendChild(card(e));
    });

    status.textContent = terms.length
      ? hits.length + " of " + entries.length + " plugin(s) match"
      : entries.length + " plugin(s) in the catalogue";
  }

  fetch("../registry/v1/index.json", { cache: "no-cache" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(function (doc) {
      entries = (doc.signed && doc.signed.plugins) || [];
      entries.forEach(function (e) {
        e._h = haystack(e);
      });
      // Said out loud, because an unsigned catalogue is exactly what a build
      // outside `main` produces and a reader has no other way to tell.
      if (!doc.signatures || doc.signatures.length === 0) {
        status.textContent = "This catalogue carries no signature. Astra will refuse it — do not install from it.";
        status.className = "alert";
        return;
      }
      render();
      q.addEventListener("input", render);
    })
    .catch(function (e) {
      status.textContent = "Could not load the catalogue (" + e.message + "). It is at ../registry/v1/index.json if you want to read it directly.";
    });
})();
