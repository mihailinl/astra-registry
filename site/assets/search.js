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
