// The two GitHub reads the bot needs, and nothing else.
//
// Both are unauthenticated-capable: a public release is public. A token, when
// GITHUB_TOKEN is set, buys rate limit and nothing more — the bot never needs
// write access to anything, which is deliberate. A registry bot that can push
// is a registry bot whose compromise is a supply-chain event.

const API = "https://api.github.com";

function headers() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-registry-bot",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/** @returns {Promise<{tag_name: string, html_url: string, published_at: string, target_commitish: string, assets: {name: string, size: number, browser_download_url: string}[]}>} */
export async function fetchRelease(repo, tag) {
  const url = `${API}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
  const res = await fetch(url, { headers: headers() });
  if (res.status === 404) {
    throw new Error(`no release tagged ${tag} in ${repo} (404)`);
  }
  if (!res.ok) {
    throw new Error(`GitHub returned HTTP ${res.status} for ${url}`);
  }
  return res.json();
}

/**
 * Download a release asset.
 *
 * The URL is the one recorded in the LISTING, not one discovered from the API
 * response: the listing's URL is what a user's daemon will fetch, so it is the
 * one whose bytes have to be checked. Capped, because an unbounded download
 * driven by a stranger's release is a denial-of-service primitive.
 *
 * The token goes to GitHub or nowhere. `headers()` attaches
 * `Authorization: Bearer $GITHUB_TOKEN` whenever the environment has one, and
 * the URL here comes out of a LISTING — a string a submitter wrote. A listing
 * can now name a non-GitHub origin (`release.kind: "direct"`, for a self-hosted
 * or staging catalogue), so an unconditional header would mail the bot's
 * credential to whatever host a pull request typed. Exact host match, never a
 * suffix: `evil-github.com` and `github.com.attacker.net` both fail it.
 */
export async function downloadAsset(url, maxBytes) {
  let host = "";
  try { host = new URL(url).host.toLowerCase(); } catch { /* fetch will fail on it too */ }
  const toGitHub = host === "github.com" ||
    host === "objects.githubusercontent.com" ||
    host === "release-assets.githubusercontent.com";
  const h = headers();
  if (!toGitHub) delete h.Authorization;

  const res = await fetch(url, { headers: h, redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  if (!res.url.startsWith("https://")) throw new Error(`redirected off https: ${res.url}`);
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error(`asset declares ${declared} bytes, over the ${maxBytes} cap`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error(`asset is ${buf.length} bytes, over the ${maxBytes} cap`);
  return buf;
}
