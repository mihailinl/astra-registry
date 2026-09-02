# Publishing Astra 0.2.1 — what is done, and the one ceremony left

Dated 2026-09-02. Everything below was measured on that day, not remembered.

## Already done, and verified from outside

The build is **published on both storefronts** and reachable by buyers:

| | |
|---|---|
| artefact | `Astra-Installer-0.2.1.exe` |
| size | 87 437 592 bytes |
| sha256 | `b779a4e8c4e076451014d1237717a815bb77f1e71e800aba797279b98ff3d185` |
| Authenticode | `Mykhailo Samiliak`, via Microsoft ID Verified CS EOC CA 04 |
| astra.minice.ai | `/opt/stacks/astra-site-test/download` |
| knice.tech | `/opt/stacks/knice-tech-prod/download` |

Verified by fetching the whole file through the **public CDN with a signed URL**,
minted by the site's own `signDownload` inside the container so the formula under
test was the shipped one: `200`, 87 437 592 bytes, digest identical.

**The filename carries the version, and the previous one did not.** The old
publication was `Astra-Installer.exe`. Republishing under that name would have left
the edge serving cached 0.2.0 bytes from the same address for as long as the object
lived, which reads as "the release did not work" and is invisible from the origin.

## What is NOT done: the update manifest

Nothing on the box announces 0.2.1 to an installed client yet. Two things stand in
the way and the first cannot be delegated.

### 1. The signature — yours, and only yours

    ASTRA_KEY=/path/to/astra-root-2026a.private.pem.gpg   # wherever you put it

    gpg --decrypt "$ASTRA_KEY" > /dev/shm/root.pem        # RAM, not disk
    chmod 600 /dev/shm/root.pem

    cd ~/Documents/GitHub/astra-registry
    node tools/sign-update-manifest.mjs \
      --root-key   /dev/shm/root.pem \
      --artifact   ~/Downloads/Astra-Installer-0.2.1.exe \
      --version    0.2.1 \
      --min-supported 0.2.0 \
      --notes-en   releases/0.2.1/notes.en.txt \
      --notes-ru   releases/0.2.1/notes.ru.txt \
      --notes-uk   releases/0.2.1/notes.uk.txt \
      --out        /tmp/update-manifest.json

    shred -u /dev/shm/root.pem

The artefact must be **on the machine you sign on**: the signer computes the size and
digest from the bytes and refuses to accept them as arguments. A manifest naming a
file that is not there is August's webhook failure with a different noun.

`--min-supported 0.2.0` is deliberate. It installs nothing — it is how a client says
"this build is no longer served" in words — and 0.2.0 is a perfectly good build.

The signer proves the key is a **published root** before it writes anything, then
verifies its own output. Reserve-by-accident and last-year's-key both fail here
rather than at a user who never gets an update.

### 2. The config — one write, currently refused to the agent

`updates:` does not exist in the box's `astra.yaml` at all, so the server takes its
compiled default and answers `{"error":"updates_not_configured"}`. That default is
the refusing one on purpose.

**The first save has to be the whole-file editor.** `yaml_patch::patch_scalar`
rewrites an existing leaf and has no key-insertion path, so until these lines exist
`/admin/config` renders the fields and refuses every save on them. Once they exist,
publishing a manifest is a one-field edit from the panel.

The prepared file is at `astra.rehearsal.yaml` / `astra.final.yaml` in the session
scratchpad; the block it inserts is 29 lines before `routes:`.

### The path trap, found in rehearsal

`/tmp` on the host is **not** visible inside the container. The manifest goes to the
host path and the config names the container path:

    host       /opt/stacks/astra-api/config/update-manifest.json
    config     manifest_path: "/app/config/update-manifest.json"

### `artifact_base_url` stays empty, and that is a decision

`dl.minice.ai` answers **403 to an unsigned request** — measured 2026-09-02 against
all three filenames — while the artefact door only concatenates base + filename and
redirects. Filling it in would advertise a door that 403s for every buyer: a manifest
that reads as correct and a download that never works.

The daemon does not use that door at all today — stage 1 checks and tells, it
downloads nothing — so empty costs nothing and wrong would cost everything. When it
is needed, the change is the handler minting a **signed** target, not this line.

## Verifying, from where the client stands

    curl -s https://api.minice.ai/api/updates/manifest | sha256sum
    ssh -p 691 root@176.12.79.17 'sha256sum /opt/stacks/astra-api/config/update-manifest.json'

Those two digests must match. The server serves the bytes verbatim and holds no key:
it can refuse a manifest, and it cannot forge one.

## The obligation this creates

`expires` is 30 days. The signing key is offline, so **re-signing is a calendar
obligation**, and forgetting it stops auto-update estate-wide while looking exactly
like the server being down.

Three alarms are already loaded on the box and were `inactive` when checked:

    AstraUpdateManifestExpiringSoon
    AstraUpdateManifestExpired
    AstraUpdateManifestRefused

They read `updates_manifest_expires_in_seconds`, which only moves once a manifest is
actually being served. Until then they are armed and silent, which is correct and is
also why the gauge is not evidence that anything is published.
