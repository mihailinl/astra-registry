# Minecraft for Astra

Astra plays Minecraft. This plugin is the body — a [mineflayer][mineflayer] bot
exposed as 23 tools and 6 triggers, plus a two-way chat bridge — and Astra is
the brain that decides what the body does.

The Minecraft layer is a port of the mineflayer half of [AIRI][airi]
(`integrations/minecraft`, MIT): its bot core, its navigation, and the skills
its agent calls. What is deliberately **not** ported is AIRI's `cognitive/` —
the planner, the prompt, the LLM loop. Astra already is that. Porting it would
have given the plugin a second brain that argues with the first one.

## What it can do

| Tool | What it does |
|---|---|
| `minecraft_connect` / `minecraft_disconnect` | join and leave a server |
| `minecraft_status` | the bot's eyes: position, health, food, time, weather, biome, nearby players, mobs, block types, inventory |
| `minecraft_inventory`, `minecraft_players` | cheap, focused reads |
| `minecraft_goto` | walk to coordinates, a player, the nearest block or mob of a type, or simply away |
| `minecraft_follow`, `minecraft_stop` | a standing order, and the way to cancel everything |
| `minecraft_collect` | mine a whole vein of something and pick the drops up |
| `minecraft_dig`, `minecraft_place` | one block, exactly there |
| `minecraft_pillar` | gain height with nothing to climb: jump and place underneath, repeatedly |
| `minecraft_craft`, `minecraft_smelt` | craft (finding or placing a table) and smelt |
| `minecraft_equip`, `minecraft_drop`, `minecraft_give`, `minecraft_chest` | items in, out and across |
| `minecraft_attack`, `minecraft_defend` | hunt one mob or fight one player by name, or clear the hostiles nearby |
| `minecraft_eat`, `minecraft_sleep` | stay alive, skip the night |
| `minecraft_say` | talk in chat |
| `minecraft_chat_mode` | who the bot answers in chat: off / mention / all |

Triggers a saved command can listen for: `minecraft_chat_message`,
`minecraft_damaged`, `minecraft_low_health`, `minecraft_death`,
`minecraft_spawned`, `minecraft_disconnected`.

Variables it publishes: `position`, `health`, `food`.

## Talking in chat

A player writes to the bot in Minecraft, Astra answers there. The turn is a real
one — she can call this plugin's own tools mid-answer, so "astra, get me some
wood" both replies and goes chopping.

The bridge is narrow on purpose, because the input is a stranger on a game
server and the output is a box that also accepts commands:

- **Who gets answered** — `off`, `mention` (default: the trigger word or the
  bot's own name, and whispers always count), or `all`. `minecraft_chat_mode`
  changes it mid-session; **Only answer these players** narrows it to an
  allowlist.
- **How often** — one answer at a time, and no more than one every 2.5 s. On a
  busy server `all` means an AI turn per line, which is why it is not the
  default.
- **What can come back** — the answer is flattened to one line, cut at 500
  characters and stripped of any leading `/`, because Minecraft's chat box is
  also its command line. `minecraft_say` refuses `/` outright for the same
  reason.
- **What Astra is told** — `[Minecraft] Player "Steve" said in public chat: …`,
  with the way it addressed the bot removed. It is labelled as a third party on
  a server rather than as the user speaking, because that is what it is.

**This needs the `send_chat_message` permission, and a hand-imported bundle does
not get it** — tier 2 refuses it outright (see below). From an imported file the
bridge reports itself unavailable in `minecraft_status` and everything else
works; for the two-way bridge, sideload the source directory. The other route
that survives tier 2 is a saved command listening on `minecraft_chat_message`:
the turn it starts is the user's, not the plugin's, and it can still call
`minecraft_say`.

## Three things happen without Astra

A round trip to a language model takes seconds. Lava kills in about two. So the
body keeps three reflexes of its own, on a 300 ms tick, and they are the whole
of what this plugin does unasked:

1. **Escape a hazard** — in lava or out of air, it aims at the nearest safe
   standing block and swims or climbs out.
2. **Eat at low health** — under 6 health and below the regeneration threshold,
   it eats the best food that does not want cooking first. Raw beef is left
   alone: cooking it is a decision, and decisions belong to Astra.
3. **Hit back** — a hostile within 6 blocks gets fought, except a close creeper,
   which gets backed away from.

Turn all three off with the **Survival reflexes** setting if you want a bot that
does nothing you did not ask for.

## Every tool answers

The failure mode this plugin is built against is a tool that hangs or throws a
bare string, because a model cannot act on either. So:

- **Navigation always settles.** The timeout is computed from the path's own ETA
  and recomputed on every replan, and stagnation is measured — moved? mining?
  building? closer? — rather than assumed from wall time. Digging through stone
  counts as progress; walking into a wall does not. (This is AIRI's
  `patched-goto`, and it is the single most valuable thing in the port.)
- **Failures say what to do next.** `MISSING_RESOURCE: Cannot craft 3x
  wooden_pickaxe — missing: 3x oak_planks, 2x stick.` — not `false`.
- **Loose names work.** A model that asks for `wood` gets every log type; a
  model that asks for `diamond_ore` gets the deepslate variant too.

## Setup

Needs Node 20+.

```bash
npm install
npm test
```

Configure the server in Astra's plugin settings, or pass it to
`minecraft_connect` per call. `auth: microsoft` signs in with a device code
written to the plugin log — no password is ever handled by this plugin.

### Which Minecraft versions

Whatever the bundled mineflayer speaks: **1.8.8 through 1.21.11** at the time of
writing, with 1.21.11 the newest. Leave the version setting blank and the bot
takes the version from the server's ping, which is right far more often than a
guess; pin it only when that detection fails.

The ceiling moves when mineflayer's does, not when this plugin changes — a
version newer than the bundle is answered with the version it can speak instead
of a stack trace, and the fix is a newer release rather than a setting.

### Installing it in Astra

```bash
npm run build
astra-plugin build .
```

That writes `minecraft-for-astra-0.3.3-noarch.astraplugin` next to `plugin.toml`,
and Astra imports it from **Plugins → Development → Import plugin**.

Two things the tier table does not tell you, both learned by hitting them:

- **An unsigned file is refused until `safety.allow_unsigned_plugins` is on**
  (Settings → Privacy). Nothing countersigned these bytes, so the daemon says
  *"nothing here vouches for these bytes"* and stops. The switch lowers the bar
  for every plugin on the machine, not just this one. `local-install.md`
  documents the tier-2 ceiling but never mentions this prerequisite.
- **Tier 2 drops `send_chat_message`**, so an imported build has everything
  except the two-way chat bridge: `fire_trigger` and `set_variable` survive the
  ceiling, and the bridge reports itself unavailable in `minecraft_status`.
  Sideload for the bridge, or drive it from a saved command on the
  `minecraft_chat_message` trigger.

**How the dependencies get in there**, because the number is the interesting
part. `astra-plugin build` packs `dist/` and skips any directory called
`node_modules`, and the registry's release workflow enforces the same idea from
the other side: it walks every `.js` in the finished bundle and refuses one that
names a package it would have to resolve at run time, because a `.astraplugin`
carries no `node_modules` and that resolution is a `MODULE_NOT_FOUND` on
somebody else's machine.

So everything is inlined, `minecraft-data` included — its 2477 requires of JSON
are all static, so all of them are followable. Followed literally they weigh
**500 MB**, and **377 MB of that is Bedrock Edition data** that mineflayer, a
Java Edition client, can never read. `scripts/build.mjs` replaces exactly that
with `{}` — and exactly not the three files `minecraft-data/index.js` reads from
`bedrock/common/` at import time. Comments go too, which is not cosmetic: the
workflow's guard is a regular expression over the finished file, and a JSDoc
`@param {import('vec3').Vec3}` in somebody else's source reads to it as this
bundle resolving `vec3`.

| | Bytes | Files |
|---|---|---|
| everything inlined, as esbuild first produces it | 500 MB | 1 |
| minus Bedrock data | 124 MB | 1 |
| minus comments and whitespace | 48 MB | 1 |
| packed | **6.6 MB** | 5 |

`encoding` and `supports-color` are dependencies for the same reason and no
other: `node-fetch` and `debug` each `require()` them inside a `try`/`catch`,
which is unresolvable-on-purpose and therefore left in the output. Installed,
they are inlined like everything else.

For development, sideloading from the source directory is still the faster loop:

```bash
astra-plugin dev .
```

It is refused until **Settings → Privacy → Allow unsigned plugins**
(`safety.allow_unsigned_plugins`) is on, and that switch lowers the bar for
*every* plugin on the machine — read [`sideload.md`][sideload] first, and turn
it back off afterwards.

## Tests

`npm test` needs no daemon and no Minecraft: it checks that every tool's schema
matches the handler that reads it, that every tool fails in-band with
`NOT_CONNECTED` rather than throwing when there is no bot, and that the pure
navigation and naming rules hold.

`node test/live.mjs [host] [port] [version]` is the other half — it joins a real
server and drives the same tool calls Astra makes. Two of its steps pass by
failing: refusing a `/` server command, and naming the missing ingredients
instead of crafting.

Both live files honour `ASTRA_TEST_BUNDLE`, which `npm run build:test-bundle`
produces: a plugin built the way the shipped one is — everything inlined, nothing resolved at run time.
That is a different module graph from the test build and the only one a user
ever runs, so it is the one that proves `minecraft-data` still answers with no
`node_modules` anywhere near it.

`node test/live-pillar.mjs [host] [port] [version]` is there for the one skill
whose correctness is a matter of timing. A block cannot be placed inside a
player, so the block the bot is standing in is the only one it has to jump for,
and a jump is six ticks wide. A mock cannot vouch for that — the refusal has to
come from a server, and it comes silently, as a placement that simply does not
happen. Set `JUMP_CLEARANCE` to zero and every step of that file fails, which
is the check that the check is real.

`node test/live-chat.mjs [host] [port] [version]` proves the chat bridge with a
second, plain mineflayer client playing the player: it types at the bot and
asserts that *another client on the server* sees the answer. Only Astra herself
is stood in for, by the SDK's `RecordingHost` with a scripted reply.

A throwaway server to test against, no Java needed:

```bash
npm install flying-squid
```

## What it will not do

- **Send server commands.** `minecraft_say` refuses a message starting with `/`.
  A chat tool that accepts them is an operator console, and `/op`, `/ban` and
  `/kill` all start that way.
- **Answer a stranger by default.** The chat bridge is `mention`-only out of the
  box, one answer at a time, and can be narrowed to an allowlist or turned off.
- **Handle a password.** Microsoft accounts authenticate by device code.

## Licence

MIT. The ported Minecraft layer is MIT from [AIRI][airi], Copyright (c)
2024-PRESENT Neko Ayaka; the files that carry a port say so at the top.

[airi]: https://github.com/moeru-ai/airi
[mineflayer]: https://github.com/PrismarineJS/mineflayer
[sideload]: https://github.com/mihailinl/AstraPlugins/blob/master/docs/en/5-publish/sideload.md
