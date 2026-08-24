# Astra Chess

Play chess against a classical local bot or the model currently selected in Astra, directly in a dedicated app tab.

> Official Astra plugin by KNICE — Astra co-founder and main developer.

## Features

- complete chess rules: check, checkmate, stalemate, castling, en passant, and pawn promotion;
- four local difficulty levels plus **Astra AI**, which plays through the provider and model selected in Astra;
- move calculation in a Web Worker, keeping the interface responsive during local search;
- smooth piece movement, including castling and history replay, with `prefers-reduced-motion` support;
- play as White or Black, undo moves, and locally restore an unfinished game;
- step through the entire game with first, previous, next, and current-position controls;
- **Realism** mode enabled by default, adding a natural pause, a thought bubble, and readable chess remarks;
- local levels work entirely offline;
- Astra AI validates every model-selected move against the legal move list before changing the board;
- built-in chat with Astra AI, including the current position and move history as context.
- automatic restoration of the current game, history position, settings, and Astra chat after leaving the plugin tab;
- **English, Russian and Ukrainian**, following the language Astra is set to when the board opens. Changing Astra's language while the board is already open does not repaint it: the strings are fetched once, in `initialize()`, and nothing listens for a change. Close the tab and open it again.

Rules and move validation use [chess.js](https://github.com/jhlywa/chess.js), distributed under BSD-2-Clause. In Astra AI mode, the model also receives the narrow `play_chess_move` tool, which accepts one UCI move for the active turn.

## Languages

The plugin ships `locales/en.json`, `locales/ru.json` and `locales/uk.json` beside `plugin.toml`. English is the base; the other two are defined against it, and `locales.lock.json` records which English each translation was made from, so rewriting an English sentence marks its translations stale instead of leaving them quietly wrong.

Where each string is resolved is the thing to know before editing any of them.

| | Rendered by | Written as |
|---|---|---|
| the store card — the name and summary in the catalogue | the **registry**, out of the bundle | `listing.name` / `listing.description`, the two reserved keys |
| the board page, the chess remarks, every error a player reads | **this plugin**, at the moment it produces the string | a key, resolved through the SDK's `I18n` |
| the page's label in Astra's sidebar | the **daemon** | a literal English string — deliberately, see below |

The page is an iframe and cannot read a file, so it asks the plugin process for the active language over one UI call (`get_locale`) and the plugin process resolves it with `I18n`. `src/en.generated.ts` is the English base compiled into the page bundle, so a page that has not heard back is English rather than a wall of identifiers; `npm run locales:gen` writes it from `locales/en.json`, and `npm test` fails if the two disagree.

The **sidebar label is not a `$key`**, and that is not an oversight. A daemon resolves plugin keys outside `[config] schema` only from a build newer than any published Astra release, and `plugin.min_astra_version` — the only thing that would stop an older daemon installing this plugin — has no release number to name yet. A key there would reach users as the literal text `$ui.chess.label`. When such a release exists, the label becomes a key and `min_astra_version` names that release.

Adding a language:

```bash
astra-plugin locale add <code>     # seeds locales/<code>.json from en.json
# translate the values in place; leave the keys alone
astra-plugin locale sync           # restamps locales.lock.json
astra-plugin locale check
npm run locales:gen && npm test
```

The ten codes Astra can be set to are bare ISO-639-1 — `zh`, never `zh-CN`. A file named anything else is packed, signed, shipped and read by nothing.

## Data sent to the selected model

The **Astra AI** level and in-game chat require the `send_chat_message` permission. After the user grants it, the plugin sends the selected Astra provider the current FEN position, move history, legal move list, and messages entered in the in-game chat. Local bot levels do not use the network.

Astra shows this high-risk permission and its reason on the installation consent screen. A bundle imported manually cannot receive this permission; the Astra AI level and chat require the verified catalogue release.

## Licences

Author: KNICE. The plugin's original code is released under the MIT licence. The bundle also contains:

- [chess.js 1.4.0](https://github.com/jhlywa/chess.js) — BSD-2-Clause;
- [Astra Plugin SDK for TypeScript 0.5.0](https://github.com/mihailinl/AstraPlugins/tree/master/astra-plugin-sdk-ts) — MPL-2.0.

Full notices and source links are in `LICENSE`, which is included in the plugin bundle.

## Development

```bash
npm install
npm run locales:gen        # after any edit to locales/en.json
npm test
npm run typecheck
astra-plugin check --strict .
astra-plugin test .        # the only gate that reads the sidebar label
```

To load the source folder into a running Astra instance:

```bash
astra-plugin dev .
```
