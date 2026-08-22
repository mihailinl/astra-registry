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

Rules and move validation use [chess.js](https://github.com/jhlywa/chess.js), distributed under BSD-2-Clause. In Astra AI mode, the model also receives the narrow `play_chess_move` tool, which accepts one UCI move for the active turn.

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
npm test
npm run typecheck
astra-plugin check --strict .
astra-plugin test .
```

To load the source folder into a running Astra instance:

```bash
astra-plugin dev .
```
