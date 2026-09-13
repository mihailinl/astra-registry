# Web Speech-to-Text — Free STT plugin for Astra

Speech recognition via Google Web Speech API — **free, no API key required, no registration, no setup**. Install the plugin, pick it as your STT engine in Astra and talk.

![icon](https://raw.githubusercontent.com/LilKALINOV/Astra-Google-STT/779e2957f8e90f3046c742f22f92b6f02472e8ba/icon.svg)

## What it does and why you need it

Astra can turn your voice into typed text, but out of the box it ships without a speech-to-text engine. This plugin provides one — a small process that takes the microphone audio Astra captures and turns it into a transcript.

It uses the same free Web Speech API endpoint that Google Chrome and the Python `SpeechRecognition` library call, with the `client=chromium` handshake and a built-in public key. Speech in, text out — nothing more.

**Real-world use cases:**

- Dictate messages by voice instead of typing.
- Feed transcribed voice into your AI so it reads what was said.
- Hands-free control while your hands are busy.

## How a phrase turns into text

1. Astra captures microphone audio and runs its own VAD (voice-activity detection) — it listens for speech and decides where one phrase ends.
2. The finished phrase is streamed to the plugin as raw PCM audio, chunk by chunk.
3. The plugin watches the stream live and spots silence itself.
4. When the phrase is done (Astra's silence or the plugin's own, whichever comes first), the audio is converted from f32 to 16-bit little-endian PCM and posted to Google's speech endpoint.
5. The JSON answer is parsed and returned to Astra as a final `SttEvent`.

> Astra normally "waits for silence" by itself before handing a phrase to the plugin. If that pause feels too long or too short for you, set **Silence to end phrase** below — the plugin then finishes the phrase on its own after that much quiet, without waiting for Astra's VAD.

## What it requires and why

| What | Why this plugin asks |
| --- | --- |
| Outbound network access to Google's speech servers (`www.google.com:80`) | The recognition request is sent from the plugin's own process to Google directly. Astra never sees the audio, the transcript or the network traffic. |

One `[permissions]` grant is declared — the one thing this plugin may grow into:

| Permission | Why it is asked |
| --- | --- |
| `client` | Lets the plugin act as a client front-end, so a future release can send the recognized speech straight into an Astra chat conversation (dictation). Declared up front because a listing cannot add a high-risk permission without going back through review. Today's code calls none of the permission-gated host RPCs — pure STT needs nothing from the daemon beyond the `stt` capability — and the daemon grants the session only if the user consents on the permission screen.

## Configuration

The plugin works out of the box — Russian by default. Every setting is a convenience, not a requirement.

| Setting | Required | Default | Meaning |
| --- | --- | --- | --- |
| Language | No | `ru-RU` | Recognition language, from a dropdown of 38 supported locales (Russian, English US/UK, Ukrainian, German, French, Spanish, Italian, Portuguese BR, Japanese, Korean, Chinese Simplified/Traditional, Arabic, Hindi, Turkish, Polish, Dutch, Swedish, Norwegian, Finnish, Danish, Greek, Hebrew, Romanian, Hungarian, Czech, Bulgarian, Croatian, Slovenian, Serbian, Slovak, Lithuanian, Latvian, Estonian, Indonesian, Thai, Vietnamese). The plugin's own settings are localized: they follow Astra's UI language in English, Russian or Ukrainian. |
| Google API key | No | built-in free key | Your own key for `www.google.com/speech-api`. Leave empty to use the shared free key. Useful if the built-in one is throttled. |
| Max phrase length (seconds) | No | `55` | Audio longer than this is cut before sending. Google rejects requests over ~60 s, so the default keeps you under the limit. `0` = no limit. |
| Network timeout (seconds) | No | `10` | How long to wait for Google to answer before the request fails. `0` = default 10 s. |
| Silence to end phrase (ms) | No | `0` | End the phrase and send it after this much quiet, without waiting for Astra's own silence detection. `0` = use Astra's setting (recommended first). |

> The language picked in Astra's own STT picker overrides this plugin's Language setting for that call.

## Set up in Astra

1. Install the plugin (see **Installation** below).
2. Press `Ctrl+P` to open Astra's settings, or go to **Settings**.
3. Open the **Voice** tab.
4. Go down to the **STT (Speech-to-Text)** section.
5. Change the STT engine from the default to **Web Speech-to-Text**.
6. Optionally, open the plugin's config (the settings gear next to it) and set Language / API key / limits.
7. Done — the next time voice is used, Web STT transcribes it.

If your plugin does not appear in the STT list, you likely forgot a licence: **Settings → Privacy → Enable "Allow unsigned plugins"**.

## Installation

1. In Astra: **Settings → Privacy** → enable **"Allow unsigned plugins"**
2. **Plugins → Dev** → paste the plugin folder path and click **Load**
3. Pick it as your STT engine in **Settings → Voice**.

## Limitations

- One request at a time; a phrase is limited to ~60 s (configurable, see Max phrase length).
- Requires an internet connection — every request goes to Google's servers, and the transcript leaves your machine.
- The endpoint is the free, unofficial one. It is not a guaranteed SLA service; treat it as best-effort.
- Google may throttle, require a personal key, or change the free endpoint at any time. That is the price of a free, keyless engine.

## Build it yourself

```sh
cargo build --release
astra-plugin build
```

## Files

- `src/main.rs` — plugin lifecycle, config handling, f32→i16 PCM conversion, live streaming hook with the plugin's own silence endpointing, phrase-length cutting, Google request and JSON parsing.
- `locales/` — English, Russian and Ukrainian translations: store-card text (`listing.*`) and every settings label (`config.*`), resolved by Astra in the user's current UI language.
- `icon.svg` / `icon.png` — store icons, drawn by hand.

Licensed MIT.
