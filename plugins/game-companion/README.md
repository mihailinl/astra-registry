# Game Companion

Astra notices which game you are playing and keeps you company like a gamer friend sitting next to you.

## What it does

- **Knows what you play.** Every few seconds it checks running processes against about 60 popular games, your local Steam library, and games you add by hand (process name + title). Desktop apps from Steam such as Bongo Cat or Wallpaper Engine are not counted as games.
- **Reacts out loud** (each reaction can be switched off):
  - a short line when a game starts, written by Astra's AI so it does not repeat itself;
  - a gentle stretch-and-water reminder after a long session (2 hours by default, then at most once an hour);
  - a caring bedtime hint once per session when you play past night time (01:00 by default);
  - a short summary when the game closes ("2 hours 15 minutes in Elden Ring, not bad").
- **Answers game questions.** Ask "how do I beat this boss?" or "which build is best?" and Astra puts the current game's name into her web search and answers briefly, without story spoilers unless you ask for them.
- **Cheers Steam achievements** (optional). Enter a Steam Web API key and your SteamID64 and Astra checks the current game for new achievements every 2 minutes. Your Steam profile must be public.
- **Keeps play statistics** locally: ask "how much did I play today?" or "what did I play most this week?".
- **Fires automation triggers**: Game started, Game closed, Steam achievement unlocked.

## The Games tab

- **Now**: the current game, a session timer and a box to ask a question about the game.
- **Statistics**: time today and this week, the last 7 days as bars, top games of the week and recent sessions.
- **Settings**: tracked games (add, remove, Steam library on/off), a switch for every reaction, break and night times, speaking aloud, and the Steam achievement fields.

## Recommended: one line in Astra's AI instruction

Astra shows the AI only some of the installed tools at a time, so for a vague voice question like "which truck is best?" she may not realise you mean the game. Adding this line to the end of Astra's AI instruction (the character text in Astra's AI settings) makes her check the current game first:

```text
If the user asks anything that could be about a computer game (bosses, builds, mods, items, quests, vehicles, "which truck / car / weapon is best", "how do I pass", "where do I find"), first find and call the get_current_game tool of the Game Companion plugin to learn what the user is playing right now, and answer about that game.
```

The "Ask about this game" box on the Games tab works without it.

## Permissions

- **Send chat messages**: Astra's comments, reminders, summaries and answers are written in the plugin's own chat thread, and spoken when voice is on.
- **Fire triggers**: so your own automations can react to a game starting or closing, or to an achievement.

## Privacy

Play history, settings and the Steam key are stored only on your computer, in `%APPDATA%\astra-game-companion\data.json`. The plugin reads the list of running processes, the Steam folders and Steam's registry entries; it sends nothing anywhere except Steam Web API requests when you enter a key, and the messages it asks Astra to say.

Windows only.

## Development

```bash
bun install
bun run pretest && node --test test/plugin.test.mjs
astra-plugin check . --strict
astra-plugin test .
```

## License

MIT
