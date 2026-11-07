# Wallpaper Engine for Astra

![Cover illustration: Wallpaper Engine for Astra — browse your local Steam Wallpaper Engine library and apply video, image and experimental Web backgrounds inside Astra.](https://raw.githubusercontent.com/Dtierofficial/astra-wallpaper-engine/f3e9ac33162ea8317a5e1a1e915e9cd85080ed24/docs/assets/cover-en.png)

**Browse your downloaded Steam Wallpaper Engine library and apply supported backgrounds directly inside Astra.**

- **Author:** DtieR
- **License:** MIT (third-party notices in `ui/legal/NOTICE.md`)
- **Languages:** English & Russian in a single package (automatically follows Astra's language, with a manual switcher in the header)
- **Platform:** Windows 10/11 x64 (the bundle target is `noarch` because it contains a small Windows window-visibility helper)

---

## Features

![Gallery preview (English): grid of downloaded wallpapers with type badges, search/filter toolbar, and the right-hand inspector panel showing playback and Wallpaper Engine settings.](https://raw.githubusercontent.com/Dtierofficial/astra-wallpaper-engine/f3e9ac33162ea8317a5e1a1e915e9cd85080ed24/docs/assets/gallery-en.png)

- **Automatic Steam Library Discovery:** Finds your installed Steam libraries (`libraryfolders.vdf`), Workshop content (`431960`) and local projects (`myprojects`) without manual folder copying.
- **Desktop-Style Browser & Inspector:** Search by title or tags, filter by format (`Video`, `Images / GIF`, `Web`, `Scenes`), sort by name or modification date, mark favorites (`★`), and adjust card size.
- **Format Support Matrix:**
  - **Video (`MP4`, `WebM`, `OGV`):** Native playback behind Astra's UI with volume, playback speed (`0.25x–4x`), scaling mode (`Fill / crop`, `Fit`, `Stretch`) and UI dimming (`0–90%`).
  - **Images & GIF (`PNG`, `JPG`, `WebP`, `GIF`, `BMP`):** Direct background display with scaling and dimming controls.
  - **Web Wallpapers (`HTML / CSS / JS`):** Experimental isolated sandbox playback with `wallpaperPropertyListener` (`applyUserProperties`, `applyGeneralProperties`, `setPaused`), interactive property editors in the inspector, and approximate audio-spectrum forwarding.
  - **Scene / PKG (`scene.pkg`):** Shown in the catalog with properties and previews, **not rendered as live scenes**. Preview images are never misrepresented as running scenes.
- **Read-Only Wallpaper Engine Settings Import:** Reads saved per-monitor values (`Monitor0`, `Monitor1`, etc.) and author defaults from `project.json` and `config.json` without modifying Wallpaper Engine's files.
- **Resource-Friendly Lifecycle:** Releases the active `<video>`, `<img>` or Web `<iframe>` when the document is hidden (`visibilitychange` / `pagehide`). On Windows, a lightweight read-only helper (`window-monitor.exe`) checks whether `astraui.exe` is minimized or hidden and pauses rendering via `push_to_ui`.

---

## Русское описание (Russian)

![Обложка: Wallpaper Engine для Astra — твоя локальная библиотека обоев внутри интерфейса Astra.](https://raw.githubusercontent.com/Dtierofficial/astra-wallpaper-engine/f3e9ac33162ea8317a5e1a1e915e9cd85080ed24/docs/assets/cover-ru.png)

**Локальная галерея скачанных обоев Wallpaper Engine и фоновый плеер прямо внутри интерфейса Astra.**

![Скриншот галереи (Русский): сетка установленных обоев с фильтрами, поиском, избранным и правой панелью свойств.](https://raw.githubusercontent.com/Dtierofficial/astra-wallpaper-engine/f3e9ac33162ea8317a5e1a1e915e9cd85080ed24/docs/assets/gallery-ru.png)

### Что умеет плагин
- **Один пакет — два языка (RU / EN):** при запуске плагин автоматически включает язык самой Astra (до получения ответа показывается только нейтральный экран загрузки без мигания чужого языка). В шапке галереи также есть ручной переключатель языка.
- **Автопоиск библиотеки Steam:** автоматически находит папки `steamapps/workshop/content/431960` и локальные проекты `myprojects`. Никакие файлы оригинального Wallpaper Engine не изменяются.
- **Поддерживаемые форматы:**
  - **Видео (`MP4`, `WebM`, `OGV`):** воспроизводятся прямо под интерфейсом Astra; настраиваются громкость, скорость, заполнение и затемнение фона.
  - **Картинки и GIF (`PNG`, `JPG`, `WebP`, `GIF`, `BMP`):** отображаются в фоне с выбором масштабирования и затемнения.
  - **Web-обои (`HTML / CSS / JS`):** экспериментальный запуск в изолированном sandbox-фрейме с передачей пользовательских свойств, FPS и аудиоспектра (требует подтверждения доверия перед первым запуском).
  - **Сцены (`scene.pkg`):** отображаются в каталоге для просмотра свойств, но **не воспроизводятся** (превью-картинка не выдаётся за живую 3D/2D-сцену).
- **Остановка при сворачивании и закрытии окна:** когда окно Astra свёрнуто или закрыто в трей, видеоплеер и фрейм выгружаются из памяти, а при открытии окна — создаются заново.

---

## Permissions & Privacy

- **`push_to_ui`:** Used only to notify the plugin's background renderer when the native Astra window is minimized, hidden or restored so playback stops while hidden.
- **Local-First Operation:** The plugin serves media only over `127.0.0.1` with a per-session random token, strict path-containment checks, and Content Security Policy isolation for Web wallpapers. It makes no external network requests and sends no telemetry.

---

## Development & Verification

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, reproducible cross-compilation of the Windows visibility helper (`dotnet build`), unit tests (`npm test`), and end-to-end sandbox UI tests (`npm run test:ui`).

*This project is an independent community integration by DtieR and is not affiliated with or endorsed by Wallpaper Engine, Valve/Steam, or Minice/Astra.*
