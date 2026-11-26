# FBX to VRM in a couple of clicks / Из FBX в VRM за пару кликов

Author / Автор: **VovaBOOMs** · License / Лицензия: **GPL-3.0-only** (see / см. `COPYING`)

[English](#english) · [Русский](#русский)

---

## English

An Astra plugin built on the mmd2vrm 2.3 converter. It turns character models into VRM 0.x / 1.0 avatars:
MMD (.pmx, .pmd), FBX (game rips, Mixamo, Blender, Unity, Unreal) and VRM.

### What it does

Just ask the assistant:

- "Make a VRM from D:\models\Kei.fbx": the model is converted and the .vrm is saved **next to the original**
  (or into the folder from the settings). The original file is never changed, moved or deleted.
- "…as VRM 1.0", "…and save the wave and bow animations": VRM version and built-in animations
  (.vrma files next to the VRM).
- "Which animations are there?": the list of built-in animations.
- "Open the VRM editor with this model": the full editor (3D preview, physics, materials, body fill,
  animations) opens in the browser, just like the stand-alone program.

> **Recommended:** automatic conversion gives a good result for most models, but for **more precise tuning**
> (physics of hair, skirts and tails, expressions, materials and transparency, skeleton) open the model in the
> editor. The edits are saved for that model, and the next conversion through Astra uses them automatically.

### Differences from the stand-alone mmd2vrm

- No "Wardrobe" tab (wardrobe clothes from the stand-alone program are not applied).
- Hair and clothes physics defaults to **smooth** (`soft`), so models converted by Astra on its own move softly.
  You can change it in the plugin settings or in the editor.

### Settings

Workshop → Plugins → this plugin → settings: VRM version, output folder, hair and clothes physics,
best texture quality, file size limit, Russian names for expressions and parts, plugin language.

The settings page is shown in Astra's interface language (Russian and English are included). The
"Plugin language" option forces the language of the plugin's own messages (Like Astra / Русский / English).

### Installing for testing

1. Astra → Settings → Privacy → turn on "Allow unsigned plugins".
2. Workshop → Development → paste the path to this folder into "Load a plugin" and press the load button.
3. On first start Astra installs the required libraries (numpy, Pillow and others); this can take a couple of minutes.
4. After Astra restarts, a plugin loaded from a folder is switched off: turn it on in the Installed tab.

Details about the converter itself: `src/engine/README_mmd2vrm.md` (in Russian).

---

## Русский

Плагин для Astra на основе конвертера mmd2vrm 2.3. Превращает модели персонажей в аватары VRM 0.x / 1.0:
MMD (.pmx, .pmd), FBX (рипы из игр, Mixamo, Blender, Unity, Unreal) и VRM.

### Что умеет

Просто попросите ассистента:

- «Сделай VRM из D:\models\Kei.fbx» — модель конвертируется, файл .vrm сохраняется **рядом с исходником**
  (или в папку из настроек). Исходный файл не изменяется, не переносится и не удаляется.
- «…в VRM 1.0», «…и сохрани анимации wave и bow» — версия VRM и встроенные анимации (.vrma рядом с VRM).
- «Какие есть анимации?» — список встроенных анимаций.
- «Открой редактор VRM с этой моделью» — полный редактор (3D-превью, физика, материалы, достройка тела,
  анимации) открывается в браузере, как в обычной программе.

> **Рекомендация:** автоматическая конвертация даёт хороший результат для большинства моделей, но для
> **более точной настройки** (физика волос, юбок и хвостов, выражения лица, материалы и прозрачность, скелет)
> откройте модель в редакторе. Настройки сохраняются для этой модели, и следующая конвертация через Astra
> использует их автоматически.

### Отличия от обычной программы mmd2vrm

- Нет вкладки «Гардероб» (одежда из гардероба обычной программы при конвертации не применяется).
- По умолчанию физика волос и одежды **«Плавная»** (`soft`) — чтобы модели, которые Astra конвертирует сама,
  двигались мягко. Поменять можно в настройках плагина или в редакторе.

### Настройки

Workshop → Plugins → этот плагин → настройки: версия VRM, папка для результата, физика волос и одежды,
максимальное качество текстур, ограничение размера файла, русские названия выражений и частей, язык плагина.

Страница настроек показывается на языке интерфейса Astra (есть русский и английский). Пункт «Язык плагина»
принудительно переключает язык сообщений самого плагина (Как в Astra / Русский / English).

### Установка для проверки

1. Astra → Settings → Privacy → включить «Allow unsigned plugins».
2. Workshop → Development → вставить путь к этой папке в поле «Load a plugin» и нажать кнопку загрузки.
3. При первом запуске Astra сама поставит нужные библиотеки (numpy, Pillow и др.) — это может занять пару минут.
4. После перезапуска Astra плагин, загруженный из папки, выключен — включите его на вкладке Installed.

Подробности о самом конвертере — в `src/engine/README_mmd2vrm.md`.
