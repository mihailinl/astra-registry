# Anim Studio — плагин для Astra

Добавляй аватару Astra свои анимации без ручной правки файлов и выбирай, когда она их играет.

## Установка

1. Скачай `anim-studio.astraplugin`.
2. Astra → **Мастерская** → **Разработка** → **Импорт плагина** → **Выбрать файл…** → выбери файл → **Установить**.
3. Страница плагина: меню **☰ (Навигация)** справа вверху → **Плагины** → **Anim Studio**.

## Как пользоваться

1. **＋ Добавить анимацию** → выбери файл:
   - `.vrma` — VRM Animation (VRoid, BOOTH);
   - `.fbx` — из [Mixamo](https://www.mixamo.com): Download → *FBX Binary, Without Skin, 30 fps*;
   - `.glb` — паки вроде Quaternius Universal Animation Library (при добавлении выбери нужные анимации).
2. У каждой анимации выбери, когда её играть:
   - **Сама, от скуки** — иногда играет, когда стоит без дела (ползунок «редко — часто»);
   - **Под музыку** — медленная / средняя / быстрая музыка;
   - **На месте** (для FBX) — убирает скольжение в сторону, чтобы она не уходила за край окна;
   - **Скорость**.
3. Нажми **Применить** — аватар перезапустится на пару секунд.

Каждая анимация получает своё состояние `as_…`:
- посмотреть: Astra → **Модель** → **Анимации** → **Показать**;
- реакция на событие: **Модель** → **Триггеры**;
- голосовая команда: создай команду с действием «Анимация компаньона», режим **state**, имя `as_…`.

## Как это устроено

Плагин ведёт отдельный набор-дополнение `animpacks/anim-studio` и подключает его к отмеченным персонажам строкой
`addons = ["anim-studio"]` в их `character.toml` (копия до изменения сохраняется как `character.toml.before-anim-studio`).
Собственный набор анимаций персонажа не меняется. Встроенные персонажи дополнения не поддерживают — сделай копию персонажа
(Модель → Персонажи → Добавить персонажа) и отметь её.

## Сборка из исходников

Нужны [bun](https://bun.sh) и [astra-plugin](https://github.com/mihailinl/AstraPlugins/blob/HEAD/docs/en/install-cli.md) 0.5.0+.

```
bun install
bun run test
astra-plugin check . --strict
astra-plugin test .
astra-plugin build .
```

Релизы собирает и подписывает GitHub Actions (`.github/workflows/release.yml`) по тегу `vX.Y.Z`.

---

# Anim Studio — an Astra plugin

Add your own animations to the Astra avatar without editing files by hand, and choose when she plays them:
when bored (idle), to music (slow / mid / fast), or as her own state `as_…` that you can bind to triggers and
commands. Supports `.vrma`, Mixamo `.fbx` (with an *in place* option) and multi-animation `.glb`.
Install: Astra → Workshop → Development → Import plugin → choose `anim-studio.astraplugin`.
The page lives in the ☰ Navigation menu → Plugins → Anim Studio.
