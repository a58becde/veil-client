# veil-client

Эталонный бот пользователя для [Veil](https://github.com/a58becde/veil-protocol): пишешь своему боту,
и сообщение анонимно публикуется в группе. Ты владеешь своим ботом, своим ключом и своими токенами.

**12 слов восстановления существуют только в терминале** машины, где работает бот: бот их не хранит,
в Telegram не показывает и не принимает. Бот действует отдельным ключом устройства, который можно отозвать.
(Бот в пуле — на чужой машине, без терминала — по умолчанию создаёт личность без слов: [`docs/POOL.md`](docs/POOL.md).)

- Архитектура и API для доработок: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Установка и запуск своего бота по шагам: [`docs/INSTALL.md`](docs/INSTALL.md)
- Экспорт и перенос бота: [`docs/EXPORT.md`](docs/EXPORT.md); пул управляемых ботов: [`docs/POOL.md`](docs/POOL.md)
- Плагины (код на события бота, работает в движке WebAssembly без доступа к ключам): [`docs/PLUGINS.md`](docs/PLUGINS.md); маркет плагинов —
  [`docs/MARKET.md`](docs/MARKET.md)
- Протокол: [veil-protocol](https://github.com/a58becde/veil-protocol)
- Как сообщить об уязвимости: [`SECURITY.md`](SECURITY.md)

Статус: реализовано протокольное ядро (`veil/core/protocol`, `veil/core/crypto`, `veil/core/identity`):
конверт, подписи, sealed box, JCS, 12 слов → корень → сертификат устройства, медленные метки, ники,
клиентская часть токенов RFC 9497,
обмен с ботом-эмитентом (`veil/core/wallet/issue.py`: запрос `VEILREQ`, проверка ответа `VEILRES`).
Есть рабочий бот (MVP, 2026-10-15): черновики с кнопками, публикация (текст, медиа, альбомы, опросы),
анонимно или с ником, скрытые ссылки и сообщения, ответы и действия через пересылку поста (UPD, исправить,
удалить), токены через бота-эмитента, ник, личность и восстановление по 12 словам (только в консоли), уведомления
об ответах и скрытом для вас, экспорт и импорт (`/export`, `/import`, команды `export`/`import`), плагины.
Пока нет: /settings.

Принципы интерфейса (по проверке владельцем 2026-10-15): кодов ошибок пользователь не видит — только
объяснение и что делать (`[error]` в `locales/ru.toml`, тест `test_every_server_error_has_explanation`);
статус «Отправляю…» превращается в итог; если черновик меняется после ввода текста (например, получатель «Лично для…»),
старый черновик удаляется и новый приходит внизу — правку сообщения выше по чату легко не заметить; меню поста одноразовое;
12 слов в Telegram не появляются вообще (с 2026-10-16). Токен тратится только на выполненное
действие (публикация, правка, удаление, ник), не на нажатия кнопок.

## Запуск бота
```sh
python3 -m venv .venv && .venv/bin/pip install -e .
cp config.example.toml config.toml        # owner_id, server_sig (из keys.json сервера)
cp ../veil-protocol/keys.json keys.json   # keys.json из публичного репозитория — из него закрепляется ключ эмитента
.venv/bin/python -m veil config.toml init # личность: 12 слов покажутся здесь, в терминале; запишите их на бумагу
export VEIL_BOT_TOKEN=...                 # токен вашего бота от @BotFather (включите bot-to-bot)
.venv/bin/python -m veil config.toml      # при первом запуске бот зарегистрирует устройство (1 токен)
```
В @BotFather у вашего бота должен быть включён режим общения с другими ботами (Bot Settings →
Bot-to-Bot Communication). Если он выключен, бот при старте это заметит и подскажет владельцу, где включить.

Владелец: если `owner_id = 0`, бот при запуске кладёт ссылку с одноразовым кодом в `data/owner-link.txt` (права 600)
и показывает её в терминале, но не пишет в журнал: кто читает журнал, иначе стал бы владельцем первым. Откройте ссылку
из своего аккаунта — вы станете владельцем (сохраняется в `data/`), файл со ссылкой удалится. Меню команд (кнопка
«Меню» в Telegram) бот ставит сам.
Без личности бот тоже работает — только для анонимных постов.

Восстановление и перенос: на машине с ботом `python -m veil config.toml restore` (12 слов скрытым вводом). Новое
устройство отзывает прежнее — так же отзывается украденный бот или его файлы. Старый формат (до 2026-10-16, слова
в `data/identity.json`) переводится командой `migrate`: файл со словами затирается.

## Разработка
Требования: Python ≥ 3.11, системная libsodium ≥ 1.0.18 из пакетов дистрибутива (обновления безопасности
дистрибутив ставит сам, часто не меняя номер версии; Veil не вызывает функцию, затронутую CVE-2025-69277).
```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock   # точные версии с хешами
.venv/bin/pip install --no-deps -e . && .venv/bin/pip install pytest ruff   # ruff: правила в pyproject.toml
.venv/bin/pip-compile --generate-hashes --strip-extras -o requirements.lock pyproject.toml   # обновить lock
.venv/bin/pip install --require-hashes -r requirements-dev.lock   # import-linter (границы модулей)
.venv/bin/pip-compile --generate-hashes --no-emit-index-url --strip-extras -o requirements-dev.lock requirements-dev.in
.venv/bin/lint-imports --no-cache          # проверка границ модулей (контракты — pyproject.toml)
.venv/bin/python -m pytest                 # нужен соседний клон veil-protocol (тестовые векторы)
.venv/bin/python -m tools.gen_vectors      # перегенерировать veil-protocol/test-vectors/veil-v1.json
```
Ручная проверка бота-эмитента: `python -m tools.issue_manual` (описание в начале файла; состояние
кладите в `data/`, он в .gitignore).

Лицензия: MIT.
