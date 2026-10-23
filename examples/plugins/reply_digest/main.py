"""Пример плагина: копит ответы на ваши посты и по команде /digest присылает сводку.

Включить: скопируйте каталог в plugins/ рядом с config.toml и добавьте в config.toml
    [plugins]
    enabled = ["reply_digest"]
    [plugins.settings.reply_digest]
    keep = 50          # сколько последних ответов помнить
Ответы переживают перезапуск: они в хранилище плагина.
"""
from veil import plugins

KEEP = int(plugins.settings().get("keep", 50))
STORE = plugins.storage()


@plugins.on_reply
async def remember(reply: plugins.Reply) -> None:
    replies = STORE.get("replies", []) + [reply.to]
    STORE.put("replies", replies[-KEEP:])


@plugins.on_command("digest", "Сводка ответов на мои посты")
async def digest(arg: str) -> None:
    replies = STORE.get("replies", [])
    if not replies:
        await plugins.notify_owner("Новых ответов нет.")
        return
    by_post: dict[int, int] = {}
    for to in replies:
        by_post[to] = by_post.get(to, 0) + 1
    lines = [f"№{n}: {count}" for n, count in sorted(by_post.items())]
    await plugins.notify_owner("Ответы на ваши посты (пост: сколько):\n" + "\n".join(lines))
    STORE.put("replies", [])


@plugins.on_tokens_low
async def low(left: int) -> None:
    await plugins.notify_owner(f"Токенов на сегодня осталось: {left}. Пополнить — /tokens.")
