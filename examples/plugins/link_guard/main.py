"""Пример плагина: не даёт опубликовать пост с открытой ссылкой.

Ссылка в посте может выдать автора (личный сайт, реферальный код, уникальный адрес). Плагин останавливает отправку
и объясняет почему; черновик остаётся — нажмите «Скрыть ссылки» и отправьте снова. Плагин читает текст поста до
отправки, но в сеть не ходит: унести текст ему некуда.

Включить: скопируйте каталог в plugins/ рядом с config.toml и добавьте "link_guard" в [plugins] enabled.
"""
import re

from veil import plugins

LINK = re.compile(r"https?://|t\.me/|www\.", re.IGNORECASE)


@plugins.before_send
async def guard(out: plugins.Outgoing):
    if out.hide in ("links", "message", "to"):
        return None  # ссылки уже скрыты
    if LINK.search(out.text):
        return "в посте есть открытая ссылка — нажмите «Скрыть ссылки» или уберите её"
    return None
