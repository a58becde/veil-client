"""/market в боте (docs/MARKET.md, «Каталог»): список плагинов каталога, карточка, установка, обновление, удаление.

Всё скачивается и проверяется в veil.market; здесь — кнопки и тексты. Установка: скачать и проверить пакет → показать
разрешения → «Разрешить» → поставить и запустить в движке плагинов. Платный плагин: «Купить» → запрос VEILLIC для
бота-магазина → владелец платит Stars и пересылает ответ VEILLICRES сюда → бот проверяет лицензию, активирует её
на сервере анонимно и продолжает установку. Обновление с теми же разрешениями того же автора ставится
по кнопке «Обновить» без повторного вопроса; просит больше — снова согласие. Раз в сутки бот проверяет каталог: сборку,
которую каталог отозвал, останавливает и удаляет, о новых версиях сообщает (ставит — только по кнопке).
"""
from __future__ import annotations

import logging
import shutil
from typing import TYPE_CHECKING

from veil import market as mk
from veil import plugin_manifest as pm
from veil import plugins as plug
from veil.core import api

if TYPE_CHECKING:
    from veil.ui.bot import UI

log = logging.getLogger("veil.ui")
PAGE = 8


class MarketUI:
    def __init__(self, ui: "UI", market: mk.Market | None):
        self.ui, self.market = ui, market
        self.staged: dict[str, tuple] = {}  # id → (каталог пакета, манифест, запись индекса), ждут «Разрешить»

    @property
    def tr(self):
        return self.ui.T

    async def _say(self, text: str, markup: dict | None = None):
        return await self.ui._say(text, markup)

    async def _edit(self, msg: dict | None, text: str, markup: dict | None = None) -> None:
        """Поправить сообщение под кнопкой; нет его (продолжение после ответа магазина) — новым сообщением."""
        if msg is None:
            await self._say(text, markup)
            return
        await self.ui.bot.edit(msg["chat"]["id"], msg["message_id"], text, markup=markup)

    def _unavailable(self) -> str | None:
        if self.market is None:
            return self.tr("text.market_off")
        return None

    # --- список и карточка ---
    async def open(self, msg: dict | None = None, page: int = 0) -> None:
        if why := self._unavailable():
            await self._say(why)
            return
        try:
            idx = await self.market.refresh(force=msg is None)
        except mk.MarketError as e:
            await self._say(self.tr("text.market_error", err=e))
            return
        installed = self.market.installed()
        # Установленные, но убранные из каталога — в конце списка: иначе их не удалить кнопкой.
        items: list = sorted(idx.plugins.values(), key=lambda e: e.name.lower()) + \
            sorted(set(installed) - set(idx.plugins))
        if not items:
            await self._say(self.tr("text.market_empty"))
            return
        pages = (len(items) + PAGE - 1) // PAGE
        page = max(0, min(page, pages - 1))
        chunk = items[page * PAGE:(page + 1) * PAGE]
        lines = [self._line(e, installed.get(e.id)) if isinstance(e, mk.Entry) else
                 self.tr("text.market_delisted_line", name=e, version=installed[e]["version"]) for e in chunk]
        text = self.tr("text.market_list", lines="\n".join(lines), page=page + 1, pages=pages)
        if self.market.stale():
            text += "\n\n" + self.tr("text.market_stale", date=idx.generated)
        rows = [[(e.name[:40], f"mk:v:{e.id}")] if isinstance(e, mk.Entry) else [(e[:40], f"mk:v:{e}")]
                for e in chunk]
        nav = ([(f"← {page}", f"mk:p:{page - 1}")] if page else []) + \
              ([(f"{page + 2} →", f"mk:p:{page + 1}")] if page + 1 < pages else [])
        if nav:
            rows.append(nav)
        markup = api.keyboard(rows)
        if msg:
            await self._edit(msg, text, markup)
        else:
            await self._say(text, markup)

    def _line(self, e: mk.Entry, inst: dict | None) -> str:
        price = self.tr("text.market_price", n=e.price_stars) if e.price_stars else self.tr("text.market_free")
        state = ""
        if inst:
            newer = mk.version_key(e.version) > mk.version_key(inst["version"])
            state = " · " + (self.tr("text.market_has_update", v=e.version) if newer
                             else self.tr("text.market_installed"))
        desc = e.description if len(e.description) <= 90 else e.description[:89] + "…"
        return f"• {e.name} {e.version} — {desc} ({price}{state})"

    async def view(self, id_: str, msg: dict) -> None:
        idx = self.market.index
        e = idx.plugins.get(id_) if idx else None
        inst = self.market.installed().get(id_)
        if e is None and inst:
            await self._edit(msg, self.tr("text.market_delisted_card", name=id_, version=inst["version"]),
                             api.keyboard([[(self.tr("button.market_remove"), f"mk:r:{id_}")]]))
            return
        if e is None:
            await self._edit(msg, self.tr("text.market_gone"))
            return
        m = pm.from_fields({**e.manifest_fields(), "api": pm.API, "entry": "main"})
        text = self.tr("text.market_card", name=e.name, version=e.version, author=e.author, license=e.license,
                      description=e.description, reviewed=e.reviewed, size=max(1, e.size // 1024),
                      sha=e.sha256[:12])
        text += "\n\n" + self.ui.grant_text(m)
        licensed = id_ in self.market.licenses()
        if e.price_stars:
            text += "\n\n" + self.tr("text.market_paid", n=e.price_stars) + " " + \
                (self.tr("text.market_licensed") if licensed else self.tr("text.market_paid_how"))
        rows = []
        if inst:
            if mk.version_key(e.version) > mk.version_key(inst["version"]):
                rows.append([(self.tr("button.market_update", v=e.version), f"mk:u:{id_}")])
            rows.append([(self.tr("button.market_remove"), f"mk:r:{id_}")])
        elif not e.price_stars or licensed:
            rows.append([(self.tr("button.market_install"), f"mk:i:{id_}")])
        elif self.market.index.shop:
            rows.append([(self.tr("button.market_buy", n=e.price_stars), f"mk:b:{id_}")])
        rows.append([(self.tr("button.market_back"), "mk:p:0")])
        await self._edit(msg, text, api.keyboard(rows))

    # --- установка и обновление ---
    async def fetch(self, id_: str, msg: dict) -> None:
        """«Установить» / «Обновить»: скачать и проверить; разрешения уже одобрены — поставить, иначе спросить."""
        idx = self.market.index
        e = idx.plugins.get(id_) if idx else None
        if e is None:
            await self._edit(msg, self.tr("text.market_gone"))
            return
        await self._edit(msg, self.tr("text.market_checking", name=e.name))
        try:
            key = await self._license_key(e) if e.encrypted else None
            pdir, m = await self.market.fetch_package(e, key)
        except mk.MarketError as err:
            await self._edit(msg, self.tr("text.market_install_failed", name=e.name, err=err))
            return
        grant = (self.ui.core.store.get("plugin_grants") or {}).get(id_)
        if id_ in self.market.installed() and m.covered_by(grant):
            await self._install(pdir, m, e, msg)
            return
        self.staged[id_] = (pdir, m, e)
        allow = (self.tr("button.plugin_allow"), f"mk:ok:{id_}:{e.sha256[:12]}")
        deny = (self.tr("button.plugin_deny"), f"mk:no:{id_}")
        await self._edit(msg, self.ui.grant_text(m), api.keyboard([[allow, deny]]))

    # --- покупка ---
    async def buy(self, id_: str, msg: dict) -> None:
        """«Купить»: ослеплённый запрос лицензии для бота-магазина. Платит владелец сам, в чате магазина."""
        idx = self.market.index
        e = idx.plugins.get(id_) if idx else None
        if e is None or not e.price_stars:
            await self._edit(msg, self.tr("text.market_gone"))
            return
        try:
            req = self.market.start_purchase(e)
        except mk.MarketError as err:
            await self._edit(msg, self.tr("text.market_install_failed", name=e.name, err=err))
            return
        await self._edit(msg, self.tr("text.market_buy_how", name=e.name, n=e.price_stars, bot=idx.shop.bot))
        await self._say(req)  # отдельным сообщением — переслать или скопировать целиком

    async def license_response(self, text: str) -> None:
        """Ответ магазина VEILLICRES, пересланный владельцем: проверить лицензию и сразу продолжить установку."""
        if why := self._unavailable():
            await self._say(why)
            return
        try:
            plugin = self.market.accept_license(text)
        except mk.MarketError as err:
            await self._say(self.tr("text.market_license_bad", err=err))
            return
        await self._say(self.tr("text.market_license_ok", name=self._name(plugin)))
        try:
            if self.market.index is None:
                await self.market.refresh()
        except mk.MarketError as err:
            await self._say(self.tr("text.market_error", err=err))
            return
        await self.fetch(plugin, None)

    async def _license_key(self, e: mk.Entry) -> bytes:
        """Ключ версии платного пакета: активация или ключ обновления на сервере — анонимным конвертом."""
        try:
            return await self.market.license_key(self.ui.core.market_request, e, self.ui.core.server_sig_pk())
        except api.ServerError as err:
            known = {"E_TOKEN_SPENT": "text.market_license_spent", "E_TOKEN_INVALID": "text.market_license_rejected",
                     "E_UNSUPPORTED": "text.market_server_off", "E_NOT_FOUND": "text.market_no_version_key"}
            raise mk.MarketError(self.tr(known[err.code]) if err.code in known else self.ui.explain(err)) from None
        except api.NoReplyError:
            raise mk.MarketError(self.tr("text.no_reply")) from None

    async def confirm(self, id_: str, sha12: str, msg: dict) -> None:
        staged = self.staged.pop(id_, None)
        if staged is None or staged[2].sha256[:12] != sha12:  # кнопка от другой, уже не актуальной сборки
            await self._edit(msg, self.tr("text.market_gone"))
            return
        await self._install(*staged, msg)

    async def deny(self, id_: str, msg: dict) -> None:
        staged = self.staged.pop(id_, None)
        if staged:
            shutil.rmtree(staged[0], ignore_errors=True)
        await self._edit(msg, self.tr("text.cancelled"))

    async def _install(self, pdir, m, e: mk.Entry, msg: dict) -> None:
        reg = self.ui.plugins
        await reg.remove(e.id)  # прежняя версия снимается до замены файлов
        self.market.install(pdir, e)
        grants = dict(self.ui.core.store.get("plugin_grants") or {})
        grants[e.id] = m.grant()
        self.ui.core.store.put("plugin_grants", grants)
        try:
            p = plug.load_package(self.market.plugins_dir, e.id)
        except plug.PluginError as err:
            await self._edit(msg, self.tr("text.market_install_failed", name=e.name, err=err))
            return
        reg.packages.append(p)
        if await reg.start_package(p):
            self.ui.core.store.put("plugins_seen", plug.changes(reg, None)[0] or None)
            await self._edit(msg, self.tr("text.market_done", name=e.name, version=e.version))
            await self.ui._set_menu()
        else:
            await self._edit(msg, self.tr("text.plugin_not_loaded", name=e.id, err=reg.failed[-1][1]))

    # --- удаление ---
    async def ask_remove(self, id_: str, msg: dict) -> None:
        name = self._name(id_)
        await self._edit(msg, self.tr("text.market_remove_ask", name=name),
                         api.keyboard([[(self.tr("button.market_remove_yes"), f"mk:rok:{id_}"),
                                    (self.tr("button.cancel"), "mk:p:0")]]))

    async def remove(self, id_: str, msg: dict | None = None, reason: str = "") -> None:
        """Удалить плагин маркета: обработчики, файлы, хранилище плагина и согласие."""
        name = self._name(id_)
        await self.ui.plugins.remove(id_)
        self.market.remove(id_)
        self.ui.core.store.put(plug.storage_key(id_), None)
        grants = dict(self.ui.core.store.get("plugin_grants") or {})
        grants.pop(id_, None)
        self.ui.core.store.put("plugin_grants", grants or None)
        self.ui.core.store.put("plugins_seen", plug.changes(self.ui.plugins, None)[0] or None)
        await self.ui._set_menu()
        text = self.tr("text.market_revoked", name=name, reason=reason) if reason else \
            self.tr("text.market_removed", name=name)
        if msg:
            await self._edit(msg, text)
        else:
            await self._say(text)

    def _name(self, id_: str) -> str:
        idx = self.market.index if self.market else None
        e = idx.plugins.get(id_) if idx else None
        return e.name if e else id_

    # --- кнопки и ежедневная проверка ---
    async def callback(self, rest: str, msg: dict) -> None:
        if why := self._unavailable():
            await self._edit(msg, why)
            return
        action, _, arg = rest.partition(":")
        if action == "p":
            await self.open(msg, int(arg or 0))
        elif self.market.index is None:  # бот перезапустился после показа списка
            await self.open(msg)
        elif action == "v":
            await self.view(arg, msg)
        elif action in ("i", "u"):
            await self.fetch(arg, msg)
        elif action == "b":
            await self.buy(arg, msg)
        elif action == "ok":
            id_, _, sha12 = arg.partition(":")
            await self.confirm(id_, sha12, msg)
        elif action == "no":
            await self.deny(arg, msg)
        elif action == "r":
            await self.ask_remove(arg, msg)
        elif action == "rok":
            await self.remove(arg, msg)

    async def daily(self) -> None:
        """Отозванные сборки — остановить и удалить; о новых версиях — сообщить один раз (ставит владелец сам)."""
        if self._unavailable() or not self.market.installed():
            return
        try:
            await self.market.refresh(force=True)
        except mk.MarketError as e:
            log.info("market refresh: %s", e)
            return
        for id_, reason in self.market.revoked_installed().items():
            await self.remove(id_, reason=reason or "—")
        told = dict(self.ui.core.store.get("market_told") or {})
        for e in self.market.updates():
            if told.get(e.id) != e.version:
                told[e.id] = e.version
                await self._say(self.tr("text.market_update_available", name=e.name, version=e.version))
        self.ui.core.store.put("market_told", told or None)
