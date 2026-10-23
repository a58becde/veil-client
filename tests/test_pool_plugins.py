"""Плагины в пуле (docs/POOL.md, «Плагины»): движок — один на группу, без компиляции на сервере; песочница группы
пропускает движок и локальный каталог маркета; плагины одного бота не занимают движок всей группы."""
import asyncio
import time

from veil import plugins, pool, sandbox

from plugkit import bot, new_engine, package, settle, shutdown, start_all, texts


def test_group_engine_from_config(tmp_path):
    cfg = {"telegram": {}, "privacy": {}, "pool": {}, "server": {},
           "plugins": {"engine_sha256": "ab" * 32, "workers": 3, "precompiled_dir": "eng"}}
    g = pool.Group(cfg, tmp_path, tmp_path / "g0", None, None)
    assert not g.engine.compile_ok and g.engine.workers == 3 and g.engine.cache == tmp_path / "eng"
    assert "ab" * 32 in g.engine.trusted and g.engine.memory_mb == 64
    g2 = pool.Group({"telegram": {}, "privacy": {}, "pool": {}, "server": {}}, tmp_path, tmp_path / "g1", None, None)
    assert g2.engine.workers == 2 and g2.engine.cache == tmp_path / "engine"   # по умолчанию — 2 потока


def test_group_sandbox_reads_engine_and_market(tmp_path, monkeypatch):
    """Landlock группы: кроме кода — движок, его машинный код и локальная копия каталога маркета (file://)."""
    seen = {}

    def fake_restrict(root, app, files, ports, extra_read=()):
        seen.update(root=root, files=files, read=list(extra_read))
        return 6
    monkeypatch.setattr(sandbox, "restrict_group", fake_restrict)
    market_dir = tmp_path / "market dir"
    cfg = {"telegram": {}, "privacy": {}, "pool": {}, "server": {},
           "plugins": {"engine": "eng/veil-engine.wasm", "precompiled_dir": "cw"},
           "market": {"urls": [market_dir.as_uri() + "/", "https://example.com/catalog/"]}}
    pool._sandbox(cfg, tmp_path, tmp_path / "g0", 0)
    assert seen["read"] == [tmp_path / "eng", tmp_path / "cw", market_dir]


SPIN = """
from veil import plugins
@plugins.on_command("{cmd}", "Крутиться")
async def spin(arg):
    while True:
        pass
"""


def test_one_bot_does_not_hold_the_group_engine(tmp_path, monkeypatch):
    """Бот, у которого два плагина зависли (до своего лимита времени), занимает в движке группы не больше двух
    мест: команда соседнего бота выполняется сразу."""
    monkeypatch.setattr(plugins, "COMMAND_TIMEOUT", 6.0)
    package(tmp_path / "a", "spin_one", SPIN.format(cmd="one"), permissions=["commands"])
    package(tmp_path / "a", "spin_two", SPIN.format(cmd="two"), permissions=["commands"])
    package(tmp_path / "a", "spin_three", SPIN.format(cmd="three"), permissions=["commands"])
    package(tmp_path / "b", "quick", """
        from veil import plugins
        @plugins.on_command("quick", "Быстро")
        async def quick(arg):
            await plugins.notify_owner("готово")
    """, permissions=["commands", "notify"])
    eng = new_engine(workers=3)
    ea, ra = bot(tmp_path / "a", ["spin_one", "spin_two", "spin_three"], eng)
    eb, rb = bot(tmp_path / "b", ["quick"], eng)

    async def body():
        await start_all(ra)
        await start_all(rb)
        try:
            busy = [asyncio.create_task(ra.run_command(c, "")) for c in ("one", "two", "three")]
            await asyncio.sleep(0.5)
            t = time.monotonic()
            await rb.run_command("quick", "")
            await settle(eb)
            took = time.monotonic() - t
            await asyncio.gather(*busy)
            return took
        finally:
            await shutdown(ra, rb)
    took = asyncio.run(body())
    assert took < 3 and any("готово" in t for t in texts(eb))
    assert sum("TimeoutError" in t for t in texts(ea)) == 3

