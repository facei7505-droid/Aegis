"""Shared immunity: one site's attacker is every site's attacker (for a while)."""
from __future__ import annotations

import time

from aegis.shield.core import ShieldConfig, ShieldCore
from aegis.shield.immunity import SharedBans

ATTACK = [("query", "id", "1' UNION SELECT password FROM users--")]
CLEAN = [("query", "q", "кроссовки")]


def shop(shared, name, mode="block"):
    return ShieldCore(ShieldConfig(mode=mode, ban_after=3, ban_seconds=900), shared=shared, name=name)


def attack(core, client, times=3):
    for _ in range(times):
        core.inspect(client, "GET", "/catalog", ATTACK)


def test_a_ban_on_one_site_protects_the_others(tmp_path):
    shared = SharedBans(tmp_path / "bans.json")
    a, b = shop(shared, "a.kz"), shop(shared, "b.kz")
    assert not b.inspect("203.0.113.5", "GET", "/", CLEAN).blocked
    attack(a, "203.0.113.5")
    verdict = b.inspect("203.0.113.5", "GET", "/", CLEAN)
    assert verdict.blocked and verdict.banned
    assert shared.source("203.0.113.5") == "a.kz"
    assert not b.inspect("203.0.113.6", "GET", "/", CLEAN).blocked     # nobody else is touched


def test_learning_sites_do_not_ban_for_others(tmp_path):
    shared = SharedBans()
    learning, other = shop(shared, "new.kz", mode="monitor"), shop(shared, "b.kz")
    attack(learning, "203.0.113.7")
    assert not other.inspect("203.0.113.7", "GET", "/", CLEAN).blocked
    assert shared.active() == {}


def test_owner_can_pardon_for_their_own_site_only():
    shared = SharedBans()
    a, b = shop(shared, "a.kz"), shop(shared, "b.kz")
    attack(a, "203.0.113.8")
    assert b.unlock("203.0.113.8")                                      # b's owner: "that is my customer"
    assert not b.inspect("203.0.113.8", "GET", "/", CLEAN).blocked
    assert a.inspect("203.0.113.8", "GET", "/", CLEAN).blocked          # a keeps its ban


def test_bans_survive_a_restart_and_expire(tmp_path):
    path = tmp_path / "bans.json"
    SharedBans(path).ban("203.0.113.9", time.time() + 600, "a.kz")
    SharedBans(path).ban("203.0.113.10", time.time() - 1, "a.kz")       # already over
    reloaded = SharedBans(path)
    assert reloaded.until("203.0.113.9") > time.time()
    assert reloaded.until("203.0.113.10") == 0.0
    assert shop(reloaded, "b.kz").inspect("203.0.113.9", "GET", "/", CLEAN).blocked
    assert reloaded.lift("203.0.113.9") and reloaded.until("203.0.113.9") == 0.0


def test_gateway_apps_share_bans(tmp_path):
    from aegis.gateway import AppSpec, Gateway
    gw = Gateway([AppSpec("a", "http://127.0.0.1:9", ["a.kz"], heal="off", options={"ban_after": 2}),
                  AppSpec("b", "http://127.0.0.1:9", ["b.kz"], heal="off")], log_dir=str(tmp_path))
    core_a, core_b = gw.shields["a"].core, gw.shields["b"].core
    assert core_a.shared is core_b.shared is gw.shared_bans
    attack(core_a, "198.51.100.4", times=2)
    assert core_b.inspect("198.51.100.4", "GET", "/", CLEAN).blocked
    assert (tmp_path / "bans.json").is_file()


def test_a_broken_bans_file_costs_the_bans_not_the_start(tmp_path):
    path = tmp_path / "bans.json"
    path.write_text('{"1.2.3.4": ["soon", "x"], "5.6.7.8": [' + str(time.time() + 600) + ', "a.kz"], "9.9.9.9": 7}')
    bans = SharedBans(path)
    assert bans.until("5.6.7.8") > 0 and bans.until("1.2.3.4") == 0.0
    path.write_text("[1, 2")
    assert SharedBans(path).active() == {}


def test_a_scanner_wave_does_not_rewrite_the_file_per_ban(tmp_path):
    path = tmp_path / "bans.json"
    bans = SharedBans(path)
    t0 = time.time()
    for i in range(5000):
        bans.ban(f"10.{i // 256}.{i % 256}.1", time.time() + 600, "a.kz")
    assert time.time() - t0 < 2.0
    bans.flush()
    assert len(SharedBans(path).active()) == 5000
