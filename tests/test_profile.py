"""Positive security model: learned per-endpoint parameter profiles."""
from aegis.shield.core import ShieldConfig, ShieldCore
from aegis.shield.profile import TrafficProfile, template


def q(**params):
    return [("path", "path", "/shop/item")] + [("query", k, v) for k, v in params.items()]


def trained(n=50):
    prof = TrafficProfile(min_samples=20)
    for i in range(n):
        prof.learn("/shop/item", q(id=str(i), name=f"Laptop Pro {i}", lang="ru"))
    return prof


def test_template_generalises_ids():
    assert template("/user/42/orders/9f8e7d6c5b4a3f2e") == "/user/{id}/orders/{id}"


def test_normal_values_pass():
    prof = trained()
    assert prof.check("/shop/item", q(id="77", name="Laptop Air 5", lang="kk")) is None


def test_renamed_parameter_text_in_number_quote_and_overlong():
    prof = trained()
    assert "never sent" in prof.check("/shop/item", q(idA="2", name="x")).reasons[0]
    assert "always a number" in prof.check("/shop/item", q(id="2x", name="Laptop")).reasons[0]
    assert "'" in prof.check("/shop/item", q(id="2", name="Laptop' --")).reasons[0]
    assert "longest seen" in prof.check("/shop/item", q(id="2", name="A" * 400)).reasons[0]


def test_tracking_parameters_are_ignored_and_young_endpoints_not_judged():
    prof = trained()
    assert prof.check("/shop/item", q(id="1", name="Laptop", utm_source="tg")) is None
    young = trained(n=5)
    assert young.check("/shop/item", q(idA="2")) is None


def test_strict_paths_flag_unknown_files():
    prof = TrafficProfile(min_samples=2, strict_paths=True)
    for i in range(20):
        prof.learn("/a", [("path", "path", "/a")])
    assert prof.check("/backup.sql", [("path", "path", "/backup.sql")]).score >= 0.8
    assert TrafficProfile(min_samples=2).check("/new", []) is None  # default: new pages are fine


def test_profile_round_trip(tmp_path):
    prof = trained()
    prof.save(str(tmp_path / "p.json"))
    again = TrafficProfile.load(str(tmp_path / "p.json"))
    assert again.check("/shop/item", q(idA="2")) is not None and again.learned == prof.learned


def test_shield_learns_then_enforces_and_persists(tmp_path):
    path = str(tmp_path / "profile.json")
    core = ShieldCore(ShieldConfig(learn=30, profile_path=path, ban_after=0))
    for i in range(30):
        assert not core.inspect("1.1.1.1", "GET", "/shop/item", q(id=str(i), name="Laptop")).blocked
    assert core.profile_state()["mode"] == "enforcing"
    v = core.inspect("1.1.1.1", "GET", "/shop/item", q(idA="2", name="Laptop"))
    assert v.blocked and v.incident.attack_type == "anomaly"
    assert not core.inspect("1.1.1.1", "GET", "/shop/item", q(id="31", name="Laptop")).blocked
    restarted = ShieldCore(ShieldConfig(learn=30, profile_path=path, ban_after=0))
    assert restarted.profile_state()["mode"] == "enforcing"


def test_attacks_are_never_learned():
    core = ShieldCore(ShieldConfig(learn=25, ban_after=0))
    for i in range(25):
        core.inspect("1.1.1.1", "GET", "/s", [("path", "path", "/s"), ("query", "q", "' UNION SELECT 1--" if i == 3 else "tea")])
    assert "'" not in core.profile.endpoints["/s"].params["q"].classes


def test_password_fields_keep_their_relaxed_threshold():
    core = ShieldCore(ShieldConfig(learn=25, ban_after=0))
    for i in range(25):
        core.inspect("1.1.1.1", "POST", "/login", [("path", "path", "/login"), ("form", "password", "abc123")])
    assert not core.inspect("1.1.1.1", "POST", "/login", [("path", "path", "/login"), ("form", "password", "p@ss;w0rd!")]).blocked
