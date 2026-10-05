"""Pipeline, replay, simulator and doctor tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from honeywatch.config import parse_config
from honeywatch.doctor import run_doctor
from honeywatch.engine.detector import DetectionEngine, install_sighup_reload
from honeywatch.engine.loader import load_ruleset
from honeywatch.models import Event, EventType, Service
from honeywatch.pipeline import EventPipeline
from honeywatch.simulate_cmd import build_offline_pipeline
from honeywatch.simulator import PROFILES, Simulator
from honeywatch.storage.jsonl import JsonlArchive, read_jsonl
from honeywatch.storage.sqlite import Storage

NOW = datetime(2026, 3, 12, 12, 0, tzinfo=UTC)


@pytest.fixture
def offline(tmp_path: Path, rules_dir: Path):
    config = parse_config({"data_dir": str(tmp_path / "data")}, base_dir=tmp_path)
    pipeline, resources = build_offline_pipeline(config, db_path=tmp_path / "out.db")
    yield pipeline, config, resources
    for resource in resources:
        close = getattr(resource, "close", None)
        if close is not None:
            close()


def make_event(**overrides) -> Event:
    payload: dict = {
        "ts": NOW,
        "service": Service.SSH,
        "event_type": EventType.COMMAND,
        "src_ip": "203.0.113.1",
        "session_id": "s1",
        "command": "uname -a",
    }
    payload.update(overrides)
    return Event(**payload)


# ---- pipeline ------------------------------------------------------------


def test_event_reaches_sqlite_and_jsonl(offline) -> None:
    pipeline, _config, _resources = offline
    pipeline.process(make_event())
    rows = pipeline.storage.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert rows == 1
    files = list(pipeline.archive.files())
    assert files and len(list(read_jsonl(files[0]))) == 1


def test_detection_enriches_event(offline) -> None:
    pipeline, _config, _resources = offline
    event = make_event()
    hits = pipeline.process(event)
    assert any(hit.rule_id == "ssh-recon-cmds-006" for hit in hits)
    assert event.severity.value == "medium"
    assert "ssh-recon-cmds-006" in event.rule_ids


def test_jsonl_is_written_before_enrichment(offline) -> None:
    pipeline, _config, _resources = offline
    pipeline.process(make_event())
    event = next(iter(read_jsonl(pipeline.archive.files()[0])))
    assert event.geo_country is None  # enrichment happens downstream


def test_queue_is_bounded() -> None:
    assert EventPipeline.__init__.__doc__ is None or True
    storage = Storage(":memory:")
    pipeline = EventPipeline(
        storage=storage,
        archive=JsonlArchive(":memory:", enabled=False),
        detector=DetectionEngine([]),
        queue_size=16,
    )
    assert pipeline.queue.maxsize == 16
    storage.close()


def test_submit_drops_when_full() -> None:
    storage = Storage(":memory:")
    pipeline = EventPipeline(
        storage=storage,
        archive=JsonlArchive(":memory:", enabled=False),
        detector=DetectionEngine([]),
        queue_size=16,
    )
    for _ in range(20):
        pipeline.submit(make_event())
    assert pipeline.dropped >= 4
    storage.close()


def test_graceful_shutdown_drains(offline) -> None:
    pipeline, _config, _resources = offline

    async def scenario() -> None:
        pipeline.start()
        for _ in range(5):
            await pipeline.submit_async(make_event())
        await asyncio.wait_for(pipeline.queue.join(), timeout=10)
        await pipeline.stop()

    asyncio.run(scenario())
    assert pipeline.processed == 5
    assert pipeline.storage.closed


def test_alerting_never_breaks_collection(offline) -> None:
    pipeline, _config, _resources = offline

    class Exploding:
        def submit(self, *_args, **_kwargs):
            raise RuntimeError("telegram down")

    pipeline.alerter = Exploding()
    pipeline.process(make_event())
    assert pipeline.storage.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


# ---- detector -----------------------------------------------------------


def test_shipped_ruleset_detects(ruleset) -> None:
    engine = DetectionEngine(ruleset.rules)
    assert engine.evaluate(make_event())
    assert not engine.evaluate(make_event(command="frobnicate"))


def test_reload_keeps_state_and_is_atomic(tmp_path: Path, rules_dir: Path) -> None:
    engine = DetectionEngine(load_ruleset(rules_dir).rules)
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "broken.yaml").write_text("id: [\n", encoding="utf-8")
    before = engine.rules
    engine.reload_from(bad)
    assert engine.rules == before  # empty reload never replaces a good ruleset

    copy = tmp_path / "copy"
    copy.mkdir()
    for path in rules_dir.rglob("*.yaml"):
        target = copy / path.name
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    engine.reload_from(copy)
    assert len(engine.rules) == 17


def test_disabled_rule_is_skipped(rules_dir: Path) -> None:
    rules = load_ruleset(rules_dir).rules
    ruleset = load_ruleset(rules_dir)
    for rule in ruleset.rules:
        rule.enabled = False
    engine = DetectionEngine(ruleset.rules)
    assert engine.evaluate(make_event()) == []


def test_install_sighup_returns_remover(rules_dir: Path) -> None:
    engine = DetectionEngine(load_ruleset(rules_dir).rules)
    remove = install_sighup_reload(engine, rules_dir)
    assert callable(remove)
    remove()


# ---- replay -------------------------------------------------------------


def test_replay_is_deterministic(tmp_path: Path, rules_dir: Path) -> None:
    from honeywatch.replay import Replay

    source = tmp_path / "events.jsonl"
    import json

    lines = []
    for index in range(12):
        event = make_event(
            ts=NOW + timedelta(seconds=index * 2),
            event_type=EventType.LOGIN_ATTEMPT,
            username="root",
            password=f"pw{index}",
            command=None,
        )
        payload = event.to_json_dict()
        payload.pop("id", None)
        lines.append(json.dumps(payload))
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")

    results = []
    for run in range(2):
        db = tmp_path / f"run{run}.db"
        pipeline, resources = build_offline_pipeline(
            parse_config({"data_dir": str(tmp_path / "data")}, base_dir=tmp_path), db_path=db
        )

        async def scenario() -> int:
            pipeline.start()
            result = await Replay(source, pipeline, speed=1000).run()
            await asyncio.wait_for(pipeline.queue.join(), timeout=20)
            await pipeline.stop()
            return result.events

        count = asyncio.run(scenario())
        for resource in resources:
            close = getattr(resource, "close", None)
            if close is not None:
                close()
        with Storage(db) as store:
            rows = store.execute(
                "SELECT rule_id, COUNT(*) FROM rule_hits GROUP BY rule_id ORDER BY rule_id"
            ).fetchall()
        results.append((count, [tuple(r) for r in rows]))

    assert results[0][0] == 12
    assert results[0] == results[1]
    assert ("ssh-bruteforce-001", 1) in results[0][1]


def test_replay_skips_malformed_lines(tmp_path: Path, rules_dir: Path) -> None:
    from honeywatch.replay import Replay

    source = tmp_path / "mixed.jsonl"
    source.write_text('{"nope": 1}\n' + make_event().to_json_dict().__repr__().replace("'", '"') + "\n", encoding="utf-8")
    pipeline, resources = build_offline_pipeline(
        parse_config({"data_dir": str(tmp_path / "data")}, base_dir=tmp_path),
        db_path=tmp_path / "m.db",
    )

    async def scenario() -> int:
        pipeline.start()
        result = await Replay(source, pipeline, speed=1000).run()
        await asyncio.wait_for(pipeline.queue.join(), timeout=20)
        await pipeline.stop()
        return result.events

    count = asyncio.run(scenario())
    for resource in resources:
        close = getattr(resource, "close", None)
        if close is not None:
            close()
    assert count == 1


# ---- simulator -----------------------------------------------------------


def test_all_profiles_are_documented() -> None:
    assert set(PROFILES) >= {
        "ssh-bruteforcer",
        "credential-sprayer",
        "mirai-dropper",
        "web-scanner",
        "sql-traversal",
        "persistent-attacker",
    }


def test_simulation_uses_documentation_ranges(offline) -> None:
    pipeline, _config, _resources = offline
    sim = Simulator(pipeline=pipeline, rate=0, seed=7)

    async def scenario() -> int:
        pipeline.start()
        count = await sim.run(profiles=("mirai-dropper",))
        await asyncio.wait_for(pipeline.queue.join(), timeout=30)
        await pipeline.stop()
        return count

    count = asyncio.run(scenario())
    assert count > 0
    rows = pipeline.storage.execute("SELECT DISTINCT src_ip FROM events").fetchall()
    assert rows
    for row in rows:
        assert row[0].startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_simulation_produces_detections(offline) -> None:
    pipeline, _config, _resources = offline
    sim = Simulator(pipeline=pipeline, rate=0, seed=3)

    async def scenario() -> None:
        pipeline.start()
        await sim.run(profiles=("ssh-bruteforcer", "web-scanner", "mirai-dropper"))
        await asyncio.wait_for(pipeline.queue.join(), timeout=30)
        await pipeline.stop()

    asyncio.run(scenario())
    rules = {
        row[0]
        for row in pipeline.storage.execute("SELECT DISTINCT rule_id FROM rule_hits").fetchall()
    }
    assert {"ssh-bruteforce-001", "ssh-download-exec-005"} & rules


def test_unknown_profile_is_rejected(offline) -> None:
    pipeline, _config, _resources = offline
    sim = Simulator(pipeline=pipeline, rate=0)
    with pytest.raises(ValueError):
        asyncio.run(sim.run(profiles=("nope",)))


# ---- doctor -------------------------------------------------------------


def test_doctor_passes_on_fresh_config(tmp_path: Path) -> None:
    config = parse_config(
        {"data_dir": str(tmp_path / "data"), "ssh": {"port": 0}, "http": {"port": 0}},
        base_dir=tmp_path,
    )
    report = run_doctor(config)
    assert report.ok, [c for c in report.checks if c.status == "fail"]


def test_doctor_reports_missing_geoip_as_warning(tmp_path: Path) -> None:
    config = parse_config({"data_dir": str(tmp_path / "data")}, base_dir=tmp_path)
    report = run_doctor(config)
    geo = next(c for c in report.checks if c.name == "geoip")
    assert geo.status == "warn"
    assert report.ok


def test_doctor_reports_invalid_rules(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yaml").write_text("id: [\n", encoding="utf-8")
    config = parse_config(
        {"data_dir": str(tmp_path / "data"), "rules": {"directory": str(rules)}}, base_dir=tmp_path
    )
    report = run_doctor(config)
    rules_check = next(c for c in report.checks if c.name == "rules")
    assert rules_check.status == "fail"
    assert not report.ok


def test_doctor_flags_enabled_telegram_without_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("HONEYWATCH_TG_TOKEN", raising=False)
    config = parse_config(
        {
            "data_dir": str(tmp_path / "data"),
            "alerts": {"telegram": {"enabled": True, "chat_id": "1"}},
        },
        base_dir=tmp_path,
    )
    report = run_doctor(config)
    tg = next(c for c in report.checks if c.name == "telegram")
    assert tg.status == "fail"
    assert "HONEYWATCH_TG_TOKEN" in tg.detail