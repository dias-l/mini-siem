"""Tests du stockage SQLite (Lot 2) : idempotence, filtres, anti-injection."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from siem.config import Config
from siem.models import Alert, Event
from siem.parsers import parse_all
from siem.storage import Storage

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path) -> Storage:
    s = Storage(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture(scope="module")
def config() -> Config:
    return Config.load(ROOT / "config.yaml")


def _event(ip="203.0.113.45", etype="ssh_failed", raw="ligne") -> Event:
    return Event(
        timestamp=datetime(2026, 10, 12, 6, 0, 0, tzinfo=timezone.utc),
        source="ssh", event_type=etype, raw=raw, src_ip=ip, user="root",
    )


# --- Idempotence (F3) -----------------------------------------------------

def test_insert_returns_number_of_new_events(store):
    assert store.insert_events([_event(raw="a"), _event(raw="b")]) == 2


def test_reingesting_same_events_creates_no_duplicate(store):
    events = [_event(raw="a"), _event(raw="b")]
    store.insert_events(events)
    added = store.insert_events(events)          # deuxième ingestion identique
    assert added == 0
    assert sum(store.count_events_by_source().values()) == 2


def test_full_reingest_is_idempotent(config, tmp_path):
    """Ingérer deux fois les logs réels ne crée aucun doublon (F3)."""
    events, _ = parse_all(config)
    with Storage(tmp_path / "real.db") as store:
        first = store.insert_events(events)
        second = store.insert_events(events)
        assert first == len(events)
        assert second == 0


# --- Filtres de consultation (F4) ----------------------------------------

def test_query_events_filters(store):
    store.insert_events([
        _event(ip="1.1.1.1", etype="ssh_failed", raw="x"),
        _event(ip="2.2.2.2", etype="ssh_success", raw="y"),
    ])
    assert len(store.query_events(src_ip="1.1.1.1")) == 1
    assert len(store.query_events(event_type="ssh_success")) == 1
    assert len(store.query_events(source="ssh")) == 2


def test_query_alerts_filters(store):
    store.replace_alerts([
        Alert("R1", "HIGH", "1.1.1.1",
              datetime(2026, 10, 12, 6, tzinfo=timezone.utc),
              datetime(2026, 10, 12, 6, tzinfo=timezone.utc), 5, "brute force"),
        Alert("R4", "MEDIUM", "2.2.2.2",
              datetime(2026, 10, 12, 7, tzinfo=timezone.utc),
              datetime(2026, 10, 12, 7, tzinfo=timezone.utc), 20, "scan web"),
    ])
    assert len(store.query_alerts(severity="HIGH")) == 1
    assert len(store.query_alerts(rule_id="R4")) == 1
    assert len(store.query_alerts(src_ip="2.2.2.2")) == 1


# --- NF3 : résistance aux injections SQL ----------------------------------

def test_sql_injection_in_filter_is_harmless(store):
    store.insert_events([_event(ip="1.1.1.1", raw="x")])
    # Une valeur malveillante est traitée comme une donnée, pas comme du SQL.
    malicious = "1.1.1.1'; DROP TABLE events; --"
    assert store.query_events(src_ip=malicious) == []
    # La table existe toujours et contient toujours l'événement.
    assert sum(store.count_events_by_source().values()) == 1


# --- Aller-retour Event <-> base -----------------------------------------

def test_get_events_roundtrip(store):
    store.insert_events([_event(ip="9.9.9.9", raw="z")])
    (loaded,) = store.get_events(src_ip="9.9.9.9")
    assert loaded.src_ip == "9.9.9.9"
    assert loaded.timestamp.tzinfo is not None     # date restaurée en UTC
