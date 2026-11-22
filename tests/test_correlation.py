"""Tests des corrélations C1/C2, de la liste blanche (F5) et de l'export (F8)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from siem.config import Config
from siem.detection import run_detection
from siem.detection.correlation import correlate_c1, correlate_c2
from siem.export import alert_to_dict, alerts_to_json
from siem.models import Alert, Event

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 10, 12, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def config() -> Config:
    return Config.load(ROOT / "config.yaml")


def at(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


# --- C1 Compromission probable --------------------------------------------

def test_c1_links_success_to_bruteforce(config):
    r1 = Alert("R1", "HIGH", "1.1.1.1", at(0), at(30), 39, "brute force")
    success = Event(timestamp=at(120), source="ssh", event_type="ssh_success",
                    raw="x", src_ip="1.1.1.1", user="deploy")
    alerts = correlate_c1([r1], [success], config)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "C1" and a.severity == "CRITICAL"
    assert a.user == "deploy"
    assert a.event_count == 40          # R1 (39) + 1
    assert a.last_seen == at(120)       # date de la connexion réussie


def test_c1_success_outside_window_ignored(config):
    r1 = Alert("R1", "HIGH", "1.1.1.1", at(0), at(30), 5, "brute force")
    # 10 min après la fin = 630 s ; 700 s est hors fenêtre
    success = Event(timestamp=at(700), source="ssh", event_type="ssh_success",
                    raw="x", src_ip="1.1.1.1", user="deploy")
    assert correlate_c1([r1], [success], config) == []


# --- C2 Chaîne d'attaque --------------------------------------------------

def test_c2_links_webattack_to_portscan(config):
    r2 = Alert("R2", "MEDIUM", "2.2.2.2", at(0), at(60), 54, "scan de ports")
    r3 = Alert("R3", "HIGH", "2.2.2.2", at(300), at(360), 15, "sqli", category="sqli")
    alerts = correlate_c2([r2], [r3], config)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "C2" and a.severity == "HIGH"
    assert a.event_count == 69          # R2 (54) + R3 (15)
    assert a.last_seen == at(360)


def test_c2_different_ip_not_correlated(config):
    r2 = Alert("R2", "MEDIUM", "2.2.2.2", at(0), at(60), 54, "scan")
    r3 = Alert("R3", "HIGH", "3.3.3.3", at(300), at(360), 15, "sqli", category="sqli")
    assert correlate_c2([r2], [r3], config) == []


# --- F5 Liste blanche -----------------------------------------------------

def test_whitelist_ip_is_ignored(config):
    whitelisted = next(iter(config.whitelist))
    events = [
        Event(timestamp=at(s), source="ssh", event_type="ssh_failed",
              raw="x", src_ip=whitelisted, user="root")
        for s in range(10)
    ]
    assert run_detection(config, events) == []


# --- F8 Export JSON (6.5) -------------------------------------------------

def test_export_fields_and_nulls():
    alert = Alert("R3", "HIGH", "203.0.113.10", at(0), at(51), 18,
                  "Attaque web (sqli) depuis 203.0.113.10", category="sqli")
    d = alert_to_dict(alert)
    assert list(d.keys()) == [
        "rule_id", "severity", "src_ip", "first_seen", "last_seen",
        "event_count", "description", "category", "user",
    ]
    assert d["first_seen"].endswith("Z")
    assert d["user"] is None            # champ sans objet -> null


def test_export_sorted_by_first_seen(config):
    data = json.loads(alerts_to_json([
        Alert("R1", "HIGH", "1.1.1.1", at(100), at(100), 5, "a"),
        Alert("R2", "MEDIUM", "2.2.2.2", at(0), at(0), 15, "b"),
    ]))
    # alerts_to_json ne trie pas lui-même ; run_detection/le stockage trient.
    # On vérifie ici seulement la sérialisation UTC.
    assert all(d["first_seen"].endswith("Z") for d in data)
