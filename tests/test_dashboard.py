"""Tests du tableau de bord Flask (Lot 4) : routes, filtres, 400, sécurité XSS."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from siem.config import Config
from siem.dashboard.app import create_app
from siem.models import Alert, Event
from siem.storage import Storage

ROOT = Path(__file__).resolve().parents[1]


def _ts():
    return datetime(2026, 10, 12, 6, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "dash.db"
    with Storage(db) as store:
        store.insert_events([
            Event(timestamp=_ts(), source="ssh", event_type="ssh_failed",
                  raw="x", src_ip="203.0.113.45", user="root"),
        ])
        store.replace_alerts([
            Alert("R1", "HIGH", "203.0.113.45", _ts(), _ts(), 5, "Force brute SSH"),
            Alert("R4", "MEDIUM", "192.0.2.168", _ts(), _ts(), 20, "Scan web"),
            # Charge XSS injectée pour vérifier l'échappement (NF4).
            Alert("R3", "HIGH", "198.51.100.1", _ts(), _ts(), 1,
                  "Attaque web <script>alert('xss')</script>", category="xss"),
        ])
    config = Config.load(ROOT / "config.yaml")
    app = create_app(config, db_path=db)
    return app.test_client()


# --- Routes de base -------------------------------------------------------

def test_home_page_ok(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Mini-SIEM".encode() in r.data


def test_alerts_page_ok(client):
    r = client.get("/alerts")
    assert r.status_code == 200
    assert b"203.0.113.45" in r.data


def test_api_returns_json_list(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list) and len(data) == 3


# --- Filtres (F4/F9) ------------------------------------------------------

def test_api_filter_by_severity(client):
    data = client.get("/api/alerts?severity=HIGH").get_json()
    assert len(data) == 2 and all(a["severity"] == "HIGH" for a in data)


def test_api_filter_by_rule(client):
    data = client.get("/api/alerts?rule_id=R4").get_json()
    assert len(data) == 1 and data[0]["rule_id"] == "R4"


def test_api_filter_by_ip(client):
    data = client.get("/api/alerts?src_ip=192.0.2.168").get_json()
    assert len(data) == 1


# --- Sévérité inconnue -> 400 ---------------------------------------------

def test_api_unknown_severity_returns_400(client):
    r = client.get("/api/alerts?severity=BOGUS")
    assert r.status_code == 400


def test_alerts_page_unknown_severity_returns_400(client):
    assert client.get("/alerts?severity=BOGUS").status_code == 400


# --- NF4 : échappement des charges XSS issues des logs --------------------

def test_xss_payload_is_escaped(client):
    r = client.get("/alerts")
    body = r.data.decode()
    assert "<script>alert('xss')</script>" not in body   # pas de balise brute
    assert "&lt;script&gt;" in body                       # échappée par Jinja2
