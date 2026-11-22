"""Tests des règles de détection R1-R5 et du moteur de rafales (Lot 3)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from siem.config import Config
from siem.detection import rules
from siem.detection.burst import find_bursts
from siem.detection.signatures import compile_signatures, match_categories
from siem.models import Event

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 10, 12, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def config() -> Config:
    return Config.load(ROOT / "config.yaml")


def ssh_failed(ip, seconds, user="root") -> Event:
    return Event(timestamp=BASE + timedelta(seconds=seconds), source="ssh",
                 event_type="ssh_failed", raw="x", src_ip=ip, user=user)


def deny(ip, seconds, port) -> Event:
    return Event(timestamp=BASE + timedelta(seconds=seconds), source="firewall",
                 event_type="firewall_deny", raw="x", src_ip=ip, dst_port=port)


def web(ip, seconds, url, status=200) -> Event:
    return Event(timestamp=BASE + timedelta(seconds=seconds), source="web",
                 event_type="web_request", raw="x", src_ip=ip, url=url,
                 http_status=status, http_method="GET")


# --- Moteur de rafales (fenêtre glissante) --------------------------------

def test_burst_single_alert_for_many_events():
    """500 essais rapprochés -> une seule rafale, pas 496."""
    events = [ssh_failed("1.1.1.1", s) for s in range(500)]
    bursts = find_bursts(events, 60, lambda w: len(w) >= 5)
    assert len(bursts) == 1
    assert len(bursts[0]) == 500


def test_burst_bounds_are_inclusive():
    """5 événements étalés sur exactement 60 s déclenchent (bornes incluses)."""
    events = [ssh_failed("1.1.1.1", s) for s in (0, 15, 30, 45, 60)]
    assert len(find_bursts(events, 60, lambda w: len(w) >= 5)) == 1


def test_burst_below_threshold_span_no_alert():
    """5 événements étalés sur 64 s : aucune fenêtre de 60 s n'en contient 5."""
    events = [ssh_failed("1.1.1.1", s) for s in (0, 16, 32, 48, 64)]
    assert find_bursts(events, 60, lambda w: len(w) >= 5) == []


def test_burst_new_attack_after_gap():
    """Deux salves séparées par un écart > fenêtre -> deux rafales."""
    first = [ssh_failed("1.1.1.1", s) for s in range(5)]
    second = [ssh_failed("1.1.1.1", 200 + s) for s in range(5)]
    bursts = find_bursts(first + second, 60, lambda w: len(w) >= 5)
    assert len(bursts) == 2


# --- R1 Force brute SSH ---------------------------------------------------

def test_r1_triggers_at_threshold(config):
    events = [ssh_failed("9.9.9.9", s) for s in range(5)]
    alerts = rules.detect_r1(events, config)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "R1" and alerts[0].severity == "HIGH"
    assert alerts[0].event_count == 5


def test_r1_below_threshold_no_alert(config):
    events = [ssh_failed("9.9.9.9", s) for s in range(4)]
    assert rules.detect_r1(events, config) == []


# --- R2 Scan de ports (ports distincts) -----------------------------------

def test_r2_counts_distinct_ports(config):
    # 15 ports distincts en moins de 60 s
    events = [deny("5.5.5.5", s, port=1000 + s) for s in range(15)]
    alerts = rules.detect_r2(events, config)
    assert len(alerts) == 1 and alerts[0].rule_id == "R2"


def test_r2_same_port_repeated_no_alert(config):
    # 30 refus mais toujours le même port -> pas un scan
    events = [deny("5.5.5.5", s, port=22) for s in range(30)]
    assert rules.detect_r2(events, config) == []


# --- R3 Signatures web ----------------------------------------------------

def test_r3_detects_sqli(config):
    alerts = rules.detect_r3([web("7.7.7.7", 0, "/p?id=1 UNION SELECT pw FROM u")], config)
    assert len(alerts) == 1 and alerts[0].category == "sqli"


def test_r3_legitimate_words_no_false_positive(config):
    """Des mots comme union/select/script dans une URL légitime ne déclenchent pas."""
    urls = ["/union-jack", "/products?sort=select", "/scripts/app.js", "/or-else"]
    events = [web("7.7.7.7", i, u) for i, u in enumerate(urls)]
    assert rules.detect_r3(events, config) == []


def test_r3_double_encoded_payload(config):
    signatures = compile_signatures(config.signatures)
    # <script> encodé deux fois
    assert "xss" in match_categories("%253Cscript%253E", signatures)


def test_r3_one_alert_per_ip_category(config):
    events = [
        web("7.7.7.7", 0, "/?q=<script>"),
        web("7.7.7.7", 10, "/?q=<script>alert(1)"),
    ]
    alerts = rules.detect_r3(events, config)
    assert len(alerts) == 1
    assert alerts[0].event_count == 2 and alerts[0].category == "xss"


def test_r3_path_traversal(config):
    alerts = rules.detect_r3([web("7.7.7.7", 0, "/download?f=../../etc/passwd")], config)
    assert len(alerts) == 1 and alerts[0].category == "path_traversal"


# --- R4 Scan web (404) ----------------------------------------------------

def test_r4_counts_404(config):
    events = [web("8.8.8.8", s, f"/p{s}", status=404) for s in range(20)]
    alerts = rules.detect_r4(events, config)
    assert len(alerts) == 1 and alerts[0].rule_id == "R4"


def test_r4_ignores_non_404(config):
    events = [web("8.8.8.8", s, f"/p{s}", status=200) for s in range(30)]
    assert rules.detect_r4(events, config) == []


# --- R5 Réputation d'IP ---------------------------------------------------

def test_r5_matches_threat_intel(config):
    events = [web("203.0.113.119", 0, "/"), web("203.0.113.119", 10, "/x")]
    alerts = rules.detect_r5(events, {"203.0.113.119": "botnet"})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "R5" and alerts[0].category == "botnet"
    assert alerts[0].event_count == 2
