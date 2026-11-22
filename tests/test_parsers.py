"""Tests des analyseurs et de la normalisation (Lot 1).

Les volumes attendus proviennent de docs/formats_logs.md :
    SSH et sudo  : 190 événements, 3 lignes corrompues
    Web          : 3060 événements, 3 lignes corrompues
    Pare-feu     : 1946 événements, 3 lignes corrompues
"""
from __future__ import annotations

from datetime import timezone
from pathlib import Path

import pytest

from siem import timeutils
from siem.config import Config
from siem.parsers import apache, auth, firewall, parse_all

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def config() -> Config:
    return Config.load(ROOT / "config.yaml")


# --- Volumes attendus par source -----------------------------------------

def test_auth_volumes(config):
    events, stats = auth.parse(config.path("logs_dir") / "auth.log", config)
    assert stats.events == 190
    assert stats.corrupted == 3
    assert len(events) == 190


def test_apache_volumes(config):
    events, stats = apache.parse(config.path("logs_dir") / "apache_access.log", config)
    assert stats.events == 3060
    assert stats.corrupted == 3


def test_firewall_volumes(config):
    events, stats = firewall.parse(config.path("logs_dir") / "firewall.csv", config)
    assert stats.events == 1946
    assert stats.corrupted == 3


def test_stats_consistency(config):
    """lignes lues = événements + ignorées + corrompues, pour chaque source."""
    _, stats_list = parse_all(config)
    for s in stats_list:
        assert s.lines_read == s.events + s.ignored + s.corrupted


# --- Types d'événements ---------------------------------------------------

def test_auth_event_types(config):
    events, _ = auth.parse(config.path("logs_dir") / "auth.log", config)
    types = {e.event_type for e in events}
    assert types == {"ssh_failed", "ssh_success", "sudo_command"}


def test_all_timestamps_are_utc(config):
    events, _ = parse_all(config)
    assert all(e.timestamp.utcoffset() == timezone.utc.utcoffset(None) for e in events)


# --- Conversion des fuseaux horaires -------------------------------------

def test_syslog_utc_conversion():
    # 08:14:03 en UTC+2 -> 06:14:03 UTC
    dt = timeutils.parse_syslog_time("Oct", "12", "08:14:03", 2026, 2)
    assert timeutils.to_iso_z(dt) == "2026-10-12T06:14:03Z"


def test_apache_utc_conversion():
    # 15:21:33 +0200 -> 13:21:33 UTC
    dt = timeutils.parse_apache_time("12/Oct/2026:15:21:33 +0200")
    assert timeutils.to_iso_z(dt) == "2026-10-12T13:21:33Z"


def test_firewall_utc_conversion():
    dt = timeutils.parse_firewall_time("2026-10-12T06:00:12Z")
    assert timeutils.to_iso_z(dt) == "2026-10-12T06:00:12Z"


# --- Cas limites : lignes corrompues et champs ----------------------------

def test_apache_dash_bytes_is_zero(config):
    """Un champ octets à '-' doit valoir 0."""
    events, _ = apache.parse(config.path("logs_dir") / "apache_access.log", config)
    assert any(e.bytes_sent == 0 for e in events)


def test_url_kept_encoded(config):
    """L'URL est conservée telle quelle (non décodée à ce stade)."""
    events, _ = apache.parse(config.path("logs_dir") / "apache_access.log", config)
    assert all(e.url is not None for e in events)


def test_apache_escaped_quotes_in_user_agent(config, tmp_path):
    """Une ligne combined valide dont le User-Agent contient un guillemet
    échappé (\\") doit être analysée, pas comptée comme corrompue."""
    log = tmp_path / "ua.log"
    log.write_text(
        r'10.0.1.25 - - [12/Oct/2026:15:21:33 +0200] "GET /x HTTP/1.1" '
        r'200 5 "-" "Mozilla/5.0 (compatible; \"bot\")"' + "\n",
        encoding="utf-8",
    )
    events, stats = apache.parse(log, config)
    assert stats.events == 1 and stats.corrupted == 0
    assert events[0].http_method == "GET" and events[0].url == "/x"
