"""Orchestration de la détection et de la corrélation (F6, F7)."""
from __future__ import annotations

from ..config import Config
from ..models import Alert, Event
from ..threat_intel import load_threat_intel
from . import rules
from .correlation import correlate_c1, correlate_c2


def run_detection(config: Config, events: list[Event]) -> list[Alert]:
    """Applique toutes les règles et corrélations, renvoie les alertes triées
    par ``first_seen``."""
    # F5 : la liste blanche est ignorée par toutes les règles.
    whitelist = config.whitelist
    events = [e for e in events if e.src_ip not in whitelist]

    threat_intel = load_threat_intel(config.path("threat_intel"))

    r1 = rules.detect_r1(events, config)
    r2 = rules.detect_r2(events, config)
    r3 = rules.detect_r3(events, config)
    r4 = rules.detect_r4(events, config)
    r5 = rules.detect_r5(events, threat_intel)

    ssh_success = [e for e in events if e.event_type == "ssh_success"]
    c1 = correlate_c1(r1, ssh_success, config)
    c2 = correlate_c2(r2, r3, config)

    alerts = r1 + r2 + r3 + r4 + r5 + c1 + c2
    alerts.sort(key=lambda a: a.first_seen)
    return alerts
