"""Règles de corrélation C1 et C2 (F7).

Elles croisent les alertes produites par les règles de détection pour révéler un
scénario d'attaque complet.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..config import Config
from ..models import Alert, Event


def correlate_c1(
    r1_alerts: list[Alert], ssh_success: list[Event], config: Config
) -> list[Alert]:
    """Compromission probable : une connexion SSH réussie, depuis la même IP
    qu'une alerte R1, entre le début de la rafale et 10 min après sa fin.
    Une alerte par couple (alerte R1, compte)."""
    window_after = config.correlation["C1"]["window_after_seconds"]

    success_by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in ssh_success:
        success_by_ip[e.src_ip].append(e)

    alerts: list[Alert] = []
    for r1 in r1_alerts:
        start = r1.first_seen
        end = r1.last_seen + timedelta(seconds=window_after)
        candidates = [
            e for e in success_by_ip.get(r1.src_ip, [])
            if start <= e.timestamp <= end
        ]

        # Première connexion réussie par compte (last_seen = cette date).
        earliest_per_user: dict[str, Event] = {}
        for e in sorted(candidates, key=lambda e: e.timestamp):
            earliest_per_user.setdefault(e.user, e)

        for user, e in earliest_per_user.items():
            alerts.append(Alert(
                "C1", "CRITICAL", r1.src_ip, r1.first_seen, e.timestamp,
                r1.event_count + 1,
                f"Compromission probable du compte {user} depuis {r1.src_ip}",
                user=user,
            ))
    return alerts


def correlate_c2(
    r2_alerts: list[Alert], r3_alerts: list[Alert], config: Config
) -> list[Alert]:
    """Chaîne d'attaque : une alerte R3 depuis la même IP qu'une alerte R2,
    commençant entre le début du scan et 30 min après sa fin.
    Une seule alerte par scan."""
    window_after = config.correlation["C2"]["window_after_seconds"]

    r3_by_ip: dict[str, list[Alert]] = defaultdict(list)
    for a in r3_alerts:
        r3_by_ip[a.src_ip].append(a)

    alerts: list[Alert] = []
    for r2 in r2_alerts:
        start = r2.first_seen
        end = r2.last_seen + timedelta(seconds=window_after)
        matched = [
            a for a in r3_by_ip.get(r2.src_ip, [])
            if start <= a.first_seen <= end
        ]
        if not matched:
            continue

        last_seen = max(a.last_seen for a in matched)
        event_count = r2.event_count + sum(a.event_count for a in matched)
        alerts.append(Alert(
            "C2", "HIGH", r2.src_ip, r2.first_seen, last_seen, event_count,
            f"Chaîne d'attaque (scan de ports puis attaque web) depuis {r2.src_ip}",
        ))
    return alerts
