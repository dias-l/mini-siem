"""Règles de détection R1 à R5 (F6).

Chaque règle produit une liste d'objets ``Alert``. La liste blanche (F5) et le
renseignement sur les menaces sont fournis par l'orchestrateur (``__init__``).
"""
from __future__ import annotations

from collections import defaultdict

from ..config import Config
from ..models import Alert, Event
from .burst import find_bursts
from .signatures import compile_signatures, match_categories


def _group_by_ip(events: list[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        groups[e.src_ip].append(e)
    return groups


def detect_r1(events: list[Event], config: Config) -> list[Alert]:
    """Force brute SSH : >= N ssh_failed depuis une même IP en fenêtre glissante."""
    cfg = config.rules["R1"]
    threshold, window = cfg["threshold"], cfg["window_seconds"]
    failed = [e for e in events if e.event_type == "ssh_failed"]

    alerts: list[Alert] = []
    for ip, evs in _group_by_ip(failed).items():
        evs.sort(key=lambda e: e.timestamp)
        for burst in find_bursts(evs, window, lambda w: len(w) >= threshold):
            alerts.append(Alert(
                "R1", "HIGH", ip, burst[0].timestamp, burst[-1].timestamp,
                len(burst), f"Force brute SSH depuis {ip}",
            ))
    return alerts


def detect_r2(events: list[Event], config: Config) -> list[Alert]:
    """Scan de ports : >= N ports de destination distincts en firewall_deny."""
    cfg = config.rules["R2"]
    distinct_ports, window = cfg["distinct_ports"], cfg["window_seconds"]
    denies = [e for e in events if e.event_type == "firewall_deny"]

    alerts: list[Alert] = []
    for ip, evs in _group_by_ip(denies).items():
        evs.sort(key=lambda e: e.timestamp)
        meets = lambda w: len({e.dst_port for e in w}) >= distinct_ports
        for burst in find_bursts(evs, window, meets):
            alerts.append(Alert(
                "R2", "MEDIUM", ip, burst[0].timestamp, burst[-1].timestamp,
                len(burst), f"Scan de ports depuis {ip}",
            ))
    return alerts


def detect_r3(events: list[Event], config: Config) -> list[Alert]:
    """Attaque web : URL décodée correspondant à une signature. Une alerte par
    couple (IP, catégorie)."""
    signatures = compile_signatures(config.signatures)
    web = [e for e in events if e.event_type == "web_request"]

    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in web:
        for category in match_categories(e.url, signatures):
            hits[(e.src_ip, category)].append(e)

    alerts: list[Alert] = []
    for (ip, category), evs in hits.items():
        evs.sort(key=lambda e: e.timestamp)
        alerts.append(Alert(
            "R3", "HIGH", ip, evs[0].timestamp, evs[-1].timestamp,
            len(evs), f"Attaque web ({category}) depuis {ip}", category=category,
        ))
    return alerts


def detect_r4(events: list[Event], config: Config) -> list[Alert]:
    """Scan web : >= N réponses HTTP 404 depuis une même IP en fenêtre glissante."""
    cfg = config.rules["R4"]
    threshold, window = cfg["threshold"], cfg["window_seconds"]
    not_found = [
        e for e in events
        if e.event_type == "web_request" and e.http_status == 404
    ]

    alerts: list[Alert] = []
    for ip, evs in _group_by_ip(not_found).items():
        evs.sort(key=lambda e: e.timestamp)
        for burst in find_bursts(evs, window, lambda w: len(w) >= threshold):
            alerts.append(Alert(
                "R4", "MEDIUM", ip, burst[0].timestamp, burst[-1].timestamp,
                len(burst), f"Scan web (erreurs 404) depuis {ip}",
            ))
    return alerts


def detect_r5(events: list[Event], threat_intel: dict[str, str]) -> list[Alert]:
    """Réputation d'IP : IP présente dans malicious_ips.csv, toutes sources
    confondues. Une alerte par IP."""
    alerts: list[Alert] = []
    for ip, evs in _group_by_ip(events).items():
        if ip not in threat_intel:
            continue
        evs.sort(key=lambda e: e.timestamp)
        category = threat_intel[ip]
        alerts.append(Alert(
            "R5", "MEDIUM", ip, evs[0].timestamp, evs[-1].timestamp,
            len(evs), f"IP malveillante ({category}) : {ip}", category=category,
        ))
    return alerts
