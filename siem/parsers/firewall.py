"""Analyseur de ``firewall.csv`` (pare-feu, en UTC).

Colonnes : ``timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port,bytes``

Une ligne est corrompue si elle n'a pas 8 champs, si un champ est invalide, ou
si l'action n'est ni ``ALLOW`` ni ``DENY``. L'en-tête CSV est ignoré sans être
compté comme corrompu.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

from .. import timeutils
from ..config import Config
from ..models import Event, SourceStats


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_port(value: str) -> bool:
    return value.isdigit() and 0 <= int(value) <= 65535


def parse(path: str | Path, config: Config) -> tuple[list[Event], SourceStats]:
    events: list[Event] = []
    stats = SourceStats(source="firewall")

    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            stats.lines_read += 1
            raw = line.rstrip("\n")
            if raw.strip() == "":
                continue
            if raw.startswith("timestamp,"):  # en-tête CSV : ignoré
                continue

            parts = raw.split(",")
            if len(parts) != 8:
                stats.corrupted += 1
                continue

            ts_s, action, protocol, src_ip, src_port, dst_ip, dst_port, nbytes = parts
            if (
                action not in ("ALLOW", "DENY")
                or not _valid_ip(src_ip) or not _valid_ip(dst_ip)
                or not _valid_port(src_port) or not _valid_port(dst_port)
                or not nbytes.isdigit()
            ):
                stats.corrupted += 1
                continue

            try:
                ts = timeutils.parse_firewall_time(ts_s)
            except ValueError:
                stats.corrupted += 1
                continue

            events.append(Event(
                timestamp=ts, source="firewall",
                event_type="firewall_allow" if action == "ALLOW" else "firewall_deny",
                raw=raw,
                src_ip=src_ip, src_port=int(src_port),
                dst_ip=dst_ip, dst_port=int(dst_port),
                protocol=protocol, action=action,
            ))
            stats.events += 1

    return events, stats
