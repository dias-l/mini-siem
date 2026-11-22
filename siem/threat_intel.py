"""Chargement du renseignement sur les menaces (malicious_ips.csv)."""
from __future__ import annotations

import csv
from pathlib import Path


def load_threat_intel(path: str | Path) -> dict[str, str]:
    """Retourne un dictionnaire ``{ip: catégorie}``."""
    intel: dict[str, str] = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            intel[row["ip"]] = row["category"]
    return intel
