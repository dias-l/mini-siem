"""Collecte et normalisation des trois sources de logs (F1, F2)."""
from __future__ import annotations

from ..config import Config
from ..models import Event, SourceStats
from . import apache, auth, firewall

# (module analyseur, nom de fichier attendu dans data/logs/)
_SOURCES = [
    (auth, "auth.log"),
    (apache, "apache_access.log"),
    (firewall, "firewall.csv"),
]


def parse_all(config: Config) -> tuple[list[Event], list[SourceStats]]:
    """Analyse les trois sources et renvoie (événements, statistiques par source)."""
    logs_dir = config.path("logs_dir")
    all_events: list[Event] = []
    all_stats: list[SourceStats] = []

    for module, filename in _SOURCES:
        events, stats = module.parse(logs_dir / filename, config)
        all_events.extend(events)
        all_stats.append(stats)

    return all_events, all_stats
