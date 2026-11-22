"""Modèle d'événement normalisé commun aux trois sources (section 6.2).

Toutes les sources produisent la même structure. Un champ sans objet reste à
``None`` (traduit en ``null`` à l'export JSON).
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    # Champs communs
    timestamp: datetime            # date de l'événement, en UTC (timezone-aware)
    source: str                    # "ssh", "web" ou "firewall"
    event_type: str                # ssh_failed, ssh_success, sudo_command,
                                   # web_request, firewall_allow, firewall_deny
    raw: str                       # ligne d'origine, sans le saut de ligne final

    # Réseau (source / destination)
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None

    # SSH / sudo
    host: Optional[str] = None
    user: Optional[str] = None
    command: Optional[str] = None

    # Web
    http_method: Optional[str] = None
    url: Optional[str] = None       # conservée encodée, telle qu'elle figure dans le log
    http_status: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None

    def field_names(self) -> list[str]:
        return [f.name for f in fields(self)]


@dataclass
class Alert:
    """Alerte produite par une règle de détection ou de corrélation (6.5)."""

    rule_id: str                   # R1..R5 ou C1..C3
    severity: str                  # LOW, MEDIUM, HIGH ou CRITICAL
    src_ip: Optional[str]
    first_seen: datetime           # UTC
    last_seen: datetime            # UTC
    event_count: int
    description: str
    category: Optional[str] = None
    user: Optional[str] = None


@dataclass
class SourceStats:
    """Compteurs affichés par source pour F1."""

    source: str
    lines_read: int = 0
    events: int = 0
    corrupted: int = 0

    @property
    def ignored(self) -> int:
        """Lignes lues qui ne sont ni des événements ni des lignes corrompues
        (lignes vides, en-tête CSV, lignes valides mais non pertinentes)."""
        return self.lines_read - self.events - self.corrupted
