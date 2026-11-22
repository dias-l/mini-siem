"""Persistance des événements et des alertes dans SQLite (F3, F4).

Garanties :
* **Idempotence (F3)** : chaque événement porte une empreinte unique
  (``event_hash``). L'insertion se fait en ``INSERT OR IGNORE`` : réingérer le
  même fichier n'ajoute aucun doublon.
* **NF3 (anti-injection SQL)** : toutes les requêtes utilisent des paramètres
  ``?``. Aucune valeur externe n'est concaténée dans une requête. Les seuls
  éléments interpolés sont des noms de colonnes internes, jamais des entrées.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from . import timeutils
from .models import Alert, Event

# Colonnes de la table events, dans l'ordre du modèle normalisé.
_EVENT_COLUMNS = [
    "timestamp", "source", "event_type", "raw",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action",
    "host", "user", "command",
    "http_method", "url", "http_status", "bytes_sent", "user_agent",
]

_ALERT_COLUMNS = [
    "rule_id", "severity", "src_ip", "first_seen", "last_seen",
    "event_count", "description", "category", "user",
]


def _event_hash(event: Event) -> str:
    """Empreinte stable d'un événement, pour la déduplication (F3)."""
    parts = [timeutils.to_iso_z(event.timestamp)]
    parts += [str(getattr(event, name)) for name in _EVENT_COLUMNS[1:]]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


class Storage:
    def __init__(self, db_path: str | Path) -> None:
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_schema()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- Schéma -------------------------------------------------------------
    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash  TEXT UNIQUE NOT NULL,
                timestamp   TEXT NOT NULL,
                source      TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                raw         TEXT NOT NULL,
                src_ip      TEXT, src_port INTEGER,
                dst_ip      TEXT, dst_port INTEGER,
                protocol    TEXT, action   TEXT,
                host        TEXT, user     TEXT, command TEXT,
                http_method TEXT, url      TEXT, http_status INTEGER,
                bytes_sent  INTEGER, user_agent TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_source  ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_type    ON events(event_type);

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id     TEXT NOT NULL,
                severity    TEXT NOT NULL,
                src_ip      TEXT,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                description TEXT NOT NULL,
                category    TEXT,
                user        TEXT
            );
            """
        )
        self.conn.commit()

    # -- Événements ---------------------------------------------------------
    def insert_events(self, events: list[Event]) -> int:
        """Insère les événements et renvoie le nombre réellement ajoutés."""
        placeholders = ", ".join(["?"] * (len(_EVENT_COLUMNS) + 1))
        sql = (
            f"INSERT OR IGNORE INTO events (event_hash, {', '.join(_EVENT_COLUMNS)}) "
            f"VALUES ({placeholders})"
        )
        rows = []
        for e in events:
            values = [_event_hash(e), timeutils.to_iso_z(e.timestamp)]
            values += [getattr(e, name) for name in _EVENT_COLUMNS[1:]]
            rows.append(values)

        before = self.conn.total_changes
        self.conn.executemany(sql, rows)
        self.conn.commit()
        return self.conn.total_changes - before

    def query_events(self, source=None, event_type=None, src_ip=None, limit=None):
        """Filtre les événements par source, type et IP (F4). Requête paramétrée."""
        clauses, params = [], []
        if source:
            clauses.append("source = ?"); params.append(source)
        if event_type:
            clauses.append("event_type = ?"); params.append(event_type)
        if src_ip:
            clauses.append("src_ip = ?"); params.append(src_ip)

        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp, id"
        if limit:
            sql += " LIMIT ?"; params.append(limit)
        return self.conn.execute(sql, params).fetchall()

    def get_events(self, **filters) -> list[Event]:
        """Comme query_events mais reconstruit des objets Event (pour la détection)."""
        return [_row_to_event(r) for r in self.query_events(**filters)]

    def count_events_by_source(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT source, COUNT(*) AS n FROM events GROUP BY source"
        ).fetchall()
        return {r["source"]: r["n"] for r in rows}

    # -- Alertes ------------------------------------------------------------
    def replace_alerts(self, alerts: list[Alert]) -> None:
        """Remplace toutes les alertes (la détection recalcule tout à chaque fois)."""
        self.conn.execute("DELETE FROM alerts")
        sql = (
            f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) "
            f"VALUES ({', '.join(['?'] * len(_ALERT_COLUMNS))})"
        )
        rows = [
            [
                a.rule_id, a.severity, a.src_ip,
                timeutils.to_iso_z(a.first_seen), timeutils.to_iso_z(a.last_seen),
                a.event_count, a.description, a.category, a.user,
            ]
            for a in alerts
        ]
        self.conn.executemany(sql, rows)
        self.conn.commit()

    def query_alerts(self, severity=None, rule_id=None, src_ip=None):
        """Filtre les alertes par sévérité, règle et IP (F4). Requête paramétrée."""
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if rule_id:
            clauses.append("rule_id = ?"); params.append(rule_id)
        if src_ip:
            clauses.append("src_ip = ?"); params.append(src_ip)

        sql = "SELECT * FROM alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY first_seen, id"
        return self.conn.execute(sql, params).fetchall()

    def count_alerts_by_severity(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["n"] for r in rows}


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        timestamp=timeutils.parse_firewall_time(row["timestamp"]),
        source=row["source"], event_type=row["event_type"], raw=row["raw"],
        src_ip=row["src_ip"], src_port=row["src_port"],
        dst_ip=row["dst_ip"], dst_port=row["dst_port"],
        protocol=row["protocol"], action=row["action"],
        host=row["host"], user=row["user"], command=row["command"],
        http_method=row["http_method"], url=row["url"],
        http_status=row["http_status"], bytes_sent=row["bytes_sent"],
        user_agent=row["user_agent"],
    )
