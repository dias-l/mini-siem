"""Export des alertes au format JSON (F8, section 6.5).

Liste triée par ``first_seen``, dates en UTC, champ sans objet à ``null``.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Alert
from .timeutils import to_iso_z

# Ordre exact des champs attendus par l'énoncé (6.5).
_FIELDS = [
    "rule_id", "severity", "src_ip", "first_seen", "last_seen",
    "event_count", "description", "category", "user",
]


def alert_to_dict(alert: Alert) -> dict:
    return {
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "first_seen": to_iso_z(alert.first_seen),
        "last_seen": to_iso_z(alert.last_seen),
        "event_count": alert.event_count,
        "description": alert.description,
        "category": alert.category,
        "user": alert.user,
    }


def alerts_to_json(alerts: list[Alert]) -> str:
    data = [alert_to_dict(a) for a in alerts]
    return json.dumps(data, ensure_ascii=False, indent=2)


def export_alerts(alerts: list[Alert], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(alerts_to_json(alerts), encoding="utf-8")
