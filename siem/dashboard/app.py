"""Tableau de bord web Flask (F9) et sécurité associée (NF4, NF5).

Pages :
* ``/``            : volumes par source, alertes par sévérité, un graphique ;
* ``/alerts``      : tableau filtrable des alertes ;
* ``/api/alerts``  : même contenu en JSON.

``/alerts`` et ``/api/alerts`` acceptent les filtres ``severity``, ``rule_id`` et
``src_ip``. Une sévérité inconnue renvoie une erreur 400.

Sécurité :
* NF4 : les gabarits Jinja2 échappent automatiquement les données issues des
  logs (le filtre ``safe`` n'est jamais utilisé) ;
* NF5 : l'application écoute sur 127.0.0.1 avec le mode debug désactivé
  (voir ``main.py dashboard``).
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from ..config import Config
from ..export import alert_to_dict
from ..storage import Storage

VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Couleurs des barres du graphique par sévérité.
_SEVERITY_COLORS = {
    "LOW": "#6b7280",
    "MEDIUM": "#d97706",
    "HIGH": "#dc2626",
    "CRITICAL": "#9333ea",
}


def _bars(counts: dict[str, int], colors: dict[str, str] | None = None) -> list[dict]:
    """Prépare des barres (label, valeur, pourcentage, couleur) pour le graphique."""
    maximum = max(counts.values(), default=1) or 1
    return [
        {
            "label": label,
            "count": value,
            "pct": round(value / maximum * 100, 1),
            "color": (colors or {}).get(label, "#4f8cff"),
        }
        for label, value in counts.items()
    ]


def create_app(config: Config, db_path: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    database = Path(db_path) if db_path else config.path("database")

    def read_filters() -> tuple[str | None, str | None, str | None]:
        severity = request.args.get("severity") or None
        rule_id = request.args.get("rule_id") or None
        src_ip = request.args.get("src_ip") or None
        if severity is not None and severity not in VALID_SEVERITIES:
            abort(400, description=f"Sévérité inconnue : {severity}")
        return severity, rule_id, src_ip

    @app.route("/")
    def index():
        with Storage(database) as store:
            by_source = store.count_events_by_source()
            by_severity_raw = store.count_alerts_by_severity()
        # Ordonne les sévérités et complète les manquantes à 0.
        by_severity = {s: by_severity_raw.get(s, 0) for s in VALID_SEVERITIES}
        return render_template(
            "index.html",
            total_events=sum(by_source.values()),
            total_alerts=sum(by_severity.values()),
            source_bars=_bars(by_source),
            severity_bars=_bars(by_severity, _SEVERITY_COLORS),
        )

    @app.route("/alerts")
    def alerts_page():
        severity, rule_id, src_ip = read_filters()
        with Storage(database) as store:
            alerts = [alert_to_dict(a) for a in
                      store.get_alerts(severity=severity, rule_id=rule_id, src_ip=src_ip)]
        return render_template(
            "alerts.html",
            alerts=alerts,
            severities=VALID_SEVERITIES,
            filters={"severity": severity or "", "rule_id": rule_id or "",
                     "src_ip": src_ip or ""},
        )

    @app.route("/api/alerts")
    def api_alerts():
        severity, rule_id, src_ip = read_filters()
        with Storage(database) as store:
            alerts = store.get_alerts(severity=severity, rule_id=rule_id, src_ip=src_ip)
        return jsonify([alert_to_dict(a) for a in alerts])

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(error=str(error.description)), 400

    return app
