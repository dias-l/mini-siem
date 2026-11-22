"""Point d'entrée en ligne de commande du mini-SIEM (F10).

Commandes :
    python main.py ingest      collecte, normalisation et stockage
    python main.py detect      détection et corrélation
    python main.py report      export des alertes vers output/alertes.json
    python main.py run         les trois étapes à la suite
    python main.py dashboard   lance le tableau de bord web

Les étapes detect / report / dashboard arriveront aux lots suivants.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Affichage UTF-8 fiable sur les consoles Windows (accents).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from siem.config import Config
from siem.detection import run_detection
from siem.export import export_alerts
from siem.models import SourceStats
from siem.parsers import parse_all
from siem.storage import Storage

ROOT = Path(__file__).resolve().parent


def print_summary(stats_list: list[SourceStats]) -> None:
    """Affiche le tableau F1 : lignes lues, événements, ignorées, corrompues."""
    header = f"{'Source':<10}{'Lues':>8}{'Événements':>12}{'Ignorées':>10}{'Corrompues':>12}"
    print(header)
    print("-" * len(header))
    totals = [0, 0, 0, 0]
    for s in stats_list:
        print(f"{s.source:<10}{s.lines_read:>8}{s.events:>12}{s.ignored:>10}{s.corrupted:>12}")
        totals[0] += s.lines_read
        totals[1] += s.events
        totals[2] += s.ignored
        totals[3] += s.corrupted
    print("-" * len(header))
    print(f"{'TOTAL':<10}{totals[0]:>8}{totals[1]:>12}{totals[2]:>10}{totals[3]:>12}")


def cmd_ingest(config: Config) -> None:
    events, stats = parse_all(config)
    print_summary(stats)
    print(f"\n{len(events)} événements normalisés.")

    with Storage(config.path("database")) as store:
        inserted = store.insert_events(events)
        total = sum(store.count_events_by_source().values())
    print(f"{inserted} nouveaux événements stockés "
          f"({len(events) - inserted} déjà présents) — {total} en base.")


def cmd_detect(config: Config) -> None:
    with Storage(config.path("database")) as store:
        events = store.get_events()
        alerts = run_detection(config, events)
        store.replace_alerts(alerts)
        by_rule = store.count_alerts_by_rule()

    print(f"{len(alerts)} alertes produites :")
    for rule_id, n in by_rule.items():
        print(f"  {rule_id} : {n}")


def cmd_report(config: Config) -> None:
    out = config.path("output")
    with Storage(config.path("database")) as store:
        alerts = store.get_alerts()           # triées par first_seen
    export_alerts(alerts, out)
    print(f"{len(alerts)} alertes exportées vers {out}")


def cmd_run(config: Config) -> None:
    cmd_ingest(config)
    print()
    cmd_detect(config)
    print()
    cmd_report(config)


def cmd_dashboard(config: Config) -> None:
    from siem.dashboard.app import create_app

    app = create_app(config)
    print("Tableau de bord sur http://127.0.0.1:5000  (Ctrl+C pour arrêter)")
    # NF5 : écoute locale uniquement, mode debug désactivé.
    app.run(host="127.0.0.1", port=5000, debug=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini-SIEM")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("ingest", "detect", "report", "run", "dashboard"):
        sub.add_parser(name)

    args = parser.parse_args()
    config = Config.load(ROOT / "config.yaml")

    commands = {
        "ingest": cmd_ingest,
        "detect": cmd_detect,
        "report": cmd_report,
        "run": cmd_run,
        "dashboard": cmd_dashboard,
    }
    commands[args.command](config)


if __name__ == "__main__":
    main()
