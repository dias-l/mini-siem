"""Analyse de sensibilité des seuils (section 6 du rapport).

Relance la détection sur les logs fournis en faisant varier le seuil des règles
R1 (force brute SSH), R2 (scan de ports) et R4 (scan web), et affiche pour
chaque valeur le nombre d'alertes produites par la règle concernée.

Usage :
    python scripts/analyse_seuils.py
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from siem.config import Config          # noqa: E402
from siem.detection import run_detection  # noqa: E402
from siem.parsers import parse_all      # noqa: E402

VARIANTS = {
    "R1": ("rules", "R1", "threshold", [3, 5, 8]),
    "R2": ("rules", "R2", "distinct_ports", [10, 15, 20]),
    "R4": ("rules", "R4", "threshold", [10, 20, 30]),
}


def config_with(base: Config, section, rule, key, value) -> Config:
    data = copy.deepcopy(base._data)
    data[section][rule][key] = value
    return Config(data, base.base_dir)


def main() -> None:
    base = Config.load(ROOT / "config.yaml")
    events, _ = parse_all(base)

    print("Analyse de sensibilité des seuils (logs fournis)\n")
    for rule_id, (section, rule, key, values) in VARIANTS.items():
        default = base.rules[rule][key]
        print(f"=== {rule_id} — paramètre '{key}' (défaut : {default}) ===")
        print(f"{'seuil':>8} | {rule_id + ' alertes':>12} | total alertes")
        print("-" * 40)
        for value in values:
            cfg = config_with(base, section, rule, key, value)
            alerts = run_detection(cfg, events)
            rule_count = sum(1 for a in alerts if a.rule_id == rule_id)
            marker = "  <- défaut" if value == default else ""
            print(f"{value:>8} | {rule_count:>12} | {len(alerts):>13}{marker}")
        print()


if __name__ == "__main__":
    main()
