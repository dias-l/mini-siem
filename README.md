# Mini-SIEM — Projet Python Cybersécurité

SIEM simplifié qui collecte les logs de trois sources (SSH/sudo, serveur web
Apache, pare-feu), les normalise en UTC, les stocke dans SQLite, détecte les
comportements suspects (force brute, scan de ports, attaques web, réputation
d'IP), corrèle les indices et présente des alertes exploitables via une API et
un tableau de bord Flask.

## Prérequis

- Python 3.10 ou plus récent

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Utilisation

```bash
# 1. Collecte + normalisation + stockage
python main.py ingest

# 2. Détection + corrélation
python main.py detect

# 3. Export des alertes vers output/alertes.json
python main.py report

# Les trois étapes à la suite
python main.py run

# Tableau de bord web (http://127.0.0.1:5000)
python main.py dashboard
```

Les logs sont lus dans `data/logs/` et `data/threat_intel/`.
La configuration (seuils, fenêtres, signatures, liste blanche) se trouve dans
`config.yaml`.

## Tests

```bash
pytest
```

## Structure

| Dossier / fichier      | Rôle                                               |
|------------------------|----------------------------------------------------|
| `main.py`              | Point d'entrée CLI                                 |
| `config.yaml`          | Configuration (NF2)                                |
| `siem/parsers/`        | Analyseurs des trois sources                       |
| `siem/storage.py`      | Base SQLite (idempotente, requêtes paramétrées)    |
| `siem/detection/`      | Règles R1–R5 et corrélations C1–C2                 |
| `siem/export.py`       | Export JSON des alertes                            |
| `siem/dashboard/`      | Application web Flask                              |
| `tests/`               | Tests pytest                                       |
