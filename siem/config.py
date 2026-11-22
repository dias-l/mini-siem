"""Chargement de la configuration (config.yaml).

NF2 : tous les seuils, fenêtres, signatures et la liste blanche vivent dans le
fichier YAML. Le code accède à ces valeurs via cet objet Config, jamais en dur.
"""
from __future__ import annotations

from pathlib import Path

import yaml


class Config:
    """Enveloppe pratique autour du dictionnaire de configuration.

    Les chemins déclarés dans la section ``paths`` sont résolus relativement au
    dossier qui contient le fichier ``config.yaml`` (la racine du projet), ce qui
    rend le programme indépendant du répertoire courant.
    """

    def __init__(self, data: dict, base_dir: Path) -> None:
        self._data = data
        self.base_dir = Path(base_dir)

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data, path.resolve().parent)

    # -- Accès générique ----------------------------------------------------
    def __getitem__(self, key: str):
        return self._data[key]

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    # -- Raccourcis fréquents ----------------------------------------------
    def path(self, key: str) -> Path:
        """Retourne un chemin de la section ``paths`` résolu en absolu."""
        return (self.base_dir / self._data["paths"][key]).resolve()

    @property
    def whitelist(self) -> set[str]:
        """IP à ignorer dans toutes les règles (F5)."""
        return set(self._data.get("whitelist", []))

    @property
    def rules(self) -> dict:
        return self._data.get("rules", {})

    @property
    def correlation(self) -> dict:
        return self._data.get("correlation", {})

    @property
    def signatures(self) -> dict:
        return self._data.get("signatures", {})

    @property
    def parsing(self) -> dict:
        return self._data.get("parsing", {})
