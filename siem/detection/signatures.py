"""Signatures d'attaque web pour la règle R3 (sqli, path_traversal, xss).

Les expressions régulières sont définies dans ``config.yaml`` (NF2) et compilées
ici, insensibles à la casse. L'URL est décodée **deux fois** avec
``unquote_plus`` car certaines charges sont encodées deux fois.

Les motifs sont volontairement ancrés (``union\\s+select``, ``<script`` ...) pour
éviter les faux positifs : une URL légitime contenant simplement un mot comme
« union », « select », « or » ou « script » ne doit pas déclencher d'alerte.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus


def compile_signatures(sig_config: dict[str, list[str]]) -> dict[str, list[re.Pattern]]:
    return {
        category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        for category, patterns in sig_config.items()
    }


def decode_url(url: str) -> str:
    """Décode l'URL deux fois (charges éventuellement double-encodées)."""
    return unquote_plus(unquote_plus(url))


def match_categories(url: str, signatures: dict[str, list[re.Pattern]]) -> set[str]:
    """Retourne l'ensemble des catégories dont au moins une signature matche."""
    decoded = decode_url(url)
    return {
        category
        for category, patterns in signatures.items()
        if any(p.search(decoded) for p in patterns)
    }
