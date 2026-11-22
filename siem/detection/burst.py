"""Moteur de détection de rafales par fenêtre glissante (R1, R2, R4).

Problème à éviter : une attaque de 500 essais doit produire **une** alerte, pas
496 (ce qui arriverait avec des fenêtres de 5 événements qui se chevauchent) ni
une par minute (un découpage fixe couperait une attaque à cheval sur deux
minutes).

Règle retenue, conforme à l'énoncé :

* une rafale **démarre** dès qu'une fenêtre glissante de ``window_seconds``
  (bornes incluses) satisfait un critère de seuil — par exemple 5 événements
  pour R1, ou 15 ports distincts pour R2 ;
* elle contient alors **tous les événements de cette fenêtre** ;
* elle **se prolonge** tant que l'écart entre un nouvel événement et le dernier
  événement de la rafale ne dépasse pas ``window_seconds`` ;
* au-delà de cet écart, une nouvelle attaque de la même IP démarre une nouvelle
  rafale.

Le critère de seuil est injecté (``meets_threshold``) pour couvrir aussi bien le
comptage d'événements (R1, R4) que le comptage de ports distincts (R2).
"""
from __future__ import annotations

from typing import Callable

from ..models import Event


def find_bursts(
    events: list[Event],
    window_seconds: int,
    meets_threshold: Callable[[list[Event]], bool],
) -> list[list[Event]]:
    """Découpe les événements d'UNE même IP (triés par date) en rafales.

    ``events`` doit être trié par timestamp croissant.
    Retourne la liste des rafales, chacune étant la liste de ses événements.
    """
    n = len(events)
    ts = [e.timestamp for e in events]
    bursts: list[list[Event]] = []
    start = 0

    while start < n:
        # 1) Formation : chercher le premier instant où une fenêtre glissante
        #    de durée window_seconds atteint le seuil (bornes incluses).
        j = start
        trigger = burst_start = None
        for i in range(start, n):
            while (ts[i] - ts[j]).total_seconds() > window_seconds:
                j += 1
            if meets_threshold(events[j:i + 1]):
                trigger, burst_start = i, j
                break

        if trigger is None:
            break  # plus aucune rafale possible dans le reste

        # 2) Prolongation : tant que l'écart avec le dernier événement de la
        #    rafale reste <= window_seconds.
        last = trigger
        k = trigger + 1
        while k < n and (ts[k] - ts[last]).total_seconds() <= window_seconds:
            last = k
            k += 1

        bursts.append(events[burst_start:last + 1])
        start = last + 1  # la prochaine rafale démarre après l'écart

    return bursts
