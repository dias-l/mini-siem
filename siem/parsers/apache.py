"""Analyseur de ``apache_access.log`` (format combined).

Format : ``ip - user [date] "méthode url protocole" statut octets "ref" "ua"``

Une ligne est corrompue si elle ne respecte pas le format combined, ou si sa
requête ne contient pas exactement trois éléments (méthode, URL, protocole) —
par exemple une requête réduite à ``"-"``.

L'URL est conservée **encodée**, telle qu'elle figure dans le log ; elle sera
décodée plus tard par la règle R3.
"""
from __future__ import annotations

import re
from pathlib import Path

from .. import timeutils
from ..config import Config
from ..models import Event, SourceStats

# Les champs entre guillemets peuvent contenir des guillemets internes échappés
# (`\"`), comme le permet le format combined d'Apache. Le motif `(?:[^"\\]|\\.)*`
# accepte ces échappements au lieu de s'arrêter au premier guillemet, ce qui
# évite de rejeter à tort une ligne valide (et empêche un attaquant de masquer sa
# requête via un User-Agent ou un Referer piégé).
_QUOTED = r'(?:[^"\\]|\\.)*'
_COMBINED = re.compile(
    rf'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] "(?P<request>{_QUOTED})" '
    rf'(?P<status>\d{{3}}) (?P<bytes>\d+|-) "(?P<referer>{_QUOTED})" "(?P<ua>{_QUOTED})"$'
)


def parse(path: str | Path, config: Config) -> tuple[list[Event], SourceStats]:
    events: list[Event] = []
    stats = SourceStats(source="web")

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            stats.lines_read += 1
            raw = line.rstrip("\n")
            if raw.strip() == "":
                continue

            m = _COMBINED.match(raw)
            if not m:
                stats.corrupted += 1
                continue

            # La requête doit contenir exactement méthode, URL et protocole.
            parts = m.group("request").split(" ")
            if len(parts) != 3:
                stats.corrupted += 1
                continue
            method, url, _protocol = parts

            byte_field = m.group("bytes")
            events.append(Event(
                timestamp=timeutils.parse_apache_time(m.group("date")),
                source="web", event_type="web_request", raw=raw,
                src_ip=m.group("ip"),
                http_method=method, url=url,
                http_status=int(m.group("status")),
                bytes_sent=0 if byte_field == "-" else int(byte_field),  # "-" vaut 0
                user_agent=m.group("ua"),
            ))
            stats.events += 1

    return events, stats
