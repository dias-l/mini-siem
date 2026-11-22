"""Conversion des dates hétérogènes vers UTC (F2).

Les trois sources expriment le temps différemment :

* auth.log  : ``Oct 12 08:14:03`` — sans année, en heure locale (UTC+02:00) ;
* apache    : ``12/Oct/2026:15:21:33 +0200`` — décalage indiqué dans la ligne ;
* firewall  : ``2026-10-12T06:00:12Z`` — déjà en UTC.

On n'utilise pas ``strptime('%b')`` pour les mois car il dépend de la locale du
système (``Oct`` est l'anglais). Une table explicite rend le programme portable
et conforme à NF7 (généricité).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_time(mon: str, day: str, hms: str, year: int, offset_hours: int) -> datetime:
    """auth.log : construit la date locale puis la convertit en UTC."""
    hour, minute, second = (int(x) for x in hms.split(":"))
    local_tz = timezone(timedelta(hours=offset_hours))
    dt = datetime(year, MONTHS[mon], int(day), hour, minute, second, tzinfo=local_tz)
    return dt.astimezone(timezone.utc)


_APACHE_RE = re.compile(
    r"(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s*(?P<off>[+-]\d{4})"
)


def parse_apache_time(value: str) -> datetime:
    """apache : ``12/Oct/2026:15:21:33 +0200`` -> datetime UTC."""
    m = _APACHE_RE.match(value.strip())
    if not m:
        raise ValueError(f"date apache invalide : {value!r}")
    off = m.group("off")                       # ex. "+0200" ou "-0230"
    tz = timezone(timedelta(hours=int(off[:3]), minutes=int(off[0] + off[3:])))
    dt = datetime(
        int(m.group("year")), MONTHS[m.group("mon")], int(m.group("day")),
        int(m.group("h")), int(m.group("m")), int(m.group("s")), tzinfo=tz,
    )
    return dt.astimezone(timezone.utc)


def parse_firewall_time(value: str) -> datetime:
    """firewall : ``2026-10-12T06:00:12Z`` -> datetime UTC."""
    dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return dt.replace(tzinfo=timezone.utc)


def to_iso_z(dt: datetime) -> str:
    """Formate une date UTC en ``2026-10-12T13:24:13Z`` pour l'export/SQLite."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
