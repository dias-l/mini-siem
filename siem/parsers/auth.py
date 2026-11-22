"""Analyseur de ``auth.log`` (SSH et sudo).

Une ligne est corrompue si elle ne commence pas par
``Mois Jour HH:MM:SS machine processus:``.

Événements produits :
* ``ssh_failed``   : ``Failed password for [invalid user] <user> from <ip> ...``
* ``ssh_success``  : ``Accepted <méthode> for <user> from <ip> ...``
* ``sudo_command`` : ``<user> : ... COMMAND=<cmd>``

Les autres lignes valides (CRON, ``Invalid user`` seul, ``Connection closed``,
sessions pam) sont ignorées sans être comptées comme corrompues.
"""
from __future__ import annotations

import re
from pathlib import Path

from .. import timeutils
from ..config import Config
from ..models import Event, SourceStats

# Préfixe syslog : mois, jour (1 ou 2 chiffres), heure, machine, processus[pid]:
_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\w+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

# L'optionnel « invalid user » couvre les deux variantes du même échec.
_FAILED = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPT = re.compile(
    r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO = re.compile(r"^(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.*)$")


def parse(path: str | Path, config: Config) -> tuple[list[Event], SourceStats]:
    year = config.parsing["auth_log"]["year"]
    offset = config.parsing["auth_log"]["timezone_offset_hours"]

    events: list[Event] = []
    stats = SourceStats(source="ssh")

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            stats.lines_read += 1
            raw = line.rstrip("\n")
            if raw.strip() == "":
                continue  # ligne vide : ignorée

            m = _PREFIX.match(raw)
            if not m:
                stats.corrupted += 1
                continue

            proc, msg = m.group("proc"), m.group("msg")
            ts = timeutils.parse_syslog_time(
                m.group("mon"), m.group("day"), m.group("time"), year, offset
            )
            host = m.group("host")

            if proc == "sshd":
                fm = _FAILED.match(msg)
                if fm:
                    events.append(Event(
                        timestamp=ts, source="ssh", event_type="ssh_failed", raw=raw,
                        src_ip=fm.group("ip"), src_port=int(fm.group("port")),
                        host=host, user=fm.group("user"),
                    ))
                    stats.events += 1
                    continue

                am = _ACCEPT.match(msg)
                if am:
                    events.append(Event(
                        timestamp=ts, source="ssh", event_type="ssh_success", raw=raw,
                        src_ip=am.group("ip"), src_port=int(am.group("port")),
                        host=host, user=am.group("user"),
                    ))
                    stats.events += 1
                    continue
                # autres lignes sshd : ignorées

            elif proc == "sudo":
                sm = _SUDO.match(msg)
                if sm:
                    events.append(Event(
                        timestamp=ts, source="ssh", event_type="sudo_command", raw=raw,
                        host=host, user=sm.group("user"), command=sm.group("cmd").strip(),
                    ))
                    stats.events += 1
                    continue

            # CRON et tout le reste : ignoré

    return events, stats
