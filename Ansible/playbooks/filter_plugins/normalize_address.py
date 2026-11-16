# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Ansible filter `normalize_address`: one canonical text for one network address, standard library only.

    {{ '[2001:0DB8:0:0::30]' | normalize_address }}   ->  2001:db8::30
    {{ '::ffff:192.0.2.1'    | normalize_address }}   ->  192.0.2.1
    {{ ' Backup.Example.ORG ' | normalize_address }}  ->  backup.example.org

Used to COMPARE two spellings of an address (`retarget-backups-web3c.yml`, guard of `purge_old`), never to build
a connection string. Rules:
  • surrounding blanks, and one pair of brackets around an IPv6 literal, are dropped ;
  • an IPv4 or IPv6 address is rendered by `ipaddress` (IPv6 compressed, lower case) ; an IPv4-mapped IPv6 address
    (`::ffff:a.b.c.d`, or its hexadecimal spelling) becomes the IPv4 address ;
  • an IPv6 zone (`fe80::1%eth0`) is DROPPED: the guard compares destinations, and treating two zones of one link-local
    address as the same destination can only make it refuse more, never less ;
  • anything else is taken for a DNS name and returned in lower case, trimmed, UNRESOLVED (no lookup, ever) ;
  • never raises: a value that is not text goes through `str()` (None gives an empty string).
Not recognised as equal, on purpose: a name and the address it resolves to ; an IPv4 written with leading zeros
(`192.000.002.001`, refused by `ipaddress` since Python 3.9.5, so handled as a name)."""
import ipaddress


def normalize_address(value):
    text = "" if value is None else str(value).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    candidate = text.partition("%")[0] if ":" in text else text
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return text.lower()
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped if mapped is not None else address)


class FilterModule:
    def filters(self):
        return {"normalize_address": normalize_address}
