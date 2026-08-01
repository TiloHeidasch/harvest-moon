#!/usr/bin/env python3
"""Fail-closed validation of one Nmap XML /24 result.

The scanner is deliberately asked for XML on stdout.  This validator only
returns the number of observed up IPv4 hosts; a malformed or incomplete
document is an error and can never be interpreted as a zero-host result.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import sys
from typing import NoReturn
import xml.etree.ElementTree as ET


def fail(message: str) -> NoReturn:
    print(f"nmap XML rejected: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical_uint(value: str, name: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        fail(f"{name} is not a canonical decimal integer")
    if len(value) > 1 and value[0] == "0":
        fail(f"{name} has leading zeroes")
    number = int(value)
    return number


def canonical_ipv4(value: str) -> ipaddress.IPv4Address:
    if not value or value != value.strip():
        fail(f"invalid IPv4 address {value!r}")
    parts = value.split(".")
    if len(parts) != 4:
        fail(f"invalid IPv4 address {value!r}")
    octets = [canonical_uint(part, "IPv4 octet") for part in parts]
    if any(octet > 255 for octet in octets):
        fail(f"IPv4 octet out of range in {value!r}")
    canonical = ".".join(str(octet) for octet in octets)
    if value != canonical:
        fail(f"noncanonical IPv4 address {value!r}")
    return ipaddress.IPv4Address(value)


def parse(path: Path, expected: ipaddress.IPv4Network) -> int:
    root: ET.Element
    try:
        if not path.is_file() or path.stat().st_size == 0:
            fail("empty or missing document")
        # ElementTree rejects truncated XML, multiple roots, malformed
        # attributes, and invalid entities.  It also consumes the complete
        # file rather than accepting a useful-looking prefix.
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        fail(f"malformed or truncated XML ({exc})")
    except OSError as exc:
        fail(f"cannot read document ({exc})")

    if root.tag != "nmaprun":
        fail("document root is not nmaprun")

    runstats = [child for child in root if child.tag == "runstats"]
    if len(runstats) != 1:
        fail("document must contain exactly one runstats element")
    runstats_element = runstats[0]
    finished = [child for child in runstats_element if child.tag == "finished"]
    hosts_elements = [child for child in runstats_element if child.tag == "hosts"]
    if len(finished) != 1 or len(hosts_elements) != 1:
        fail("runstats must contain exactly one finished and hosts element")
    if finished[0].attrib.get("exit") != "success":
        fail("run did not finish successfully")

    hosts_summary = hosts_elements[0]
    summary_values = {}
    for name in ("total", "up", "down"):
        if name not in hosts_summary.attrib:
            fail(f"runstats hosts is missing {name}")
        summary_values[name] = canonical_uint(hosts_summary.attrib[name], f"hosts {name}")
    if summary_values["total"] != 256:
        fail(f"runstats total is {summary_values['total']}, expected 256")
    if summary_values["up"] > 256 or summary_values["down"] > 256:
        fail("runstats host counts exceed 256")
    if summary_values["up"] + summary_values["down"] != summary_values["total"]:
        fail("runstats up plus down does not equal total")

    seen: set[str] = set()
    observed_up = 0
    for host in [child for child in root if child.tag == "host"]:
        statuses = [child for child in host if child.tag == "status"]
        if len(statuses) != 1:
            fail("each host must contain exactly one status")
        state = statuses[0].attrib.get("state")
        if state not in {"up", "down"}:
            fail(f"invalid host status {state!r}")

        addresses = [child for child in host if child.tag == "address"]
        ipv4_addresses = [
            child for child in addresses if child.attrib.get("addrtype") == "ipv4"
        ]
        if len(ipv4_addresses) != 1:
            fail("each observed host must contain exactly one IPv4 address")
        address_text = ipv4_addresses[0].attrib.get("addr")
        if address_text is None:
            fail("IPv4 address is missing addr")
        address = canonical_ipv4(address_text)
        if address not in expected:
            fail(f"host {address} is outside requested {expected}")
        if str(address) in seen:
            fail(f"duplicate host {address}")
        seen.add(str(address))
        if state == "up":
            observed_up += 1

    if observed_up != summary_values["up"]:
        fail(
            f"observed up count is {observed_up}, stated up count is {summary_values['up']}"
        )
    print(observed_up)
    return observed_up


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", type=Path)
    parser.add_argument("class_a", type=int)
    parser.add_argument("class_b", type=int)
    parser.add_argument("class_c", type=int)
    args = parser.parse_args()
    values = (args.class_a, args.class_b, args.class_c)
    if any(value < 0 or value > 255 for value in values):
        fail("target octet is outside 0..255")
    network = ipaddress.IPv4Network(f"{args.class_a}.{args.class_b}.{args.class_c}.0/24")
    parse(args.xml, network)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
