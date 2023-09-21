#!/usr/bin/env python3

import sys
import json
import logging as log

log.basicConfig(level=log.INFO)

ID = "id"
OBJECTS = "objects"
COUNTRY_CODE = "country_code"
TAGS = "tags"
STATUS = "status_name"

CC_LEN = 2  # Length of the ISO 3166 country code.
IPV4_ADDR = "address_v4"
IPV6_ADDR = "address_v6"
BAD_TAGS = [
    "system-geoloc-disputed",
    "core",
    "cloud",
    "vps",
    "ixp",
]
GOOD_TAGS = [
    "deutsche-glasfaser",
    "dn42",
    "fiona",
    "freedom-internet",
    "fttb",
    "fttp",
    "gpnrp",
    "hybrid",
    "makerspace",
    "mesh",
    "openfiber",
    "pon",
    "ukraine",
    "verizon",
    "virgin-media",
    "6in4",
    "fiber",
    "frontier",
    "lxc",
    "swisscom",
    "bell",
    "cox-3",
    "fttp-2",
    "container",
    "fbnh",
    "fttb-2",
    "464xlat",
    "system-wifi",
    "telenet",
    "sixxs",
    "google-fiber",
    "system-flakey-power",
    "o2",
    "system-flakey-connection",
    "xfinity",
    "freifunk",
    "no-ipv4",
    "xs4all",
    "t-mobile",
    "kpn",
    "5g",
    "sfr",
    "ipv6nat",
    "spectrum",
    "att",
    "nat64",
    "wimax",
    "epix",
    "ipv6-only",
    "v5hitron",
    "starlink",
    "fttc",
    "twc",
    "3g",
    "6rd",
    "telekom",
    "system-resolves-aaaa-incorrectly",
    "known-ipv4-issues",
    "satellite",
    "vodafone",
    "ziggo",
    "docsis-31",
    "openwrt-3",
    "ds-lite",
    "6to4",
    "pi-hole",
    "nosi",
    "fios",
    "hackerspace",
    "upc",
    "pppoe",
    "vpn",
    "wi-fi",
    "docker",
    "he",
    "gpon",
    "homelab",
    "orange",
    "4g",
    "comcast",
    "cgn",
    "dtag",
    "mobile",
    "lte",
    "double-nat",
    "wireless-isp",
    "adsl",
    "docsis3",
    "ipv6-tunnel",
    "vdsl",
    "vdsl2",
    "ftth",
    "office",
    "dsl",
    "cable",
    "home",
    "nat",
]
BAD_STATUS_NAMES = ["Disconnected", "Abandoned"]


def tags_are_bad(tags: list) -> bool:
    """Return True if any of the probe's tags violate our selection criteria."""
    for tag in tags:
        if tag in BAD_TAGS:
            return True
        if tag.startswith("data-center") or tag.startswith("datacenter"):
            return True
    return False


def pct(numerator: int, denominator: int) -> float:
    """Turn the given ratio into a percentage."""
    assert denominator > 0
    return numerator / denominator * 100


def filter_probes(all_probes: list) -> list:
    """Return the subset of probes that are eligible for measurements."""
    num_bad_cc, num_bad_tags, num_bad_status, num_addrless = 0, 0, 0, 0

    subset_probes = []
    for probe in all_probes:
        if probe[COUNTRY_CODE] is None or len(probe[COUNTRY_CODE]) != CC_LEN:
            num_bad_cc += 1
            continue
        if tags_are_bad(probe[TAGS]):
            num_bad_tags += 1
            continue
        if probe[STATUS] in BAD_STATUS_NAMES:
            num_bad_status += 1
            continue
        if probe[IPV4_ADDR] is None and probe[IPV6_ADDR] is None:
            num_addrless += 1
            continue
        if any([t in GOOD_TAGS for t in probe[TAGS]]):
            subset_probes.append(probe)

    num_probes = len(all_probes)
    log.info("Processed {0:,} probes.".format(num_probes))
    log.info(
        "Skipped {:,} ({:.1f}%) probes because they have no public addresses.".format(
            num_addrless, pct(num_addrless, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad country code.".format(
            num_bad_cc, pct(num_bad_cc, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad tags.".format(
            num_bad_tags, pct(num_bad_tags, num_probes)
        )
    )
    log.info(
        "Skipped {:,} ({:.1f}%) probes because of bad status.".format(
            num_bad_status, pct(num_bad_status, num_probes)
        )
    )

    return subset_probes


def load_probes(probe_file: str) -> list:
    """Load the probes from the given JSON file."""
    log.info("Reading {}.".format(probe_file))

    with open(probe_file, "r") as f:
        records = json.load(f)
    return records[OBJECTS]


def print_probes(our_probes: list):
    """Print CSV data, with one ID,addr pair per line."""
    probe_by_id = {p[ID]: p for p in our_probes}
    for id in sorted(probe_by_id.keys()):
        probe = probe_by_id[id]
        addr = probe[IPV4_ADDR]
        if addr is None:  # Probe may only be reachable via IPv6.
            addr = probe[IPV6_ADDR]
            assert addr is not None, probe
        print("{},{}".format(id, addr))


def main(probe_file: str):
    """The entry point of this script."""
    all_probes = load_probes(probe_file)
    our_probes = filter_probes(all_probes)
    log.info("Proceeding with {:,} probes.".format(len(our_probes)))
    print_probes(our_probes)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "PROBE_FILE", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
