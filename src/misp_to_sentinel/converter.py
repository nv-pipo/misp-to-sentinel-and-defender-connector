#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Converter from MISP to Sentinel format."""

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

logger = logging.getLogger("misp_to_sentinel")


@dataclass(kw_only=True)
class SentinelIOC:
    # pylint: disable=invalid-name
    source: str
    displayName: str
    description: str
    externalId: str
    threatIntelligenceTags: list[str]
    threatTypes: list[str]
    pattern: str
    patternType: str
    validFrom: datetime
    validUntil: datetime

    def as_dict(self) -> dict[str, str]:
        return self.__dict__


class CustomTypes(Enum):
    IP = "ipv4/ipv6"
    HASH = "hash"
    FILENAME_AND_HASH = "filename|hash"


TYPE_MAPPINGS = {
    # IP
    "ip-dst": CustomTypes.IP,
    "ip-dst|port": CustomTypes.IP,
    "ip-src": CustomTypes.IP,
    "ip-src|port": CustomTypes.IP,
    # Hashes
    "authentihash": CustomTypes.HASH,
    "impfuzzy": CustomTypes.HASH,
    "imphash": CustomTypes.HASH,
    "md5": CustomTypes.HASH,
    "pehash": CustomTypes.HASH,
    "sha1": CustomTypes.HASH,
    "sha224": CustomTypes.HASH,
    "sha256": CustomTypes.HASH,
    "sha3-224": CustomTypes.HASH,
    "sha3-256": CustomTypes.HASH,
    "sha3-384": CustomTypes.HASH,
    "sha3-512": CustomTypes.HASH,
    "sha384": CustomTypes.HASH,
    "sha512": CustomTypes.HASH,
    "sha512/224": CustomTypes.HASH,
    "sha512/256": CustomTypes.HASH,
    "ssdeep": CustomTypes.HASH,
    "tlsh": CustomTypes.HASH,
    "vhash": CustomTypes.HASH,
    # File name and hashes
    "filename|authentihash": CustomTypes.FILENAME_AND_HASH,
    "filename|impfuzzy": CustomTypes.FILENAME_AND_HASH,
    "filename|imphash": CustomTypes.FILENAME_AND_HASH,
    "filename|md5": CustomTypes.FILENAME_AND_HASH,
    "filename|pehash": CustomTypes.FILENAME_AND_HASH,
    "filename|sha1": CustomTypes.FILENAME_AND_HASH,
    "filename|sha224": CustomTypes.FILENAME_AND_HASH,
    "filename|sha256": CustomTypes.FILENAME_AND_HASH,
    "filename|sha3-224": CustomTypes.FILENAME_AND_HASH,
    "filename|sha3-256": CustomTypes.FILENAME_AND_HASH,
    "filename|sha3-384": CustomTypes.FILENAME_AND_HASH,
    "filename|sha3-512": CustomTypes.FILENAME_AND_HASH,
    "filename|sha384": CustomTypes.FILENAME_AND_HASH,
    "filename|sha512": CustomTypes.FILENAME_AND_HASH,
    "filename|sha512/224": CustomTypes.FILENAME_AND_HASH,
    "filename|sha512/256": CustomTypes.FILENAME_AND_HASH,
    "filename|ssdeep": CustomTypes.FILENAME_AND_HASH,
    "filename|tlsh": CustomTypes.FILENAME_AND_HASH,
    "filename|vhash": CustomTypes.FILENAME_AND_HASH,
    # Email
    "email-dst": "email-addr:value",
    "email-src": "email-addr:value",
    "email": "email-addr:value",
    "email-subject": "email-message:subject",
    # Others
    "domain": "domain-name:value",
    "filename": "file:name",
    "url": "url:value",
}

SUPPORTED_TYPES = list(TYPE_MAPPINGS.keys())


def transform_iocs_misp_to_sentinel(
    misp_iocs: list[dict[str, any]], ioc_days_to_live: int, misp_label: str
) -> list[SentinelIOC]:
    """Receive a 'misp attribute' and return a sentinel IOC."""
    converted_iocs = [
        sentinel_ioc
        for misp_ioc in misp_iocs
        if (
            sentinel_ioc := __transform_ioc_misp_to_sentinel(
                misp_ioc, ioc_days_to_live, misp_label
            )
        )
    ]
    logger.info("Converted IOCs (MISP to Sentinel): %s", len(converted_iocs))
    return converted_iocs


def __ip_version_chooser(address: str) -> str | None:
    try:
        match ipaddress.ip_address(address).version:
            case 4:
                return "ipv4-addr"
            case 6:
                return "ipv6-addr"
    except ValueError:
        pass
    return None


def __transform_ioc_misp_to_sentinel(
    misp_ioc: dict[str, any], ioc_days_to_live: int, misp_label: str
) -> SentinelIOC | None:

    valid_from = datetime.fromtimestamp(int(misp_ioc["timestamp"]), timezone.utc)

    pattern_type = TYPE_MAPPINGS.get(misp_ioc["type"])
    if not pattern_type:
        return None
    simple_value = misp_ioc["value"].split("|")[0]  # split by pipes and take first
    pattern = f"[{pattern_type} = '{simple_value}']"

    match pattern_type:
        case CustomTypes.IP:
            pattern = f"[{__ip_version_chooser(simple_value)}:value = '{simple_value}']"
        case CustomTypes.HASH:
            pattern = f"[file:hashes.'{misp_ioc['type'].upper()}' = '{misp_ioc['value']}']"
        case CustomTypes.FILENAME_AND_HASH:
            value_parts = misp_ioc["value"].split("|")
            hash_type = misp_ioc["type"].split("|")[1]
            pattern = (
                f"[file:name = '{value_parts[0]}' AND "
                f"file:hashes.'{hash_type.upper()}' = '{value_parts[1]}']"
            )

    sentinel_ioc = SentinelIOC(
        source=misp_label,
        displayName=f"{misp_label}_attribute_{misp_ioc['id']}",
        description=(
            f'({misp_label} event_id: {misp_ioc["event_id"]}) {misp_ioc["Event"]["info"]}'
        ),
        externalId=misp_ioc["uuid"],
        threatIntelligenceTags=[
            f"{misp_label}_event_id_{misp_ioc['event_id']}",
            f"{misp_label}_attribute_id_{misp_ioc['id']}",
        ],
        threatTypes=[misp_ioc["category"].strip()],
        pattern=pattern,
        patternType="stix",
        validFrom=valid_from.isoformat(),
        validUntil=(valid_from + timedelta(days=ioc_days_to_live)).isoformat(),
    )

    return sentinel_ioc
