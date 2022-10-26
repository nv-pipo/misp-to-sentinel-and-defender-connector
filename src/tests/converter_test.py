#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test of converter from MISP to MS graph format."""

import json

# from converter import transform_iocs_misp_to_sentinel
# from src import converter
from misp_to_sentinel import converter


def test_converter_url_complete():
    misp_ioc = json.loads(
        """
            {
                "id": "3931551",
                "event_id": "8608",
                "category": "Network activity",
                "type": "url",
                "uuid": "d3f50f40-3b30-4909-94c0-f2e7370c71be",
                "timestamp": "1666161611",
                "value": "https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe",
                "Event": {
                    "info": "Online File Converter Phishing Page Spreads RedLine Stealer"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=(
            "(misp_label event_id: 8608) Online File "
            "Converter Phishing Page Spreads RedLine Stealer"
        ),
        displayName="misp_label_attribute_3931551",
        externalId="d3f50f40-3b30-4909-94c0-f2e7370c71be",
        pattern="[url:value = 'https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe']",
        patternType="stix",
        source="misp_label",
        threatIntelligenceTags=["misp_label_event_id_8608", "misp_label_attribute_id_3931551"],
        threatTypes=["Network activity"],
        validFrom="2022-10-19T06:40:11+00:00",
        validUntil="2022-10-21T06:40:11+00:00",
    )

    assert misp_iocs_as_sentinel[0] == expected_sentinel_ioc


def test_converter_url():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666161611",
                "type": "url",
                "value": "https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=("-"),
        displayName="-",
        externalId="-",
        pattern="[url:value = 'https://convertigoto.net/cc/flesd/YourConvertedFile59417.exe']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_domain():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666161611",
                "type": "domain",
                "value": "bharatbhushanaward.net",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "misp_label")

    expected_sentinel_ioc = converter.SentinelIOC(
        description=("-"),
        displayName="-",
        externalId="-",
        pattern="[domain-name:value = 'bharatbhushanaward.net']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_ipv4():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666296048",
                "type": "ip-src",
                "value": "192.71.166.142",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[ipv4-addr:value = '192.71.166.142']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_ipv6():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666296048",
                "type": "ip-src",
                "value": "2001:DB8::1",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[ipv6-addr:value = '2001:DB8::1']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_ipv4_with_port():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666296048",
                "type": "ip-dst|port",
                "value": "192.71.166.142|1233",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[ipv4-addr:value = '192.71.166.142']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_ipv6_with_port():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666296048",
                "type": "ip-src|port",
                "value": "2001:DB8::1|5234",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[ipv6-addr:value = '2001:DB8::1']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_hash():
    misp_ioc = json.loads(
        """
            {
                "timestamp": "1666296048",
                "type": "vhash",
                "value": "017057555d6d141az25!z",
                "id": "-",
                "event_id": "-",
                "category": "-",
                "uuid": "-",
                "Event": {
                    "info": "-"
                }
            }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[file:hashes.'VHASH' = '017057555d6d141az25!z']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_filename_and_hash():
    misp_ioc = json.loads(
        """
        {
            "timestamp": "1666296048",
            "type": "filename|authentihash",
            "value": "corona.exe|f95796ef376e55fb9671fa604c8955ffbfbad9f96936b3acca3e52b0992414af",
            "id": "-",
            "event_id": "-",
            "category": "-",
            "uuid": "-",
            "Event": {
                "info": "-"
            }
        }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern=(
            "[file:name = 'corona.exe' AND file:hashes.'AUTHENTIHASH' = "
            "'f95796ef376e55fb9671fa604c8955ffbfbad9f96936b3acca3e52b0992414af']"
        ),
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_email_addr():
    misp_ioc = json.loads(
        """
        {
            "timestamp": "1666296048",
            "type": "email",
            "value": "postmaster@mertalijaveral.com",
            "id": "-",
            "event_id": "-",
            "category": "-",
            "uuid": "-",
            "Event": {
                "info": "-"
            }
        }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[email-addr:value = 'postmaster@mertalijaveral.com']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_email_subject():
    misp_ioc = json.loads(
        """
        {
            "timestamp": "1666296048",
            "type": "email-subject",
            "value": "Storage Capacity Full",
            "id": "-",
            "event_id": "-",
            "category": "-",
            "uuid": "-",
            "Event": {
                "info": "-"
            }
        }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[email-message:subject = 'Storage Capacity Full']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern


def test_converter_mutex():
    misp_ioc = json.loads(
        """
        {
            "timestamp": "1666296048",
            "type": "mutex",
            "value": "vBQA5vjd0gKHLwQyJK86NhVS",
            "id": "-",
            "event_id": "-",
            "category": "-",
            "uuid": "-",
            "Event": {
                "info": "-"
            }
        }
        """
    )
    misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel([misp_ioc], 2, "-")

    expected_sentinel_ioc = converter.SentinelIOC(
        description="-",
        displayName="-",
        externalId="-",
        pattern="[mutex:name = 'vBQA5vjd0gKHLwQyJK86NhVS']",
        patternType="-",
        source="-",
        threatIntelligenceTags=[],
        threatTypes=[],
        validFrom="-",
        validUntil="-",
    )

    assert misp_iocs_as_sentinel[0].pattern == expected_sentinel_ioc.pattern
