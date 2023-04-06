"""Sync MISP to Sentinel."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from misp_to_sentinel.misp import MISPAttribute, MISPConnector
from misp_to_sentinel.sentinel import SentinelConnector, SentinelIndicator
from misp_to_sentinel.utils.environ_utils import load_env_variable
from misp_to_sentinel.utils.timing import timefunc_async


def __init_connectors() -> tuple[MISPConnector, SentinelConnector]:
    misp_connector = MISPConnector(
        misp_base_url=load_env_variable("MISP_BASE_URL"),
        misp_ca_bundle_path=load_env_variable("MISP_CA_BUNDLE_PATH"),
        misp_key=load_env_variable("MISP_KEY"),
        misp_label=load_env_variable("MISP_LABEL"),
    )
    sentinel_connector = SentinelConnector(
        tenant_id=load_env_variable("AZ_TENANT_ID"),
        client_id=load_env_variable("SP_SENTINEL_CLIENT_ID"),
        client_secret=load_env_variable("SP_SENTINEL_CLIENT_SECRET"),
        subscription_id=load_env_variable("AZ_SUBSCRIPTION_ID"),
        resource_group_name=load_env_variable("SENTINEL_RESOURCE_GROUP_NAME"),
        workspace_name=load_env_variable("SENTINEL_WORKSPACE_NAME"),
    )
    return misp_connector, sentinel_connector


@timefunc_async
async def __get_current_state(
    misp_connector: MISPConnector, sentinel_connector: SentinelConnector
) -> tuple[set[str], list[MISPAttribute]]:
    look_back_days = int(load_env_variable("LOOK_BACK_DAYS"))
    sentinel_days_to_expire = int(load_env_variable("SENTINEL_DAYS_TO_EXPIRE"))

    sentinel_min_valid_until_utc = (
        datetime.utcnow()
        + timedelta(days=-look_back_days)
        + timedelta(days=sentinel_days_to_expire)
    )
    tasks = [
        sentinel_connector.get_indicators(sentinel_min_valid_until_utc.isoformat() + "Z"),
        misp_connector.get_attributes_with_stix2_patterns(
            look_back_days=load_env_variable("LOOK_BACK_DAYS"),
        ),
    ]

    existing_iocs_sentinel, available_misp = await asyncio.gather(*tasks)
    existing_iocs_sentinel_external_ids = {
        ioc["properties"]["externalId"] for ioc in existing_iocs_sentinel
    }
    return existing_iocs_sentinel_external_ids, available_misp


def __compute_iocs_to_create(
    existing_iocs_sentinel_external_ids: set[str], available_misp: list[MISPAttribute]
) -> list[SentinelIndicator]:
    misp_label = load_env_variable("MISP_LABEL")
    sentinel_days_to_expire = int(load_env_variable("SENTINEL_DAYS_TO_EXPIRE"))
    iocs_to_create = [
        SentinelIndicator(
            source=misp_label,
            externalId=attr.stix_id,
            displayName=f"{misp_label}_attribute_{attr.attribute_id}",
            description=f"({misp_label} event_id: {attr.event_id}) {attr.event_info}",
            threatIntelligenceTags=[
                f"{misp_label}_event_id_{attr.event_id}",
                f"{misp_label}_attribute_id_{attr.attribute_id}",
            ],
            validFrom=datetime.fromtimestamp(attr.timestamp, timezone.utc),
            validUntil=(
                datetime.fromtimestamp(attr.timestamp, timezone.utc)
                + timedelta(days=sentinel_days_to_expire)
            ),
            pattern=attr.pattern,
            patternType="stix2",
            threatTypes=[attr.category],
        )
        for attr in available_misp
        if attr.stix_id not in existing_iocs_sentinel_external_ids
    ]
    return iocs_to_create


@timefunc_async
async def __push_to_sentinel(
    sentinel_connector: SentinelConnector, iocs_to_create: list[SentinelIndicator]
) -> list[dict]:
    tasks = [sentinel_connector.create_indicator(ioc) for ioc in iocs_to_create]
    responses = await asyncio.gather(*tasks)
    logging.info("Created %d indicators in Sentinel.", len(responses))
    return responses


@timefunc_async
async def sync():
    """Sync MISP to Sentinel."""
    # Retrieve from MISP

    misp_connector, sentinel_connector = __init_connectors()

    existing_iocs_sentinel_external_ids, available_misp = await __get_current_state(
        misp_connector, sentinel_connector
    )

    iocs_to_create = __compute_iocs_to_create(existing_iocs_sentinel_external_ids, available_misp)

    _ = await __push_to_sentinel(sentinel_connector, iocs_to_create)
