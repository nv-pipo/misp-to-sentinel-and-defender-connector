"""Sync MISP to Sentinel."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from result import Err

from misp_to_sentinel.misp import MISPAttribute, MISPConnector
from misp_to_sentinel.sentinel import SentinelConnector, SentinelIndicator
from misp_to_sentinel.utils.environ_utils import load_env_variable
from misp_to_sentinel.utils.timing import timefunc_async

logger = logging.getLogger(__name__)


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
    misp_label = load_env_variable("MISP_LABEL")
    look_back_days = int(load_env_variable("LOOK_BACK_DAYS"))
    sentinel_days_to_expire = int(load_env_variable("SENTINEL_DAYS_TO_EXPIRE"))

    sentinel_min_valid_until_utc = (
        datetime.now(UTC)
        + timedelta(days=-look_back_days)
        + timedelta(days=sentinel_days_to_expire)
    )
    tasks = [
        sentinel_connector.get_indicators(
            min_valid_until=sentinel_min_valid_until_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            sources=[misp_label],
        ),
        misp_connector.get_attributes_with_stix2_patterns(
            look_back_days=load_env_variable("LOOK_BACK_DAYS"),
        ),
    ]

    existing_iocs_sentinel, available_misp = await asyncio.gather(*tasks)
    existing_iocs_sentinel_external_ids = {
        ioc["properties"]["externalId"] for ioc in existing_iocs_sentinel
    }
    # For backwards compatibility, add "indicator--" to iocs not conforming to STIX2
    additional_iocs_sentinel_external_ids = {
        f"indicator--{uuid}"
        for uuid in existing_iocs_sentinel_external_ids
        if not uuid.startswith("indicator--")
    }
    existing_iocs_sentinel_external_ids.update(additional_iocs_sentinel_external_ids)
    return existing_iocs_sentinel_external_ids, available_misp


def __compute_iocs_to_create(
    existing_iocs_sentinel_external_ids: set[str], available_misp: list[MISPAttribute]
) -> list[SentinelIndicator]:
    misp_label = load_env_variable("MISP_LABEL")
    sentinel_days_to_expire = int(load_env_variable("SENTINEL_DAYS_TO_EXPIRE"))
    return [
        SentinelIndicator(
            source=misp_label,
            externalId=attr.stix_id,
            displayName=f"{misp_label}_attribute_{attr.attribute_id}",
            description=f"({misp_label} event_id: {attr.event_id}) {attr.event_info}",
            threatIntelligenceTags=attr.tags,
            validFrom=datetime.fromtimestamp(attr.timestamp, UTC),
            validUntil=(
                datetime.fromtimestamp(attr.timestamp, UTC)
                + timedelta(days=sentinel_days_to_expire)
            ),
            pattern=attr.pattern,
            patternType="stix2",
            threatTypes=[attr.category],
        )
        for attr in available_misp
        if attr.stix_id not in existing_iocs_sentinel_external_ids
    ]


@timefunc_async
async def __push_to_sentinel(
    sentinel_connector: SentinelConnector, iocs_to_create: list[SentinelIndicator]
) -> None:
    if len(iocs_to_create) == 0:
        logger.info("No new indicators to push to Sentinel.")
        return

    logger.info("Attempting to push %d indicators to Sentinel.", len(iocs_to_create))
    failed = 0
    for counter, ioc in enumerate(iocs_to_create, start=1):
        result = await sentinel_connector.create_indicator(ioc)
        if isinstance(result, Err):
            failed += 1
        else:
            logger.info("Successfully pushed indicator %s to Sentinel.", ioc.external_id)
        msg = f"Indicator {counter}/{len(iocs_to_create)} = {counter / len(iocs_to_create):.2%}"
        logger.info(msg)

    logger.info(
        "SUMMARY: attempted: %d, successful: %d, failed: %d",
        len(iocs_to_create),
        len(iocs_to_create) - failed,
        failed,
    )


@timefunc_async
async def sync() -> None:
    """Sync MISP to Sentinel."""
    # Retrieve from MISP

    misp_connector, sentinel_connector = __init_connectors()

    existing_iocs_sentinel_external_ids, available_misp = await __get_current_state(
        misp_connector, sentinel_connector
    )

    iocs_to_create = __compute_iocs_to_create(existing_iocs_sentinel_external_ids, available_misp)

    await __push_to_sentinel(sentinel_connector, iocs_to_create)
