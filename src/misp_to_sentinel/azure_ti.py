import logging
from datetime import datetime, timedelta, timezone

import httpx

from misp_to_sentinel import azure_api
from misp_to_sentinel.config import (
    AZ_DAYS_TO_EXPIRE,
    AZ_MISP_CLIENT_ID,
    AZ_MISP_CLIENT_SECRET,
    AZ_SENTINEL_RG,
    AZ_SENTINEL_WORKSPACE_NAME,
    AZ_SUBSCRIPTION,
    AZ_TENANT_ID,
    RECENT_NUM_DAYS_SENTINEL,
)
from misp_to_sentinel.converter import SentinelIOC

logger = logging.getLogger("misp_to_sentinel")


def __ma_url_base() -> str:
    return (
        "https://management.azure.com/"
        f"subscriptions/{AZ_SUBSCRIPTION}/"
        f"resourceGroups/{AZ_SENTINEL_RG}/"
        f"providers/Microsoft.OperationalInsights/workspaces/{AZ_SENTINEL_WORKSPACE_NAME}/"
        "providers/Microsoft.SecurityInsights/threatIntelligence/main/"
    )


def __get_misp_ids_of_recent_ioc_in_sentinel(ma_client: httpx.Client) -> list[str]:

    url = __ma_url_base() + "queryIndicators?api-version=2022-07-01-preview"

    data = {
        "pageSize": 100000,
        "minValidUntil": (
            datetime.now(timezone.utc)
            + timedelta(days=-RECENT_NUM_DAYS_SENTINEL)
            + timedelta(days=AZ_DAYS_TO_EXPIRE)
        ).isoformat(),
    }
    misp_ids_of_recent_ioc_in_sentinel = []
    response = ma_client.post(url, json=data)
    while True:
        response_json = response.json()
        misp_ids_of_recent_ioc_in_sentinel.extend(
            [ma_ioc["properties"]["externalId"] for ma_ioc in response_json["value"]]
        )
        if "nextLink" not in response_json:
            break
        raise Exception(
            "API (management.azure.com for querying TIs) seems to be broken: "
            "Can't get next page"
        )

    logger.info(
        "Retrieved %s IOCs from sentinel (last %s days)",
        len(misp_ids_of_recent_ioc_in_sentinel),
        RECENT_NUM_DAYS_SENTINEL,
    )

    return misp_ids_of_recent_ioc_in_sentinel


def __create_api_client() -> httpx.Client:
    if not (
        AZ_MISP_CLIENT_ID
        and AZ_MISP_CLIENT_SECRET
        and AZ_TENANT_ID
        and AZ_SUBSCRIPTION
        and AZ_SENTINEL_RG
    ):
        raise Exception("AZ env variables not set.")
    ma_client = azure_api.generate_httpx_client(
        AZ_MISP_CLIENT_ID,
        AZ_MISP_CLIENT_SECRET,
        AZ_TENANT_ID,
        resource="https://management.azure.com/",
    )
    return ma_client


def __create_ti_sentinel(ma_client: httpx.Client, sentinel_ioc: SentinelIOC):
    url = __ma_url_base() + "createIndicator?api-version=2022-07-01-preview"
    data = {"kind": "indicator", "properties": sentinel_ioc.as_dict()}
    response = ma_client.post(url, json=data)
    if response.status_code not in [200, 201]:
        logger.error(
            "Couldn't create IOC. status_code: %s, data sent: %s. response.content: %s",
            response.status_code,
            data,
            response.content,
        )


def sync_misp_iocs(recent_misp_iocs_as_sentinel: list[dict[str, any]]):
    """Push MISP iocs to sentinel (ignoring previously synched IOCs)"""
    ma_client = __create_api_client()
    # Get current IOCs in Sentinel
    recent_ioc_in_sentinel = __get_misp_ids_of_recent_ioc_in_sentinel(ma_client)
    # Filter out previously synced IOCs
    iocs_to_push = [
        ioc
        for ioc in recent_misp_iocs_as_sentinel
        if ioc and ioc.externalId not in recent_ioc_in_sentinel
    ]
    logger.info("New MISP IOCs to push: %s", len(iocs_to_push))
    # Sync
    for sentinel_ioc in iocs_to_push:
        __create_ti_sentinel(ma_client, sentinel_ioc)
