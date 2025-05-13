"""MISP connector."""
import asyncio
import logging
from typing import Optional

import httpx
from pydantic.dataclasses import dataclass
from tenacity import retry
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed

from misp_to_sentinel.utils.environ_utils import load_env_variable
from misp_to_sentinel.utils.timing import timefunc_async

logger = logging.getLogger(__name__)


@dataclass
class MISPAttribute:
    """MISP attribute."""

    stix_id: str
    attribute_id: str
    timestamp: int
    pattern: str
    category: str
    event_id: str
    event_info: str
    tags: list[str]


class MISPConnectorRetrieveException(Exception):
    """Exception raised when MISP connector fails to retrieve data."""


class MISPConnector:
    """MISP connector."""

    def __init__(
        self,
        misp_base_url: str,
        misp_ca_bundle_path: str,
        misp_key: str,
        misp_label: str,
    ) -> None:
        headers = {
            "Authorization": misp_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        ssl_verify = True
        if misp_ca_bundle_path:
            ssl_verify = httpx.create_ssl_context()
            ssl_verify.load_verify_locations(misp_ca_bundle_path)

        self.misp_base_url = misp_base_url
        self.misp_label = misp_label
        self.client_async = httpx.AsyncClient(verify=ssl_verify, headers=headers)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def __request_async(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.misp_base_url}/{path}"
        logging.debug("Requesting %s %s", method, url)
        response = await self.client_async.request(
            method=method,
            url=url,
            **kwargs,
        )

        if response.status_code != 200:
            logging.error(
                "Error while requesting %s %s: %s",
                method,
                url,
                response.content,
            )
            raise MISPConnectorRetrieveException()

        return response

    @timefunc_async
    async def get_attributes_with_stix2_patterns(
        self, look_back_days: int, ioc_types: Optional[list[str]] = None
    ) -> list[MISPAttribute]:
        """Search for attributes (IOCs) in MISP."""
        data = {
            "timestamp": f"{look_back_days}d",
            "published": True,
            # "limit": 5,
        }
        if ioc_types:
            data["type"] = ioc_types

        # Retrieve attributes from MISP as JSON and STIX2 to return all required data
        tasks = [
            self.__request_async(
                method="POST",
                path="/attributes/restSearch",
                json=data | {"includeEventTags": True},
                timeout=120,
            ),
            self.__request_async(
                method="POST",
                path="/attributes/restSearch",
                json=data | {"returnFormat": "stix2"},
                timeout=120,
            ),
        ]

        response_details, response_stix = await asyncio.gather(*tasks)

        stix_partterns_per_id = {
            o["id"]: o["pattern"]
            for o in response_stix.json()["objects"]
            if o["id"].startswith("indicator--")
        }

        misp_label = load_env_variable("MISP_LABEL")

        misp_attributes = [
            MISPAttribute(
                stix_id=stix_id,
                attribute_id=attribute["id"],
                timestamp=attribute["timestamp"],
                pattern=stix_partterns_per_id[stix_id],
                category=attribute["category"],
                event_id=attribute["Event"]["id"],
                event_info=attribute["Event"]["info"],
                tags=[
                    f"{misp_label}_{tag['name']}"
                    for tag in attribute.get("Tag", [])
                    if not tag.get("name", "").startswith("tlp:")
                ]
                + [
                    f"{misp_label}_event_id_{attribute['Event']['id']}",
                    f"{misp_label}_attribute_id_{attribute['id']}",
                ],
            )
            for attribute in response_details.json()["response"]["Attribute"]
            if (stix_id := f'indicator--{attribute["uuid"]}') in stix_partterns_per_id
        ]
        logger.info(
            "Retrieved %s IOCs from %s (for the last %s days)",
            len(misp_attributes),
            self.misp_base_url,
            look_back_days,
        )

        return misp_attributes
