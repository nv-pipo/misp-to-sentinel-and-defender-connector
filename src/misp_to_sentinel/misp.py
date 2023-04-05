"""MISP connector."""
import asyncio
import logging
import re
from typing import Optional

import httpx
from pydantic.dataclasses import dataclass
from tenacity import retry
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed

from misp_to_sentinel.utils.timing import timefunc_async

RE_EXTRACT_ID = re.compile(r"indicator--(?P<id>.*)$")


@dataclass
class MISPAttribute:
    """MISP attribute."""

    attribute_id: str
    pattern: str
    category: str
    event_id: str
    event_info: str


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
        self.client_sync = httpx.Client(verify=ssl_verify, headers=headers)
        self.client_async = httpx.AsyncClient(verify=ssl_verify, headers=headers)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def __request_async(self, method: str, path: str, **kwargs) -> httpx.Response:
        logging.info("Requesting %s %s", method, path)
        response = await self.client_async.request(
            method=method,
            url=f"{self.misp_base_url}/{path}",
            **kwargs,
        )

        if response.status_code != 200:
            logging.error(
                "Error while requesting %s %s: %s",
                method,
                path,
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
                json=data,
                timeout=40,
            ),
            self.__request_async(
                method="POST",
                path="/attributes/restSearch",
                json=data | {"returnFormat": "stix2"},
                timeout=40,
            ),
        ]

        response_details, response_stix = await asyncio.gather(*tasks)

        stix_partterns_per_id = {
            match.group("id"): o["pattern"]
            for o in response_stix.json()["objects"]
            if (match := RE_EXTRACT_ID.match(o["id"]))
        }

        misp_attributes = [
            MISPAttribute(
                attribute_id=attribute["id"],
                pattern=stix_partterns_per_id[attribute["uuid"]],
                category=attribute["category"],
                event_id=attribute["Event"]["id"],
                event_info=attribute["Event"]["info"],
            )
            for attribute in response_details.json()["response"]["Attribute"]
            if attribute["uuid"] in stix_partterns_per_id
        ]
        logging.info(
            "Retrieved %s IOCs from %s (for the last %s days)",
            len(misp_attributes),
            self.misp_base_url,
            look_back_days,
        )

        return misp_attributes
