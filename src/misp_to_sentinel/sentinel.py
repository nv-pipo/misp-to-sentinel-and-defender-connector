# ruff: noqa: ANN003

import logging
import re
from typing import Any

import httpx
from pydantic import BaseModel, Field
from result import Err, Ok, Result
from tenacity import retry
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed

from misp_to_sentinel.utils.timing import timefunc_async

logger = logging.getLogger(__name__)


class SentinelSyncError(Exception):
    pass


class SentinelIndicator(BaseModel):
    """Sentinel indicator"""

    source: str
    external_id: str = Field(alias="externalId")
    display_name: str = Field(alias="displayName")
    description: str
    threat_intelligence_tags: list[str] = Field(alias="threatIntelligenceTags")
    valid_from: str = Field(alias="validFrom")
    valid_until: str = Field(alias="validUntil")
    pattern: str
    pattern_type: str = Field(alias="patternType")
    threat_types: list[str] = Field(alias="threatTypes")

    def __init__(self, **data) -> None:
        data["validFrom"] = data["validFrom"].strftime("%Y-%m-%dT%H:%M:%SZ")
        data["validUntil"] = data["validUntil"].strftime("%Y-%m-%dT%H:%M:%SZ")
        super().__init__(**data)


class SentinelConnectorRetrieveError(Exception):
    """Exception raised when Sentinel connector fails to retrieve data."""


class SentinelConnector:
    """Sentinel connector"""

    def __init__(  # noqa: PLR0913
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> None:
        # Get bearer token
        resource = "https://management.azure.com/"
        transport = httpx.HTTPTransport(retries=3)
        with httpx.Client(timeout=5, transport=transport) as client:
            auth_request = client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
                data={
                    "resource": resource,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                },
            )
        access_token = auth_request.json()["access_token"]

        headers = {"Authorization": f"Bearer {access_token}", "user-agent": "ILO_MISP/2.0"}

        self.client_async = httpx.AsyncClient(headers=headers)
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.workspace_name = workspace_name

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    async def __request_async(self, method: str, url: str, **kwargs) -> httpx.Response:
        return await self.__request_async_no_retries(method, url, **kwargs)

    async def __request_async_no_retries(self, method: str, url: str, **kwargs) -> httpx.Response:
        response = await self.client_async.request(
            method=method,
            url=url,
            **kwargs,
        )

        if response.status_code != httpx.codes.OK:
            logger.error(
                "Error while requesting (%s) %s %s: %s",
                response.status_code,
                method,
                url,
                response.content,
            )
            raise SentinelConnectorRetrieveError

        return response

    async def __retrieve_all_pages(self, method: str, url: str, **kwargs) -> list[Any]:
        """Retrieve all pages of a request."""
        data = []
        while True:
            response = await self.__request_async(method=method, url=url, **kwargs)
            data.extend(response.json()["value"])
            if not (next_link := response.json().get("nextLink")):
                break
            if method == "POST":
                params = re.findall("[&](.*)", next_link)
                split_params = {
                    match["key"]: match["value"]
                    for param in params
                    if (match := re.match(r"(?P<key>.*?)=(?P<value>.*)", param))
                }
                skip_token = split_params["$skipToken"]
                kwargs["json"] = {"skipToken": skip_token}
            else:
                url = next_link

        return data

    @timefunc_async
    async def get_indicators(self, min_valid_until: str, sources: list[str]) -> list[str]:
        url = (
            f"https://management.azure.com"
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
            "/threatIntelligence/main/queryIndicators?api-version=2023-02-01"
        )
        # Retrieve attributes from MISP as JSON and STIX2 to return all required data
        data = await self.__retrieve_all_pages(
            method="POST",
            url=url,
            json={
                "sources": sources,
                "minValidUntil": min_valid_until,
            },
            timeout=40,
        )
        logger.info("Retrieved %s indicators from Sentinel", len(data))
        return data

    async def create_indicator(self, indicator: SentinelIndicator) -> Result[dict, str]:
        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
            "/threatIntelligence/main/createIndicator?api-version=2023-02-01"
        )

        response = await self.__request_async_no_retries(
            method="POST",
            url=url,
            json={
                "kind": "indicator",
                "properties": indicator.model_dump(by_alias=True)
                | {"createdByRef": "MISP_CONNECTOR"},
            },
            timeout=60,
        )
        if response.status_code != httpx.codes.OK:
            logger.error(
                "Error while creating indicator (%s): %s",
                response.status_code,
                response.content,
            )
            return Err(response.content.decode())
        return Ok(response.json())
