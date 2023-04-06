import logging
from typing import Any

import httpx
from pydantic import BaseModel
from tenacity import retry
from tenacity.stop import stop_after_attempt
from tenacity.wait import wait_fixed

from misp_to_sentinel.utils.timing import timefunc_async


class SentinelIndicator(BaseModel):
    source: str
    externalId: str
    displayName: str
    description: str
    threatIntelligenceTags: list[str]
    validFrom: str
    validUntil: str
    pattern: str
    patternType: str
    threatTypes: list[str]

    def __init__(self, **data):
        data["validFrom"] = data["validFrom"].strftime("%Y-%m-%dT%H:%M:%SZ")
        data["validUntil"] = data["validUntil"].strftime("%Y-%m-%dT%H:%M:%SZ")
        super().__init__(**data)


class SentinelConnectorRetrieveException(Exception):
    pass


class SentinelConnector:
    def __init__(
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
        with httpx.Client() as client:
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
        logging.info("Requesting %s %s", method, url)
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
            raise SentinelConnectorRetrieveException()

        return response

    async def __retrieve_all_pages(self, method: str, url: str, **kwargs) -> list[Any]:
        """Retrieve all pages of a request."""
        response = await self.__request_async(method=method, url=url, **kwargs)
        data = response.json()
        if "nextLink" in data:
            next_link = data["nextLink"]
            data["value"] += await self.__retrieve_all_pages(
                method=method, url=next_link, **kwargs
            )
        return data["value"]

    @timefunc_async
    async def get_indicators(self, min_valid_until: str) -> list[str]:

        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group_name}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
            "/threatIntelligence/main/queryIndicators?api-version=2023-02-01"
        )
        # Retrieve attributes from MISP as JSON and STIX2 to return all required data
        response = await self.__request_async(
            method="POST",
            url=url,
            json={
                "pageSize": 1000000,
                "sources": ["MISP_ICC"],
                "minValidUntil": min_valid_until,
            },
            timeout=40,
        )
        return response.json()["value"]

    async def create_indicator(self, indicator: SentinelIndicator) -> None:

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
                "properties": indicator.dict() | {"createdByRef": "MISP_CONNECTOR"},
            },
            timeout=10,
        )
        logging.info("Created IOC %s in Sentinel", repr(indicator))
        return response.json()
