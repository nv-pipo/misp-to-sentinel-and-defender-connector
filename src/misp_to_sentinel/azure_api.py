#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Push to MS graph, sentinel or defender."""


import logging

import httpx

logger = logging.getLogger("misp_to_sentinel")


def generate_httpx_client(
    client_id: str, client_secret: str, tenant_id: str, resource: str
) -> httpx.Client:
    """Return a httpx.Client with bearer token for later requests"""
    logger.info("Generating auth token for %s for resource %s", client_id, resource)
    # Get bearer token
    data = {
        "resource": resource,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    auth_request = httpx.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
        data=data,
    )
    access_token = auth_request.json()["access_token"]

    # Create client
    headers = {"Authorization": f"Bearer {access_token}", "user-agent": "ILO_MISP/2.0"}
    client = httpx.Client(headers=headers)
    return client
