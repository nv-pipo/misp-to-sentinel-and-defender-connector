"""Config variables script."""
from os import environ

RECENT_NUM_DAYS_MISP = 5
RECENT_NUM_DAYS_SENTINEL = 10  # recommended that Sentinel range is longer than MISP

# MISP
MISP_LABEL = environ.get("MISP_TAG_BASE")
MISP_BASE_URL = environ.get("MISP_BASE_URL")
MISP_KEY = environ.get("MISP_KEY")
MISP_CA_BUNDLE = environ.get("MISP_CA_BUNDLE")
MISP_EVENT_FILTERS = {
    "timestamp": f"{RECENT_NUM_DAYS_MISP}d",
    "published": True,
    # "limit": 1,
}
MISP_TIMEOUT = 120

# AZURE
AZ_TIMEOUT = 120
AZ_TENANT_ID = environ.get("AZ_TENANT_ID")
AZ_MISP_CLIENT_ID = environ.get("AZ_MISP_CLIENT_ID")
AZ_MISP_CLIENT_SECRET = environ.get("AZ_MISP_CLIENT_SECRET")

AZ_SUBSCRIPTION = environ.get("AZ_SUBSCRIPTION")
AZ_SENTINEL_RG = environ.get("SENTINEL_RG")
AZ_SENTINEL_WORKSPACE_NAME = environ.get("SENTINEL_WORKSPACE_NAME")

AZ_DAYS_TO_EXPIRE = int(environ.get("DAYS_TO_EXPIRE")) if "DAYS_TO_EXPIRE" in environ else None
