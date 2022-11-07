"""Config variables script."""
from os import environ

RECENT_NUM_DAYS_MISP = 5
RECENT_NUM_DAYS_SENTINEL = 10  # recommended that Sentinel range is longer than MISP

# MISP
MISP_LABEL = environ.get("ISAS_MISP_TAG_BASE")
MISP_BASE_URL = environ.get("ISAS_MISP_BASE_URL")
MISP_KEY = environ.get("ISAS_MISP_KEY")
MISP_CA_BUNDLE = environ.get("ISAS_MISP_CA_BUNDLE")
MISP_EVENT_FILTERS = {
    "timestamp": f"{RECENT_NUM_DAYS_MISP}d",
    "published": True,
    # "limit": 1,
}
MISP_TIMEOUT = 120

# AZURE
AZ_TIMEOUT = 120
AZ_TENANT_ID = environ.get("ISAS_AZ_TENANT_ID")
AZ_MISP_CLIENT_ID = environ.get("ISAS_AZ_MISP_CLIENT_ID")
AZ_MISP_CLIENT_SECRET = environ.get("ISAS_AZ_MISP_CLIENT_SECRET")

AZ_SUBSCRIPTION = environ.get("ISAS_AZ_SUBSCRIPTION")
AZ_SENTINEL_RG = environ.get("ISAS_SENTINEL_RG")
AZ_SENTINEL_WORKSPACE_NAME = environ.get("ISAS_SENTINEL_WORKSPACE_NAME")

AZ_DAYS_TO_EXPIRE = (
    int(environ.get("ISAS_DAYS_TO_EXPIRE")) if "ISAS_DAYS_TO_EXPIRE" in environ else None
)
