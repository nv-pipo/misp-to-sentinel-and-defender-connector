"""Sync MISP to Sentinel."""
import logging

from misp_to_sentinel.misp import MISPConnector
from misp_to_sentinel.utils.environ_utils import load_env_variable


async def sync():
    """Sync MISP to Sentinel."""
    # Retrieve from MISP
    misp = MISPConnector(
        misp_base_url=load_env_variable("MISP_BASE_URL"),
        misp_ca_bundle_path=load_env_variable("MISP_CA_BUNDLE_PATH"),
        misp_key=load_env_variable("MISP_KEY"),
        misp_label=load_env_variable("MISP_LABEL"),
    )
    misp_attributes = await misp.get_attributes_with_stix2_patterns(
        look_back_days=load_env_variable("MISP_LOOK_BACK_DAYS"),
    )

    # Compare with existing

    # Push to Sentinel

    logging.info(misp_attributes)
