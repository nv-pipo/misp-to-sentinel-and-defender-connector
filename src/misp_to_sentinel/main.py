#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
In-house script for pushing ICC MISP IOCs onto Sentinel and Defender. MS' tool is overly complex
and buggy.
"""

import logging

from misp_to_sentinel import azure_ti, converter, misp
from misp_to_sentinel.config import AZ_DAYS_TO_EXPIRE, MISP_LABEL


def __setup_logging():
    logger = logging.getLogger("misp_to_sentinel")
    logger.setLevel(logging.INFO)

    # Create handler
    c_handler = logging.StreamHandler()

    # Create formatter and add it to handler
    c_format = logging.Formatter(
        fmt="%(asctime)s %(name)s (%(levelname)s) %(filename)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    c_handler.setFormatter(c_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)

    logger.propagate = False


def main():
    """Main script/function of the whole project."""
    __setup_logging()
    logger = logging.getLogger("misp_to_sentinel")
    logger.info("Starting")

    # Retrieve from MISP
    misp_iocs = misp.get_iocs(converter.SUPPORTED_TYPES)

    # Convert
    recent_misp_iocs_as_sentinel = converter.transform_iocs_misp_to_sentinel(
        misp_iocs, AZ_DAYS_TO_EXPIRE, MISP_LABEL
    )

    # Push to Sentinel
    azure_ti.sync_misp_iocs(recent_misp_iocs_as_sentinel)

    logger.info("Finished")


if __name__ == "__main__":
    main()
