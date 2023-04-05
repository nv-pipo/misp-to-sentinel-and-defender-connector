#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
In-house script for pushing ICC MISP IOCs onto MS Sentinel. MS' tool is overly complex and buggy.
"""

import asyncio
import logging

from misp_to_sentinel.syncher import sync


def main():
    """Main script/function of the whole project."""
    logging.basicConfig(
        format="%(asctime)s %(levelname)-10s [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        level=logging.INFO,
    )

    logging.info("Starting")

    asyncio.run(sync())

    logging.info("Finished")


if __name__ == "__main__":
    main()
