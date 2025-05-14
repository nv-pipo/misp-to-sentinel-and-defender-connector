import asyncio
import logging
from datetime import date

from dotenv import load_dotenv
from filelock import FileLock, Timeout

from misp_to_sentinel.syncher import sync

logger = logging.getLogger(__name__)


def main() -> None:
    """Main script/function of the whole project."""
    load_dotenv()
    logging.basicConfig(
        filename=f"logs/sync_ms_announcements_{date.today()}.log",  # noqa: DTZ011
        format="%(asctime)s %(levelname)-10s [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        level=logging.INFO,
    )

    try:
        logger.info("Acquiring lock")
        with FileLock("sync_ms_announcements.lock", timeout=1):
            logger.info("Lock acquired")
            logger.info("Starting")
            asyncio.run(sync())
            logger.info("Finished")
    except Timeout:
        logger.warning("Couldn't acquire lock, another instance is running. Exiting.")


if __name__ == "__main__":
    main()
