import asyncio
import logging
from datetime import date

from dotenv import load_dotenv
from filelock import FileLock, Timeout

from misp_to_sentinel.syncher import sync

logger = logging.getLogger(__name__)

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "%(asctime)s %(levelname)-10s [%(name)s:%(filename)s] %(message)s"},
    },
    "handlers": {
        "file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "when": "midnight",
            "formatter": "simple",
            "filename": "logs/misp_to_sentinel.log",
            "backupCount": 90,
        },
    },
    "loggers": {
        "root": {
            "level": "INFO",
            "handlers": ["file"],
        },
    },
}


def main() -> None:
    """Main script/function of the whole project."""
    load_dotenv()
    logging.config.dictConfig(logging_config)

    try:
        logger.info("Acquiring lock")
        with FileLock("misp_to_sentinel.lock", timeout=1):
            logger.info("Lock acquired")
            logger.info("Starting")
            asyncio.run(sync())
            logger.info("Finished")
    except Timeout:
        logger.warning("Couldn't acquire lock, another instance is running. Exiting.")


if __name__ == "__main__":
    main()
