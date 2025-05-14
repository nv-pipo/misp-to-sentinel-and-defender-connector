# ruff: noqa: ANN002, ANN003

import asyncio
import logging
import time
from functools import wraps

logger = logging.getLogger(__name__)


def timefunc_async(func: callable) -> callable:
    """Wrapper to time time spent on ASYNC function"""

    async def process(func: callable, *args, **params) -> callable:
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **params)
        logger.error("this is not a coroutine")
        return func(*args, **params)

    async def helper(*args, **params) -> callable:
        logger.info("Starting function %s.", func.__name__)
        start = time.time()
        result = await process(func, *args, **params)
        logger.info("Function %s took %ss", func.__name__, (time.time() - start))
        return result

    return helper


def timefunc(func: callable) -> callable:
    """Wrapper to time time spent on SYNC function"""

    @wraps(func)
    def wrapper(*func_args, **func_kwargs) -> callable:
        logger.info("Starting function %s.", func.__name__)
        start = time.time()
        result = func(*func_args, **func_kwargs)
        end = time.time()
        logger.info("Function %s took %ss", func.__name__, (end - start))
        return result

    return wrapper
