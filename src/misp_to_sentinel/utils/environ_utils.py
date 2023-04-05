"""Utility functions for working with environment variables."""
from os import environ
from typing import Any


class MissingEnvironmentVariable(Exception):
    """Exception raised when an environment variable is missing."""


def load_env_variable(key: str) -> Any:
    """Load an environment variable, or raise an exception if it does not exist."""
    if key not in environ:
        raise MissingEnvironmentVariable(f"Environment variable {key} does not exist")
    return environ[key]
