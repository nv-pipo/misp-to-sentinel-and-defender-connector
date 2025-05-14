"""Utility functions for working with environment variables."""

from os import environ


class MissingEnvVariableError(Exception):
    """Exception raised when an environment variable is missing."""


def load_env_variable(key: str) -> str:
    """Load an environment variable, or raise an exception if it does not exist."""
    if key not in environ:
        msg = f"Environment variable {key} does not exist"
        raise MissingEnvVariableError(msg)
    return environ[key]
