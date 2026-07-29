"""Mercury network diagnostics."""

from __future__ import annotations

__version__ = "0.1.0"
MODEL_SCHEMA_VERSION = "1.0"
DB_SCHEMA_VERSION = 1


def is_compatible_model_schema(value: object) -> bool:
    """Return whether a document uses Mercury's supported schema major."""
    if type(value) is not str or len(value) > 32:
        return False
    major, separator, minor = value.partition(".")
    if separator != "." or not major.isdecimal() or not minor.isdecimal():
        return False
    supported_major = MODEL_SCHEMA_VERSION.partition(".")[0]
    return major == supported_major


__all__ = [
    "__version__",
    "MODEL_SCHEMA_VERSION",
    "DB_SCHEMA_VERSION",
    "is_compatible_model_schema",
]

