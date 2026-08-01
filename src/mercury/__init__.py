"""Mercury network diagnostics."""

from __future__ import annotations

__version__ = "0.1.0"
MODEL_SCHEMA_VERSION = "1.1"
SUPPORTED_MODEL_SCHEMA_VERSIONS = frozenset({"1.0", "1.1"})
DB_SCHEMA_VERSION = 2


def is_compatible_model_schema(value: object) -> bool:
    """Return whether a document uses one of Mercury's implemented schemas."""
    return type(value) is str and value in SUPPORTED_MODEL_SCHEMA_VERSIONS


__all__ = [
    "__version__",
    "MODEL_SCHEMA_VERSION",
    "SUPPORTED_MODEL_SCHEMA_VERSIONS",
    "DB_SCHEMA_VERSION",
    "is_compatible_model_schema",
]

