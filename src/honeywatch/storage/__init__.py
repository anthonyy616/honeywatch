"""SQLite and JSONL storage for HoneyWatch."""

from __future__ import annotations

from .jsonl import JsonlArchive, read_jsonl
from .queries import ReadStore
from .sqlite import SCHEMA_VERSION, Storage, StorageError

__all__ = [
    "SCHEMA_VERSION",
    "JsonlArchive",
    "ReadStore",
    "Storage",
    "StorageError",
    "read_jsonl",
]