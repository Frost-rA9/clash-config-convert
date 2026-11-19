"""Node data is kept in Clash form so protocol fields survive rendering."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Node:
    name: str
    kind: str
    clash: dict[str, Any]
    region: str | None = None


@dataclass(slots=True)
class LoadResult:
    nodes: list[Node]
    hosts: dict[str, Any] = field(default_factory=dict)
