"""Resolve node membership without translating or discarding protocol options."""

import re
from copy import deepcopy
from typing import Any

from .artifacts import Artifact, Slot
from .check import BUILTINS
from .models import Node


class RenderError(ValueError):
    pass


def render(artifact: Artifact, nodes: list[Node], hosts: dict[str, Any] | None = None) -> tuple[dict[str, Any], list[str]]:
    if not nodes:
        raise RenderError("No nodes remain after cleaning")
    config = deepcopy(artifact.config)
    warnings = []
    groups = []
    skipped = set()
    declared = set(BUILTINS)
    for group in artifact.groups:
        if isinstance(group, Slot):
            raise RenderError("Merge the template before rendering")
        for name in group.groups:
            if name not in declared:
                raise RenderError(f"Group {group.name!r} references {name!r}; declare referenced groups first")
        declared.add(group.name)
        members = [name for name in group.groups if name not in skipped]
        picked = [node.name for node in nodes
                  if ("*" in group.regions or node.region in group.regions)
                  and node.region not in group.exclude_regions
                  and (not group.include or re.search(group.include, node.name))
                  and (not group.exclude or not re.search(group.exclude, node.name))]
        members = list(dict.fromkeys(members + picked))
        if not members:
            if not group.regions and not group.groups:
                raise RenderError(f"Group {group.name!r} is empty; set groups or regions")
            skipped.add(group.name)
            warnings.append(f"Omitted empty group {group.name}")
            continue
        if group.default:
            if group.default not in members:
                raise RenderError(f"Default {group.default!r} is not a member of group {group.name!r}")
            members.remove(group.default)
            members.insert(0, group.default)
        native = {"name": group.name, "type": group.type, "proxies": members, **deepcopy(group.options)}
        if group.type != "select":
            native.setdefault("url", "https://www.gstatic.com/generate_204")
            native.setdefault("interval", 300)
        groups.append(native)

    merged_hosts = {**deepcopy(hosts or {}), **config.pop("hosts", {})}
    if merged_hosts:
        config["hosts"] = merged_hosts
    config["proxies"] = [{"name": node.name, "type": node.kind, **deepcopy(node.clash)} for node in nodes]
    config["proxy-groups"] = groups
    config["rule-providers"] = deepcopy(artifact.rule_providers)
    config["rules"] = list(artifact.rules)
    return config, warnings
