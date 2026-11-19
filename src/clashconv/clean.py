"""Remove information nodes before deduplication so real nodes are retained."""

from copy import deepcopy
from dataclasses import dataclass, field

from .artifacts import NodeRules
from .models import Node
from .regions import match_chinese_name, match_flag, match_iso_code


@dataclass(slots=True)
class CleanReport:
    dropped: list[tuple[str, str]] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    distribution: dict[str, int] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)


def detect_region(name: str, rules: NodeRules) -> str | None:
    for override in rules.region_overrides:
        if override.match_name in name:
            return override.region
    matchers = {"chinese_name": match_chinese_name, "flag_emoji": match_flag, "iso_code": match_iso_code}
    for key in rules.region_keys:
        hit = matchers[key.type](name)
        if hit:
            return hit[1]
    return None


def clean(nodes: list[Node], rules: NodeRules) -> tuple[list[Node], CleanReport]:
    report = CleanReport()
    kept = []
    seen = set()
    keywords = [word.casefold() for word in rules.drop_name_keywords]
    for node in deepcopy(nodes):
        hit = next((word for word in keywords if word in node.name.casefold()), None)
        if hit is not None:
            report.dropped.append((node.name, f"name contains {hit}"))
            continue
        values = {"type": node.kind, "server": node.clash.get("server"), "port": node.clash.get("port")}
        fields = rules.drop_duplicate_by
        if fields and all(values[k] is not None for k in fields):
            key = tuple(str(values[k]) for k in fields)
            if key in seen:
                report.dropped.append((node.name, f"duplicate {'+'.join(fields)}"))
                continue
            seen.add(key)
        kept.append(node)

    # Reserve original names before adding suffixes; an existing 'node 2' must survive.
    reserved = {node.name for node in kept}
    used = set()
    for node in kept:
        original = node.name
        if original in used:
            suffix = 2
            while f"{original} {suffix}" in reserved or f"{original} {suffix}" in used:
                suffix += 1
            node.name = f"{original} {suffix}"
            report.renamed.append((original, node.name))
        used.add(node.name)
        node.region = detect_region(node.name, rules)
        if node.region is None:
            node.region = rules.fallback_region
            report.unknown.append(node.name)
        report.distribution[node.region] = report.distribution.get(node.region, 0) + 1
    return kept, report
