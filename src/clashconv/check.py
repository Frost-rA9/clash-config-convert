"""Check generated references before the kernel validates native configuration."""

import re
from collections import Counter
from typing import Any

BUILTINS = frozenset({"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"})
_RULE_SET = re.compile(r"(?:^|[(,])RULE-SET,([^,()]+)")


def check(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors = []
    warnings = []
    nodes = config.get("proxies", [])
    groups = config.get("proxy-groups", [])
    names = [entry["name"] for entry in nodes + groups]
    for name, count in Counter(names).items():
        if count > 1 or name in BUILTINS:
            errors.append(f"duplicate or reserved proxy name: {name}")
    defined = set(names) | BUILTINS
    providers = config.get("rule-providers", {})
    graph: dict[str, list[str]] = {name: [] for name in names}

    def reference(target: str, where: str, owner: str | None = None) -> None:
        if target not in defined:
            errors.append(f"{where} references missing proxy/group {target!r}")
        elif owner is not None and target in graph:
            graph[owner].append(target)

    def rule_sets(rule: str, where: str) -> None:
        for tag in _RULE_SET.findall(rule):
            if tag.strip() not in providers:
                errors.append(f"{where} references missing rule provider {tag.strip()!r}")

    for node in nodes:
        if node.get("dialer-proxy"):
            reference(node["dialer-proxy"], f"node {node['name']}", node["name"])
    for group in groups:
        if not group.get("proxies"):
            errors.append(f"group {group['name']!r} is empty")
        for member in group.get("proxies", []):
            reference(member, f"group {group['name']}", group["name"])
    for tag, provider in providers.items():
        if provider.get("proxy"):
            reference(provider["proxy"], f"rule provider {tag}")

    # A dependency can pass through both a policy group and a dialer-proxy node.
    visited = set()
    active = set()

    def visit(name: str) -> None:
        if name in active:
            errors.append(f"proxy/group dependency cycle at {name!r}")
            return
        if name in visited:
            return
        active.add(name)
        for member in graph[name]:
            visit(member)
        active.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)

    rules = config.get("rules", [])
    if not rules or not isinstance(rules[-1], str) or not rules[-1].startswith("MATCH,"):
        errors.append("The last routing rule must be MATCH")
    for i, rule in enumerate(rules):
        if not isinstance(rule, str):
            errors.append(f"rules[{i}] must be a string; merge all template slots first")
            continue
        parts = [part.strip() for part in rule.split(",")]
        while parts and parts[-1] in {"no-resolve", "src"}:
            parts.pop()
        minimum = 2 if parts and parts[0] == "MATCH" else 3
        if len(parts) < minimum or any(not part for part in parts):
            errors.append(f"rules[{i}] has an invalid rule format")
            continue
        if parts[0] == "MATCH" and i != len(rules) - 1:
            errors.append(f"rules[{i}] MATCH hides subsequent rules")
        reference(parts[-1], f"rules[{i}]")
        rule_sets(rule, f"rules[{i}]")

    dns = config.get("dns", {})
    entries = list(dns.get("fake-ip-filter", []))
    for key in ("nameserver-policy", "proxy-server-nameserver-policy"):
        entries.extend(dns.get(key, {}).keys())
    for entry in entries:
        if not isinstance(entry, str):
            continue
        if entry.startswith("rule-set:"):
            for tag in entry[len("rule-set:"):].split(","):
                if tag.strip() not in providers:
                    errors.append(f"dns references missing rule provider {tag.strip()!r}")
        else:
            rule_sets(entry, "dns")

    referenced = {member for group in groups for member in group.get("proxies", [])}
    orphaned = [node["name"] for node in nodes if node["name"] not in referenced]
    if orphaned:
        warnings.append(f"{len(orphaned)} nodes are not selected by any group")
    return errors, warnings
