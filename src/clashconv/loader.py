"""Read nodes and hosts from one local YAML file without fetching providers."""

from copy import deepcopy
from pathlib import Path

import yaml

from .models import LoadResult, Node


class LoadError(ValueError):
    pass


def load(source: str | Path) -> LoadResult:
    if str(source).startswith(("http://", "https://")):
        raise LoadError("Expected a local Clash YAML file, not a subscription URL")
    try:
        doc = yaml.safe_load(Path(source).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        # YAML exceptions can contain a source line with a credential.
        raise LoadError(f"Cannot read Clash YAML: {source} ({type(exc).__name__})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list) or not doc["proxies"]:
        raise LoadError("Expected a non-empty proxies list; remote proxy-providers are not fetched")
    nodes = []
    for i, item in enumerate(doc["proxies"]):
        if not isinstance(item, dict):
            raise LoadError(f"proxies[{i}] must be a mapping")
        if not all(isinstance(item.get(k), str) and item[k].strip() for k in ("name", "type")):
            raise LoadError(f"proxies[{i}] requires name and type")
        nodes.append(Node(name=item["name"].strip(), kind=item["type"].strip().lower(),
                          clash=deepcopy({k: v for k, v in item.items() if k not in ("name", "type")})))
    hosts = doc.get("hosts", {})
    if not isinstance(hosts, dict) or not all(isinstance(k, str) for k in hosts):
        raise LoadError("hosts must be a mapping with string keys")
    return LoadResult(nodes=nodes, hosts=deepcopy(hosts))
