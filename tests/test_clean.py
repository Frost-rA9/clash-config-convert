import pytest

from clashconv.artifacts import NodeRules
from clashconv.clean import clean
from clashconv.models import Node


def test_information_nodes_are_filtered_before_endpoint_deduplication():
    endpoint = {"server": "192.0.2.1", "port": 443}
    nodes = [Node("Traffic remaining", "ss", dict(endpoint)), Node("HK 1", "ss", dict(endpoint))]
    kept, report = clean(nodes, NodeRules(drop_name_keywords=["traffic"]))
    assert [node.name for node in kept] == ["HK 1"]
    assert report.dropped == [("Traffic remaining", "name contains traffic")]


@pytest.mark.parametrize(("fields", "accounts"), [
    (["type", "server", "port"], ["account-a"]),
    ([], ["account-a", "account-b"]),
])
def test_deduplication_can_be_disabled_for_multiple_accounts(fields, accounts):
    nodes = [Node(account, "ss", {"server": "192.0.2.1", "port": 443, "password": account})
             for account in ["account-a", "account-b"]]
    kept, report = clean(nodes, NodeRules(drop_duplicate_by=fields))
    assert [node.clash["password"] for node in kept] == accounts
    assert len(report.dropped) == len(nodes) - len(accounts)
    assert [node.name for node in nodes] == ["account-a", "account-b"]


@pytest.mark.parametrize(("overrides", "keys", "expected"), [
    ([{"match_name": "Special", "region": "SG"}, {"match_name": "日本", "region": "TW"}],
     ["chinese_name", "flag_emoji", "iso_code"], "SG"),
    ([], ["chinese_name", "flag_emoji", "iso_code"], "JP"),
    ([], ["flag_emoji", "chinese_name", "iso_code"], "HK"),
    ([], ["iso_code", "flag_emoji", "chinese_name"], "US"),
])
def test_region_overrides_and_detection_order(overrides, keys, expected):
    nodes = [Node("🇭🇰 日本 US Special", "ss", {"server": "192.0.2.1", "port": 443})]
    rules = NodeRules(region_overrides=overrides, region_keys=[{"type": key} for key in keys])
    kept, report = clean(nodes, rules)
    assert kept[0].region == expected
    assert report.distribution == {expected: 1}
    assert report.unknown == []
    assert nodes[0].region is None


@pytest.mark.parametrize("fallback", ["XX", "CUSTOM"])
def test_unknown_region_uses_configured_fallback(fallback):
    nodes = [Node("Relay 01", "ss", {"server": "192.0.2.1", "port": 443})]
    rules = NodeRules(region_keys=[{"type": "chinese_name"}, {"type": "flag_emoji"}, {"type": "iso_code"}],
                      fallback_region=fallback)
    kept, report = clean(nodes, rules)
    assert kept[0].region == fallback
    assert report.unknown == ["Relay 01"]
    assert report.distribution == {fallback: 1}
