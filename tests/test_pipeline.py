from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from clashconv import load, load_artifact, load_profile, merge
from clashconv.artifacts import Artifact, GroupSpec, Profile
from clashconv.check import check
from clashconv.clean import clean
from clashconv.loader import LoadError
from clashconv.merge import MergeError
from clashconv.models import Node
from clashconv.render import RenderError, render

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "tests/fixtures/sample-clash.yaml"


def prepare(profile=True):
    base = load_artifact(ROOT / "artifacts/base.yaml")
    artifact = merge(base, load_profile(ROOT / "artifacts/services.yaml") if profile else None)
    source = load(SOURCE)
    kept, report = clean(source.nodes, artifact.nodes)
    config, warnings = render(artifact, kept, source.hosts)
    return artifact, source, kept, report, config, warnings


def test_extract_nodes_without_source_policy():
    _, source, _, _, config, _ = prepare()
    assert len(source.nodes) == 8
    assert config["mixed-port"] == 7890
    assert "SourceGroup" not in [g["name"] for g in config["proxy-groups"]]
    assert config["hosts"] == source.hosts
    assert config["proxies"][0]["server"] == "node.example.test"


def test_clean_then_render_preserves_protocol_fields():
    _, source, kept, report, config, warnings = prepare()
    assert len(kept) == 6
    assert len(report.dropped) == 2
    assert warnings == []
    assert source.nodes[1].region is None
    originals = {n.name: n for n in source.nodes}
    for node in config["proxies"]:
        original = originals[node["name"]]
        assert node == {"name": original.name, "type": original.kind, **original.clash}
    assert check(config)[0] == []


def test_deterministic_output_and_no_input_mutation():
    artifact, source, kept, _, config, _ = prepare()
    before = deepcopy(artifact)
    assert render(artifact, kept, source.hosts)[0] == config
    assert artifact == before
    assert yaml.safe_dump(config, allow_unicode=True, sort_keys=False) == yaml.safe_dump(
        render(artifact, kept, source.hosts)[0], allow_unicode=True, sort_keys=False
    )


def test_profile_groups_and_rules_at_template_slots():
    _, _, _, _, config, _ = prepare()
    names = [g["name"] for g in config["proxy-groups"]]
    assert names.index("Proxy") < names.index("YouTube") < names.index("Final")
    rules = config["rules"]
    assert rules.index("RULE-SET,private-ip,DIRECT,no-resolve") < rules.index("RULE-SET,youtube,YouTube")
    assert rules.index("RULE-SET,youtube,YouTube") < rules.index("RULE-SET,google,Google")
    assert rules.index("RULE-SET,microsoft,Microsoft") < rules.index("RULE-SET,cn,DIRECT")
    assert rules[-1] == "MATCH,Final"
    assert all(isinstance(r, str) for r in rules)


def test_group_references_stay_group_names_and_default_is_first():
    config = prepare()[4]
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["Proxy"]["proxies"] == ["Auto", "HK", "JP", "SG", "TW", "US", "other"]
    assert groups["Apple"]["proxies"][0] == "DIRECT"
    assert "default" not in groups["Apple"]
    assert "regions" not in groups["HK"]


@pytest.mark.parametrize(("selection", "expected"), [
    ({"regions": ["HK", "JP"]}, ["香港 1", "日本 1"]),
    ({"regions": ["*"], "exclude_regions": ["HK", "JP"]}, ["美国 1", "新加坡 1", "台湾 1", "other"]),
    ({"regions": ["HK", "JP"], "include": "^日本"}, ["日本 1"]),
    ({"regions": ["HK", "JP"], "exclude": "^日本"}, ["香港 1"]),
    ({"regions": ["*"], "exclude_regions": ["US"], "include": "1$", "exclude": "香港|日本|台湾"}, ["新加坡 1"]),
    ({"regions": ["HK", "JP"], "include": "^香港", "exclude": "1$"}, []),
])
def test_group_filters_select_nodes_without_filtering_group_references(selection, expected):
    _, source, kept, _, _, _ = prepare()
    artifact = Artifact(
        groups=[GroupSpec(name="Existing", groups=["DIRECT"]),
                GroupSpec(name="Selected", groups=["Existing"], **selection)],
        rules=["MATCH,Selected"],
    )
    config, warnings = render(artifact, kept, source.hosts)
    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert groups["Selected"]["proxies"] == ["Existing", *expected]
    assert warnings == []
    assert check(config)[0] == []


def test_empty_region_groups_are_removed_with_references():
    artifact, source, kept, _, _, _ = prepare()
    config, warnings = render(artifact, kept[:1], source.hosts)
    assert {g["name"] for g in config["proxy-groups"]}.isdisjoint({"JP", "SG", "TW", "US"})
    assert len(warnings) == 4
    assert check(config)[0] == []


def test_missing_and_forward_group_references_are_rejected():
    artifact, source, kept, _, _, _ = prepare()
    artifact.groups[0].groups = ["Proxy"]
    with pytest.raises(RenderError, match="declare referenced groups first"):
        render(artifact, kept, source.hosts)


def test_groups_need_members_and_default_must_exist():
    artifact, source, kept, _, _, _ = prepare()
    artifact.groups[0].regions = []
    with pytest.raises(RenderError, match="empty"):
        render(artifact, kept, source.hosts)
    artifact.groups[0].regions = ["*"]
    artifact.groups[0].default = "missing"
    with pytest.raises(RenderError, match="Default"):
        render(artifact, kept, source.hosts)


def test_same_name_rename_does_not_collide_with_existing_suffix():
    artifact = prepare(False)[0]
    nodes = [Node(name=n, kind="ss", clash={"server": f"n{i}.test", "port": 443})
             for i, n in enumerate(["香港", "香港", "香港 2"])]
    kept, report = clean(nodes, artifact.nodes)
    assert [n.name for n in kept] == ["香港", "香港 3", "香港 2"]
    assert report.renamed == [("香港", "香港 3")]


def test_different_protocols_on_same_endpoint_are_kept():
    artifact = prepare(False)[0]
    nodes = [Node(name=k, kind=k, clash={"server": "node.test", "port": 443}) for k in ["ss", "trojan"]]
    assert len(clean(nodes, artifact.nodes)[0]) == 2


@pytest.mark.parametrize("text", ["[]", "proxies: []", "proxies: [null]", "proxies: [{name: n}]", "hosts: []\nproxies: [{name: n, type: ss}]", "proxies: ["])
def test_invalid_sources_are_rejected(tmp_path, text):
    path = tmp_path / "input.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(LoadError):
        load(path)


def test_subscription_urls_are_not_fetched():
    with pytest.raises(LoadError, match="local"):
        load("https://example.invalid/subscription")


def test_profile_conflicts_and_missing_slots():
    base = load_artifact(ROOT / "artifacts/base.yaml")
    with pytest.raises(MergeError, match="HK"):
        merge(base, Profile(groups=[{"name": "HK", "regions": ["HK"]}]))
    with pytest.raises(MergeError, match="cn"):
        merge(base, Profile.model_validate({"rule-providers": {"cn": {"type": "inline", "payload": []}}}))
    with pytest.raises(MergeError, match="user_rules"):
        merge(Artifact(config={}, rules=["MATCH,DIRECT"]), Profile(rules=["DOMAIN,example.test,DIRECT"]))


@pytest.mark.parametrize("doc", [
    {"rules": [{"insert": "bad"}]},
    {"rules": [{"insert": "user_rules"}, {"insert": "user_rules"}]},
    {"groups": [{"insert": "profile_groups"}, {"insert": "profile_groups"}]},
    {"config": {"proxies": []}},
    {"groups": [{"name": "x", "include": "["}]},
    {"nodes": {"drop_duplicate_by": ["password"]}},
])
def test_invalid_templates_are_rejected(doc):
    with pytest.raises(ValidationError):
        Artifact.model_validate(doc)


def test_profile_cannot_override_template_settings_or_catch_all():
    with pytest.raises(ValidationError):
        Profile.model_validate({"config": {"mixed-port": 9999}})
    with pytest.raises(ValidationError):
        Profile(rules=["MATCH,DIRECT"])


def test_base_hosts_override_source_hosts():
    artifact, source, kept, _, _, _ = prepare()
    artifact.config["hosts"] = {"node.example.test": "192.0.2.99"}
    assert render(artifact, kept, source.hosts)[0]["hosts"]["node.example.test"] == "192.0.2.99"
    assert source.hosts["node.example.test"] == "192.0.2.11"


@pytest.mark.parametrize("change, fragment", [
    (lambda c: c["proxy-groups"][0].update(proxies=[]), "empty"),
    (lambda c: c["proxy-groups"][0]["proxies"].append("missing"), "missing"),
    (lambda c: c["proxies"][0].update(name="Proxy"), "duplicate"),
    (lambda c: c["rules"].insert(0, "DOMAIN,example.test,missing"), "missing"),
    (lambda c: c["rules"].insert(0, "RULE-SET,missing,DIRECT"), "missing"),
    (lambda c: c["rules"].insert(0, "AND,((NETWORK,TCP),(RULE-SET,missing)),DIRECT"), "missing"),
    (lambda c: c["proxies"][0].update({"dialer-proxy": "missing"}), "missing"),
    (lambda c: c["dns"]["nameserver-policy"].update({"rule-set:missing": ["223.5.5.5"]}), "missing"),
    (lambda c: c["proxy-groups"][0].update(proxies=["Proxy"]), "cycle"),
])
def test_static_checks_detect_broken_references(change, fragment):
    config = prepare()[4]
    change(config)
    assert any(fragment in error for error in check(config)[0])
