from copy import deepcopy

import pytest

from clashconv.artifacts import Artifact, Profile
from clashconv.merge import merge


@pytest.mark.parametrize(("owner", "with_profile"), [("base", True), ("profile", True), ("base", False)])
def test_merge_keeps_mutable_values_independent(owner, with_profile):
    base = Artifact(
        groups=[{"name": "Base", "regions": ["*"], "options": {"icon": "base.png"}},
                {"insert": "profile_groups"}],
        rule_providers={"base": {"type": "inline", "behavior": "domain", "payload": ["+.base.test"]}},
        rules=[{"insert": "user_rules"}, "MATCH,DIRECT"],
    )
    profile = Profile(
        groups=[{"name": "Custom", "groups": ["Base"], "options": {"icon": "custom.png"}}],
        rule_providers={"profile": {"type": "inline", "behavior": "domain", "payload": ["+.custom.test"]}},
        rules=["RULE-SET,profile,Custom"],
    )
    original = base if owner == "base" else profile
    before = deepcopy(original)
    merged = merge(base, profile if with_profile else None)

    group = merged.groups[0 if owner == "base" else 1]
    group.name = "Changed"
    group.groups.append("DIRECT")
    group.options["icon"] = "changed.png"
    merged.rule_providers[owner]["payload"].append("+.changed.test")
    assert original == before

    before = deepcopy(merged)
    original.groups[0].groups.append("REJECT")
    original.groups[0].options["icon"] = "input.png"
    original.rule_providers[owner]["payload"].append("+.input.test")
    assert merged == before
