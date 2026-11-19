"""The base template controls where personal groups and rules are inserted."""

from .artifacts import Artifact, Profile, Slot


class MergeError(ValueError):
    pass


def merge(base: Artifact, profile: Profile | None = None) -> Artifact:
    profile = profile or Profile()
    shared_groups = {g.name for g in base.groups if not isinstance(g, Slot)} & {g.name for g in profile.groups}
    shared_providers = base.rule_providers.keys() & profile.rule_providers.keys()
    if shared_groups or shared_providers:
        raise MergeError(f"Profile names conflict with the base: {sorted(shared_groups | shared_providers)}")

    groups = []
    for item in base.groups:
        groups.extend(profile.groups if isinstance(item, Slot) else [item])
    if not any(isinstance(g, Slot) for g in base.groups):
        groups.extend(profile.groups)

    rules = []
    for item in base.rules:
        rules.extend(profile.rules if isinstance(item, Slot) else [item])
    if profile.rules and not any(isinstance(r, Slot) for r in base.rules):
        raise MergeError("The base template requires an {insert: user_rules} slot")

    # Copy after updates because model_copy does not deep-copy update values.
    return base.model_copy(update={
        "groups": groups,
        "rules": rules,
        "rule_providers": {**base.rule_providers, **profile.rule_providers},
    }).model_copy(deep=True)
