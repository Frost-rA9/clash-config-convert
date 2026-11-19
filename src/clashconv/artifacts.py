"""Validate template directives separately from native Mihomo configuration."""

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RegionKey(StrictModel):
    type: Literal["chinese_name", "flag_emoji", "iso_code"]


class RegionOverride(StrictModel):
    match_name: str = Field(min_length=1)
    region: str = Field(min_length=1)


class NodeRules(StrictModel):
    drop_name_keywords: list[str] = Field(default_factory=list)
    drop_duplicate_by: list[Literal["type", "server", "port"]] = Field(default_factory=lambda: ["type", "server", "port"])
    region_keys: list[RegionKey] = Field(default_factory=list)
    region_overrides: list[RegionOverride] = Field(default_factory=list)
    fallback_region: str = "XX"


class GroupSpec(StrictModel):
    name: str = Field(min_length=1)
    type: Literal["select", "url-test", "fallback", "load-balance"] = "select"
    groups: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    exclude_regions: list[str] = Field(default_factory=list)
    include: str | None = None
    exclude: str | None = None
    default: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("include", "exclude")
    @classmethod
    def valid_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"Invalid group regex: {exc}") from None
        return value

    @field_validator("options")
    @classmethod
    def native_options_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        reserved = {"name", "type", "proxies", "use", "include-all", "include-all-proxies", "include-all-providers", "default-selected"}
        if reserved & value.keys():
            raise ValueError(f"Group membership is generated; reserved options: {sorted(reserved & value.keys())}")
        return value


class Slot(StrictModel):
    insert: Literal["profile_groups", "user_rules"]


def validate_groups(groups: list[GroupSpec | Slot]) -> None:
    names = [g.name for g in groups if isinstance(g, GroupSpec)]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate group names")


class Artifact(StrictModel):
    config: dict[str, Any] = Field(default_factory=dict)
    nodes: NodeRules = Field(default_factory=NodeRules)
    groups: list[GroupSpec | Slot] = Field(default_factory=list)
    rule_providers: dict[str, dict[str, Any]] = Field(default_factory=dict, alias="rule-providers")
    rules: list[str | Slot] = Field(default_factory=list)

    @field_validator("config")
    @classmethod
    def no_generated_sections(cls, value: dict[str, Any]) -> dict[str, Any]:
        reserved = {"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules", "sub-rules"}
        if reserved & value.keys():
            raise ValueError(f"Generated sections cannot appear in config: {sorted(reserved & value.keys())}")
        for key in ("dns", "hosts"):
            if key in value and not isinstance(value[key], dict):
                raise ValueError(f"config.{key} must be a mapping")
        dns = value.get("dns", {})
        for key in ("nameserver-policy", "proxy-server-nameserver-policy"):
            if key in dns and not isinstance(dns[key], dict):
                raise ValueError(f"config.dns.{key} must be a mapping")
        if "fake-ip-filter" in dns and not isinstance(dns["fake-ip-filter"], list):
            raise ValueError("config.dns.fake-ip-filter must be a list")
        return value

    @model_validator(mode="after")
    def valid_slots(self):
        validate_groups(self.groups)
        for items, expected in ((self.groups, "profile_groups"), (self.rules, "user_rules")):
            slots = [item for item in items if isinstance(item, Slot)]
            if len(slots) > 1 or any(s.insert != expected for s in slots):
                raise ValueError(f"Only one {{insert: {expected}}} slot is allowed here")
        return self


class Profile(StrictModel):
    groups: list[GroupSpec] = Field(default_factory=list)
    rule_providers: dict[str, dict[str, Any]] = Field(default_factory=dict, alias="rule-providers")
    rules: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def additions_only(self):
        validate_groups(self.groups)
        if any(rule.split(",", 1)[0].strip().upper() == "MATCH" for rule in self.rules):
            raise ValueError("A profile cannot add MATCH; the base template owns the catch-all rule")
        return self


def _load_yaml(path: str | Path) -> Any:
    try:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read template YAML: {path} ({type(exc).__name__})") from None


def load_artifact(path: str | Path) -> Artifact:
    return Artifact.model_validate(_load_yaml(path))


def load_profile(path: str | Path) -> Profile:
    return Profile.model_validate(_load_yaml(path))
