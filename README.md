# clash-config-convert

Convert a Clash configuration into a custom configuration that Mihomo loads.

## How it works

One local Clash YAML file supplies the nodes and `hosts`. The tool reads the
file and fetches no subscription or proxy provider. It preserves each node's
protocol fields. Identify the source file as `local/<name>.yaml`. Two YAML files
supply the rest.

| File | Holds |
|---|---|
| `artifacts/base.yaml` | The base template: DNS, ports, TUN, node cleaning, rule order, and fixed groups |
| `artifacts/services.yaml` | The template profile: service groups, rule providers, and rules |
| `local/services.yaml` | Your profile: the template profile plus your own rules. Git ignores this directory. |

The tool merges the base template and the profile, then renders the configuration.
The same source file, base template, and profile always produce the same YAML.

A profile holds additions only, so a base template update does not force a profile
update. Personal rules stay in `local/services.yaml`, so the template stays generic.

## Requirements

- Python 3.14 or later, managed by `uv`
- Mihomo. Local checks used v1.19.34.

## For an agent

Run these commands from the project root. Replace `<name>` and `<Mihomo path>` with the actual file names and paths.

```bash
uv sync                                                                                     # install
cp artifacts/services.yaml local/services.yaml                                               # once: your profile
uv run python -m clashconv report local/<name>.yaml -p local/services.yaml                    # cleaning report
uv run python -m clashconv render local/<name>.yaml -o local/config.yaml -p local/services.yaml --mihomo "<Mihomo path>"
uv run pytest
```

Skip the copy command if `local/services.yaml` already exists.

The base template listens on `127.0.0.1:7890` and disables TUN by default.
Set `config.tun.enable` to `true` in `artifacts/base.yaml` to enable TUN.

Work steps:

1. Read the request, `artifacts/base.yaml`, and `local/services.yaml`.
2. Add groups, rule providers, and rules to `local/services.yaml`.
3. Render the configuration.
4. Read the exit code, warnings, and check output. Change the profile until all checks pass.
5. Test how each new rule routes traffic. The checks cannot detect overlaps between rule providers.

| Exit code | Meaning |
|---|---|
| 0 | The static check passed. If the tool found a kernel, the kernel check also passed. |
| 2 | An input, base template, profile, or output path is invalid. |
| 3 | The static check failed. |
| 4 | The Mihomo kernel check failed. |

## Conventions

- The first matching rule wins. Write specific rules before broad rules.
- To split a rule provider, place a `DOMAIN-SUFFIX` rule before its `RULE-SET` rule. See `artifacts/example.yaml`.
- Declare referenced groups first. A group without `default` takes its first member.
- The base template places profile groups with `{insert: profile_groups}` and profile rules with `{insert: user_rules}`.
- `DIRECT` is the built-in direct policy, in uppercase.
- Source files and products contain node credentials. Store them in `local/`, which `.gitignore` excludes.

## Checks

Every render runs a static check. When Mihomo is available, it also runs a kernel check:

- The static check detects name conflicts, empty groups, missing references, and dependency cycles.
- `mihomo -t` checks the native configuration. Use `--mihomo` to specify the executable, or make `mihomo` available on PATH.

To test a new rule, inspect its matched rule and selected group in the client.
Configuration checks do not test node connectivity.

## License

GPL-3.0-or-later. See `LICENSE`.
