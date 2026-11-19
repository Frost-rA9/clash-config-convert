"""Report cleaning decisions or render and validate a Mihomo configuration."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from .artifacts import load_artifact, load_profile
from .check import check
from .clean import clean
from .loader import load
from .merge import merge
from .regions import REGION_NAMES
from .render import render


def prepare(args: argparse.Namespace):
    artifact = merge(load_artifact(args.artifact), load_profile(args.profile) if args.profile else None)
    source = load(args.source)
    kept, report = clean(source.nodes, artifact.nodes)
    return artifact, source, kept, report


def report_command(args: argparse.Namespace) -> int:
    artifact, source, kept, report = prepare(args)
    print(f"Loaded nodes: {len(source.nodes)}")
    print(f"Kept nodes: {len(kept)}")
    print(f"Dropped nodes: {len(report.dropped)}")
    for name, reason in report.dropped:
        print(f"  {name}: {reason}")
    for old, new in report.renamed:
        print(f"Renamed: {old} -> {new}")
    for region, count in sorted(report.distribution.items()):
        print(f"Region {region} ({REGION_NAMES.get(region, region)}): {count}")
    print(f"Unknown regions: {len(report.unknown)}")
    print(f"Template groups: {len(artifact.groups)}")
    print(f"Rule providers: {len(artifact.rule_providers)}")
    return 0


def render_command(args: argparse.Namespace) -> int:
    artifact, source, kept, report = prepare(args)
    config, warnings = render(artifact, kept, source.hosts)
    errors, check_warnings = check(config)
    for warning in warnings + check_warnings:
        print(f"Warning: {warning}")
    if errors:
        for error in errors:
            print(f"Static check failed: {error}", file=sys.stderr)
        return 3
    print(f"Nodes: {len(kept)} (dropped {len(report.dropped)})")
    print("Static check: passed")

    output = Path(args.output).resolve()
    inputs = [Path(args.source), Path(args.artifact)]
    if args.profile:
        inputs.append(Path(args.profile))
    if output in {path.resolve() for path in inputs}:
        raise ValueError("Output must not overwrite the source, base template or profile")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")
    print(f"Output: {output}")

    kernel = args.mihomo or shutil.which("mihomo")
    if not kernel:
        print("Kernel check: skipped (use --mihomo to specify the executable)")
        return 0
    executable = str(Path(kernel).resolve())
    try:
        proc = subprocess.run([executable, "-t", "-d", str(output.parent), "-f", str(output)],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Kernel check failed: {type(exc).__name__}", file=sys.stderr)
        return 4
    message = (proc.stdout + proc.stderr).strip()
    if message:
        print(message)
    if proc.returncode:
        print(f"Kernel check failed (exit {proc.returncode})", file=sys.stderr)
        return 4
    print("Kernel check: passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows redirected streams can otherwise encode node names with a legacy code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Build a custom Mihomo YAML from local Clash nodes")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, function in (("report", report_command), ("render", render_command)):
        command = commands.add_parser(name)
        command.add_argument("source", help="Local Clash YAML containing proxies")
        command.add_argument("-a", "--artifact", default="artifacts/base.yaml", help="Base template")
        command.add_argument("-p", "--profile", help="Additive groups, rule-providers and rules")
        command.set_defaults(function=function)
        if name == "render":
            command.add_argument("-o", "--output", default="local/config.yaml")
            command.add_argument("--mihomo", help="Mihomo executable for configuration validation")
    args = parser.parse_args(argv)
    try:
        return args.function(args)
    except ValidationError as exc:
        # Exclude input values because a private profile can contain credentials.
        for error in exc.errors(include_input=False, include_url=False):
            print(f"Invalid template: {error['loc']}: {error['msg']}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"Failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
