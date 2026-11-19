import os
import subprocess
from pathlib import Path

import pytest
import yaml

from clashconv.__main__ import main

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "tests/fixtures/sample-clash.yaml"
BASE = ROOT / "artifacts/base.yaml"
PROFILE = ROOT / "artifacts/services.yaml"


def arguments(tmp_path):
    return ["render", str(SOURCE), "-a", str(BASE), "-p", str(PROFILE), "-o", str(tmp_path / "config.yaml")]


def test_report_does_not_print_credentials(capsys):
    assert main(["report", str(SOURCE), "-a", str(BASE)]) == 0
    output = capsys.readouterr().out
    assert "Kept nodes: 6" in output
    assert "test-password" not in output
    assert "test-public-key" not in output


def test_render_without_kernel_is_explicit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("clashconv.__main__.shutil.which", lambda name: None)
    assert main(arguments(tmp_path)) == 0
    assert "Kernel check: skipped" in capsys.readouterr().out
    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert len(config["proxies"]) == 6
    assert config["rules"][-1] == "MATCH,Final"


def test_invalid_yaml_returns_two_without_echoing_source(tmp_path, capsys):
    source = tmp_path / "bad.yaml"
    source.write_text("proxies: [secret-password", encoding="utf-8")
    assert main(["report", str(source), "-a", str(BASE)]) == 2
    assert "secret-password" not in capsys.readouterr().err


@pytest.mark.parametrize("command", ["report", "render"])
@pytest.mark.parametrize(("settings", "field"), [
    ({"dns": None}, "config.dns"),
    ({"hosts": []}, "config.hosts"),
    ({"dns": {"nameserver-policy": []}}, "config.dns.nameserver-policy"),
    ({"dns": {"proxy-server-nameserver-policy": None}}, "config.dns.proxy-server-nameserver-policy"),
    ({"dns": {"fake-ip-filter": None}}, "config.dns.fake-ip-filter"),
    ({"dns": {"fake-ip-filter": "*.lan"}}, "config.dns.fake-ip-filter"),
])
def test_invalid_native_containers_return_two_without_overwriting_output(tmp_path, capsys, command, settings, field):
    base = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    base["config"] = settings
    artifact = tmp_path / "bad-base.yaml"
    artifact.write_text(yaml.safe_dump(base), encoding="utf-8")
    output = tmp_path / "config.yaml"
    output.write_text("previous output", encoding="utf-8")
    args = [command, str(SOURCE), "-a", str(artifact)]
    if command == "render":
        args.extend(["-o", str(output)])
    assert main(args) == 2
    assert field in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "previous output"


def test_static_failure_does_not_overwrite_output(tmp_path):
    base = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    base["rules"].insert(0, "DOMAIN,example.test,missing")
    artifact = tmp_path / "bad-base.yaml"
    artifact.write_text(yaml.safe_dump(base, allow_unicode=True), encoding="utf-8")
    output = tmp_path / "config.yaml"
    output.write_text("previous output", encoding="utf-8")
    assert main(["render", str(SOURCE), "-a", str(artifact), "-o", str(output)]) == 3
    assert output.read_text(encoding="utf-8") == "previous output"


@pytest.mark.parametrize("input_name", ["source", "artifact", "profile"])
def test_output_cannot_overwrite_inputs(tmp_path, input_name):
    paths = {"source": SOURCE, "artifact": BASE, "profile": PROFILE}
    target = tmp_path / "input.yaml"
    original = paths[input_name].read_bytes()
    target.write_bytes(original)
    paths[input_name] = target
    assert main(["render", str(paths["source"]), "-a", str(paths["artifact"]),
                 "-p", str(paths["profile"]), "-o", str(target)]) == 2
    assert target.read_bytes() == original


def test_kernel_failure_returns_four(tmp_path, monkeypatch):
    seen = []

    def failed(command, **kwargs):
        seen.append(command)
        return subprocess.CompletedProcess(command, 1, "kernel error", "")

    monkeypatch.setattr("clashconv.__main__.subprocess.run", failed)
    assert main(arguments(tmp_path) + ["--mihomo", "kernel.exe"]) == 4
    assert "-t" in seen[0]
    assert "-d" in seen[0]


def test_missing_kernel_returns_four(tmp_path):
    assert main(arguments(tmp_path) + ["--mihomo", str(tmp_path / "missing.exe")]) == 4


def test_kernel_timeout_returns_four(tmp_path, monkeypatch):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 60)

    monkeypatch.setattr("clashconv.__main__.subprocess.run", timeout)
    assert main(arguments(tmp_path) + ["--mihomo", "kernel.exe"]) == 4


@pytest.mark.parametrize("protocol", [
    {"type": "ss", "cipher": "aes-128-gcm", "password": "test-password", "udp": True,
     "plugin": "obfs", "plugin-opts": {"mode": "http", "host": "example.com"}},
    {"type": "vmess", "uuid": "00000000-0000-0000-0000-000000000000", "alterId": 0,
     "cipher": "auto", "tls": True, "network": "ws",
     "ws-opts": {"path": "/test", "headers": {"Host": "example.com"}}},
    {"type": "trojan", "password": "test-password", "sni": "example.com", "udp": True},
    {"type": "vless", "uuid": "00000000-0000-0000-0000-000000000000", "tls": True,
     "servername": "example.com", "client-fingerprint": "chrome", "flow": "xtls-rprx-vision",
     "reality-opts": {"public-key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short-id": "0123456789abcdef"}},
], ids=["shadowsocks-obfs", "vmess-websocket-tls", "trojan", "vless-reality"])
def test_mihomo_accepts_native_nodes_and_inline_rules(tmp_path, protocol):
    kernel = os.environ.get("CLASHCONV_MIHOMO")
    if not kernel:
        pytest.skip("Set CLASHCONV_MIHOMO to the Mihomo executable")
    node = {"name": "香港 1", "server": "192.0.2.1", "port": 443, **protocol}
    source = tmp_path / "nodes.yaml"
    source.write_text(yaml.safe_dump({"proxies": [node]}, allow_unicode=True), encoding="utf-8")
    artifact = tmp_path / "base.yaml"
    artifact.write_text(yaml.safe_dump({
        "config": {"mixed-port": 17890, "mode": "rule"},
        "groups": [{"name": "Proxy", "regions": ["*"]}, {"insert": "profile_groups"}],
        "rule-providers": {"test": {"type": "inline", "behavior": "domain", "payload": ["+.example.com"]}},
        "rules": ["RULE-SET,test,Proxy", {"insert": "user_rules"}, "MATCH,DIRECT"],
    }), encoding="utf-8")
    assert main(["render", str(source), "-a", str(artifact), "-o", str(tmp_path / "config.yaml"),
                 "--mihomo", kernel]) == 0
    config = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert config["proxies"] == [node]
