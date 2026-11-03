"""Persistence, scenarios and the /_mws control API through boto3.

These tests run their own MWS processes (with a state database and a
scenario file) so resets cannot disturb the shared server other tests use.
"""

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import boto3
import pytest

from conftest import ROOT, ROOT_KEY, ROOT_SECRET

SCENARIO = ROOT / "examples" / "scenario.json"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, db: Path, scenario: Path | None):
        self.db, self.scenario, self.proc, self.url = db, scenario, None, None

    def start(self):
        port = _free_port()
        env = {**os.environ, "MWS_LISTEN": f"127.0.0.1:{port}", "MWS_DB": str(self.db), "RUST_LOG": "warn"}
        if self.scenario:
            env["MWS_SCENARIO"] = str(self.scenario)
        binary = os.environ.get("MWS_BIN", str(ROOT / "target" / "debug" / "mws"))
        self.proc = subprocess.Popen([binary], env=env)
        self.url = f"http://127.0.0.1:{port}"
        for _ in range(200):
            try:
                urllib.request.urlopen(f"{self.url}/_mws/health", timeout=0.2)
                return self
            except OSError:
                time.sleep(0.05)
        self.proc.kill()
        raise RuntimeError("MWS did not start")

    def stop(self):
        self.proc.terminate()  # SIGTERM: MWS flushes state and exits
        assert self.proc.wait(timeout=10) == 0

    def client(self, service, key=ROOT_KEY, secret=ROOT_SECRET):
        return boto3.client(
            service,
            endpoint_url=self.url,
            region_name="us-east-1",
            aws_access_key_id=key,
            aws_secret_access_key=secret,
        )

    def control(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")


@pytest.fixture
def server(tmp_path):
    s = Server(tmp_path / "mws.db", SCENARIO).start()
    yield s
    if s.proc.poll() is None:
        s.stop()


def users(iam):
    return [u["UserName"] for u in iam.list_users()["Users"]]


def test_scenario_seeds_resources(server):
    iam = server.client("iam")
    assert users(iam) == ["deployer"]
    r53 = server.client("route53")
    zone = r53.list_hosted_zones_by_name(DNSName="example.internal")["HostedZones"][0]
    names = [r["Name"] for r in r53.list_resource_record_sets(HostedZoneId=zone["Id"])["ResourceRecordSets"]]
    assert "api.example.internal." in names
    pca = server.client("acm-pca")
    assert pca.list_certificate_authorities()["CertificateAuthorities"][0]["Status"] == "ACTIVE"


def test_state_persists_across_restart_and_reset_returns_to_scenario(server):
    iam = server.client("iam")
    iam.create_user(UserName="extra")
    server.stop()
    server.start()
    iam = server.client("iam")
    assert users(iam) == ["deployer", "extra"]

    assert server.control("POST", "/_mws/reset") == (200, {"status": "ok"})
    assert users(iam) == ["deployer"]


def test_snapshots_and_runtime_scenarios(server):
    iam = server.client("iam")
    status, body = server.control(
        "POST",
        "/_mws/scenario",
        {
            "steps": [
                {"service": "iam", "action": "CreateUser", "input": {"UserName": "ci"}},
                {"id": "key", "service": "iam", "action": "CreateAccessKey", "input": {"UserName": "ci"}},
            ]
        },
    )
    assert status == 200, body
    key = body["outputs"]["key"]["AccessKey"]
    me = server.client("sts", key["AccessKeyId"], key["SecretAccessKey"]).get_caller_identity()
    assert me["Arn"] == "arn:aws:iam::123456789012:user/ci"

    assert server.control("PUT", "/_mws/snapshots/with-ci")[0] == 200
    server.control("POST", "/_mws/reset?to=empty")
    assert users(iam) == []
    assert server.control("POST", "/_mws/snapshots/with-ci/restore")[0] == 200
    assert users(iam) == ["ci", "deployer"]

    status, body = server.control(
        "POST", "/_mws/scenario", {"steps": [{"service": "iam", "action": "DeleteUser", "input": {"UserName": "nobody"}}]}
    )
    assert status == 400
    assert body["code"] == "NoSuchEntity" and body["step"] == 1
