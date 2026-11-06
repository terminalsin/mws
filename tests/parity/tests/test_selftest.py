"""End-to-end check of the suite against two MWS instances.

Two identical emulators must produce no disparities: anything reported here
is nondeterminism the normalizer does not cover, or a bug in the suite.
Needs the MWS binary (target/debug/mws or $MWS_BIN); skipped without it.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from parity.__main__ import main  # noqa: E402

BINARY = os.environ.get("MWS_BIN", str(ROOT / "target" / "debug" / "mws"))
SERVICES = "sqs,sns,s3,iam,sts,kms,ssm,secretsmanager,logs,events,cloudwatch,route53,acm,kinesis"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def two_mws():
    if not Path(BINARY).exists():
        pytest.skip(f"no MWS binary at {BINARY}")
    procs, urls = [], []
    for _ in range(2):
        port = _free_port()
        env = {"MWS_EC2_BACKEND": "metadata", **os.environ, "MWS_LISTEN": f"127.0.0.1:{port}", "RUST_LOG": "warn"}
        procs.append(subprocess.Popen([BINARY], env=env))
        urls.append(f"http://127.0.0.1:{port}")
    for url in urls:
        for _ in range(200):
            try:
                urllib.request.urlopen(f"{url}/_mws/health", timeout=0.2)
                break
            except OSError:
                time.sleep(0.05)
    yield urls
    for p in procs:
        p.terminate()
        p.wait(timeout=10)


def test_identical_emulators_have_no_disparities(two_mws, tmp_path):
    a, b = two_mws
    code = main(["--mws", a, "--localstack", b, "--self-test", "--services", SERVICES, "--mode", "all", "--out", str(tmp_path), "--jobs", "4"])
    assert code == 0
    report = json.loads((tmp_path / "report.json").read_text())
    outcomes = report["summary"]["outcomes"]
    assert outcomes.get("match", 0) > 300, outcomes
    bad = [c["id"] for c in report["cases"] if c["outcome"] in ("disparity", "minor", "blocked")]
    assert not bad, f"differences between two identical MWS instances: {bad} (see {tmp_path}/report.md)"
    assert (tmp_path / "report.md").read_text().startswith("# MWS vs LocalStack parity report")
