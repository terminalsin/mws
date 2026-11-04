"""Start a real MWS binary on a free port for the test session."""

import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[2]
ROOT_KEY = "AKIAMWSROOTEXAMPLE00"
ROOT_SECRET = "mwsRootSecretAccessKeyEXAMPLEKEY00000000"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def endpoint():
    existing = os.environ.get("MWS_ENDPOINT")
    if existing:
        yield existing
        return
    binary = os.environ.get("MWS_BIN", str(ROOT / "target" / "debug" / "mws"))
    port = _free_port()
    proc = subprocess.Popen(
        [binary],
        env={
            # EC2 instances are metadata only unless a test run asks for Docker.
            "MWS_EC2_BACKEND": "metadata",
            **os.environ,
            "MWS_LISTEN": f"127.0.0.1:{port}",
            "RUST_LOG": "warn",
        },
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{url}/_mws/health", timeout=0.2)
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        raise RuntimeError("MWS did not start")
    yield url
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def session_for(endpoint):
    def make(key=ROOT_KEY, secret=ROOT_SECRET, token=None):
        return boto3.session.Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            aws_session_token=token,
            region_name="us-east-1",
        )

    return make


@pytest.fixture
def iam(endpoint, session_for):
    return session_for().client("iam", endpoint_url=endpoint)
