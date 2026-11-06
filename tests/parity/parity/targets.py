"""The two emulators under comparison and how to build SDK clients for them.

Every client records the raw HTTP exchange of each call (botocore's
`before-send` and `response-received` events), so a disparity report can show
exactly what went over the wire on both sides.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import boto3
from botocore.config import Config

ROOT = Path(__file__).resolve().parents[3]

# The root identity MWS seeds by default (see tests/e2e-python/conftest.py).
MWS_ROOT_KEY = "AKIAMWSROOTEXAMPLE00"
MWS_ROOT_SECRET = "mwsRootSecretAccessKeyEXAMPLEKEY00000000"


@dataclass
class Exchange:
    """One HTTP request and its response, as seen by botocore."""

    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)


class Recorder:
    """Collects the exchanges of the call currently in flight on a client.

    Clients are used by one thread at a time (each service runs on its own
    worker), so a per-recorder list is enough.
    """

    def __init__(self) -> None:
        self.exchanges: list[Exchange] = []
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self.exchanges = []

    def before_send(self, request, **_):
        body = request.body
        if hasattr(body, "read"):
            # A file-like body (streaming upload): botocore can rewind it.
            try:
                pos = body.tell()
                data = body.read()
                body.seek(pos)
                body = data
            except Exception:  # noqa: BLE001 - best effort only
                body = "<unreadable stream>"
        with self._lock:
            self.exchanges.append(
                Exchange(
                    request={
                        "method": request.method,
                        "url": request.url,
                        "headers": {k: _text(v) for k, v in request.headers.items()},
                        "body": body,
                    }
                )
            )
        return None

    def response_received(self, response_dict=None, exception=None, **_):
        with self._lock:
            if not self.exchanges:
                self.exchanges.append(Exchange())
            ex = self.exchanges[-1]
            if exception is not None:
                ex.response = {"exception": f"{type(exception).__name__}: {exception}"}
                return
            if response_dict is None:
                return
            body = response_dict.get("body")
            if not isinstance(body, (bytes, bytearray, str)):
                body = "<streaming body; see parsed response>"
            ex.response = {
                "status": response_dict.get("status_code"),
                "headers": dict(response_dict.get("headers", {})),
                "body": body,
            }


def _text(v):
    return v.decode("latin-1") if isinstance(v, bytes) else str(v)


@dataclass
class Target:
    """One emulator endpoint (MWS or LocalStack)."""

    name: str
    endpoint: str
    access_key: str
    secret_key: str
    region: str = "us-east-1"
    session_token: str | None = None
    info: dict = field(default_factory=dict)

    def client(self, service: str, validate: bool = True):
        config = Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            s3={"addressing_style": "path"},
            parameter_validation=validate,
            connect_timeout=10,
            read_timeout=120,
            # Both emulators speak HTTP on one port; don't let the SDK
            # compute host prefixes such as `{AccountId}.` that would need DNS.
            inject_host_prefix=False,
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        )
        session = boto3.session.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token,
            region_name=self.region,
        )
        client = session.client(service, endpoint_url=self.endpoint, config=config)
        # Endpoint rules (S3 Control) put `{AccountId}.` in front of the host
        # even with inject_host_prefix off; that name needs wildcard DNS.
        # Connect to the configured host instead, before the request is signed.
        client.meta.events.register("before-sign", _strip_host_prefix(self.endpoint))
        recorder = Recorder()
        client.meta.events.register("before-send", recorder.before_send)
        client.meta.events.register("response-received", recorder.response_received)
        client._parity_recorder = recorder  # noqa: SLF001
        return client


def _strip_host_prefix(endpoint: str):
    want = urllib.parse.urlsplit(endpoint).netloc

    def handler(request, **_):
        parts = urllib.parse.urlsplit(request.url)
        if parts.netloc != want and parts.netloc.endswith("." + want):
            # Keep the prefixed name in Host (signed, and read by both
            # emulators) but connect to the configured address.
            request.headers["Host"] = parts.netloc
            request.url = urllib.parse.urlunsplit(parts._replace(netloc=want))

    return handler


def _get_json(url: str, timeout: float = 2.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - local endpoints
        return json.loads(r.read() or b"{}")


def wait_until_up(url: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _get_json(url, timeout=1)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return False


def localstack_health(endpoint: str) -> dict:
    """`/_localstack/health`: which services this LocalStack edition offers."""
    try:
        return _get_json(endpoint.rstrip("/") + "/_localstack/health")
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def localstack_info(endpoint: str) -> dict:
    try:
        return _get_json(endpoint.rstrip("/") + "/_localstack/info")
    except Exception:  # noqa: BLE001
        return {}


def mws_health(endpoint: str) -> dict:
    try:
        return _get_json(endpoint.rstrip("/") + "/_mws/health")
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


class Launched:
    """Processes/containers this run started, stopped again at exit."""

    def __init__(self) -> None:
        self.procs: list[subprocess.Popen] = []
        self.containers: list[str] = []

    def stop(self) -> None:
        for p in self.procs:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        for c in self.containers:
            subprocess.run(["docker", "rm", "-f", c], capture_output=True, check=False)


def start_mws(port: int, launched: Launched, binary: str | None, log_path: Path) -> str:
    """Start MWS on `port` (the binary if given or built, else `cargo run`)."""
    binary = binary or os.environ.get("MWS_BIN")
    if not binary:
        built = ROOT / "target" / "debug" / "mws"
        binary = str(built) if built.exists() else None
    cmd = [binary] if binary else ["cargo", "run", "-q", "-p", "mws"]
    env = {
        "MWS_EC2_BACKEND": "metadata",
        "RUST_LOG": "warn",
        **os.environ,
        "MWS_LISTEN": f"127.0.0.1:{port}",
    }
    log = open(log_path, "wb")  # noqa: SIM115 - lives as long as the process
    launched.procs.append(subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT))
    url = f"http://127.0.0.1:{port}"
    # `cargo run` may have to compile first.
    if not wait_until_up(url + "/_mws/health", timeout=1800 if not binary else 60):
        raise SystemExit(f"MWS did not come up on {url}; see {log_path}")
    return url


def start_localstack(port: int, launched: Launched, image: str) -> str:
    if not shutil.which("docker"):
        raise SystemExit("--start-localstack needs docker on PATH")
    name = f"mws-parity-localstack-{port}"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    cmd = [
        "docker", "run", "-d", "--name", name,
        "-p", f"{port}:4566",
        "-e", f"LOCALSTACK_HOST=localhost:{port}",
        # Lambda invocations run in sibling containers.
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
    ]
    for var in ["LOCALSTACK_AUTH_TOKEN", "LOCALSTACK_API_KEY", "ACTIVATE_PRO", "DEBUG"]:
        if os.environ.get(var):
            cmd += ["-e", var]
    cmd.append(image)
    subprocess.run(cmd, check=True, capture_output=True)
    launched.containers.append(name)
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 180
    while time.time() < deadline:
        h = localstack_health(url)
        if "services" in h:
            return url
        time.sleep(1)
    raise SystemExit(f"LocalStack did not come up on {url} (docker logs {name})")
