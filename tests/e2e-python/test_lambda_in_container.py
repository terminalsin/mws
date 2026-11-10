"""MWS itself in a container (with the host's Docker socket) runs Lambda
functions in AWS's base images: the function containers join MWS's network
namespace and get their code copied in, as no host path is shared.

Needs Docker and pulls images, so it runs only with
MWS_TEST_DOCKER_IN_CONTAINER=1 (CI's python job sets it).
"""

import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path

import boto3
import pytest

from conftest import ROOT, ROOT_KEY, ROOT_SECRET, _free_port

pytestmark = pytest.mark.skipif(
    os.environ.get("MWS_TEST_DOCKER_IN_CONTAINER") != "1", reason="set MWS_TEST_DOCKER_IN_CONTAINER=1"
)

# The binary is built on the runner, so the image matches its glibc.
BASE = os.environ.get("MWS_TEST_CONTAINER_BASE", "public.ecr.aws/docker/library/ubuntu:24.04")

HANDLER = """
export const handler = async (event) => {
  const health = await fetch(`${process.env.AWS_ENDPOINT_URL}/_mws/health`);
  return { node: process.version, taskRoot: process.env.LAMBDA_TASK_ROOT, health: health.status, event };
};
"""

TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def docker(*args, **kw):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, **kw).stdout.strip()


@pytest.fixture(scope="module")
def endpoint_in_container():
    binary = Path(os.environ.get("MWS_BIN", str(ROOT / "target" / "debug" / "mws")))
    cli = shutil.which("docker")
    tag = f"mws-in-container-test:{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory() as ctx:
        shutil.copy(binary, Path(ctx) / "mws")
        shutil.copy(cli, Path(ctx) / "docker")
        (Path(ctx) / "Dockerfile").write_text(
            f"FROM {BASE}\nCOPY mws docker /usr/local/bin/\nENTRYPOINT [\"/usr/local/bin/mws\"]\n"
        )
        docker("build", "-q", "-t", tag, ctx)
    # The same port inside and out, so AWS_ENDPOINT_URL (from the request's
    # Host) also reaches MWS from the functions, which share its network.
    port = _free_port()
    name = f"mws-in-container-{uuid.uuid4().hex[:8]}"
    docker(
        "run", "-d", "--name", name,
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-p", f"127.0.0.1:{port}:{port}",
        "-e", f"MWS_LISTEN=0.0.0.0:{port}",
        "-e", "MWS_LAMBDA_RUNTIME_EXECUTOR=docker",
        "-e", "MWS_EC2_BACKEND=metadata",
        tag,
    )  # fmt: skip
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(200):
            try:
                urllib.request.urlopen(f"{url}/_mws/health", timeout=0.5)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("MWS did not start: " + docker("logs", name, stderr=subprocess.STDOUT))
        yield url, name
    finally:
        subprocess.run(["docker", "logs", "--tail", "50", name])
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


def test_functions_run_in_base_images_from_a_containerized_mws(endpoint_in_container):
    url, mws_container = endpoint_in_container
    session = boto3.session.Session(
        aws_access_key_id=ROOT_KEY, aws_secret_access_key=ROOT_SECRET, region_name="us-east-1"
    )
    iam = session.client("iam", endpoint_url=url)
    lam = session.client("lambda", endpoint_url=url)
    role = iam.create_role(RoleName="in-container", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.mjs", HANDLER)
    fn = lam.create_function(
        FunctionName="node22-in-container",
        Runtime="nodejs22.x",
        Handler="index.handler",
        Role=role,
        Code={"ZipFile": buf.getvalue()},
    )
    lam.get_waiter("function_active_v2").wait(FunctionName="node22-in-container")

    out = lam.invoke(FunctionName="node22-in-container", Payload=b'{"n": 1}')
    body = json.loads(out["Payload"].read())
    assert "FunctionError" not in out, body
    assert body["node"].startswith("v22."), body
    assert body["taskRoot"] == "/var/task"
    assert body["health"] == 200
    assert body["event"] == {"n": 1}

    # The function's container shares MWS's network namespace and runs an
    # image holding its code.
    containers = docker(
        "ps", "--filter", f"label=mws.lambda.function={fn['FunctionArn']}",
        "--format", "{{.Image}} {{.ID}}",
    ).splitlines()  # fmt: skip
    assert len(containers) == 1, containers
    image, cid = containers[0].split()
    assert image.startswith("mws-lambda-package:")
    mws_id = docker("inspect", "--format", "{{.Id}}", mws_container)
    assert docker("inspect", "--format", "{{.HostConfig.NetworkMode}}", cid) == f"container:{mws_id}"

    lam.delete_function(FunctionName="node22-in-container")
