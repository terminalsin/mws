"""Offline checks of the parity suite itself (no emulator needed).

- every scenario step names a real boto3 method and passes botocore's
  parameter validation (unless it deliberately sends invalid input),
- every documented AWS expectation names an error the Smithy model declares
  for that operation (or a common AWS error) with the model's HTTP status,
- every MWS service has at least one scenario,
- normalization, diffing and verdicts behave.
"""

import datetime as dt
import sys
from pathlib import Path

import boto3
import pytest
from botocore.validate import ParamValidator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parity import judge, scenarios, smithy  # noqa: E402,F401
from parity.diff import Difference, diff_values, make_ignore  # noqa: E402
from parity.dsl import REGISTRY, VAR, substitute  # noqa: E402
from parity.normalize import Normalizer  # noqa: E402
from parity.services import mws_services  # noqa: E402

SESSION = boto3.session.Session(aws_access_key_id="x", aws_secret_access_key="x", region_name="us-east-1")
CLIENTS = {}


def client(service):
    if service not in CLIENTS:
        CLIENTS[service] = SESSION.client(service, endpoint_url="http://localhost:1")
    return CLIENTS[service]


def dummy(shape):
    t = shape.type_name
    lo = shape.metadata.get("min", 1)
    return {
        "string": "x" * max(int(lo), 1),
        "integer": max(int(lo), 1),
        "long": max(int(lo), 1),
        "boolean": True,
        "blob": b"x",
        "timestamp": dt.datetime(2026, 1, 1),
        "double": 1.0,
        "float": 1.0,
        "list": [],
        "map": {},
        "structure": {},
    }[t]


def fill(value, shape):
    """Replace whole-value `${var}` references with dummies of the member type."""
    if isinstance(value, str) and VAR.fullmatch(value):
        return dummy(shape)
    if isinstance(value, dict) and shape.type_name == "structure":
        return {k: fill(v, shape.members[k]) if k in shape.members else v for k, v in value.items()}
    if isinstance(value, dict) and shape.type_name == "map":
        return {k: fill(v, shape.value) for k, v in value.items()}
    if isinstance(value, list) and shape.type_name == "list":
        return [fill(v, shape.member) for v in value]
    return value


def steps():
    for sc in REGISTRY:
        for i, st in enumerate(sc.steps, 1):
            yield pytest.param(sc, st, id=f"{sc.service}/{sc.slug}/{i:02d}-{st.op}")


class AnyVars(dict):
    """Built-in variables, and a dummy for anything an earlier step saves."""

    def __contains__(self, k):
        return True

    def __missing__(self, k):
        return "x" * 24


VARS = AnyVars({"name": "pty-abc123-1", "alnum": "ptyabc1231", "run": "abc123", "account": "123456789012", "region": "us-east-1", "endpoint": "http://x"})


@pytest.mark.parametrize("sc,st", list(steps()))
def test_step_is_valid(sc, st):
    c = client(st.service)
    assert hasattr(c, st.op), f"{st.service} has no method {st.op}"
    op = c.meta.method_to_api_mapping[st.op]
    om = c.meta.service_model.operation_model(op)
    params = st.params(VARS) if callable(st.params) else st.params
    if not st.raw:
        filled = fill(params, om.input_shape) if om.input_shape is not None else params
        if isinstance(filled.get("CopySource"), dict):  # boto3 turns it into a string first
            filled = {**filled, "CopySource": "bucket/key"}
        partial = substitute(filled, VARS) if not callable(st.params) else filled
        report = ParamValidator().validate(partial, om.input_shape) if om.input_shape is not None else None
        assert not (report and report.has_errors()), report.generate_report()


@pytest.mark.parametrize("sc,st", [p for p in steps() if p.values[1].expect and p.values[1].expect.get("error")])
def test_expected_error_is_declared(sc, st):
    info = mws_services()[st.service]
    op = client(st.service).meta.method_to_api_mapping[st.op]
    code = st.expect["error"]
    declared = smithy.declared_errors(info.model, op)
    # S3, S3 Control and EC2 model none of their error codes.
    if st.service in ("s3", "s3control", "ec2") or code in judge.COMMON_ERRORS:
        return
    assert code in declared, f"{code} is not declared for {op}: {sorted(declared)}"
    protocol = client(st.service).meta.service_model.metadata["protocol"]
    # awsJson services answer 400 for client errors whatever httpError says,
    # so only REST and query statuses are checked against the model.
    if "status" in st.expect and protocol in ("rest-json", "rest-xml", "query"):
        assert declared[code]["httpStatusCode"] == st.expect["status"], declared[code]


def test_every_service_has_a_scenario():
    covered = {sc.service for sc in REGISTRY}
    missing = sorted(set(mws_services()) - covered)
    assert not missing, f"no scenario for {missing}"


def test_normalizer_masks_generated_values():
    n = Normalizer("abc123")
    v = n.value(
        {
            "QueueUrl": "http://localhost:4566/000000000000/pty-abc123-1",
            "Arn": "arn:aws:sqs:us-east-1:123456789012:pty-abc123-1",
            "Id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "VpcId": "vpc-0a1b2c3d4e5f60718",
            "Created": dt.datetime.now(),
            "SentTimestamp": "1793941965787",
            "ETag": '"ef2a02275b08a52915d74cba1e1f4e3e"',
            "MD5OfMessageBody": "ef2a02275b08a52915d74cba1e1f4e3e",
            "NextToken": "abc",
        }
    )
    assert v["QueueUrl"] == "<endpoint>/<account>/pty-<run>-1"
    assert v["Arn"] == "arn:aws:sqs:us-east-1:<account>:pty-<run>-1"
    assert v["Id"] == "<uuid>"
    assert v["VpcId"] == "vpc-<id>"
    assert v["Created"] == v["SentTimestamp"] == "<timestamp>"
    assert v["MD5OfMessageBody"] == "ef2a02275b08a52915d74cba1e1f4e3e"
    assert v["NextToken"] == "<NextToken>"
    assert v["ETag"] == "<ETag>"


def test_normalizer_keeps_hex_with_digit_runs_whole():
    # A random hex id can hold twelve digits in a row; that is not an account.
    n = Normalizer("abc123")
    assert n.value({"CurrentKeyMaterialId": "ab12f0c1a4836215790436e1d7f0"})["CurrentKeyMaterialId"] == "<hex>"


def test_diff_kinds():
    out = []
    diff_values(
        {"a": 1, "b": [], "c": {"d": "x"}, "e": [1, 2]},
        {"a": "1", "c": {"d": "y"}, "e": [2, 1], "f": 3},
        "",
        out,
        False,
        make_ignore([]),
    )
    kinds = {(d.kind, d.path) for d in out}
    assert kinds == {("type", "a"), ("empty_vs_absent", "b"), ("value", "c.d"), ("order", "e"), ("missing_field", "f")}


def test_shape_only_ignores_values_and_lengths():
    out = []
    diff_values({"Items": [{"Name": "a"}, {"Name": "b"}]}, {"Items": [{"Name": "z"}]}, "", out, True, make_ignore([]))
    assert out == []


def test_ignore_patterns():
    ign = make_ignore(["Items[].Secret", "Meta*"])
    assert ign("Items[3].Secret") and ign("MetaData.x") and not ign("Items[3].Name")


def test_verdict_prefers_model_evidence():
    f = [judge.Finding("localstack", "server_error", "HTTP 500", "high")]
    v = judge.verdict([Difference("status", "http.status", 400, 500)], f, {}, {}, None)
    assert v.likely_wrong == "localstack" and v.confidence == "high"
    v = judge.verdict([Difference("value", "x", 1, 2)], [], {}, {}, None)
    assert v.likely_wrong == "undetermined"


def test_not_implemented_detection():
    assert judge.is_not_implemented({"status": 501, "error": {"code": "InternalFailure", "message": ""}})
    assert judge.is_not_implemented(
        {"status": 400, "error": {"code": "InternalFailure", "message": "The API for service 'x' is either not included in your current license plan or has not yet been emulated by LocalStack"}}
    )
    assert not judge.is_not_implemented({"status": 404, "error": {"code": "NoSuchKey", "message": "nope"}})


def test_smithy_query_error_codes():
    declared = smithy.declared_errors(mws_services()["sqs"].model, "GetQueueUrl")
    assert declared["AWS.SimpleQueueService.NonExistentQueue"]["httpStatusCode"] == 400
