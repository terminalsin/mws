"""Decide which side of a disparity is likely wrong.

LocalStack is a reference, not ground truth: MWS aims at real AWS behaviour,
so the verdict leans on evidence about AWS itself, in this order:

1. Expectations written into a scenario from AWS documentation.
2. The official service model botocore ships (the same Smithy model MWS
   generates from): declared errors and their HTTP statuses, operation
   status codes, enum values, required output members, the members a JSON
   response may contain, and the protocol's content type.
3. Generic signs of a broken emulator: 5xx answers, "not implemented"
   errors, and responses the SDK could not parse.

Anything else is reported as `undetermined`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Errors any AWS service may return without declaring them in its model
# (https://docs.aws.amazon.com/general/latest/gr/api-retries.html and the
# common-errors pages of each protocol).
COMMON_ERRORS = {
    "AccessDenied", "AccessDeniedException", "ExpiredToken", "ExpiredTokenException",
    "IncompleteSignature", "IncompleteSignatureException", "InternalFailure", "InternalError",
    "InternalServerError", "InvalidAction", "InvalidClientTokenId", "InvalidParameterCombination",
    "InvalidParameterValue", "InvalidQueryParameter", "MalformedQueryString", "MissingAction",
    "MissingAuthenticationToken", "MissingAuthenticationTokenException", "MissingParameter",
    "NotAuthorized", "OptInRequired", "RequestExpired", "RequestTimeout", "ServiceUnavailable",
    "ServiceUnavailableException", "SignatureDoesNotMatch", "Throttling", "ThrottlingException",
    "UnknownOperationException", "UnrecognizedClientException", "ValidationError",
    "ValidationException", "SerializationException", "InvalidSignatureException",
    "AccessDeniedException", "RequestEntityTooLarge", "InvalidRequest", "InvalidArgument",
    "MalformedXML", "MalformedPolicy", "InvalidInput",
}

NOT_IMPLEMENTED = re.compile(
    r"(?i)(not (yet )?(been )?(implemented|emulated|supported)|not included in your current license|"
    r"not available in your current license|pro feature|NotImplemented)"
)

# Services whose models declare (almost) none of the error codes they return.
UNMODELED_ERRORS = {"s3", "s3control", "ec2"}

JSON_CONTENT_TYPES = {"1.0": "application/x-amz-json-1.0", "1.1": "application/x-amz-json-1.1"}


@dataclass
class Finding:
    """Evidence that one side departs from the AWS model or documentation."""

    side: str  # "mws" | "localstack"
    check: str
    detail: str
    confidence: str = "medium"  # high | medium | low

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Verdict:
    likely_wrong: str  # mws | localstack | both | undetermined
    confidence: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# LocalStack routes requests for services it doesn't know to S3, or fails to
# parse them at all.
UNROUTED = re.compile(r"(<Code>NoSuchBucket</Code>.*<BucketName>|with unknown operation)", re.S)


def is_not_implemented(result: dict) -> bool:
    err = result.get("error") or {}
    text = f"{err.get('code', '')} {err.get('message', '')}"
    return result.get("status") == 501 or bool(NOT_IMPLEMENTED.search(text)) or bool(UNROUTED.search(text))


def botocore_declared_errors(op_model) -> dict[str, dict]:
    """Error codes botocore's model declares for this operation -> metadata
    (fallback when the Smithy model is not at hand)."""
    out: dict[str, dict] = {}
    for shape in op_model.error_shapes:
        meta = shape.metadata.get("error", {}) if hasattr(shape, "metadata") else {}
        info = {"shape": shape.name, "httpStatusCode": meta.get("httpStatusCode")}
        out[shape.name] = info
        if meta.get("code"):
            out[meta["code"]] = info
    return out


def _walk_enums(value, shape, path: str, out: list[tuple[str, str, list]]):
    if shape is None or value is None:
        return
    t = shape.type_name
    if t == "structure" and isinstance(value, dict):
        for name, member in shape.members.items():
            if name in value:
                _walk_enums(value[name], member, f"{path}.{name}" if path else name, out)
    elif t == "list" and isinstance(value, list):
        for i, v in enumerate(value):
            _walk_enums(v, shape.member, f"{path}[{i}]", out)
    elif t == "map" and isinstance(value, dict):
        for k, v in value.items():
            _walk_enums(v, shape.value, f"{path}.{k}", out)
    elif t == "string" and isinstance(value, str) and getattr(shape, "enum", None):
        if value not in shape.enum:
            out.append((path, value, list(shape.enum)))


def _json_unknown_members(raw, shape, path: str, out: list[str]):
    """Members in a raw JSON body that the output shape does not define."""
    if shape is None or raw is None:
        return
    t = shape.type_name
    if t == "structure" and isinstance(raw, dict):
        by_wire = {}
        for name, member in shape.members.items():
            loc = member.serialization.get("location")
            if loc in ("header", "headers", "statusCode", "uri", "querystring"):
                continue
            by_wire[member.serialization.get("name", name)] = member
        if shape.serialization.get("payload"):
            return
        for k, v in raw.items():
            if k == "__type" or k.startswith("_"):
                continue
            p = f"{path}.{k}" if path else k
            if k not in by_wire:
                out.append(p)
            else:
                _json_unknown_members(v, by_wire[k], p, out)
    elif t == "list" and isinstance(raw, list):
        for i, v in enumerate(raw[:5]):
            _json_unknown_members(v, shape.member, f"{path}[{i}]", out)
    elif t == "map" and isinstance(raw, dict):
        for k, v in list(raw.items())[:5]:
            _json_unknown_members(v, shape.value, f"{path}.{k}", out)


def model_findings(
    side: str, result: dict, op_model, protocol: str, probe: str | None, declared: dict | None = None
) -> list[Finding]:
    """Check one side's result against the service model on its own."""
    f: list[Finding] = []
    if result.get("exception"):
        f.append(Finding(side, "sdk_exception", f"the SDK raised {result['exception']}", "high"))
        return f
    status = result.get("status")
    err = result.get("error")
    headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
    if status is not None and status >= 500:
        f.append(Finding(side, "server_error", f"HTTP {status} {err}", "high"))
    if err:
        if is_not_implemented(result):
            f.append(Finding(side, "not_implemented", f"{err.get('code')}: {err.get('message')}", "high"))
            return f
        code = err.get("code") or ""
        unmodeled = op_model is not None and op_model.service_model.service_name in UNMODELED_ERRORS
        if declared is None:
            declared = botocore_declared_errors(op_model) if op_model else {}
        if code and not unmodeled and code not in declared and code not in COMMON_ERRORS:
            f.append(
                Finding(
                    side,
                    "undeclared_error",
                    f"error code {code!r} is neither declared by {op_model.name if op_model else '?'} "
                    f"({sorted(declared)}) nor a common AWS error",
                    "medium",
                )
            )
        info = declared.get(code)
        # awsJson services answer 400 for client errors whatever httpError
        # says, so the model's status is only evidence for REST and query.
        if (
            protocol in ("rest-json", "rest-xml", "query")
            and info
            and info.get("httpStatusCode")
            and status
            and info["httpStatusCode"] != status
        ):
            f.append(
                Finding(
                    side,
                    "error_status",
                    f"model declares HTTP {info['httpStatusCode']} for {code}, got {status}",
                    "medium",
                )
            )
        return f
    if probe == "validation":
        f.append(
            Finding(
                side,
                "accepted_invalid_input",
                "accepted a request that omits every required member; AWS rejects it",
                "high",
            )
        )
    if not op_model:
        return f
    expected = op_model.http.get("responseCode") if op_model.http else None
    if expected and status and expected != status:
        f.append(Finding(side, "success_status", f"model says HTTP {expected}, got {status}", "medium"))
    out_shape = op_model.output_shape
    parsed = result.get("raw_parsed")
    if out_shape is not None and isinstance(parsed, dict):
        enums: list = []
        _walk_enums(parsed, out_shape, "", enums)
        for path, value, allowed in enums[:10]:
            f.append(Finding(side, "enum", f"{path}={value!r} is not one of {allowed}", "medium"))
        for req in out_shape.required_members:
            if req not in parsed:
                f.append(Finding(side, "required_member", f"required output member {req} is missing", "medium"))
    want_id = "x-amz-request-id" if protocol == "rest-xml" and op_model.service_model.service_name in ("s3", "s3control") else "x-amzn-requestid"
    if status and not any(h in headers for h in (want_id, "x-amz-request-id", "x-amzn-requestid")):
        f.append(Finding(side, "request_id_header", f"AWS sends a {want_id} header on every response", "low"))
    ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
    has_payload = out_shape is not None and bool(out_shape.serialization.get("payload"))
    if protocol == "json":
        want = JSON_CONTENT_TYPES.get(op_model.metadata.get("jsonVersion", "1.0"))
        if ctype and want and ctype != want:
            f.append(Finding(side, "content_type", f"awsJson responses use {want}, got {ctype}", "low"))
    elif protocol == "rest-json" and not has_payload and ctype and ctype != "application/json":
        f.append(Finding(side, "content_type", f"restJson responses use application/json, got {ctype}", "low"))
    if protocol in ("json", "rest-json") and out_shape is not None and not has_payload:
        body = result.get("raw_body_text")
        if body:
            try:
                raw = json.loads(body)
            except ValueError:
                f.append(Finding(side, "malformed_json", "response body is not JSON", "high"))
                raw = None
            unknown: list[str] = []
            _json_unknown_members(raw, out_shape, "", unknown)
            if unknown:
                f.append(
                    Finding(
                        side,
                        "unknown_member",
                        f"response has members the model does not define (SDKs drop them): {unknown[:10]}",
                        "low",
                    )
                )
    return f


def expectation_findings(side: str, result: dict, expect: dict | None) -> list[Finding]:
    """Compare one side with documented AWS behaviour written in a scenario."""
    if not expect:
        return []
    out: list[Finding] = []
    err = result.get("error") or {}
    note = expect.get("source", "documented AWS behaviour")
    if "status" in expect and result.get("status") != expect["status"]:
        out.append(Finding(side, "expectation", f"AWS answers HTTP {expect['status']}, got {result.get('status')} ({note})", "high"))
    if "error" in expect:
        if expect["error"] is None and err:
            out.append(Finding(side, "expectation", f"AWS succeeds here, got {err.get('code')} ({note})", "high"))
        elif expect["error"] and err.get("code") != expect["error"]:
            out.append(Finding(side, "expectation", f"AWS answers {expect['error']}, got {err.get('code') or 'success'} ({note})", "high"))
    if "message" in expect and err and not re.search(expect["message"], err.get("message") or ""):
        out.append(Finding(side, "expectation", f"AWS message matches /{expect['message']}/, got {err.get('message')!r} ({note})", "high"))
    for path, want in (expect.get("fields") or {}).items():
        got = _lookup(result.get("raw_parsed"), path)
        ok = bool(re.fullmatch(want[3:], str(got))) if isinstance(want, str) and want.startswith("re:") else got == want
        if not ok:
            out.append(Finding(side, "expectation", f"AWS returns {path}={want!r}, got {got!r} ({note})", "high"))
    return out


def _lookup(value, path: str):
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
        if part.startswith("["):
            i = int(part[1:-1])
            value = value[i] if isinstance(value, list) and i < len(value) else None
        else:
            value = value.get(part) if isinstance(value, dict) else None
    return value


RANK = {"high": 3, "medium": 2, "low": 1}


def verdict(diffs, findings: list[Finding], mws: dict, ls: dict, probe: str | None) -> Verdict:
    """Combine model findings and the shape of the differences into a verdict."""
    score = {"mws": 0, "localstack": 0}
    reasons: list[str] = []
    best = {"mws": 0, "localstack": 0}
    for fd in findings:
        score[fd.side] += RANK[fd.confidence]
        best[fd.side] = max(best[fd.side], RANK[fd.confidence])
        reasons.append(f"{fd.side}: {fd.check}: {fd.detail}")
    # A required-member gap is a model fact; an optional field only one side
    # sends is a hint that the other side forgot it (AWS fills most fields).
    for d in diffs:
        if d.kind == "missing_field" and d.mws == "<absent>":
            reasons.append(f"hint: only LocalStack returns {d.path}; check whether AWS returns it")
        elif d.kind == "missing_field" and d.localstack == "<absent>":
            reasons.append(f"hint: only MWS returns {d.path}; check whether AWS returns it")
    if score["mws"] == score["localstack"] == 0:
        if probe == "validation" and mws.get("error") and ls.get("error"):
            reasons.append("both reject the invalid request; compare codes and messages with the model constraints")
        return Verdict("undetermined", "low", reasons or ["no model or documentation evidence either way"])
    if score["mws"] and score["localstack"]:
        if best["mws"] == best["localstack"]:
            return Verdict("both", "medium", reasons)
        side = "mws" if best["mws"] > best["localstack"] else "localstack"
        return Verdict(side, "medium", reasons)
    side = "mws" if score["mws"] else "localstack"
    conf = {3: "high", 2: "medium", 1: "low"}[best[side]]
    return Verdict(side, conf, reasons)
