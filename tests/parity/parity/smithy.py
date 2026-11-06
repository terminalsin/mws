"""Facts from the official Smithy models MWS vendors (crates/services/*/model).

botocore's JSON models drop some traits, notably the awsQuery error codes of
awsQueryCompatible services (SQS's `AWS.SimpleQueueService.NonExistentQueue`),
so error declarations are read from the Smithy model itself.
"""

from __future__ import annotations

import json
from functools import lru_cache

from .targets import ROOT


@lru_cache(maxsize=None)
def _shapes(model_path: str) -> dict:
    with open(ROOT / model_path) as f:
        return json.load(f)["shapes"]


def _error_info(shape_id: str, shape: dict) -> list[tuple[str, dict]]:
    traits = shape.get("traits", {})
    name = shape_id.split("#", 1)[1]
    status = traits.get("smithy.api#httpError")
    if status is None:
        status = 500 if traits.get("smithy.api#error") == "server" else 400
    info = {"shape": name, "httpStatusCode": status}
    out = [(name, info)]
    q = traits.get("aws.protocols#awsQueryError")
    if q:
        out.append((q["code"], {"shape": name, "httpStatusCode": q.get("httpResponseCode", status)}))
    return out


@lru_cache(maxsize=None)
def declared_errors(model_path: str, operation: str) -> dict[str, dict]:
    """Error code -> {shape, httpStatusCode} for one operation, including the
    errors the service shape declares for every operation."""
    shapes = _shapes(model_path)
    out: dict[str, dict] = {}
    ids: list[str] = []
    for sid, shape in shapes.items():
        if shape.get("type") == "service":
            ids += [e["target"] for e in shape.get("errors", [])]
        elif shape.get("type") == "operation" and sid.split("#", 1)[1] == operation:
            ids += [e["target"] for e in shape.get("errors", [])]
    for sid in ids:
        if sid in shapes:
            for code, info in _error_info(sid, shapes[sid]):
                out[code] = info
    return out


def error_status(model_path: str, code: str) -> int | None:
    """HTTP status the model gives an error code (any operation)."""
    for sid, shape in _shapes(model_path).items():
        if "smithy.api#error" in shape.get("traits", {}):
            for c, info in _error_info(sid, shape):
                if c == code:
                    return info["httpStatusCode"]
    return None
