"""Structural diff of two normalized SDK results."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

# Severity of each difference kind, most severe first.
SEVERITY = {
    "sdk_exception": "critical",
    "status": "major",
    "error_code": "major",
    "missing_field": "major",
    "type": "major",
    "value": "major",
    "length": "major",
    "error_message": "minor",
    "error_body": "minor",
    "empty_vs_absent": "minor",
    "order": "minor",
    "header": "minor",
}
SEVERITY_RANK = {"critical": 0, "major": 1, "minor": 2}


@dataclass
class Difference:
    kind: str
    path: str
    mws: object = None
    localstack: object = None
    note: str = ""

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.kind, "major")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity
        return d


def _type(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "map"
    return type(v).__name__


def _empty(v) -> bool:
    return v in ([], {}, "", None)


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


def diff_values(a, b, path: str, out: list[Difference], shape_only: bool, ignore) -> None:
    """Append differences between `a` (MWS) and `b` (LocalStack)."""
    if ignore(path):
        return
    ta, tb = _type(a), _type(b)
    if ta != tb:
        out.append(Difference("type", path, a, b, f"{ta} vs {tb}"))
        return
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if ignore(p):
                continue
            if k not in b:
                kind = "empty_vs_absent" if _empty(a[k]) else "missing_field"
                out.append(Difference(kind, p, a[k], "<absent>", "field only in MWS response"))
            elif k not in a:
                kind = "empty_vs_absent" if _empty(b[k]) else "missing_field"
                out.append(Difference(kind, p, "<absent>", b[k], "field only in LocalStack response"))
            else:
                diff_values(a[k], b[k], p, out, shape_only, ignore)
        return
    if isinstance(a, list):
        if shape_only:
            # State differs between emulators: compare the element shape only.
            if a and b:
                diff_values(a[0], b[0], f"{path}[0]", out, shape_only, ignore)
            return
        if len(a) != len(b):
            out.append(Difference("length", path, a, b, f"{len(a)} vs {len(b)} items"))
            return
        if sorted(map(_canon, a)) == sorted(map(_canon, b)) and a != b:
            out.append(Difference("order", path, a, b, "same items, different order"))
            return
        for i, (x, y) in enumerate(zip(a, b)):
            diff_values(x, y, f"{path}[{i}]", out, shape_only, ignore)
        return
    if shape_only:
        return
    if a != b:
        out.append(Difference("value", path, a, b))


def make_ignore(patterns: list[str]):
    """Paths to skip: exact (`Attributes.Policy`) or prefix with `*` suffix."""
    exact = {p for p in patterns if not p.endswith("*")}
    prefixes = [p[:-1] for p in patterns if p.endswith("*")]

    def ignore(path: str) -> bool:
        bare = path
        # `Items[3].Name` matches `Items[].Name`.
        generic = re.sub(r"\[\d+\]", "[]", bare)
        return bare in exact or generic in exact or any(generic.startswith(p) for p in prefixes)

    return ignore


# Response headers worth comparing. Values are normalized before comparing;
# for the `presence` ones only whether they are sent matters.
HEADERS_COMPARE = ["content-type"]
HEADERS_PRESENCE = [
    "x-amzn-requestid",
    "x-amz-request-id",
    "x-amz-id-2",
    "x-amzn-errortype",
    "x-amzn-query-error",
    "x-amz-crc32",
    "etag",
    "content-md5",
    "x-amz-version-id",
    "x-amz-server-side-encryption",
    "location",
]


def _content_type(v: str | None) -> str | None:
    if v is None:
        return None
    return v.split(";")[0].strip().lower()


def diff_headers(a: dict, b: dict, out: list[Difference]) -> None:
    la = {k.lower(): v for k, v in (a or {}).items()}
    lb = {k.lower(): v for k, v in (b or {}).items()}
    for h in HEADERS_COMPARE:
        va, vb = _content_type(la.get(h)), _content_type(lb.get(h))
        if va != vb:
            out.append(Difference("header", f"header:{h}", la.get(h), lb.get(h)))
    for h in HEADERS_PRESENCE:
        if (h in la) != (h in lb):
            out.append(
                Difference(
                    "header",
                    f"header:{h}",
                    la.get(h, "<absent>"),
                    lb.get(h, "<absent>"),
                    "header sent by only one side",
                )
            )
