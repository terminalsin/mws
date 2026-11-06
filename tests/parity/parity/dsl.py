"""How scenarios are written.

A scenario is a list of SDK calls that runs, in the same order and with the
same arguments, against both emulators. Arguments may reference variables
with `${var}`; each side keeps its own variables, so `${queue_url}` is MWS's
queue URL on the MWS side and LocalStack's on the other.

Built-in variables: `name` (a unique, lowercase, hyphenated name for this
scenario), `alnum` (the same without hyphens), `run`, `account`, `region`.

    @scenario("sqs", "standard queue lifecycle")
    def _(s):
        s.call("create_queue", QueueName="${name}", save={"url": "QueueUrl"})
        s.call("get_queue_url", QueueName="${name}-missing",
               expect=aws_error("AWS.SimpleQueueService.NonExistentQueue", 400))
        s.cleanup("delete_queue", QueueUrl="${url}")

`save` maps variable names to JMESPath expressions over the parsed response
(or to a callable taking the response). `expect` records what real AWS
answers, from AWS documentation: when the two sides differ, the side that
departs from it is the one to fix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

VAR = re.compile(r"\$\{([a-z][a-z0-9_]*)\}")


@dataclass
class Step:
    service: str
    op: str
    params: dict | Callable[[dict], dict] = field(default_factory=dict)
    save: dict = field(default_factory=dict)
    expect: dict | None = None
    ignore: list[str] = field(default_factory=list)
    shape_only: bool = False
    cleanup: bool = False
    # Poll (same call) until this JMESPath expression is truthy, or a
    # callable(response) returns True, for at most `wait_seconds`.
    until: str | Callable | None = None
    wait_seconds: float = 60
    note: str = ""
    # Skip parameter validation (to send what the model forbids on purpose).
    raw: bool = False


@dataclass
class Scenario:
    service: str
    title: str
    steps: list[Step] = field(default_factory=list)
    slug: str = ""
    # Services LocalStack must offer for this scenario to be meaningful.
    needs: tuple[str, ...] = ()

    def call(self, op: str, service: str | None = None, **params) -> Step:
        opts = {k: params.pop(k) for k in list(params) if k.startswith("_")}
        # `save=` and `expect=` are accepted without the underscore too.
        for k in ("save", "expect"):
            if k in params:
                opts["_" + k] = params.pop(k)
        step = Step(
            service=service or self.service,
            op=op,
            params=opts.pop("_params", params),
            save=opts.pop("_save", {}),
            expect=opts.pop("_expect", None),
            ignore=list(opts.pop("_ignore", [])),
            shape_only=opts.pop("_shape_only", False),
            until=opts.pop("_until", None),
            wait_seconds=opts.pop("_wait", 60),
            note=opts.pop("_note", ""),
            raw=opts.pop("_raw", False),
        )
        if opts:
            raise TypeError(f"unknown step options {sorted(opts)}")
        self.steps.append(step)
        return step

    def cleanup(self, op: str, service: str | None = None, **params) -> Step:
        step = self.call(op, service, **params)
        step.cleanup = True
        return step


REGISTRY: list[Scenario] = []


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def scenario(service: str, title: str, needs: tuple[str, ...] = ()):
    def register(fn: Callable[[Scenario], Any]):
        sc = Scenario(service=service, title=title, slug=slugify(title), needs=needs)
        fn(sc)
        REGISTRY.append(sc)
        return fn

    return register


def aws_error(code: str, status: int | None = None, message: str | None = None, source: str = "") -> dict:
    e: dict = {"error": code}
    if status is not None:
        e["status"] = status
    if message is not None:
        e["message"] = message
    if source:
        e["source"] = source
    return e


def aws_ok(fields: dict | None = None, status: int | None = None, source: str = "") -> dict:
    e: dict = {"error": None}
    if fields:
        e["fields"] = fields
    if status is not None:
        e["status"] = status
    if source:
        e["source"] = source
    return e


class Unresolved(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def substitute(value, variables: dict):
    """Replace `${var}` in strings (recursively). A string that is exactly
    one reference takes the variable's value with its own type."""
    if isinstance(value, str):
        m = VAR.fullmatch(value)
        if m:
            if m.group(1) not in variables:
                raise Unresolved(m.group(1))
            return variables[m.group(1)]

        def rep(mm):
            if mm.group(1) not in variables:
                raise Unresolved(mm.group(1))
            return str(variables[mm.group(1)])

        return VAR.sub(rep, value)
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value
