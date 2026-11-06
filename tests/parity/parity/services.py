"""Which services MWS implements, and where their code and models live.

Discovered from the vendored Smithy models under crates/services/*/model, so
a new MWS service is covered by the suite without editing it: its sdkId is
matched to the botocore service with the same serviceId.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import botocore.session

from .targets import ROOT


@dataclass(frozen=True)
class ServiceInfo:
    boto: str  # boto3 client name
    sdk_id: str
    crate: str  # crates/services/mws-...
    model: str  # path of the Smithy model, relative to the repo


@lru_cache(maxsize=1)
def botocore_by_service_id() -> dict[str, str]:
    session = botocore.session.get_session()
    loader = session.get_component("data_loader")
    out = {}
    for name in session.get_available_services():
        try:
            meta = loader.load_service_model(name, "service-2")["metadata"]
        except Exception:  # noqa: BLE001
            continue
        out[meta.get("serviceId", "").lower()] = name
    return out


def _sdk_ids(model_path: Path) -> list[str]:
    with open(model_path) as f:
        shapes = json.load(f).get("shapes", {})
    ids = []
    for shape in shapes.values():
        if shape.get("type") == "service":
            sdk = shape.get("traits", {}).get("aws.api#service", {}).get("sdkId")
            if sdk:
                ids.append(sdk)
    return ids


@lru_cache(maxsize=1)
def mws_services() -> dict[str, ServiceInfo]:
    by_id = botocore_by_service_id()
    out: dict[str, ServiceInfo] = {}
    for model in sorted(ROOT.glob("crates/services/*/model/*.json")):
        crate = model.parent.parent
        for sdk in _sdk_ids(model):
            boto = by_id.get(sdk.lower())
            if boto is None:
                continue
            out[boto] = ServiceInfo(
                boto=boto,
                sdk_id=sdk,
                crate=crate.relative_to(ROOT).as_posix(),
                model=model.relative_to(ROOT).as_posix(),
            )
    return out


# boto3 name -> name in /_localstack/health, where they differ. Services
# missing from health are still probed once before being skipped, so an
# unknown spelling costs one call, not coverage.
LOCALSTACK_NAMES: dict[str, str] = {}


def localstack_name(boto: str) -> str:
    return LOCALSTACK_NAMES.get(boto, boto)
