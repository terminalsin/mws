#!/usr/bin/env python3
"""Regenerate data/aws-managed-policies.jsonl from the MAMIP repository.

MAMIP (https://github.com/z0ph/MAMIP) snapshots every AWS managed policy
several times a day: `policies-list.json` is the `ListPolicies --scope AWS`
output and `policies/<name>` is each policy's default `GetPolicyVersion`.

Usage:
    git clone --depth 1 https://github.com/z0ph/MAMIP /tmp/mamip
    python3 -I crates/services/mws-iam/scripts/update-managed-policies.py /tmp/mamip

The output is JSON lines (about 4 MB, under the 5 MB point where it would
be worth compressing), one policy per line, sorted by
name:
    {"name", "path", "id", "version", "created", "updated", "attachable",
     "description"?, "document"}
`document` is the default version's document, compact JSON with the key
order AWS returns. MAMIP does not record descriptions (and nor does any
other public dump), so they come from DESCRIPTIONS below, copied from
`aws iam get-policy`; policies not listed there get no description.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "data", "aws-managed-policies.jsonl")
DESCRIPTIONS = os.path.join(HERE, "..", "data", "aws-managed-policy-descriptions.json")


def main(repo):
    with open(os.path.join(repo, "policies-list.json")) as f:
        listing = json.load(f)["Policies"]
    with open(DESCRIPTIONS) as f:
        descriptions = json.load(f)
    lines = []
    for p in sorted(listing, key=lambda p: p["PolicyName"]):
        name = p["PolicyName"]
        with open(os.path.join(repo, "policies", name)) as f:
            version = json.load(f)["PolicyVersion"]
        updated = p["UpdateDate"]
        if version["VersionId"] != p["DefaultVersionId"]:
            # The two files are snapshotted at slightly different times:
            # trust the document's own version.
            print(f"note: {name}: listing says {p['DefaultVersionId']}, document is {version['VersionId']}", file=sys.stderr)
            updated = max(updated, version["CreateDate"])
        expected = f"arn:aws:iam::aws:policy{p['Path']}{name}"
        if p["Arn"] != expected:
            sys.exit(f"{name}: unexpected ARN {p['Arn']}")
        entry = {
            "name": name,
            "path": p["Path"],
            "id": p["PolicyId"],
            "version": version["VersionId"],
            "created": p["CreateDate"],
            "updated": updated,
            "attachable": p["IsAttachable"],
        }
        if name in descriptions:
            entry["description"] = descriptions[name]
        entry["document"] = json.dumps(version["Document"], separators=(",", ":"), ensure_ascii=False)
        lines.append(json.dumps(entry, separators=(",", ":"), ensure_ascii=False))
    unknown = sorted(set(descriptions) - {p["PolicyName"] for p in listing})
    if unknown:
        print(f"warning: descriptions for unknown policies: {', '.join(unknown)}", file=sys.stderr)
    data = ("\n".join(lines) + "\n").encode()
    with open(OUT, "wb") as f:
        f.write(data)
    print(f"{len(lines)} policies, {len(data)} bytes -> {os.path.normpath(OUT)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
