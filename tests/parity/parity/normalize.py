"""Turn SDK responses into comparable values.

Generated identifiers, ARNs' account ids, timestamps, endpoints and tokens
differ between any two emulators (and between two runs of the same one), so
they are replaced by placeholders before diffing. Deterministic values such
as ETags, MD5 digests and names the suite chose stay as they are.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re

# Keys whose values are generated per call and never comparable.
VOLATILE_KEYS = re.compile(
    r"^(NextToken|nextToken|Marker|NextMarker|NextContinuationToken|ContinuationToken|"
    r"RequestId|requestId|HostId|ReceiptHandle|MessageId|SequenceNumber|"
    r"NextSequenceToken|nextSequenceToken|uploadSequenceToken|ShardIterator|NextShardIterator|"
    r"SessionToken|SecretAccessKey|AccessKeyId|Token|token|ChangeInfoId|CallerReference|"
    r"ClientRequestToken|VersionId|UploadId|ETag|DeleteMarkerVersionId|CopySourceVersionId|"
    r"ChangeId|ExecutionId|InvocationId|EventId|eventId|ResponseId)$"
)
# Binary values generated per call (ciphertexts, signatures, key material):
# only their length is compared.
RANDOM_BYTES_KEYS = re.compile(
    r"^(CiphertextBlob|Plaintext|Signature|Mac|PublicKey|KeyMaterial|CiphertextForRecipient|"
    r"PrivateKeyCiphertextBlob|PrivateKeyPlaintext|SecretBinary|EncryptionContext|Csr|Certificate|CertificateChain)$"
)
# Keys that hold digests: compared exactly even though they look random.
DIGEST_KEYS = re.compile(r"(?i)(md5|sha|checksum|digest|fingerprint|etag|hash)")
TIME_KEYS = re.compile(r"(?i)(time|date|timestamp|epoch|expir|created|modified|updated|lastupdate|since|until)")

# Keys naming generated identifiers, and what a generated value looks like.
ID_KEYS = re.compile(r"(Id|ID)$")
GENERATED = re.compile(r"[A-Za-z0-9_\-]{10,}")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
ISO_TS = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2}| ?UTC)?\b"
)
HTTP_DATE = re.compile(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT\b")
URL_HOST = re.compile(r"\bhttps?://[A-Za-z0-9.\-]+(:\d+)?")
LOCALSTACK_HOST = re.compile(r"\b[a-z0-9.\-]*localhost\.localstack\.cloud(:\d+)?")
ACCOUNT = re.compile(r"(?<![0-9])\d{12}(?![0-9])")
# AWS-style resource ids: vpc-0abc..., i-..., ami-..., sg-..., etc.
RESOURCE_ID = re.compile(r"\b([a-z][a-z0-9]{0,24})-([0-9a-f]{8}|[0-9a-f]{17})\b")
# IAM unique ids (AIDA..., AROA..., ANPA..., access key ids, ...).
IAM_ID = re.compile(r"\b(AIDA|AROA|ANPA|ANPV|AIPA|AGPA|ASIA|AKIA|ACCA|APKA|ASCA|LKIA|LSIA)[A-Z0-9]{12,}\b")
# Route 53 zone/change/health-check ids and generated name servers.
R53_ID = re.compile(r"(/hostedzone/|/change/|/delegationset/)[A-Z0-9]{8,32}\b")
R53_BARE_ID = re.compile(r"\b[ZC][A-Z0-9]{12,32}\b")
NAMESERVER = re.compile(r"\bns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)\.?")
# Secrets Manager appends six random characters to secret ARNs.
SECRET_SUFFIX = re.compile(r"(:secret:[^:\s\"]+)-[A-Za-z0-9]{6}\b")
# S3 access point aliases: `<name>-<random suffix>-s3alias`.
AP_ALIAS = re.compile(r"-[a-z0-9]{20,}-s3alias\b")
LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
# Opaque tokens: long runs of base64/base64url that mix letters and digits.
TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{40,}={0,2}")


def placeholder_for(value: str) -> str:
    return f"<{value}>"


class Normalizer:
    def __init__(self, run_id: str, extra_literals: dict[str, str] | None = None) -> None:
        self.run_id = run_id
        # Literal per-side values (account ids, access keys) to placeholder.
        self.literals = dict(extra_literals or {})

    def text(self, s: str, key: str = "") -> str:
        if self.run_id:
            s = s.replace(self.run_id, "<run>")
        for lit, ph in self.literals.items():
            if lit:
                s = s.replace(lit, ph)
        s = LOCALSTACK_HOST.sub("<host>", s)
        s = URL_HOST.sub("<endpoint>", s)
        s = s.replace("127.0.0.1", "<host>").replace("localhost", "<host>")
        s = SECRET_SUFFIX.sub(r"\1-<rand>", s)
        s = NAMESERVER.sub("<nameserver>", s)
        s = R53_ID.sub(lambda m: f"{m.group(1)}<id>", s)
        s = IAM_ID.sub(lambda m: f"{m.group(1)}<id>", s)
        s = UUID.sub("<uuid>", s)
        s = HTTP_DATE.sub("<timestamp>", s)
        s = ISO_TS.sub("<timestamp>", s)
        s = ACCOUNT.sub("<account>", s)
        if DIGEST_KEYS.search(key):
            return s
        s = AP_ALIAS.sub("-<rand>-s3alias", s)
        s = RESOURCE_ID.sub(lambda m: f"{m.group(1)}-<id>", s)
        s = R53_BARE_ID.sub(lambda m: "<id>" if any(c.isdigit() for c in m.group(0)) else m.group(0), s)
        s = LONG_HEX.sub("<hex>", s)
        s = TOKEN.sub("<token>", s)
        return s

    def value(self, v, key: str = ""):
        """Normalize one parsed value (recursively)."""
        collided: set = set()
        if isinstance(v, dict):
            out: dict = {}
            for k, x in v.items():
                nk = self.text(k) if isinstance(k, str) else k
                nv = self.value(x, k)
                if nk != k and nk in out:
                    # Generated map keys (version ids, ...) collide once
                    # normalized: keep every value, order-independent.
                    prev = out[nk] if isinstance(out[nk], list) and nk in collided else [out[nk]]
                    out[nk] = sorted(prev + [nv], key=lambda y: json.dumps(y, sort_keys=True, default=str))
                    collided.add(nk)
                else:
                    out[nk] = nv
            # A digest of a body that holds generated values can't match
            # across emulators; check it on each side instead.
            for body, digest in (("Body", "MD5OfBody"), ("MessageBody", "MD5OfMessageBody")):
                if isinstance(v.get(body), str) and isinstance(v.get(digest), str):
                    ok = hashlib.md5(v[body].encode()).hexdigest() == v[digest]
                    out[digest] = "<md5 of body: ok>" if ok else f"<md5 of body: WRONG ({v[digest]})>"
            return out
        if isinstance(v, (list, tuple)):
            return [self.value(x, key) for x in v]
        if isinstance(v, (dt.datetime, dt.date)):
            return "<timestamp>"
        if isinstance(v, (bytes, bytearray)):
            if RANDOM_BYTES_KEYS.match(key):
                return {"<bytes>": len(v)}
            return self.bytes_(bytes(v))
        if hasattr(v, "read"):  # StreamingBody
            try:
                return self.bytes_(v.read())
            except Exception as e:  # noqa: BLE001
                return f"<unreadable stream: {e}>"
        if VOLATILE_KEYS.match(key) and v not in (None, "", [], {}, "null") and not (
            isinstance(v, str) and re.fullmatch(r"v\d+", v)
        ):
            return f"<{key}>"
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, (int, float)) and TIME_KEYS.search(key) and abs(v) > 10**8:
            return "<timestamp>"
        if isinstance(v, str):
            if TIME_KEYS.search(key) and v.isdigit() and len(v) >= 9:
                return "<timestamp>"
            t = self.text(v, key)
            if t == v and ID_KEYS.search(key) and GENERATED.fullmatch(v) and any(c.isdigit() for c in v):
                # Keep the AWS id prefix (AROA, AIDA, ANPA, ...) so a wrong
                # prefix still shows up as a difference.
                m = re.match(r"[A-Z]{4}(?=[A-Z0-9]{12,}$)", v)
                return f"<id:{m.group(0)}>" if m else "<id>"
            return t
        return v

    def bytes_(self, b: bytes):
        try:
            text = b.decode("utf-8")
        except UnicodeDecodeError:
            return {"<bytes>": len(b), "sha256": hashlib.sha256(b).hexdigest()}
        return {"<bytes>": len(b), "text": self.text(text)}


def jsonable(v, limit: int = 262_144):
    """Make a raw value JSON-serialisable for the report (bodies, params)."""
    if isinstance(v, dict):
        return {str(k): jsonable(x, limit) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [jsonable(x, limit) for x in v]
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        try:
            s = b.decode("utf-8")
            return s if len(s) <= limit else s[:limit] + f"... <{len(s) - limit} more chars>"
        except UnicodeDecodeError:
            enc = base64.b64encode(b[:limit]).decode()
            return {"<base64>": enc, "length": len(b), "truncated": len(b) > limit}
    if isinstance(v, str) and len(v) > limit:
        return v[:limit] + f"... <{len(v) - limit} more chars>"
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if hasattr(v, "read"):
        return "<stream>"
    return repr(v)
