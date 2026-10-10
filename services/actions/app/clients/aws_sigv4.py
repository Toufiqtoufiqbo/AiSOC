"""AWS Signature Version 4, signed once for every AWS client in this service.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html

Why this is not boto3
---------------------
The reasoning is `aws_cloudtrail_client.py`'s and has not changed: boto3 is
not a dependency of `services/actions`, `import boto3` raises
`ModuleNotFoundError` on the published image, and boto3 plus botocore is tens
of megabytes of wheel against a service ADR-0007 moved into CORE on the
strength of a 539 MB image. SigV4 is about seventy lines of `hmac` and
`hashlib`.

Why it is a module rather than a method
---------------------------------------
Depth 5.5 adds IAM and EC2 alongside CloudTrail, and all three sign the same
way. Three copies of a signing algorithm is three places for one of them to
drift into producing a signature AWS rejects — which surfaces as an
authentication failure an operator reads as "our credentials are wrong",
sending them to look at IAM rather than at us.

Two shapes, because AWS has two
--------------------------------
CloudTrail takes a JSON body with an `X-Amz-Target` header; IAM and EC2 take
the older Query protocol, a form-encoded body with `Action=` and `Version=`.
Both are POSTs to `/` and both sign identically below the content type.

What is and is not verified
---------------------------
The canonical request, the string to sign and the derived signing key are
pinned by tests against the worked example in AWS's own documentation, so the
algorithm cannot drift silently. **No call has been made against live AWS
from this repository** — there is no funded account here — so the live path
is unverified and every capability contract built on it says so rather than
implying otherwise.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"

#: The Query-protocol content type IAM and EC2 use. Named because it is part
#: of the signature: a client that signs one content type and sends another
#: gets a signature mismatch and no hint as to why.
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_access_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key.

    Four chained HMACs over date, region, service and the fixed terminator,
    in that order. Split out so a test can pin the derivation itself rather
    than only the header it ends up in.
    """
    k_date = _sign(f"AWS4{secret_access_key}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def canonical_parts(
    *,
    headers: dict[str, str],
    payload: str,
    amz_date: str,
    date_stamp: str,
    region: str,
    service: str,
    method: str = "POST",
    path: str = "/",
    query: str = "",
) -> tuple[str, str, str]:
    """``(canonical_request, string_to_sign, signed_headers)``.

    Returned as data rather than folded into the header builder so a test can
    grade the algorithm rather than a copy of itself — the one-directional
    shape this repository keeps finding, where a test compares a producer
    against a restatement of the producer and prints OK.
    """
    signed_names = sorted(name.lower() for name in headers)
    lowered = {name.lower(): value for name, value in headers.items()}
    canonical_headers = "".join(f"{name}:{lowered[name].strip()}\n" for name in signed_names)
    signed_headers = ";".join(signed_names)

    canonical_request = "\n".join(
        [
            method,
            path,
            query,
            canonical_headers,
            signed_headers,
            hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        ]
    )
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            f"{date_stamp}/{region}/{service}/aws4_request",
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    return canonical_request, string_to_sign, signed_headers


def sign(
    *,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    region: str,
    service: str,
    host: str,
    payload: str,
    content_type: str,
    amz_target: str | None = None,
    now: dt.datetime | None = None,
    method: str = "POST",
    path: str = "/",
    query: str = "",
) -> dict[str, str]:
    """The complete header set for one signed request.

    Headers are returned lowercased, which is how they were signed. HTTP
    header names are case-insensitive, and sending exactly the bytes that
    were signed removes any chance of the signature covering one spelling
    while the wire carries another.
    """
    moment = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = moment.strftime("%Y%m%d")

    headers = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
    }
    if amz_target:
        headers["x-amz-target"] = amz_target
    if session_token:
        headers["x-amz-security-token"] = session_token

    _, string_to_sign, signed_headers = canonical_parts(
        headers=headers,
        payload=payload,
        amz_date=amz_date,
        date_stamp=date_stamp,
        region=region,
        service=service,
        method=method,
        path=path,
        query=query,
    )
    signature = hmac.new(
        signing_key(secret_access_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    return {
        **headers,
        "authorization": (
            f"{ALGORITHM} Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


def form_body(params: dict[str, str]) -> str:
    """Encode Query-protocol parameters the way the canonical request expects.

    Sorted by key and percent-encoded with ``safe=""``, because the body is
    hashed into the signature: any difference between what is encoded here
    and what is sent is a signature mismatch, and AWS reports that as a
    credential error.
    """
    return "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in sorted(params.items()))
