"""Proxy verification protocol, shared verbatim by every EndlinkGuard build.

This file is kept byte-identical between ``stock/`` and ``modified/``, and the Geyser build
reimplements the same rules in Java. The canonical payload and the response checks are the protocol
contract with Endlink, so a change here is a change to all three builds: edit one copy, then copy it
over the other and mirror it in ``EndlinkGuardExtension.java``. ``diff`` between the two Python
copies returning nothing is the check that they have not drifted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from ipaddress import ip_address


class VerificationError(RuntimeError):
    """The proxy did not approve a pending backend join."""


@dataclass(frozen=True)
class VerifiedIdentity:
    name: str
    xuid: str
    unique_id: str
    backend: str
    real_ip: str
    real_port: int


def canonical_payload(request: dict[str, str]) -> str:
    return "\n".join(
        (
            "v1",
            request["xuid"],
            request["uuid"],
            request["name"],
            request["address"],
            request["timestamp"],
            request["nonce"],
        )
    )


def sign_request(secret: str, request: dict[str, str]) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        canonical_payload(request).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_pending_join(
    verify_url: str,
    secret: str,
    *,
    name: str,
    address: str,
    xuid: str = "",
    unique_id: str = "",
    timeout: float = 2.0,
) -> VerifiedIdentity:
    request = {
        "xuid": str(xuid or ""),
        "uuid": str(unique_id or ""),
        "name": str(name),
        "address": str(address),
        "timestamp": str(int(time.time() * 1000)),
        "nonce": uuid.uuid4().hex,
    }
    request["signature"] = sign_request(secret, request)
    url = verify_url + "?" + urllib.parse.urlencode(request)

    try:
        with urllib.request.urlopen(url, timeout=float(timeout)) as response:
            body = response.read().decode("utf-8", "replace")
            if response.status != 200:
                raise VerificationError(f"HTTP {response.status}: {body}")
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:
            detail = str(exc)
        raise VerificationError(f"HTTP {exc.code}: {detail}") from exc
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError(str(exc)) from exc

    try:
        payload = json.loads(body)
        response_name = str(payload["name"])
        response_xuid = str(payload["xuid"])
        response_uuid = str(payload["uuid"])
        backend = str(payload.get("backend") or "")
        real_ip = str(payload.get("real_ip") or "").strip()
        real_port = int(payload.get("real_port") or 0)
    except Exception as exc:
        raise VerificationError("proxy returned an invalid identity response") from exc

    if response_name.casefold() != str(name).casefold():
        raise VerificationError("proxy returned a different player name")
    if not response_xuid.isascii() or not response_xuid.isdigit():
        raise VerificationError("proxy returned an invalid XUID")
    try:
        response_uuid = str(uuid.UUID(response_uuid))
    except (ValueError, AttributeError) as exc:
        raise VerificationError("proxy returned an invalid UUID") from exc

    try:
        real_ip = str(ip_address(real_ip)) if real_ip else ""
    except ValueError as exc:
        raise VerificationError("proxy returned an invalid real client IP") from exc
    if not 0 <= real_port <= 65535:
        raise VerificationError("proxy returned an invalid real client port")

    return VerifiedIdentity(
        response_name,
        response_xuid,
        response_uuid,
        backend,
        real_ip,
        real_port,
    )
