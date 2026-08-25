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
import re
import uuid
from dataclasses import dataclass
from ipaddress import ip_address

# An authority-qualified principal for an account with no Xbox identity, as issued by the proxy:
# "direct-frontend:<frontend-id>:<authenticated-uuid>". Mirrors AuthData's own pattern.
_DIRECT_PRINCIPAL = re.compile(
    r"direct-frontend:[a-z0-9][a-z0-9._-]{0,63}:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class VerificationError(RuntimeError):
    """The proxy did not approve a pending backend join."""


@dataclass(frozen=True)
class VerifiedIdentity:
    name: str
    xuid: str
    principal: str
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
        # Optional so a proxy older than the direct-frontend contract still verifies: it simply
        # never sends an empty XUID, and the branch below that needs a principal is never taken.
        response_principal = str(payload.get("principal") or "")
        backend = str(payload.get("backend") or "")
        real_ip = str(payload.get("real_ip") or "").strip()
        real_port = int(payload.get("real_port") or 0)
    except Exception as exc:
        raise VerificationError("proxy returned an invalid identity response") from exc

    if response_name.casefold() != str(name).casefold():
        raise VerificationError("proxy returned a different player name")
    try:
        response_uuid = str(uuid.UUID(response_uuid))
    except (ValueError, AttributeError) as exc:
        raise VerificationError("proxy returned an invalid UUID") from exc

    # Two kinds of account reach a backend through the proxy and they are identified differently.
    # An Xbox player has a numeric XUID. A direct frontend - a Java account admitted by a proxy
    # plugin - deliberately has none, and asserts an authority-qualified principal instead, so
    # demanding digits of everyone locks those players out permanently.
    #
    # An empty XUID is still not accepted on its own. It is accepted only when the proxy also
    # returns a direct principal bound to the UUID in the same response, which is the invariant the
    # proxy enforces when it mints one. That keeps a proxy which has simply lost a player's identity
    # from looking like a valid direct frontend.
    if response_xuid:
        if not response_xuid.isascii() or not response_xuid.isdigit():
            raise VerificationError("proxy returned an invalid XUID")
        if response_principal and response_principal != "xbox-live:" + response_xuid:
            raise VerificationError("proxy returned a principal that does not match its XUID")
    elif not _DIRECT_PRINCIPAL.fullmatch(response_principal):
        raise VerificationError("proxy returned an invalid XUID")
    elif not response_principal.endswith(":" + response_uuid):
        raise VerificationError("proxy returned a principal that does not match its UUID")

    try:
        real_ip = str(ip_address(real_ip)) if real_ip else ""
    except ValueError as exc:
        raise VerificationError("proxy returned an invalid real client IP") from exc
    if not 0 <= real_port <= 65535:
        raise VerificationError("proxy returned an invalid real client port")

    return VerifiedIdentity(
        response_name,
        response_xuid,
        response_principal,
        response_uuid,
        backend,
        real_ip,
        real_port,
    )
