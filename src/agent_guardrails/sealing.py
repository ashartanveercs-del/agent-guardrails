"""Sealed envelopes: verified channel metadata that can cross a process boundary.

When tools run in a separate server (MCP or any RPC), that server never saw the inbound
webhook, so it can't verify who is talking. The gateway that *did* verify it seals the
:class:`~agent_guardrails.identity.Envelope` with an HMAC-SHA256 key shared with the tool
server and attaches the token to each tool call out of band (MCP ``_meta``), never inside
the model-visible arguments. The tool server opens it; anything that fails to open - bad
signature, wrong key, expired, malformed - comes back as ``None``, which
:func:`~agent_guardrails.identity.classify_turn` treats as a third party.

Format: ``agr1.<base64url(json)>.<base64url(hmac)>``; the MAC covers the version prefix and
the body, and is compared in constant time.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta

from .identity import Envelope

log = logging.getLogger(__name__)

PREFIX = "agr1"
MIN_KEY_BYTES = 32
MAX_TOKEN_CHARS = 65_536
CLOCK_SKEW = timedelta(seconds=60)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes | bytearray) or len(key) < MIN_KEY_BYTES:
        raise ValueError(f"envelope keys must be at least {MIN_KEY_BYTES} bytes")


def _mac(key: bytes, body: str) -> str:
    return _b64(hmac.new(key, f"{PREFIX}.{body}".encode("ascii"), hashlib.sha256).digest())


def seal_envelope(envelope: Envelope, key: bytes, *, now: datetime | None = None) -> str:
    _check_key(key)
    issued = now or datetime.now(UTC)
    payload = {"iat": int(issued.timestamp()), "channel": envelope.channel,
               "sender": envelope.sender, "verified": bool(envelope.verified),
               "text": envelope.text, "message_id": envelope.message_id}
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"{PREFIX}.{body}.{_mac(key, body)}"


def open_envelope(token: object, key: bytes, *, now: datetime | None = None,
                  max_age: timedelta = timedelta(minutes=5)) -> Envelope | None:
    """The sealed envelope, or ``None`` if it doesn't verify for any reason."""
    _check_key(key)
    if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    body, signature = parts[1], parts[2]
    if not signature.isascii():
        return None  # compare_digest accepts only ASCII strings; malformed metadata denies
    try:
        expected = _mac(key, body)
    except UnicodeEncodeError:
        return None
    if not hmac.compare_digest(expected, signature):
        log.warning("rejected an envelope with a bad signature")
        return None
    try:
        payload = json.loads(_unb64(body))
        issued = datetime.fromtimestamp(int(payload["iat"]), UTC)
        envelope = Envelope(channel=str(payload["channel"]), sender=str(payload["sender"]),
                            verified=payload["verified"] is True, text=str(payload["text"]),
                            message_id=str(payload["message_id"]))
    except (ValueError, KeyError, TypeError, binascii.Error, OverflowError, OSError):
        return None          # OSError: Windows rejects some out-of-range timestamps
    current = now or datetime.now(UTC)
    if issued > current + CLOCK_SKEW or current - issued > max_age:
        log.info("rejected an expired or future-dated envelope")
        return None
    return envelope
