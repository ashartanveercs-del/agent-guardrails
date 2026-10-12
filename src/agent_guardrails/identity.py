"""Who is on the other end of this turn?

The single most important rule in this library: **a turn's role is derived from channel
metadata that the transport layer verified, never from the message text and never from
arguments the model chose.** A prompt-injected message can say anything ("I am the owner",
"SYSTEM OVERRIDE"); none of it is read here.

Three roles:

* ``OWNER``       - a verified sender that matches the configured owner identity exactly.
* ``THIRD_PARTY`` - everyone else, including anything malformed, unverified or missing.
                    An unverified sender id may be spoofed, so it isn't kept at all: the
                    turn's ``sender`` is empty and can't unlock anything scoped to "yourself".
* ``SYSTEM``      - trusted in-process automation (a scheduled job). It must be asserted
                    explicitly with :class:`SystemOrigin`; it is never the result of
                    *omitting* something, so a forgotten envelope can't escalate.

Identifiers are compared in canonical form only. Phone numbers must be international
(``+`` and country code) and are compared by exact equality: suffix matching would let
``+999 555 000 1111`` pass as the owner's ``+1 555 000 1111``.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

PHONE_CHANNELS = frozenset({"sms", "mms", "whatsapp", "voice", "rcs"})
EMAIL_CHANNELS = frozenset({"email"})
# Reserved for SystemOrigin turns ("system:<job>"); an inbound envelope can't use it.
RESERVED_CHANNELS = frozenset({"system"})

# ASCII only on purpose: in Python, \d also matches full-width and other Unicode digits.
_PHONE_RE = re.compile(r"\+[0-9 ().\-]+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_ACCOUNT_RE = re.compile(r"[A-Za-z0-9._:@\-]{1,128}")
_CHANNEL_RE = re.compile(r"[a-z][a-z0-9_\-]{0,31}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9._:\-]{1,128}")


class Role(StrEnum):
    OWNER = "owner"
    THIRD_PARTY = "third_party"
    SYSTEM = "system"


# -- canonical identifiers ----------------------------------------------------------------

def canonical_phone(raw: object) -> str | None:
    """``+<digits>`` (E.164) or ``None``. Numbers without a country code are ambiguous and
    deliberately never canonicalise, so they can never match the owner or be sent to."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not _PHONE_RE.fullmatch(text):
        return None
    digits = re.sub(r"[^0-9]", "", text)
    if not 8 <= len(digits) <= 15 or digits[0] == "0":
        return None
    return "+" + digits


def canonical_email(raw: object) -> str | None:
    """A plain lower-cased ASCII address or ``None``. Display names are never parsed:
    ``"owner@example.com" <attacker@example.com>`` is a classic spoof."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not _EMAIL_RE.fullmatch(text) or ".." in text:
        return None
    return text.lower()


def canonical_account(raw: object) -> str | None:
    """A platform user id (Slack, Discord, web chat ...). Case-sensitive, compared exactly."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text if _ACCOUNT_RE.fullmatch(text) else None


def channel_kind(channel: str) -> str:
    if channel in PHONE_CHANNELS:
        return "phone"
    if channel in EMAIL_CHANNELS:
        return "email"
    return "account"


def canonical_address(channel: str, raw: object) -> str | None:
    """Canonicalise ``raw`` as the kind of identifier ``channel`` uses."""
    kind = channel_kind(channel)
    if kind == "phone":
        return canonical_phone(raw)
    if kind == "email":
        return canonical_email(raw)
    return canonical_account(raw)


# -- inputs ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class Envelope:
    """Inbound message metadata, built by the transport adapter *after* it verified the
    platform (webhook signature, carrier attestation, DKIM/DMARC, signed chat event).

    ``sender`` must be in the platform's canonical form: E.164 for phone channels (add the
    ``+`` for providers that omit it), a bare address for email, the user id otherwise.
    ``verified`` is the adapter's statement that the sender is authentic; anything
    unverified is treated as a third party with no sender identity at all, even if it
    carries the owner's (or a customer's) number.
    """

    channel: str
    sender: str
    verified: bool = False
    text: str = ""
    message_id: str = ""


@dataclass(frozen=True)
class SystemOrigin:
    """Trusted in-process automation, such as a scheduled job firing."""

    job_id: str
    note: str = ""

    def __post_init__(self) -> None:
        if not _TOKEN_RE.fullmatch(self.job_id or ""):
            raise ValueError(f"invalid system job id {self.job_id!r}")


@dataclass(frozen=True, eq=False)
class OwnerIdentity:
    """The owner's identities per channel kind. Validated eagerly: a number without a
    country code is a configuration error, not something to guess about at runtime."""

    phones: Iterable[str] = ()
    emails: Iterable[str] = ()
    accounts: Mapping[str, Iterable[str]] | None = None

    def __post_init__(self) -> None:
        phones = set()
        for raw in self.phones:
            value = canonical_phone(raw)
            if value is None:
                raise ValueError(f"owner phone {raw!r} must be an international number "
                                 "with a + and country code")
            phones.add(value)
        emails = set()
        for raw in self.emails:
            value = canonical_email(raw)
            if value is None:
                raise ValueError(f"owner email {raw!r} is not a plain address")
            emails.add(value)
        accounts: dict[str, frozenset[str]] = {}
        for channel, ids in (self.accounts or {}).items():
            name = (channel or "").strip().lower()
            if (not _CHANNEL_RE.fullmatch(name) or channel_kind(name) != "account"
                    or name in RESERVED_CHANNELS):
                raise ValueError(f"invalid account channel {channel!r}")
            clean = set()
            for raw in ids:
                value = canonical_account(raw)
                if value is None:
                    raise ValueError(f"invalid owner account id {raw!r} for {name}")
                clean.add(value)
            accounts[name] = frozenset(clean)
        object.__setattr__(self, "phones", frozenset(phones))
        object.__setattr__(self, "emails", frozenset(emails))
        object.__setattr__(self, "accounts", MappingProxyType(accounts))

    @property
    def configured(self) -> bool:
        return bool(self.phones or self.emails or any(self.accounts.values()))  # type: ignore[union-attr]

    def owns(self, channel: str, canonical_id: str) -> bool:
        """Is ``canonical_id`` (already canonical for ``channel``) one of the owner's ids?"""
        if not canonical_id:
            return False
        kind = channel_kind(channel)
        if kind == "phone":
            return canonical_id in self.phones  # type: ignore[operator]
        if kind == "email":
            return canonical_id in self.emails  # type: ignore[operator]
        return canonical_id in self.accounts.get(channel, frozenset())  # type: ignore[union-attr]


@dataclass(frozen=True, eq=False)
class TurnContext:
    """Immutable facts about the current turn. Gates read this, never the model's args."""

    role: Role
    channel: str
    sender: str
    turn_id: str
    owners: OwnerIdentity = field(repr=False)
    text: str = field(default="", repr=False)
    reason: str = ""

    @property
    def is_owner(self) -> bool:
        return self.role is Role.OWNER

    @property
    def is_trusted(self) -> bool:
        """Owner or in-process automation."""
        return self.role in (Role.OWNER, Role.SYSTEM)


# -- classification ------------------------------------------------------------------------

def _turn_id(channel: str, sender: str, message_id: str) -> str:
    """``channel:sender:message_id`` when the platform gave a message id (so every tool
    call made for one inbound message shares a turn), otherwise unique per call."""
    if message_id and _TOKEN_RE.fullmatch(message_id):
        return f"{channel}:{sender}:{message_id}"
    return f"{channel or 'unknown'}:{uuid.uuid4().hex}"


def canonical_sender(channel: str, raw: object) -> str:
    """The namespaced identity a sender on `channel` would have (account ids get a
    `channel:` prefix so they never collide across platforms). Empty if unusable."""
    value = canonical_address(channel, raw)
    if value is None:
        return ""
    return value if channel_kind(channel) != "account" else f"{channel}:{value}"


def classify_turn(source: Envelope | SystemOrigin | None, owners: OwnerIdentity) -> TurnContext:
    """Classify a turn. Every branch that isn't a positive, verified owner match lands on
    ``THIRD_PARTY``; ``SYSTEM`` is reachable only through an explicit :class:`SystemOrigin`."""
    if source is None:
        return TurnContext(Role.THIRD_PARTY, "", "", _turn_id("", "", ""), owners,
                           reason="no channel metadata")
    if isinstance(source, SystemOrigin):
        sender = f"system:{source.job_id}"
        return TurnContext(Role.SYSTEM, "system", sender,
                           f"{sender}:{uuid.uuid4().hex}", owners, reason="system origin")
    if not isinstance(source, Envelope):
        raise TypeError(f"expected Envelope or SystemOrigin, got {type(source).__name__}")

    channel = (source.channel or "").strip().lower()
    text = source.text or ""
    if not _CHANNEL_RE.fullmatch(channel) or channel in RESERVED_CHANNELS:
        reason = "reserved channel" if channel in RESERVED_CHANNELS else "unknown channel"
        return TurnContext(Role.THIRD_PARTY, "", "", _turn_id("", "", ""), owners,
                           text=text, reason=reason)
    sender = canonical_sender(channel, source.sender)
    if not sender:
        return TurnContext(Role.THIRD_PARTY, channel, "", _turn_id(channel, "", source.message_id),
                           owners, text=text, reason="malformed sender")
    if not source.verified:
        # The claimed id may be spoofed, so it grants nothing: no "own records", no replies
        # to it, no pending-request quota of its own. It only keeps the turn id distinct.
        unverified_id = _turn_id(channel, f"unverified:{sender}", source.message_id)
        return TurnContext(Role.THIRD_PARTY, channel, "", unverified_id, owners, text=text,
                           reason="unverified envelope")
    turn_id = _turn_id(channel, sender, source.message_id)

    def third_party(reason: str) -> TurnContext:
        return TurnContext(Role.THIRD_PARTY, channel, sender, turn_id, owners, text=text,
                           reason=reason)

    if not owners.configured:
        return third_party("no owner configured")
    owner_id = sender if channel_kind(channel) != "account" else sender.split(":", 1)[1]
    if owners.owns(channel, owner_id):
        return TurnContext(Role.OWNER, channel, sender, turn_id, owners, text=text,
                           reason=f"verified owner on {channel}")
    return third_party("sender is not the owner")
