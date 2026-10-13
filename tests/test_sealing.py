"""Sealed envelopes carry verified channel metadata to a tool server in another process.
Anything that doesn't verify opens as None, which classifies as a third party."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

from agent_guardrails.identity import Envelope
from agent_guardrails.sealing import open_envelope, seal_envelope

KEY = b"k" * 32
NOW = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)
ENV = Envelope(channel="sms", sender="+15550001111", verified=True, text="read my email",
               message_id="SM123")


def test_round_trip():
    token = seal_envelope(ENV, KEY, now=NOW)
    assert open_envelope(token, KEY, now=NOW + timedelta(seconds=30)) == ENV


def test_the_verified_flag_is_carried_as_sealed():
    unverified = Envelope(channel="sms", sender="+15550001111", verified=False)
    assert open_envelope(seal_envelope(unverified, KEY, now=NOW), KEY, now=NOW).verified is False


def test_a_tampered_token_does_not_open():
    prefix, body, sig = seal_envelope(ENV, KEY, now=NOW).split(".")
    other = seal_envelope(Envelope("sms", "+15550002222", verified=True), KEY, now=NOW)
    forged = f"{prefix}.{other.split('.')[1]}.{sig}"            # swap the body, keep the sig
    assert open_envelope(forged, KEY, now=NOW) is None
    assert open_envelope(f"{prefix}.{body}.{sig[:-2]}AA", KEY, now=NOW) is None


def test_the_wrong_key_does_not_open():
    assert open_envelope(seal_envelope(ENV, KEY, now=NOW), b"x" * 32, now=NOW) is None


def test_expired_and_future_dated_tokens_do_not_open():
    token = seal_envelope(ENV, KEY, now=NOW)
    assert open_envelope(token, KEY, now=NOW + timedelta(minutes=6)) is None
    assert open_envelope(token, KEY, now=NOW - timedelta(minutes=2)) is None
    assert open_envelope(token, KEY, now=NOW + timedelta(minutes=4)) == ENV


@pytest.mark.parametrize("token", ["", "abc", "agr1.x.y", "agr2.e30.AAAA", None, 42,
                                   "agr1." + "A" * 70000 + ".sig"],
                         ids=["empty", "junk", "bad-sig", "wrong-version", "none", "int",
                              "oversized"])
def test_garbage_does_not_open(token):
    assert open_envelope(token, KEY, now=NOW) is None


@pytest.mark.parametrize("signature", ["\u00e9", "\uff21" * 43, "\ud800"])
def test_non_ascii_signatures_do_not_crash(signature):
    prefix, body, _ = seal_envelope(ENV, KEY, now=NOW).split(".")
    assert open_envelope(f"{prefix}.{body}.{signature}", KEY, now=NOW) is None


@pytest.mark.parametrize("iat", [10 ** 20, -10 ** 10, 2 ** 40])   # Overflow / OSError on Windows
def test_a_validly_signed_but_absurd_timestamp_does_not_crash(iat):
    body = base64.urlsafe_b64encode(json.dumps(
        {"iat": iat, "channel": "sms", "sender": "+15550001111", "verified": True,
         "text": "", "message_id": ""}).encode()).rstrip(b"=").decode()
    mac = base64.urlsafe_b64encode(hmac.new(KEY, f"agr1.{body}".encode(),
                                            hashlib.sha256).digest()).rstrip(b"=").decode()
    assert open_envelope(f"agr1.{body}.{mac}", KEY, now=NOW) is None


def test_keys_must_be_long_enough():
    with pytest.raises(ValueError):
        seal_envelope(ENV, b"short", now=NOW)
    with pytest.raises(ValueError):
        open_envelope("agr1.x.y", b"short", now=NOW)
