"""Webhook signature verification tests."""

import hashlib
import hmac

from app.services.github.webhook_verify import verify_github_signature


def test_valid_signature():
    secret = "test-secret"
    payload = b'{"action":"opened"}'
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert verify_github_signature(payload, sig, secret) is True


def test_invalid_signature():
    assert verify_github_signature(b"{}", "sha256=deadbeef", "secret") is False


def test_missing_signature():
    assert verify_github_signature(b"{}", None, "secret") is False
