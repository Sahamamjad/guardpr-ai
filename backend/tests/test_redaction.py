"""Secret redaction tests."""

from app.utils.redaction import REDACTED, redact_secrets


def test_redacts_github_token():
    text = "token=ghp_1234567890123456789012345678901234"
    assert REDACTED in redact_secrets(text)
    assert "ghp_" not in redact_secrets(text)


def test_redacts_api_key():
    text = 'api_key = "super-secret-key-value"'
    result = redact_secrets(text)
    assert "super-secret-key-value" not in result


def test_plain_text_unchanged():
    assert redact_secrets("hello world") == "hello world"
