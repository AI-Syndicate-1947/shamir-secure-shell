"""Unit tests for AWS helpers (mocked; no live AWS calls)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from shamir_ssh import aws_secrets


def _not_found() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "x"}},
        "DescribeSecret",
    )


def _session_with_client(mock_client: MagicMock):
    mock_session = MagicMock()
    mock_session.client.return_value = mock_client
    return mock_session


def test_push_create_when_missing():
    mock_client = MagicMock()
    mock_client.describe_secret.side_effect = _not_found()

    with patch("shamir_ssh.aws_secrets._session", return_value=_session_with_client(mock_client)):
        aws_secrets.push_consolidated_secret(
            "my-secret",
            '{"a":1}',
            region="ca-central-1",
            profile="default",
            create_if_missing=True,
        )

    mock_client.create_secret.assert_called_once_with(
        Name="my-secret", SecretString='{"a":1}'
    )
    mock_client.put_secret_value.assert_not_called()


def test_push_put_when_exists():
    mock_client = MagicMock()
    mock_client.describe_secret.return_value = {"ARN": "arn:..."}

    with patch("shamir_ssh.aws_secrets._session", return_value=_session_with_client(mock_client)):
        aws_secrets.push_consolidated_secret(
            "my-secret",
            '{"a":1}',
            region="ca-central-1",
            profile=None,
            create_if_missing=False,
        )

    mock_client.put_secret_value.assert_called_once_with(
        SecretId="my-secret", SecretString='{"a":1}'
    )
    mock_client.create_secret.assert_not_called()


def test_push_missing_without_create():
    mock_client = MagicMock()
    mock_client.describe_secret.side_effect = _not_found()

    with patch("shamir_ssh.aws_secrets._session", return_value=_session_with_client(mock_client)):
        with pytest.raises(ValueError, match="not found"):
            aws_secrets.push_consolidated_secret(
                "missing",
                "{}",
                region="ca-central-1",
                profile=None,
                create_if_missing=False,
            )


def test_push_create_rejects_arn():
    mock_client = MagicMock()
    mock_client.describe_secret.side_effect = _not_found()

    with patch("shamir_ssh.aws_secrets._session", return_value=_session_with_client(mock_client)):
        with pytest.raises(ValueError, match="name, not an ARN"):
            aws_secrets.push_consolidated_secret(
                "arn:aws:secretsmanager:ca-central-1:123:secret:x",
                "{}",
                region="ca-central-1",
                profile=None,
                create_if_missing=True,
            )


def test_get_secret_string():
    mock_client = MagicMock()
    mock_client.get_secret_value.return_value = {"SecretString": '{"ok":true}'}

    with patch("shamir_ssh.aws_secrets._session", return_value=_session_with_client(mock_client)):
        s = aws_secrets.get_secret_string(
            secret_id="name", region="ca-central-1", profile="p"
        )
    assert s == '{"ok":true}'
