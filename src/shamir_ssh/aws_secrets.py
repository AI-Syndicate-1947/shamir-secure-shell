"""AWS Secrets Manager: push and fetch consolidated share JSON."""

from __future__ import annotations


def _require_boto3():
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError as e:
        raise RuntimeError(
            "boto3 is required for AWS Secrets Manager. Install with: pip install shamir-ssh[aws]"
        ) from e
    return boto3, ClientError


def _session(*, region: str, profile: str | None):
    boto3, _ = _require_boto3()
    kwargs: dict = {"region_name": region}
    if profile:
        kwargs["profile_name"] = profile
    return boto3.Session(**kwargs)


def _is_arn(secret_id: str) -> bool:
    return secret_id.strip().startswith("arn:")


def push_consolidated_secret(
    secret_id: str,
    secret_string: str,
    *,
    region: str,
    profile: str | None,
    create_if_missing: bool,
) -> None:
    """Create or update secret string. Uses CreateSecret only when missing and create_if_missing is True."""
    _, ClientError = _require_boto3()
    client = _session(region=region, profile=profile).client("secretsmanager")
    try:
        client.describe_secret(SecretId=secret_id)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            if not create_if_missing:
                raise ValueError(
                    f"secret {secret_id!r} not found; create it first or pass --create-if-missing"
                ) from e
            if _is_arn(secret_id):
                raise ValueError(
                    "--create-if-missing requires a secret name, not an ARN (CreateSecret uses Name=)"
                ) from e
            client.create_secret(Name=secret_id, SecretString=secret_string)
            return
        raise
    client.put_secret_value(SecretId=secret_id, SecretString=secret_string)


def get_secret_string(*, secret_id: str, region: str, profile: str | None) -> str:
    _, ClientError = _require_boto3()
    client = _session(region=region, profile=profile).client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=secret_id)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            raise ValueError(f"secret {secret_id!r} not found") from e
        raise
    s = resp.get("SecretString")
    if s is None:
        raise ValueError("secret has no SecretString (binary secrets are not supported)")
    return s
