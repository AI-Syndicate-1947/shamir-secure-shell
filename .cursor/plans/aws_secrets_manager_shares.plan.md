---
name: AWS Secrets Manager for Shamir Shares
overview: Store all Shamir shares from one split as a single normalized JSON secret in AWS Secrets Manager (ca-central-1, profile default, ~/.aws with temporary credentials). Support push (overwrite via new version) and pull+combine round-trip via CLI flags only.
todos:
  - id: consolidated-format
    content: Add consolidate_shares / parse_consolidated_secret helpers + validation (scheme, k, n, shared fields, n distinct x)
    status: completed
  - id: boto3-extra
    content: Add optional dependency boto3 (e.g. pip install shamir-ssh[aws]) and aws_sm module for Get/Put/CreateSecret
    status: completed
  - id: cli-secrets-push
    content: Add secrets push subcommand (--secret-id, --region, --profile, share file paths, --create-if-missing)
    status: completed
  - id: cli-secrets-pull
    content: Add secrets pull-combine subcommand (same AWS flags, -o output path)
    status: completed
  - id: docs-tests
    content: Document IAM, versioning/caveats, and add unit tests for JSON consolidate/parse (mock boto3 for push/pull optional)
    status: completed
isProject: false
---

# Plan: AWS Secrets Manager storage for Shamir shares

## Decisions (confirmed)

| Topic | Choice |
|--------|--------|
| Region | `ca-central-1` (default in docs/examples; overridable via CLI) |
| Credentials | AWS profile **`default`**, files under **`~/.aws`** (session token supported automatically by boto3) |
| Scope | **Both**: upload/overwrite **and** download + `combine` to recover the key file |
| Secret identity | **CLI flags only** (e.g. `--secret-id`, `--region`, `--profile`) — no required env-based config |

## Problem: one secret vs many keys

Each generated **share JSON** today duplicates the same fields: `scheme`, `k`, `n`, `nonce_b64`, `ciphertext_b64`, `fingerprint_sha256`. Only **`x`** and **`y`** differ per share.

**AWS Secrets Manager** stores a secret value as a **single string** (typically JSON). You are not forced to use flat top-level keys `x_1`, `y_1`, … `x_20`, `y_20` unless you want that for human scanning. A **normalized** shape avoids key clashes and avoids repeating ciphertext and nonce **n** times.

### Recommended secret payload (one JSON object)

```json
{
  "scheme": "shamir_ssh_envelope_v1",
  "k": 3,
  "n": 5,
  "nonce_b64": "...",
  "ciphertext_b64": "...",
  "fingerprint_sha256": "...",
  "shares": [
    { "x": 1, "y": "....hex...." },
    { "x": 2, "y": "....hex...." }
  ]
}
```

- **`shares`**: array of `{ "x", "y" }` only — no duplicate envelope fields per entry.
- **Round-trip**: implementation expands each element plus the common fields into the full share dicts expected by existing [`combine_share_objects`](src/shamir_ssh/operations.py).

### Alternative (acceptable but not preferred)

Flat keys `x_1`, `y_1`, … — works if indices are unique; more error-prone for parsers and humans.

## AWS API behavior

- **Overwrite**: `PutSecretValue` replaces the secret **string** and creates a **new version**. Document that prior versions may remain recoverable per account/retention policy.
- **First-time create**: use `CreateSecret` when the secret name does not exist; gate behind an explicit flag **`--create-if-missing`** to avoid accidental secret creation.
- **Temporary credentials**: standard boto3 session from profile; no custom session-token logic beyond what the AWS SDK already reads from `~/.aws/credentials`.

## Planned CLI (flags only)

### `secrets push`

- **Input**: paths to existing per-share JSON files (same format as today), or stdin JSONL of shares (optional; align with one approach in implementation).
- **Flags**: `--secret-id` (name or ARN), `--region`, `--profile` (optional; default profile chain if omitted).
- **Flags**: `--create-if-missing` for initial `CreateSecret`.
- **Flow**: load → validate single bundle → build normalized JSON → `PutSecretValue` (or `CreateSecret` + optional first put).

### `secrets pull-combine`

- **Flags**: same AWS flags as push.
- **Flags**: `-o` / `--output` path for recovered private key (same semantics as local `combine`).
- **Flow**: `GetSecretValue` → parse normalized JSON → expand to list of full share dicts → `combine_share_objects` → write file + chmod where supported.

## Implementation outline

| Piece | Location / note |
|--------|------------------|
| Consolidate + parse + strict validation | e.g. [`src/shamir_ssh/consolidated_secret.py`](src/shamir_ssh/consolidated_secret.py) (new) |
| boto3 calls | e.g. [`src/shamir_ssh/aws_secrets.py`](src/shamir_ssh/aws_secrets.py) (new), thin wrapper |
| CLI wiring | extend [`src/shamir_ssh/cli.py`](src/shamir_ssh/cli.py) with `secrets` subcommand group |
| Dependency | [`pyproject.toml`](pyproject.toml): optional extra `[aws]` → `boto3>=1.34` |

**Validation rules (push):** all shares same `scheme`, `k`, `n`, `nonce_b64`, `ciphertext_b64`, `fingerprint_sha256`; `len(shares) == n`; distinct `x`; each `y` non-empty hex consistent with current format.

## IAM (reference)

Typical least-privilege for an operator or CI role:

- **Push**: `secretsmanager:PutSecretValue`; if create allowed: `secretsmanager:CreateSecret`; optional `secretsmanager:DescribeSecret` to branch create vs put.
- **Pull**: `secretsmanager:GetSecretValue`.
- **KMS**: if the secret uses a customer-managed CMK, grant `kms:Decrypt` / `kms:GenerateDataKey*` as required by your key policy.

## Documentation updates

- [README.md](README.md): new section for AWS workflow, profile/region, `--create-if-missing`, and warning about **version history** and **treating the secret like key material**.
- Optional: link this plan from README for operators who want the full design.

## Testing strategy

- **Unit tests**: consolidate + parse round-trip from synthetic share dicts; negative tests (mismatched metadata, wrong `n`, duplicate `x`).
- **Integration**: optional mocked boto3 client (no live AWS in CI) for push/pull code paths.

## Optional later enhancements

- One-shot `split` flag to push to SM without intermediate files (convenience).
- `KmsKeyId` on `CreateSecret` for CMK choice.
- Resource tags on `CreateSecret` for governance.
