# shamir-ssh

`shamir-ssh` is a small Python utility that takes a private key file (for example one produced by `ssh-keygen -t ed25519`, usually in **OpenSSH private key** format) and produces **Shamir secret shares** with a configurable threshold **k** out of **n** total shares. Any **k** valid shares can be combined to recover the **exact original file bytes**; fewer than **k** shares give no useful information about the key under the usual Shamir assumptions (random coefficients, large enough field).

This README explains what the tool does, how it is structured, and how to use it safely. For a full treatment of the mathematics (polynomials, modular arithmetic, Lagrange interpolation) with **worked numeric examples**, see [SHAMIR_SECRET_SHARING_MATH.md](SHAMIR_SECRET_SHARING_MATH.md).

---

## Why an envelope (AES) plus Shamir?

Your private key file can be thousands of bytes. Shamir’s scheme is naturally defined over a **finite field**: the secret is one field element, and each share is a point on a polynomial over that field. If we tried to treat “the whole file” as one integer, we would need a prime larger than that integer, and the arithmetic would be cumbersome. If we split the file byte-by-byte with independent Shamir instances, we would multiply overhead and complicate the story without gaining much for this use case.

This project therefore uses a standard **encrypt-then-split** pattern:

1. **Generate** a fresh random 32-byte **AES-256** key using a cryptographically secure source (`secrets` in Python).
2. **Encrypt** the entire private key file with **AES-256-GCM** (authenticated encryption: confidentiality and integrity of the ciphertext).
3. **Interpret** the 32-byte AES key as a single integer and **split that integer** with Shamir’s scheme over the integers modulo a fixed **521-bit Mersenne prime** \(p = 2^{521} - 1\). That prime is larger than any 256-bit value, so the key always fits in the field.
4. **Emit** one **share** per JSON object. Each share contains:
   - the Shamir point \((x, y)\) for that share;
   - the **same** `nonce_b64` and `ciphertext_b64` for every share (so one share alone is not enough: you need **k** Shamir points to recover the AES key, then you decrypt).

So: **Shamir protects the AES key; GCM protects the file bytes.** Reconstruction recomputes the AES key from **k** points, decrypts, and checks that the SHA-256 fingerprint of the decrypted bytes matches the fingerprint stored in every share.

---

## What is in a share (JSON)?

Each line (or file) is one JSON object. Important fields:

| Field | Meaning |
|--------|--------|
| `scheme` | Format identifier (`shamir_ssh_envelope_v1`). |
| `k` | Threshold: minimum number of shares required to reconstruct. |
| `n` | Total number of shares that were generated in that split. |
| `x` | Share index used as the polynomial input (1 … n in this implementation). |
| `y` | Polynomial value at `x`, stored as a **hexadecimal** string (can be long). |
| `nonce_b64` | Base64 AES-GCM nonce (12 bytes). |
| `ciphertext_b64` | Base64 ciphertext including the GCM authentication tag. |
| `fingerprint_sha256` | Hex SHA-256 of the **plaintext** private key file (for matching and sanity checks). |

All shares from the same run share the same `nonce_b64`, `ciphertext_b64`, `fingerprint_sha256`, `k`, and `n`. They differ in `x` and `y`.

---

## Install

From the project directory:

```bash
cd "Shamir Secret Sharing"
pip install -e ".[dev]"
```

- **Runtime**: Python 3.10+ and `cryptography`.
- **`[dev]`** adds `pytest` and `boto3` (for tests that mock AWS).
- **`[aws]`** adds `boto3` for `secrets push` / `secrets pull-combine` at runtime (optional if you only use local files).

If `shamir-ssh` is not on your `PATH` after install (common on Windows with user installs), use `python -m shamir_ssh` as shown below.

---

## Usage

### Split a private key

Default threshold is **k = 3** and total shares **n = 5**. Without `-o`, the tool prints **one JSON object per line** to standard output (suitable for piping or copy-paste).

```bash
python -m shamir_ssh split -i path/to/id_ed25519
```

Write each share to its own file (recommended for real keys). On Unix-like systems, share files are created with mode `600` when the OS allows it:

```bash
python -m shamir_ssh split -i path/to/id_ed25519 -k 3 -n 5 -o ./shares
```

**Flags:**

| Flag | Description |
|------|--------------|
| `-i`, `--input` | Path to the private key file (required). |
| `-k`, `--threshold` | **k**: minimum shares needed (default 3, must be ≥ 2). |
| `-n`, `--shares` | **n**: total shares (default 5, must be ≥ k). |
| `-o`, `--output-dir` | If set, writes `share_1.json`, …, `share_n.json` into that directory. |

### Combine shares into a key file

Provide **at least k** share files (each may contain one JSON line or multiple lines; the loader collects every non-empty JSON line). You can pass **globs** (`*`, `?`, `[]`) so patterns such as `./shares/share_*.json` work even when the shell does not expand them (common on Windows). The output path is the recovered private key:

```bash
python -m shamir_ssh combine ./shares/share_1.json ./shares/share_2.json ./shares/share_3.json -o recovered_ed25519
python -m shamir_ssh combine ./shares/share_*.json -o recovered_ed25519
```

**Flags:**

| Flag | Description |
|------|--------------|
| `share_files` | One or more paths (positional). |
| `-o`, `--output` | Output path for the recovered key (required). |

After combine, set permissions on the recovered key appropriately (e.g. `chmod 600` on Unix) before using it with `ssh`.

### AWS Secrets Manager (consolidated secret)

You can store **all n shares in a single secret** as one JSON string. The payload **deduplicates** fields that are identical across shares (`nonce_b64`, `ciphertext_b64`, `fingerprint_sha256`, `k`, `n`, `scheme`) and keeps only **`x` and `y`** per share in a `shares` array. The wrapper field `consolidated_version` identifies this layout (currently `1`).

**Install AWS support** (adds `boto3`; also included under `[dev]` for running tests):

```bash
pip install -e ".[aws]"
# or
pip install -e ".[dev]"
```

Credentials use the **standard AWS SDK chain**: shared config in `~/.aws/credentials` and `~/.aws/config`, including **temporary credentials** with `aws_session_token`. Omit `--profile` to use the default credential chain (often the `default` profile when `AWS_PROFILE` is unset). Pass `--profile default` to force that profile explicitly.

**Push** (merge share files into one secret value; **creates a new secret version** on each successful put):

```bash
python -m shamir_ssh secrets push ./shares/share_1.json ./shares/share_2.json ./shares/share_3.json ./shares/share_4.json ./shares/share_5.json \
  --secret-id my-ssh-key-shamir-shares \
  --region ca-central-1 \
  --profile default \
  --create-if-missing

# Same, using a glob (expanded by this tool if the shell passes the pattern literally):
python -m shamir_ssh secrets push "./shares/share_*.json" \
  --secret-id my-ssh-key-shamir-shares \
  --region ca-central-1 \
  --profile default \
  --create-if-missing
```

| Flag | Description |
|------|--------------|
| `share_files` | Paths or **globs** to all **n** per-share JSON files from `split` (positional; e.g. `shares/share_*.json`). |
| `--secret-id` | Secret **name** or ARN. For **first-time create**, use a **name** (not an ARN). |
| `--region` | AWS region (default: **`ca-central-1`**). |
| `--profile` | Credentials profile (optional; default: boto3 default chain). |
| `--create-if-missing` | Call `CreateSecret` if the secret does not exist; otherwise `PutSecretValue` only. |

**Pull and combine** (download the consolidated JSON and write the recovered private key):

```bash
python -m shamir_ssh secrets pull-combine \
  --secret-id my-ssh-key-shamir-shares \
  --region ca-central-1 \
  --profile default \
  -o recovered_ed25519
```

### SSH without writing the private key to disk (`ssh` subcommand)

The stock `ssh` client expects an identity file path (`-i`) or keys already loaded in an **ssh-agent**. It does **not** accept arbitrary “extra” flags that your shell forwards to a wrapper while hiding them from `ssh`, so this project uses a **separate** entry point that mirrors the flow you described:

1. **Our program** reads AWS options (`--secret-id`, `--region`, `--profile`), calls **GetSecretValue**, and reconstructs the private key **only in process memory** (same logic as `secrets pull-combine`, without `-o`).
2. It starts a **fresh `ssh-agent`**, runs **`ssh-add -`** with the key bytes on standard input (no key file on disk), then runs the real **`ssh`** with **`-F`** pointing at a **short-lived empty file** (not your `~/.ssh/config`) by default, plus **`-o IdentityFile=none`**, then your arguments. That avoids user-config **`IdentityFile`** lines, which OpenSSH can still apply after `IdentityFile=none` (and **`nul`** / `os.devnull` failed with Git’s OpenSSH on Windows: “Can't open user config file nul”). **`IdentitiesOnly=yes` is not used**: OpenSSH would then ignore keys that exist only in the agent (not listed as `IdentityFile`), so the loaded key would never be offered. The empty config file is deleted after the session; your private key is still never written to disk.
3. When the `ssh` session ends, it runs **`ssh-agent -k`** on that agent.

**Usage** (put **`--`** before any `ssh` flag that starts with `-`, so this tool does not consume `-p`, `-o`, etc.):

```bash
python -m shamir_ssh ssh \
  --secret-id my-ssh-key-shamir-shares \
  --region ca-central-1 \
  --profile default \
  -- user@host

python -m shamir_ssh ssh --secret-id my-shares --region ca-central-1 -- user@host -p 2222 -v
```

| Flag | Description |
|------|--------------|
| `--secret-id` | Consolidated secret in Secrets Manager (required). |
| `--region` | AWS region (default: `ca-central-1`). |
| `--profile` | Credentials profile (optional). |
| `--ssh-command` | `ssh` executable name or path (default: `ssh`). |
| `--merge-ssh-config` | Read your normal `~/.ssh/config` (default: **off** — uses `-F` on an empty temp file so config `IdentityFile` lines do not run). |
| `ssh_args` | Everything after `--` is passed to `ssh` unchanged (at least `user@host`). |

**Shell alias** (optional) if you want a shorter command; the real `ssh` still receives only the arguments after `--`:

```bash
alias smssh='python -m shamir_ssh ssh --secret-id my-ssh-key-shamir-shares --region ca-central-1 --profile default --'
smssh user@host
smssh -- -p 2222 user@host
```

**Caveats (important):**

- The key exists in **Python heap memory** during fetch/decrypt and in the **ssh-agent** process while connected; OpenSSH and the OS may **page or swap** memory—this is **not** a hardware security module.
- Requires **`ssh-agent`**, **`ssh-add`**, and **`ssh`** on `PATH` (e.g. **OpenSSH for Windows** or Git’s OpenSSH on Windows; OpenSSH on Linux/macOS).
- You **cannot** implement this by adding unknown long options to the real `/usr/bin/ssh` binary; use this subcommand or a small wrapper script/alias as above.

**IAM (typical):** `secretsmanager:GetSecretValue` for `pull-combine` and for **`ssh`**. For push: `PutSecretValue`; `CreateSecret` (and often `DescribeSecret`) if you use `--create-if-missing`. If the secret uses a customer-managed KMS key, KMS decrypt/encrypt permissions must match the key policy.

**Versioning:** Secrets Manager **retains prior versions** (subject to your account and rotation settings). Treat the secret like **highly sensitive** data. Overwriting does not erase old versions immediately.

Design details and todos live in [`.cursor/plans/aws_secrets_manager_shares.plan.md`](.cursor/plans/aws_secrets_manager_shares.plan.md).

---

## Security and operational notes

- **Treat each share like a secret.** It contains data needed to reconstruct the key once enough shares are collected, and it duplicates the encrypted blob (so offline guessing still runs against AES-GCM, but shares must not be published or logged).
- **Printing shares to the terminal** is convenient for demos but risky: shoulder surfing, screenshots, scrollback, and centralized logging can capture them. Prefer `-o` and store files on encrypted media with strict access control.
- **Use a trusted machine** for split and combine. Python does not guarantee that key material is erased from memory immediately after use.
- **Backup strategy**: if you lose **k** distinct shares (or the only copies of **k** shares), recovery may be impossible. **n** should reflect how many custodians or locations you want; **k** reflects how many must agree or survive.
- **Integrity**: GCM decryption fails if the ciphertext is tampered with. The implementation also compares the SHA-256 fingerprint of the decrypted file to the value embedded in the shares.
- **OpenSSH vs PEM**: The tool does not parse the key structure; it encrypts **raw file bytes**. It works for typical `id_ed25519` OpenSSH files and PEM-style private keys as long as the file is read as-is.
- **AWS Secrets Manager**: The consolidated secret value still contains **ciphertext and all Shamir points**; anyone with `GetSecretValue` and the right KMS access can download the whole blob. Use tight IAM, encryption at rest (KMS), and audit logging.
- **`ssh` subcommand**: The reconstructed key is held in **Python** and in a short-lived **ssh-agent**; it is still **sensitive memory** (swap, crash dumps, malware). This is stronger than a persistent file on disk, but not equivalent to an HSM.
- **Default `ssh` and `~/.ssh/config`**: With the default **empty config** (`-F` null), **`Host` aliases** and other settings from your user config are **not** applied unless you pass **`--merge-ssh-config`** (then you may hit `IdentityFile` paths again unless they exist).

---

## Running tests

```bash
python -m pytest tests -v
```

---

## Further reading

- [SHAMIR_SECRET_SHARING_MATH.md](SHAMIR_SECRET_SHARING_MATH.md) — Shamir’s scheme with definitions, Lagrange interpolation, and **fully worked arithmetic examples** over a small prime (by hand), plus how this repository maps those ideas to code.
