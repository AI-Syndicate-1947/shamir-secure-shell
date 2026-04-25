---
name: Shamir SSH Key Splitter
overview: Build a small Python CLI that reads an OpenSSH/PEM Ed25519 private key file, splits the raw secret material using Shamir’s Secret Sharing (threshold k-of-n), and prints share artifacts to the terminal—with clear security guidance and optional envelope encryption if you prefer not to split the PEM bytes directly.
todos:
  - id: deps-layout
    content: Add pyproject/requirements, src package layout, and CLI entry point
    status: pending
  - id: envelope-crypto
    content: Implement AES-256-GCM envelope + vetted Shamir library integration for k-of-n
    status: pending
  - id: share-format
    content: Define share encoding (metadata, index, fingerprint, base64 payload) and parse in combine
    status: pending
  - id: cli
    content: Implement split (stdout/files) and combine with validation flags
    status: pending
  - id: tests-docs
    content: Add round-trip tests, negative tests, and README security/troubleshooting
    status: pending
isProject: false
---

# Shamir Secret Sharing Utility for Ed25519 SSH Keys

## Context and scope

- **Input**: A private key file produced by `ssh-keygen -t ed25519`. In practice this is usually **OpenSSH format** (`-----BEGIN OPENSSH PRIVATE KEY-----`), not a classic PKCS#8 PEM. The utility should accept the file **as opaque bytes** (the entire file contents), so it works whether the user exports PEM or OpenSSH text.
- **Core operation**: **Shamir’s Secret Sharing (SSS)** with configurable **k-of-n** (need **k** shares to reconstruct, **n** total shares).
- **Output**: Print shares to the console when the script runs (as requested), with documented risks of doing so.

**Recommended scope for v1**

- CLI: `split` (and strongly recommended **`combine`** for a complete tool).
- Parameters: `--threshold k`, `--shares n`, input path, optional output mode (stdout vs files).

---

## Design choices

### 1. What exactly is the “secret”?

| Approach | Pros | Cons |
|----------|------|------|
| **A. Split entire private key file as one byte string** | Simple; reconstructed file is bit-identical to input | Large secret; must use a field / implementation that supports arbitrary-length secrets correctly |
| **B. Envelope: random AES-256-GCM key → encrypt PEM → Shamir-split only the AES key** | Smaller polynomial; industry-typical pattern; easier to reason about field size | Extra crypto code; slightly more complex UX |

**Recommendation**: Implement **B (envelope)** as the default or primary path for **security and correctness** (fixed-size key material for SSS, authenticated ciphertext for the PEM). Offer **A** only if you explicitly want “split raw PEM bytes” with a vetted byte-oriented SSS (see below).

### 2. Shamir implementation (do not roll your own GF math)

- Use a **maintained library** that implements SSS over a standard field (e.g. **GF(256)** for byte-oriented secrets, or a prime field for integer secrets), with a clear API and tests.
- Pin versions in `requirements.txt` / `pyproject.toml` and prefer libraries that are **actively maintained** and **document field semantics**.

Concrete direction: evaluate PyPI candidates (e.g. packages named around `shamir` / `secret-sharing`) for **API fit**, **last release date**, and **whether they support your chosen secret representation** (raw bytes vs integer). Avoid copying stack-overflow GF(256) snippets without tests.

### 3. Share encoding

- Emit shares as **unambiguous, copy-paste-safe** encodings (e.g. **base64** or **hex**) plus **metadata**: scheme version, **k**, **n**, **share index**, and a **fingerprint** of the original secret (e.g. SHA-256 of the PEM bytes) so users can match shares to the same key without revealing the key.
- Use a **single structured format** (JSON lines or a small custom header block) so `combine` can parse reliably.

---

## Security best practices (build into the plan)

1. **Cryptographic randomness**: Use `secrets` (or the Shamir library’s documented CSPRNG) for all random material (coefficients, AES keys, IVs).
2. **Authenticated encryption (envelope path)**: **AES-256-GCM** (or ChaCha20-Poly1305) for the PEM payload; never store/transmit ciphertext without authentication.
3. **Least exposure**:
   - **Printing shares to screen** is convenient but **high-risk** (shoulder surfing, screen capture, shared sessions). Document this; add optional **`--output-dir`** writing each share to a file with restrictive permissions (e.g. `0o600` on Unix; on Windows, document limitations and recommend WSL or explicit ACL guidance).
4. **Process and environment**: Warn against running on **shared/untrusted machines**; no logging of secrets or full shares at INFO level.
5. **Memory**: Python does not guarantee wiping strings; avoid unnecessary copies where practical; document that **high-assurance wiping** requires native extensions or OS-specific practices—set expectations.
6. **Validation**: Refuse absurd `k`/`n` (e.g. `k > n`, `k < 2`); validate file is non-empty and looks like a key container (basic header check).
7. **Dependencies**: Pin hashes if you use `pip-tools`/`poetry`; run **`pip audit`** or similar in CI.
8. **Testing**: Unit tests for round-trip **split → combine** equals original bytes; tests for wrong share count / tampered ciphertext.

---

## Suggested CLI shape

```text
python -m shamir_ssh split --input id_ed25519 --threshold 3 --shares 5 [--stdout | --output-dir ./shares]
python -m shamir_ssh combine --shares share1.txt share2.txt share3.txt --output recovered_ed25519
```

- Defaults (if you want): `k=3`, `n=5`.
- **`combine`** reads the same structured format the splitter prints.

---

## Project layout (minimal)

- `pyproject.toml` (or `requirements.txt`) — Python version pin, dependencies.
- `src/shamir_ssh/` — `cli.py`, `split.py`, `combine.py`, `crypto_envelope.py` (if using envelope), `share_format.py`.
- `tests/` — round-trip and negative tests.

---

## Mermaid: envelope split flow

```mermaid
flowchart LR
  pemFile[PEM_or_OpenSSH_file]
  aesKey[Random_AES_key]
  cipher[Encrypt_GCM]
  shamir[Shamir_split_k_of_n]
  shares[Print_or_write_shares]

  pemFile --> cipher
  aesKey --> cipher
  aesKey --> shamir
  cipher --> shares
  shamir --> shares
```

---

## Deliverables checklist

- Documented CLI with **split** + **combine**.
- **Envelope encryption** as recommended default; optional raw-byte path only if required and justified.
- Shares include **metadata + fingerprint**, safe encoding.
- **README** section: threats (console output), file permissions, backup strategy for shares, and that **loss of k shares** means **irrecoverable** key.
- Automated tests for round-trip integrity.

---

## Risks to call out in README

- Shamir protects **confidentiality** of the key until reconstruction; it does **not** replace secure storage of shares (each share is still sensitive).
- **n** should be chosen so loss of `n - k + 1` shares does not happen accidentally.
