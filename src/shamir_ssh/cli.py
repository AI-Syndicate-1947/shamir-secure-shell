"""Command-line interface for shamir-ssh."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from shamir_ssh import aws_secrets
from shamir_ssh import consolidated_secret
from shamir_ssh import operations
from shamir_ssh import ssh_memory


def _cmd_split(args: argparse.Namespace) -> int:
    path = Path(args.input)
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 2
    try:
        lines = operations.split_private_key_file(
            path, threshold=args.threshold, num_shares=args.shares
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, line in enumerate(lines, start=1):
            fp = out_dir / f"share_{i}.json"
            fp.write_text(line + "\n", encoding="utf-8")
            try:
                os.chmod(fp, 0o600)
            except OSError:
                pass
        print(f"Wrote {len(lines)} shares to {out_dir}", file=sys.stderr)
    else:
        for line in lines:
            print(line)
    return 0


def _cmd_combine(args: argparse.Namespace) -> int:
    try:
        paths = operations.resolve_share_path_args(list(args.share_files))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        pem = operations.combine_from_paths(paths)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: decryption or parse failed: {e}", file=sys.stderr)
        return 2
    out = Path(args.output)
    out.write_bytes(pem)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"Wrote recovered key to {out}", file=sys.stderr)
    return 0


def _cmd_secrets_push(args: argparse.Namespace) -> int:
    try:
        paths = operations.resolve_share_path_args(list(args.share_files))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        objs = operations.load_shares_from_paths(paths)
        blob = consolidated_secret.consolidate_share_dicts(objs)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        aws_secrets.push_consolidated_secret(
            args.secret_id,
            blob,
            region=args.region,
            profile=args.profile,
            create_if_missing=args.create_if_missing,
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: AWS request failed: {e}", file=sys.stderr)
        return 2
    print(f"Stored consolidated shares in secret {args.secret_id!r} ({args.region})", file=sys.stderr)
    return 0


def _cmd_secrets_pull_combine(args: argparse.Namespace) -> int:
    try:
        s = aws_secrets.get_secret_string(
            secret_id=args.secret_id, region=args.region, profile=args.profile
        )
        pem = operations.combine_from_consolidated_secret_string(s)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: AWS or decrypt failed: {e}", file=sys.stderr)
        return 2
    out = Path(args.output)
    out.write_bytes(pem)
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    print(f"Wrote recovered key to {out}", file=sys.stderr)
    return 0


def _cmd_ssh(args: argparse.Namespace) -> int:
    ssh_argv = list(args.ssh_args)
    if ssh_argv and ssh_argv[0] == "--":
        ssh_argv = ssh_argv[1:]
    if not ssh_argv:
        print(
            "error: missing ssh target/arguments; use -- then ssh args "
            "(example: -- user@host or -- -p 2222 user@host)",
            file=sys.stderr,
        )
        return 2
    try:
        s = aws_secrets.get_secret_string(
            secret_id=args.secret_id,
            region=args.region,
            profile=args.profile,
        )
        pem = operations.combine_from_consolidated_secret_string(s)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: AWS or decrypt failed: {e}", file=sys.stderr)
        return 2
    try:
        return ssh_memory.run_ssh_with_ephemeral_agent(
            pem,
            args.ssh_command,
            ssh_argv,
            merge_ssh_config=args.merge_ssh_config,
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Split or combine SSH/OpenSSH private keys using Shamir (AES-GCM envelope); "
            "optional AWS Secrets Manager and in-memory ssh via ephemeral ssh-agent."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_split = sub.add_parser("split", help="Split a private key into n shares (k required to combine)")
    p_split.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to private key file (e.g. id_ed25519)",
    )
    p_split.add_argument(
        "-k",
        "--threshold",
        type=int,
        default=3,
        metavar="K",
        help="Minimum shares needed to reconstruct (default: 3)",
    )
    p_split.add_argument(
        "-n",
        "--shares",
        type=int,
        default=5,
        metavar="N",
        help="Total number of shares (default: 5)",
    )
    p_split.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="Write one JSON file per share; omit to print JSON lines to stdout",
    )
    p_split.set_defaults(func=_cmd_split)

    p_comb = sub.add_parser("combine", help="Combine k shares into a private key file")
    p_comb.add_argument(
        "share_files",
        nargs="+",
        help="Paths or globs to share JSON files (e.g. shares/share_*.json)",
    )
    p_comb.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output path for recovered private key",
    )
    p_comb.set_defaults(func=_cmd_combine)

    p_ssh = sub.add_parser(
        "ssh",
        help="Fetch consolidated secret from AWS, reconstruct key in memory, run ssh via ephemeral ssh-agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m shamir_ssh ssh --secret-id my-shares --region ca-central-1 -- user@host\n"
            "  python -m shamir_ssh ssh --secret-id my-shares --profile default -- user@host -p 2222 -v\n"
            "\n"
            "Put -- before any ssh flag that starts with - (e.g. -p, -o), so this program does not "
            "consume them."
        ),
    )
    p_ssh.add_argument(
        "--secret-id",
        required=True,
        help="Secrets Manager secret name or ARN (consolidated JSON)",
    )
    p_ssh.add_argument(
        "--region",
        default="ca-central-1",
        help="AWS region (default: ca-central-1)",
    )
    p_ssh.add_argument(
        "--profile",
        default=None,
        help="AWS shared credentials profile (default: boto3 default chain)",
    )
    p_ssh.add_argument(
        "--ssh-command",
        default="ssh",
        help="ssh executable name or path (default: ssh)",
    )
    p_ssh.add_argument(
        "--merge-ssh-config",
        action="store_true",
        help=(
            "Read ~/.ssh/config (default: use -F os.devnull so IdentityFile entries in config "
            "do not break agent-only login)"
        ),
    )
    p_ssh.add_argument(
        "ssh_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to ssh (use -- before options like -p)",
    )
    p_ssh.set_defaults(func=_cmd_ssh)

    p_secrets = sub.add_parser(
        "secrets",
        help="AWS Secrets Manager: store or load consolidated shares",
    )
    sec_sub = p_secrets.add_subparsers(dest="secrets_command", required=True)

    p_push = sec_sub.add_parser(
        "push",
        help="Consolidate share JSON files and PutSecretValue (or CreateSecret if missing)",
    )
    p_push.add_argument(
        "share_files",
        nargs="+",
        help="Paths or globs to per-share JSON files from split (e.g. shares/share_*.json)",
    )
    p_push.add_argument(
        "--secret-id",
        required=True,
        help="Secrets Manager secret name or ARN (name required for --create-if-missing)",
    )
    p_push.add_argument(
        "--region",
        default="ca-central-1",
        help="AWS region (default: ca-central-1)",
    )
    p_push.add_argument(
        "--profile",
        default=None,
        help="AWS shared credentials profile (default: boto3 default chain)",
    )
    p_push.add_argument(
        "--create-if-missing",
        action="store_true",
        help="Create the secret if it does not exist (requires a name, not an ARN)",
    )
    p_push.set_defaults(func=_cmd_secrets_push)

    p_pull = sec_sub.add_parser(
        "pull-combine",
        help="GetSecretValue, parse consolidated JSON, recover private key",
    )
    p_pull.add_argument(
        "--secret-id",
        required=True,
        help="Secrets Manager secret name or ARN",
    )
    p_pull.add_argument(
        "--region",
        default="ca-central-1",
        help="AWS region (default: ca-central-1)",
    )
    p_pull.add_argument(
        "--profile",
        default=None,
        help="AWS shared credentials profile (default: boto3 default chain)",
    )
    p_pull.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output path for recovered private key",
    )
    p_pull.set_defaults(func=_cmd_secrets_pull_combine)

    args = parser.parse_args()
    code = args.func(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
