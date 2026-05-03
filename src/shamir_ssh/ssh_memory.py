"""Run OpenSSH client with a private key kept only in memory (via ephemeral ssh-agent)."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Sequence


def _parse_ssh_agent_env(agent_stdout: str) -> dict[str, str]:
    """Parse `ssh-agent -s` / `ssh-agent -c` style output for SSH_AUTH_SOCK and SSH_AGENT_PID."""
    env: dict[str, str] = {}
    text = agent_stdout.replace("\r\n", "\n")
    sock = re.search(r"SSH_AUTH_SOCK(?:=|\s+)([^\s;]+)", text)
    pid = re.search(r"SSH_AGENT_PID(?:=|\s+)([0-9]+)", text)
    if sock:
        env["SSH_AUTH_SOCK"] = sock.group(1).strip('"').strip("'")
    if pid:
        env["SSH_AGENT_PID"] = pid.group(1).strip()
    return env


def run_ssh_with_ephemeral_agent(
    private_key_pem: bytes,
    ssh_executable: str,
    ssh_argv: Sequence[str],
    *,
    merge_ssh_config: bool = False,
) -> int:
    """
    Load private_key_pem into a new ssh-agent via `ssh-add -`, run `ssh`, then tear down the agent.
    The key is not written to a file by this helper.

    By default we pass ``-F`` pointing at an **empty temporary file** so **user**
    ``~/.ssh/config`` is not read. (``os.devnull`` / ``nul`` is unreliable with Git/MSYS OpenSSH on
    Windows, which reported "Can't open user config file nul".) OpenSSH still appends
    ``IdentityFile`` from user config after ``IdentityFile=none`` without this.

    We pass ``IdentityFile=none`` so no on-disk identity paths are tried. We **do not** set
    ``IdentitiesOnly=yes``: with that option, OpenSSH only offers keys listed in config or on the
    command line, **not** keys held only in the agent—so the key loaded via ``ssh-add -`` would
    never be used and authentication would fail with "Permission denied (publickey)".

    The ephemeral agent should contain only the reconstructed key. The temp ``-F`` file is deleted
    before return.

    Set ``merge_ssh_config=True`` to read the normal user config (e.g. ``Host`` aliases); you may
    need valid ``IdentityFile`` paths or further ``-o`` overrides.
    """
    if not ssh_argv:
        raise ValueError("no ssh arguments (need at least user@host); use -- before ssh options")
    try:
        agent_proc = subprocess.run(
            ["ssh-agent", "-s"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "ssh-agent not found. Install OpenSSH client tools and ensure ssh-agent is on PATH."
        ) from e
    agent_env = _parse_ssh_agent_env(agent_proc.stdout)
    if "SSH_AUTH_SOCK" not in agent_env:
        raise RuntimeError(
            "could not parse SSH_AUTH_SOCK from ssh-agent output; try updating OpenSSH client"
        )
    env = os.environ.copy()
    env.update(agent_env)
    # Avoid picking up a pre-existing agent from the parent shell.
    env.pop("SSH_CONNECTION", None)
    # Prevent ssh-add from attempting graphical passphrase prompts (ssh-askpass)
    # which may not be available in non-interactive/non-graphical environments.
    env["SSH_ASKPASS_REQUIRE"] = "never"

    try:
        add_proc = subprocess.run(
            ["ssh-add", "-"],
            input=private_key_pem,
            env=env,
            check=False,
            capture_output=True,
        )
        if add_proc.returncode != 0:
            err = add_proc.stderr.decode(errors="replace") if add_proc.stderr else ""
            raise RuntimeError(f"ssh-add failed (exit {add_proc.returncode}): {err.strip()}")
    except FileNotFoundError as e:
        raise RuntimeError("ssh-add not found. Install OpenSSH client tools.") from e

    cfg_path: str | None = None
    try:
        if merge_ssh_config:
            cfg_prefix: list[str] = []
        else:
            fd, cfg_path = tempfile.mkstemp(prefix="shamir_ssh_", suffix=".conf", text=True)
            os.close(fd)
            cfg_prefix = ["-F", cfg_path]

        ssh_cmd = [
            ssh_executable,
            *cfg_prefix,
            "-o",
            "IdentityFile=none",
            *list(ssh_argv),
        ]
        proc = subprocess.run(ssh_cmd, env=env)
        return int(proc.returncode)
    finally:
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
        if "SSH_AGENT_PID" in agent_env:
            try:
                subprocess.run(
                    ["ssh-agent", "-k"],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except (FileNotFoundError, OSError):
                pass
