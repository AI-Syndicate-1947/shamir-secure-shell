"""Tests for ssh-agent output parsing."""

from shamir_ssh.ssh_memory import _parse_ssh_agent_env


def test_parse_ssh_agent_env_posix_style():
    out = """SSH_AUTH_SOCK=/tmp/ssh-XX/agent.123; export SSH_AUTH_SOCK;
SSH_AGENT_PID=999; export SSH_AGENT_PID;
echo Agent pid 999;
"""
    env = _parse_ssh_agent_env(out)
    assert env["SSH_AUTH_SOCK"] == "/tmp/ssh-XX/agent.123"
    assert env["SSH_AGENT_PID"] == "999"
