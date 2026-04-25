from pathlib import Path

import pytest

from shamir_ssh import operations


def test_resolve_glob(tmp_path: Path):
    d = tmp_path / "shares"
    d.mkdir()
    (d / "share_1.json").write_text('{"x":1}', encoding="utf-8")
    (d / "share_2.json").write_text('{"x":2}', encoding="utf-8")
    (d / "other.txt").write_text("x", encoding="utf-8")
    pat = str(d / "share_*.json")
    paths = operations.resolve_share_path_args([pat])
    assert len(paths) == 2
    names = sorted(p.name for p in paths)
    assert names == ["share_1.json", "share_2.json"]


def test_resolve_glob_backslash_style(tmp_path: Path):
    """Windows-style glob path; fallback rewrites backslashes to forward slashes."""
    d = tmp_path / "shares"
    d.mkdir()
    (d / "share_1.json").write_text('{"x":1}', encoding="utf-8")
    (d / "share_2.json").write_text('{"x":2}', encoding="utf-8")
    pat = str(d) + "\\share_*.json"
    paths = operations.resolve_share_path_args([pat])
    assert len(paths) == 2


def test_resolve_literal_file(tmp_path: Path):
    f = tmp_path / "a.json"
    f.write_text("{}", encoding="utf-8")
    paths = operations.resolve_share_path_args([str(f)])
    assert len(paths) == 1
    assert paths[0] == f


def test_resolve_glob_no_match(tmp_path: Path):
    with pytest.raises(ValueError, match="no files match"):
        operations.resolve_share_path_args([str(tmp_path / "nope_*.json")])


def test_resolve_literal_missing(tmp_path: Path):
    with pytest.raises(ValueError, match="not a file"):
        operations.resolve_share_path_args([str(tmp_path / "missing.json")])
