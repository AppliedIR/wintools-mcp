"""A saved output is never replaced, so its recorded hash always describes it.

Saves of one tool within one second used one name and "wb": the later run
replaced the earlier file, whose response still named it with the earlier
hash. Each save now has a name of its own, created exclusively. The clock is
frozen to one second; outputs are synthetic.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wintools_mcp import executor


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def save(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "datetime", _Frozen)
    out = tmp_path / "extractions" / "wintools"

    def _save(stdout: bytes, stderr: bytes = b"") -> dict:
        response: dict = {}
        executor._save_output(
            ["strings.exe", "-n", "8"], stdout, stderr, str(out), response
        )
        return response

    return _save


def _sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_thirty_saves_in_one_second_keep_thirty_files(save):
    responses = [save(f"run {i}\n".encode()) for i in range(30)]
    files = [r["output_file"] for r in responses]
    assert len(set(files)) == 30
    for r in responses:
        assert r["output_sha256"] == _sha(r["output_file"])


def test_a_save_never_replaces_a_file_already_at_its_name(save, monkeypatch):
    same = uuid.UUID(int=7)
    monkeypatch.setattr(uuid, "uuid4", lambda: same)  # every save draws one name
    first = save(b"the earlier run\n", b"its warning\n")
    second = save(b"a later run\n", b"another warning\n")
    assert Path(first["output_file"]).read_bytes() == b"the earlier run\n"
    assert Path(first["stderr_file"]).read_bytes() == b"its warning\n"
    assert first["output_sha256"] == _sha(first["output_file"])
    assert first["stderr_sha256"] == _sha(first["stderr_file"])
    assert second.get("output_file") != first["output_file"]
    assert second.get("stderr_file") != first["stderr_file"]


def test_a_single_save_writes_stdout_and_stderr_beside_it(save):
    r = save(b"strings out\n", b"a warning\n")
    out, err = Path(r["output_file"]), Path(r["stderr_file"])
    assert out.parent.name == "wintools" and out.parent == err.parent
    assert out.read_bytes() == b"strings out\n" and err.read_bytes() == b"a warning\n"
    assert r["output_sha256"] == _sha(r["output_file"])
    assert r["stderr_sha256"] == _sha(r["stderr_file"])
    assert out.name.startswith("20261012_120000_strings_exe_")
