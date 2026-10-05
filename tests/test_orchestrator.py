"""Orchestrator helpers: instance-method regression coverage."""
from main.config import Config
from main.orchestrator import Orchestrator


def test_read_lines_is_bound(tmp_path):
    orch = Orchestrator(Config(), tmp_path)
    target = tmp_path / "raw.txt"
    target.write_text("https://example.test/a\n\nhttps://example.test/b\n")
    assert orch._read_lines(target) == ["https://example.test/a",
                                        "https://example.test/b"]
    assert orch._read_lines(tmp_path / "missing.txt") == []
