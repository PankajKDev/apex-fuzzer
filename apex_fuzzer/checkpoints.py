"""Stage-level checkpointing."""
import json
from pathlib import Path
from typing import Dict
from .logging_setup import get_logger

log = get_logger("checkpoint")

STAGES = ["recon", "discovery", "mapping", "probe", "nuclei",
          "validation", "ai", "report"]


class Checkpoint:
    def __init__(self, path: Path):
        self.path = path
        self.state: Dict[str, str] = {s: "pending" for s in STAGES}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self.state.update(json.loads(self.path.read_text()))
            except Exception:
                pass

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.state, indent=2))

    def is_complete(self, stage: str) -> bool:
        return self.state.get(stage) == "complete"

    def mark(self, stage: str, status: str = "complete"):
        self.state[stage] = status
        self._save()
        log.debug("checkpoint %s=%s", stage, status)

    def fail(self, stage: str):
        self.mark(stage, "failed")

    # ── state blobs (§52): application graph, coverage, budgets, AI ──
    # memory survive resume alongside the stage checkpoints. Blobs live
    # in <out_dir>/state/ so a resumed scan reloads rather than
    # rebuilding them.
    def _blob_path(self, name: str) -> Path:
        return self.path.parent / "state" / f"{name}.json"

    def save_blob(self, name: str, data: Dict):
        p = self._blob_path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))
        log.debug("checkpoint blob saved: %s", name)

    def load_blob(self, name: str) -> Dict:
        p = self._blob_path(name)
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def has_blob(self, name: str) -> bool:
        return self._blob_path(name).exists()
