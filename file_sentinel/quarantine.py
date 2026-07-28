import json
import logging
import shutil
import time
from pathlib import Path

logger = logging.getLogger("file_sentinel.quarantine")


class QuarantineManager:
    def __init__(self, quarantine_dir: Path):
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "manifest.jsonl"

    def _log_action(self, action: str, original_path: Path, sha256: str, malicious_count: int, new_path: Path = None) -> None:
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "original_path": str(original_path),
            "sha256": sha256,
            "malicious_count": malicious_count,
            "moved_to": str(new_path) if new_path else None,
        }
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def delete(self, file_path: Path, sha256: str, malicious_count: int) -> None:
        file_path.unlink()
        self._log_action("deleted", file_path, sha256, malicious_count)
        logger.info("Deleted malicious file: %s", file_path.name)

    def quarantine(self, file_path: Path, sha256: str, malicious_count: int) -> Path:
        target = self.quarantine_dir / file_path.name
        if target.exists():
            target = self.quarantine_dir / f"{time.strftime('%Y%m%d_%H%M%S')}_{file_path.name}"

        shutil.move(str(file_path), str(target))
        self._log_action("quarantined", file_path, sha256, malicious_count, target)
        logger.info("Moved to quarantine: %s -> %s", file_path.name, target)
        return target
