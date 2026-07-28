import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv_if_present() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass


_load_dotenv_if_present()


@dataclass
class Settings:
    vt_api_key: str = field(default_factory=lambda: os.getenv("VT_API_KEY", ""))
    watch_dir: Path = field(
        default_factory=lambda: Path(os.getenv("WATCH_DIR", str(Path.home() / "Downloads")))
    )
    quarantine_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("QUARANTINE_DIR", str(Path.home() / "Desktop" / "Quarantine"))
        )
    )
    log_dir: Path = field(
        default_factory=lambda: Path(os.getenv("LOG_DIR", str(Path.home() / ".file_sentinel")))
    )
    max_scan_size_mb: int = int(os.getenv("MAX_SCAN_SIZE_MB", "650"))
    auto_action: str = os.getenv("AUTO_ACTION", "prompt")  # prompt | quarantine | delete
    vt_request_timeout: int = int(os.getenv("VT_TIMEOUT", "15"))
    scan_delay_seconds: float = float(os.getenv("SCAN_DELAY_SECONDS", "1.0"))

    temp_extensions: frozenset = frozenset({".part", ".crdownload", ".tmp", ".download"})

    def validate(self) -> None:
        if not self.vt_api_key:
            raise RuntimeError(
                "VT_API_KEY is not set. Create a .env file (see .env.example) "
                "or export VT_API_KEY before running."
            )
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        if self.auto_action not in {"prompt", "quarantine", "delete"}:
            raise ValueError("AUTO_ACTION must be one of: prompt, quarantine, delete")
