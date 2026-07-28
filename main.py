import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from file_sentinel.config import Settings
from file_sentinel.watcher import run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="File Sentinel - scans new downloads against VirusTotal and "
        "quarantines or deletes anything flagged as malicious."
    )
    parser.add_argument("--watch-dir", type=Path, help="Folder to monitor (defaults to Downloads)")
    parser.add_argument("--quarantine-dir", type=Path, help="Folder to move flagged files into")
    parser.add_argument(
        "--auto-action",
        choices=["prompt", "quarantine", "delete"],
        help="How to handle malicious files without asking (default: prompt)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def setup_logging(log_dir: Path, verbose: bool) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = RotatingFileHandler(
        log_dir / "file_sentinel.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


def main() -> None:
    args = parse_args()
    settings = Settings()

    if args.watch_dir:
        settings.watch_dir = args.watch_dir
    if args.quarantine_dir:
        settings.quarantine_dir = args.quarantine_dir
    if args.auto_action:
        settings.auto_action = args.auto_action

    setup_logging(settings.log_dir, args.verbose)

    try:
        run(settings)
    except RuntimeError as exc:
        logging.getLogger("file_sentinel").error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
