import logging
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .cache import ScanCache
from .config import Settings
from .hashing import sha256_of
from .notifier import notify
from .prompts import ask_user_action
from .quarantine import QuarantineManager
from .virustotal import VirusTotalClient

logger = logging.getLogger("file_sentinel.watcher")


class FileScanner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.vt = VirusTotalClient(settings.vt_api_key, timeout=settings.vt_request_timeout)
        self.quarantine = QuarantineManager(settings.quarantine_dir)
        self.cache = ScanCache(settings.log_dir / "scan_cache.db")

    def scan(self, file_path: Path) -> None:
        if not file_path.exists():
            return

        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > self.settings.max_scan_size_mb:
            logger.info(
                "Skipping %s (%.1f MB exceeds the %d MB scan limit)",
                file_path.name, size_mb, self.settings.max_scan_size_mb,
            )
            return

        try:
            file_hash = sha256_of(file_path)
        except (PermissionError, OSError) as exc:
            logger.warning("Could not hash %s, it may still be locked: %s", file_path.name, exc)
            return

        cached = self.cache.get(file_hash)
        if cached is not None:
            logger.info("Using cached verdict for %s (%d detections)", file_path.name, cached)
            malicious = cached
        else:
            stats = self.vt.lookup_hash(file_hash)
            if stats is None:
                logger.info("No VirusTotal record for %s (hash: %s)", file_path.name, file_hash[:12])
                return
            malicious = stats.get("malicious", 0)
            self.cache.put(file_hash, malicious)

        if malicious > 0:
            self._handle_malicious(file_path, file_hash, malicious)
        else:
            logger.info("Clean: %s", file_path.name)
            notify("Download scanned", f"{file_path.name} passed the security scan.")

    def _handle_malicious(self, file_path: Path, file_hash: str, malicious: int) -> None:
        notify(
            "Threat detected",
            f"{file_path.name} was flagged by {malicious} security vendors.",
        )
        logger.warning("MALICIOUS file detected: %s (%d detections)", file_path.name, malicious)

        action = self.settings.auto_action
        if action == "prompt":
            action = ask_user_action(file_path, malicious)

        if action == "delete":
            self.quarantine.delete(file_path, file_hash, malicious)
            notify("Action complete", f"{file_path.name} was permanently deleted.")
        else:
            target = self.quarantine.quarantine(file_path, file_hash, malicious)
            notify("Moved to quarantine", f"{file_path.name} was isolated in {target.parent}.")

    def close(self) -> None:
        self.cache.close()


class DownloadEventHandler(FileSystemEventHandler):
    def __init__(self, scanner: FileScanner, settings: Settings):
        self.scanner = scanner
        self.settings = settings

    def _maybe_scan(self, path: Path) -> None:
        if path.suffix.lower() in self.settings.temp_extensions:
            return
        time.sleep(self.settings.scan_delay_seconds)
        self.scanner.scan(path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._maybe_scan(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        src, dest = Path(event.src_path), Path(event.dest_path)
        if src.suffix.lower() in self.settings.temp_extensions and dest.suffix.lower() not in self.settings.temp_extensions:
            logger.info("Download finished: %s", dest.name)
            self._maybe_scan(dest)


def run(settings: Settings) -> None:
    settings.validate()
    scanner = FileScanner(settings)
    handler = DownloadEventHandler(scanner, settings)
    observer = Observer()
    observer.schedule(handler, path=str(settings.watch_dir), recursive=False)
    observer.start()

    logger.info("Watching %s", settings.watch_dir)
    logger.info("Quarantine folder: %s", settings.quarantine_dir)
    logger.info("Sentinel active. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
    finally:
        observer.stop()
        observer.join()
        scanner.close()
