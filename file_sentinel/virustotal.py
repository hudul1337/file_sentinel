import logging
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("file_sentinel.virustotal")

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: str, timeout: int = 15, max_retries: int = 3):
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({"accept": "application/json", "x-apikey": api_key})

    def lookup_hash(self, sha256: str) -> Optional[dict]:
        """Returns the analysis stats dict, or None if the hash is unknown to VT."""
        url = f"{BASE_URL}/files/{sha256}"

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                logger.warning("VirusTotal request failed (attempt %d): %s", attempt, exc)
                time.sleep(2 ** attempt)
                continue

            if response.status_code == 200:
                return response.json()["data"]["attributes"]["last_analysis_stats"]

            if response.status_code == 404:
                return None

            if response.status_code == 429:
                wait = 15 * attempt
                logger.info("Rate limited by VirusTotal, waiting %ds before retrying", wait)
                time.sleep(wait)
                continue

            logger.error("VirusTotal API error %d: %s", response.status_code, response.text[:200])
            return None

        logger.error("Giving up on VirusTotal lookup for %s after %d attempts", sha256, self.max_retries)
        return None

    def submit_file(self, path: Path) -> Optional[str]:
        """Uploads an unknown file for analysis. Returns the analysis id, or None on failure."""
        url = f"{BASE_URL}/files"
        try:
            with open(path, "rb") as fh:
                response = self.session.post(
                    url, files={"file": (path.name, fh)}, timeout=self.timeout * 4
                )
        except requests.RequestException as exc:
            logger.warning("Could not upload %s to VirusTotal: %s", path.name, exc)
            return None

        if response.status_code in (200, 201):
            return response.json()["data"]["id"]

        logger.error("Upload failed (%d): %s", response.status_code, response.text[:200])
        return None
