import hashlib
from pathlib import Path


def sha256_of(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
