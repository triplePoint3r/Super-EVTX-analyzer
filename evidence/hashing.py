import hashlib
from pathlib import Path


def calculate_sha256(
    file_path: Path,
    chunk_size: int = 64 * 1024
) -> str:

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()