import shutil
from datetime import datetime
from pathlib import Path

from evidence.hashing import calculate_sha256
from evidence.metadata import EvidenceMetadata


class EvidenceAcquisition:
    """
    Acquire forensic evidence while preserving integrity.
    """

    def acquire(
        self,
        source: Path,
        destination: Path
    ) -> EvidenceMetadata:

        source = Path(source)
        destination = Path(destination)

        # -----------------------------
        # Validate source
        # -----------------------------

        if not source.exists():
            raise FileNotFoundError(
                f"Evidence not found: {source}"
            )

        if not source.is_file():
            raise ValueError(
                f"Evidence is not a file: {source}"
            )

        if source.suffix.lower() != ".evtx":
            raise ValueError(
                "Only EVTX evidence is currently supported"
            )

        # -----------------------------
        # Source hash
        # -----------------------------

        source_hash = calculate_sha256(source)

        # -----------------------------
        # Create destination
        # -----------------------------

        destination.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # -----------------------------
        # Copy evidence
        # -----------------------------

        shutil.copy2(
            source,
            destination
        )

        # -----------------------------
        # Destination hash
        # -----------------------------

        destination_hash = calculate_sha256(
            destination
        )

        integrity_verified = (
            source_hash == destination_hash
        )

        if not integrity_verified:

            destination.unlink(
                missing_ok=True
            )

            raise RuntimeError(
                "Evidence integrity verification failed"
            )

        # -----------------------------
        # Metadata
        # -----------------------------

        stat = source.stat()

        created_at = datetime.fromtimestamp(
            stat.st_ctime
        ).astimezone().isoformat()

        modified_at = datetime.fromtimestamp(
            stat.st_mtime
        ).astimezone().isoformat()

        accessed_at = datetime.fromtimestamp(
            stat.st_atime
        ).astimezone().isoformat()

        return EvidenceMetadata(
            original_path=str(source.resolve()),
            acquired_path=str(destination.resolve()),
            filename=source.name,
            size=stat.st_size,
            sha256=source_hash,
            created_at=created_at,
            modified_at=modified_at,
            accessed_at=accessed_at,
            integrity_verified=True
        )