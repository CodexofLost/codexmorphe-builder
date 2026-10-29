import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class LedgerEntry:
    source_id: str
    release_tag: str
    asset_name: str
    asset_id: Optional[int]
    sha256: str
    file_path: str
    file_size: int
    last_fetched: str
    last_built_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LedgerEntry":
        # Handle backward compatibility if last_built_sha256 is absent
        if "last_built_sha256" not in data:
            data["last_built_sha256"] = None
        return cls(**data)


class CacheLedger:
    def __init__(self, ledger_file: Path):
        self.ledger_file = ledger_file
        self.entries: Dict[str, LedgerEntry] = {}
        self.load()

    def load(self) -> None:
        if self.ledger_file.exists():
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self.entries[k] = LedgerEntry.from_dict(v)
            except Exception as e:
                print(f"[WARN] Failed to read ledger file: {e}")
                self.entries = {}

    def save(self) -> None:
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        serializable = {k: v.to_dict() for k, v in self.entries.items()}
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)

    def get(self, source_id: str) -> Optional[LedgerEntry]:
        return self.entries.get(source_id)

    def is_up_to_date(self, source_id: str, tag: str, asset_id: Optional[int]) -> bool:
        entry = self.get(source_id)
        if not entry:
            return False
        if entry.release_tag != tag:
            return False
        if asset_id is not None and entry.asset_id != asset_id:
            return False
        # Verify physical file still exists on disk
        return Path(entry.file_path).exists()

    def is_build_up_to_date(self, source_id: str) -> bool:
        """
        Check if the source's compiled bundle is already up to date with its downloaded .mpp archive.
        """
        entry = self.get(source_id)
        if not entry or not entry.last_built_sha256:
            return False
        return entry.last_built_sha256 == entry.sha256

    def mark_built(self, source_id: str, mpp_sha256: str) -> None:
        """
        Record that the current .mpp SHA256 has been compiled into runtime bundles.
        """
        entry = self.get(source_id)
        if entry:
            entry.last_built_sha256 = mpp_sha256
            self.save()

    def update(
        self,
        source_id: str,
        tag: str,
        asset_name: str,
        asset_id: Optional[int],
        sha256: str,
        file_path: Path,
        file_size: int,
    ) -> LedgerEntry:
        existing = self.get(source_id)
        last_built = existing.last_built_sha256 if existing else None

        entry = LedgerEntry(
            source_id=source_id,
            release_tag=tag,
            asset_name=asset_name,
            asset_id=asset_id,
            sha256=sha256,
            file_path=str(file_path.resolve()),
            file_size=file_size,
            last_fetched=datetime.now(timezone.utc).isoformat(),
            last_built_sha256=last_built,
        )
        self.entries[source_id] = entry
        self.save()
        return entry
