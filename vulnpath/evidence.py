"""Evidence inventory: find files, hash them, never modify them."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EvidenceFile:
    path: Path                # absolute
    rel_path: str
    size: int
    sha256: str
    source_type: str = "unsupported"
    parser: str = ""
    records_parsed: int = 0
    records_skipped: int = 0
    issues: list[str] = field(default_factory=list)

    @property
    def file_id(self) -> str:
        return self.sha256[:12]

    def to_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "size_bytes": self.size,
            "sha256": self.sha256,
            "source_type": self.source_type,
            "parser": self.parser,
            "records_parsed": self.records_parsed,
            "records_skipped": self.records_skipped,
            "issues": self.issues[:50],
            "issue_count": len(self.issues),
        }


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def inventory(case_dir: Path) -> list[EvidenceFile]:
    """Walk the case folder (without following symlinks out of it) and hash every regular file."""
    case_dir = case_dir.resolve()
    files: list[EvidenceFile] = []
    for root, dirs, names in os.walk(case_dir, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            p = Path(root) / name
            if p.is_symlink() or not p.is_file():
                continue
            rp = p.resolve()
            if case_dir not in rp.parents:
                continue
            files.append(EvidenceFile(
                path=rp,
                rel_path=rp.relative_to(case_dir).as_posix(),
                size=rp.stat().st_size,
                sha256=sha256_file(rp),
            ))
    return files


def verify_unchanged(files: list[EvidenceFile]) -> list[str]:
    """Re-hash after processing to prove the originals were not modified."""
    changed = []
    for ef in files:
        if sha256_file(ef.path) != ef.sha256:
            changed.append(ef.rel_path)
    return changed
