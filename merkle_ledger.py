from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Any


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class ThreatLogEntry:
    timestamp: str
    flow_id: str
    attack_label: str
    severity: float
    src_ip: str = ""
    dst_ip: str = ""
    action: str = ""

    def to_canonical_string(self) -> str:
        return "|".join(
            [
                self.timestamp,
                self.flow_id,
                self.attack_label,
                str(self.severity),
            ]
        )

    @staticmethod
    def create(
        flow_id: Any,
        attack_label: str,
        severity: float,
        src_ip: str = "",
        dst_ip: str = "",
        action: str = "",
        timestamp: Optional[datetime] = None,
    ) -> "ThreatLogEntry":
        if timestamp is None:
            timestamp = datetime.utcnow()
        ts_str = timestamp.isoformat(timespec="seconds") + "Z"
        return ThreatLogEntry(
            timestamp=ts_str,
            flow_id=str(flow_id),
            attack_label=attack_label,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            action=action,
        )


class MerkleTree:
    def __init__(self, leaves: List[str]):
        if not leaves:
            raise ValueError("Cannot build Merkle tree with no leaves")
        self.leaf_hashes = [sha256_hex(v) for v in leaves]
        self.levels: List[List[str]] = []
        self._build()

    def _build(self) -> None:
        current_level = self.leaf_hashes
        self.levels.append(current_level)
        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level = current_level + [current_level[-1]]
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                parent_hash = sha256_hex(combined)
                next_level.append(parent_hash)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    @staticmethod
    def from_entries(entries: List[ThreatLogEntry]) -> "MerkleTree":
        leaves = [e.to_canonical_string() for e in entries]
        return MerkleTree(leaves)

    @staticmethod
    def compute_root_from_entries(entries: List[ThreatLogEntry]) -> str:
        tree = MerkleTree.from_entries(entries)
        return tree.root

    @staticmethod
    def verify(entries: List[ThreatLogEntry], expected_root: str) -> bool:
        if not entries and not expected_root:
            return True
        if not entries and expected_root:
            return False
        actual_root = MerkleTree.compute_root_from_entries(entries)
        return actual_root == expected_root


class ThreatLogLedger:
    def __init__(self):
        self._entries: List[ThreatLogEntry] = []
        self._current_root: Optional[str] = None

    def add_entry(self, entry: ThreatLogEntry) -> None:
        self._entries.append(entry)
        self._current_root = None

    def compute_merkle_root(self) -> Optional[str]:
        if not self._entries:
            self._current_root = None
            return None
        self._current_root = MerkleTree.compute_root_from_entries(self._entries)
        return self._current_root

    @property
    def merkle_root(self) -> Optional[str]:
        return self._current_root

    def verify_integrity(self) -> bool:
        if not self._entries and self._current_root is None:
            return True
        if self._current_root is None:
            return False
        return MerkleTree.verify(self._entries, self._current_root)

    def get_entries(self) -> List[ThreatLogEntry]:
        return list(self._entries)

    def to_dict_list(self) -> List[dict]:
        return [asdict(e) for e in self._entries]

    def snapshot(self) -> dict:
        return {
            "merkle_root": self._current_root,
            "entries": self.to_dict_list(),
        }

    def build_merkle_tree(self) -> Optional[MerkleTree]:
        if not self._entries:
            return None
        return MerkleTree.from_entries(self._entries)
