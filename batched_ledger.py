from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional

from merkle_ledger import ThreatLogEntry, MerkleTree, sha256_hex

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64


def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64.encode("utf-8"))
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


@dataclass
class MerkleBatch:
    batch_id: int
    sealed_at: str
    merkle_root: str
    entry_count: int
    signature: str

    def to_canonical_string(self) -> str:
        return "|".join(
            [
                str(self.batch_id),
                self.sealed_at,
                self.merkle_root,
                str(self.entry_count),
                self.signature,
            ]
        )


@dataclass
class Block:
    index: int
    batch: MerkleBatch
    prev_block_hash: str
    block_hash: str
    created_at: str

    @staticmethod
    def create(index: int, batch: MerkleBatch, prev_block_hash: str) -> "Block":
        created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        header = "|".join(
            [
                str(index),
                batch.to_canonical_string(),
                prev_block_hash,
                created_at,
            ]
        )
        block_hash = sha256_hex(header)
        return Block(
            index=index,
            batch=batch,
            prev_block_hash=prev_block_hash,
            block_hash=block_hash,
            created_at=created_at,
        )

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "batch": asdict(self.batch),
            "prev_block_hash": self.prev_block_hash,
            "block_hash": self.block_hash,
            "created_at": self.created_at,
        }


class BatchedThreatLogLedger:
    def __init__(
        self,
        batch_size: int = 50,
        private_key: Optional[rsa.RSAPrivateKey] = None,
    ):
        self.batch_size = batch_size
        self._open_entries: List[ThreatLogEntry] = []
        self._sealed_batches: List[List[ThreatLogEntry]] = []
        self._blocks: List[Block] = []
        self._private_key: rsa.RSAPrivateKey = private_key or generate_rsa_keypair()
        self._public_key = self._private_key.public_key()

    @property
    def open_entries(self) -> List[ThreatLogEntry]:
        return list(self._open_entries)

    @property
    def sealed_batches(self) -> List[List[ThreatLogEntry]]:
        return [list(b) for b in self._sealed_batches]

    @property
    def blocks(self) -> List[Block]:
        return list(self._blocks)

    @property
    def public_key_pem(self) -> str:
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def add_entry(self, entry: ThreatLogEntry) -> None:
        self._open_entries.append(entry)
        if len(self._open_entries) >= self.batch_size:
            self.seal_current_batch()

    def _create_signed_batch(self, entries: List[ThreatLogEntry]) -> MerkleBatch:
        batch_id = len(self._sealed_batches)
        merkle_root = MerkleTree.compute_root_from_entries(entries)
        sealed_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        signature = sign_bytes(self._private_key, merkle_root.encode("utf-8"))
        return MerkleBatch(
            batch_id=batch_id + 1,
            sealed_at=sealed_at,
            merkle_root=merkle_root,
            entry_count=len(entries),
            signature=signature,
        )

    def seal_current_batch(self) -> Optional[Block]:
        if not self._open_entries:
            return None
        entries = self._open_entries
        self._open_entries = []
        self._sealed_batches.append(entries)
        batch = self._create_signed_batch(entries)
        prev_block_hash = self._blocks[-1].block_hash if self._blocks else ""
        block = Block.create(index=len(self._blocks) + 1, batch=batch, prev_block_hash=prev_block_hash)
        self._blocks.append(block)
        return block

    def verify_batch_integrity(self, batch_index: int) -> bool:
        if batch_index < 0 or batch_index >= len(self._sealed_batches):
            return False
        entries = self._sealed_batches[batch_index]
        block = self._blocks[batch_index]
        batch = block.batch
        recomputed_root = MerkleTree.compute_root_from_entries(entries)
        if recomputed_root != batch.merkle_root:
            return False
        if not verify_signature(self._public_key, batch.merkle_root.encode("utf-8"), batch.signature):
            return False
        return True

    def verify_block_chain(self) -> bool:
        prev_hash = ""
        for i, block in enumerate(self._blocks, start=1):
            if block.index != i:
                return False
            header = "|".join(
                [
                    str(block.index),
                    block.batch.to_canonical_string(),
                    block.prev_block_hash,
                    block.created_at,
                ]
            )
            expected_hash = sha256_hex(header)
            if expected_hash != block.block_hash:
                return False
            if block.prev_block_hash != prev_hash:
                return False
            prev_hash = block.block_hash
        return True

    def verify_all(self) -> bool:
        for i in range(len(self._sealed_batches)):
            if not self.verify_batch_integrity(i):
                return False
        if not self.verify_block_chain():
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "batch_size": self.batch_size,
            "open_entries": [asdict(e) for e in self._open_entries],
            "sealed_batch_count": len(self._sealed_batches),
            "blocks": [b.to_dict() for b in self._blocks],
            "public_key_pem": self.public_key_pem,
        }
