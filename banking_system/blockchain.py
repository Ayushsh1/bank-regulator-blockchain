from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Block:
    index: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    nonce: int = 0
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }
        encoded = json.dumps(block_data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }


class BlockchainLedger:
    def __init__(self, existing_blocks: list[dict[str, Any]] | None = None) -> None:
        if existing_blocks:
            self.chain = [self._block_from_dict(item) for item in existing_blocks]
        else:
            self.chain = [self._create_genesis_block()]

    def _create_genesis_block(self) -> Block:
        return Block(
            index=0,
            timestamp=utc_now(),
            event_type="genesis",
            payload={"message": "Reserve bank supervision ledger initialized"},
            previous_hash="0" * 64,
        )

    def add_block(self, event_type: str, payload: dict[str, Any]) -> Block:
        previous = self.chain[-1]
        block = Block(
            index=len(self.chain),
            timestamp=utc_now(),
            event_type=event_type,
            payload=payload,
            previous_hash=previous.hash,
        )
        self.chain.append(block)
        return block

    def _block_from_dict(self, data: dict[str, Any]) -> Block:
        block = Block(
            index=data["index"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            payload=data["payload"],
            previous_hash=data["previous_hash"],
            nonce=data.get("nonce", 0),
        )
        block.hash = data["hash"]
        return block

    def verify(self) -> dict[str, Any]:
        for index in range(1, len(self.chain)):
            current = self.chain[index]
            previous = self.chain[index - 1]
            if current.previous_hash != previous.hash:
                return {
                    "valid": False,
                    "error": f"Broken chain link at block {current.index}",
                }
            if current.compute_hash() != current.hash:
                return {
                    "valid": False,
                    "error": f"Hash mismatch at block {current.index}",
                }
        return {"valid": True, "length": len(self.chain)}

    def to_list(self) -> list[dict[str, Any]]:
        return [block.to_dict() for block in self.chain]
