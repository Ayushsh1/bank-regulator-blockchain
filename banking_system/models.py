from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Bank:
    bank_id: str
    name: str
    country: str
    bank_type: str
    capital_reserve: float
    status: str = "active"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TransactionRecord:
    txn_id: str
    bank_id: str
    counterparty_bank: str
    currency: str
    amount: float
    txn_type: str
    reported_at: str = field(default_factory=utc_now)
    flagged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditCase:
    audit_id: str
    bank_id: str
    reason: str
    status: str = "open"
    findings: str | None = None
    opened_at: str = field(default_factory=utc_now)
    closed_at: str | None = None
    archived: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Sanction:
    sanction_id: str
    bank_id: str
    penalty_amount: float
    reason: str
    issued_at: str = field(default_factory=utc_now)
    archived: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RegulatorUser:
    username: str
    password_hash: str
    role: str
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("password_hash", None)
        return data
