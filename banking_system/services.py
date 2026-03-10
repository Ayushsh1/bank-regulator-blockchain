from __future__ import annotations

import csv
import hashlib
import json
import secrets
import io
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hmac
from pathlib import Path
from typing import Any

from banking_system.blockchain import BlockchainLedger
from banking_system.models import AuditCase, Bank, RegulatorUser, Sanction, TransactionRecord
from banking_system.storage import SQLiteStorage


class ValidationError(ValueError):
    """Raised when a request payload is invalid."""


class NotFoundError(KeyError):
    """Raised when a requested record does not exist."""


class AuthenticationError(PermissionError):
    """Raised when authentication fails."""


class AuthorizationError(PermissionError):
    """Raised when an authenticated user lacks permission."""


class BankingRegulatorService:
    def __init__(self, db_path: str | Path | None = None, session_timeout_minutes: int = 30) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        resolved_db_path = Path(db_path) if db_path else base_dir / "regulator.db"
        self.session_timeout_minutes = session_timeout_minutes
        self.storage = SQLiteStorage(resolved_db_path)
        existing_blocks = self.storage.load_blocks()
        self.ledger = BlockchainLedger(existing_blocks if existing_blocks else None)
        if not existing_blocks:
            self.storage.insert_block(self.ledger.chain[0].to_dict())
        self._ensure_default_admin()

    def register_bank(self, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        required = ["bank_id", "name", "country", "bank_type", "capital_reserve"]
        self._require_fields(payload, required)
        bank_id = payload["bank_id"]
        if self.storage.fetch_one("SELECT bank_id FROM banks WHERE bank_id = :bank_id", {"bank_id": bank_id}):
            raise ValidationError(f"Bank '{bank_id}' already exists.")

        bank = Bank(
            bank_id=bank_id,
            name=payload["name"],
            country=payload["country"],
            bank_type=payload["bank_type"],
            capital_reserve=float(payload["capital_reserve"]),
        )
        block = self.ledger.add_block("bank_registered", bank.to_dict())
        self.storage.insert("banks", bank.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "bank_registered", {"bank_id": bank.bank_id})
        return {"bank": bank.to_dict(), "block_hash": block.hash}

    def list_banks(self) -> list[dict[str, Any]]:
        return self.storage.fetch_all("SELECT * FROM banks ORDER BY created_at ASC")

    def record_transaction(self, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        required = ["txn_id", "bank_id", "counterparty_bank", "currency", "amount", "txn_type"]
        self._require_fields(payload, required)
        txn_id = payload["txn_id"]
        if self.storage.fetch_one("SELECT txn_id FROM transactions WHERE txn_id = :txn_id", {"txn_id": txn_id}):
            raise ValidationError(f"Transaction '{txn_id}' already exists.")
        bank = self._get_bank(payload["bank_id"])

        amount = float(payload["amount"])
        flagged = amount >= 1_000_000
        transaction = TransactionRecord(
            txn_id=txn_id,
            bank_id=bank.bank_id,
            counterparty_bank=payload["counterparty_bank"],
            currency=payload["currency"],
            amount=amount,
            txn_type=payload["txn_type"],
            flagged=flagged,
        )
        block = self.ledger.add_block("transaction_reported", transaction.to_dict())
        tx_data = transaction.to_dict()
        tx_data["flagged"] = int(tx_data["flagged"])
        self.storage.insert("transactions", tx_data)
        self.storage.insert_block(block.to_dict())
        self._log_event(
            actor,
            "transaction_reported",
            {"txn_id": transaction.txn_id, "bank_id": transaction.bank_id, "flagged": transaction.flagged},
        )
        return {"transaction": transaction.to_dict(), "block_hash": block.hash}

    def delete_transaction(self, txn_id: str, actor: str = "system") -> dict[str, Any]:
        row = self.storage.fetch_one(
            "SELECT * FROM transactions WHERE txn_id = :txn_id",
            {"txn_id": txn_id},
        )
        if row is None:
            raise NotFoundError(f"Transaction '{txn_id}' does not exist.")
        self.storage.execute(
            "DELETE FROM transactions WHERE txn_id = :txn_id",
            {"txn_id": txn_id},
        )
        block = self.ledger.add_block(
            "transaction_deleted",
            {"txn_id": row["txn_id"], "bank_id": row["bank_id"]},
        )
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "transaction_deleted", {"txn_id": row["txn_id"], "bank_id": row["bank_id"]})
        row["flagged"] = bool(row["flagged"])
        return {"transaction": row, "block_hash": block.hash}

    def list_transactions(self) -> list[dict[str, Any]]:
        rows = self.storage.fetch_all("SELECT * FROM transactions ORDER BY reported_at ASC")
        for row in rows:
            row["flagged"] = bool(row["flagged"])
        return rows

    def open_audit(self, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        required = ["audit_id", "bank_id", "reason"]
        self._require_fields(payload, required)
        audit_id = payload["audit_id"]
        if self.storage.fetch_one("SELECT audit_id FROM audits WHERE audit_id = :audit_id", {"audit_id": audit_id}):
            raise ValidationError(f"Audit '{audit_id}' already exists.")
        self._get_bank(payload["bank_id"])

        audit = AuditCase(
            audit_id=audit_id,
            bank_id=payload["bank_id"],
            reason=payload["reason"],
        )
        block = self.ledger.add_block("audit_opened", audit.to_dict())
        audit_data = audit.to_dict()
        audit_data["archived"] = int(audit_data["archived"])
        self.storage.insert("audits", audit_data)
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "audit_opened", {"audit_id": audit.audit_id, "bank_id": audit.bank_id})
        return {"audit": audit.to_dict(), "block_hash": block.hash}

    def close_audit(self, audit_id: str, findings: str, actor: str = "system") -> dict[str, Any]:
        if not findings:
            raise ValidationError("findings is required to close an audit.")
        audit = self._get_audit(audit_id)
        if audit.status == "closed":
            raise ValidationError(f"Audit '{audit_id}' is already closed.")

        audit.status = "closed"
        audit.findings = findings
        audit.closed_at = datetime.now(timezone.utc).isoformat()
        block = self.ledger.add_block("audit_closed", audit.to_dict())
        self.storage.update(
            "audits",
            "audit_id",
            audit_id,
            {
                "status": audit.status,
                "findings": audit.findings,
                "closed_at": audit.closed_at,
            },
        )
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "audit_closed", {"audit_id": audit.audit_id, "bank_id": audit.bank_id})
        return {"audit": audit.to_dict(), "block_hash": block.hash}

    def update_audit(self, audit_id: str, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        audit = self._get_audit(audit_id)
        updates: dict[str, Any] = {}
        if "reason" in payload:
            reason = str(payload["reason"]).strip()
            if not reason:
                raise ValidationError("reason cannot be empty.")
            audit.reason = reason
            updates["reason"] = reason
        if not updates:
            raise ValidationError("No audit fields provided for update.")

        self.storage.update("audits", "audit_id", audit_id, updates)
        block = self.ledger.add_block("audit_updated", audit.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "audit_updated", {"audit_id": audit.audit_id, "bank_id": audit.bank_id})
        return {"audit": audit.to_dict(), "block_hash": block.hash}

    def archive_audit(self, audit_id: str, actor: str = "system") -> dict[str, Any]:
        audit = self._get_audit(audit_id)
        if audit.archived:
            raise ValidationError(f"Audit '{audit_id}' is already archived.")
        audit.archived = True
        self.storage.update("audits", "audit_id", audit_id, {"archived": 1})
        block = self.ledger.add_block("audit_archived", audit.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "audit_archived", {"audit_id": audit.audit_id, "bank_id": audit.bank_id})
        return {"audit": audit.to_dict(), "block_hash": block.hash}

    def list_audits(self) -> list[dict[str, Any]]:
        rows = self.storage.fetch_all("SELECT * FROM audits ORDER BY opened_at ASC")
        for row in rows:
            row["archived"] = bool(row["archived"])
        return rows

    def issue_sanction(self, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        required = ["sanction_id", "bank_id", "penalty_amount", "reason"]
        self._require_fields(payload, required)
        sanction_id = payload["sanction_id"]
        if self.storage.fetch_one("SELECT sanction_id FROM sanctions WHERE sanction_id = :sanction_id", {"sanction_id": sanction_id}):
            raise ValidationError(f"Sanction '{sanction_id}' already exists.")
        self._get_bank(payload["bank_id"])

        sanction = Sanction(
            sanction_id=sanction_id,
            bank_id=payload["bank_id"],
            penalty_amount=float(payload["penalty_amount"]),
            reason=payload["reason"],
        )
        block = self.ledger.add_block("sanction_issued", sanction.to_dict())
        sanction_data = sanction.to_dict()
        sanction_data["archived"] = int(sanction_data["archived"])
        self.storage.insert("sanctions", sanction_data)
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "sanction_issued", {"sanction_id": sanction.sanction_id, "bank_id": sanction.bank_id})
        return {"sanction": sanction.to_dict(), "block_hash": block.hash}

    def update_sanction(self, sanction_id: str, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        row = self.storage.fetch_one(
            "SELECT * FROM sanctions WHERE sanction_id = :sanction_id",
            {"sanction_id": sanction_id},
        )
        if row is None:
            raise NotFoundError(f"Sanction '{sanction_id}' does not exist.")

        row["archived"] = bool(row["archived"])
        sanction = Sanction(**row)
        updates: dict[str, Any] = {}
        if "penalty_amount" in payload:
            penalty_amount = float(payload["penalty_amount"])
            if penalty_amount < 0:
                raise ValidationError("penalty_amount cannot be negative.")
            sanction.penalty_amount = penalty_amount
            updates["penalty_amount"] = penalty_amount
        if "reason" in payload:
            reason = str(payload["reason"]).strip()
            if not reason:
                raise ValidationError("reason cannot be empty.")
            sanction.reason = reason
            updates["reason"] = reason
        if not updates:
            raise ValidationError("No sanction fields provided for update.")

        self.storage.update("sanctions", "sanction_id", sanction_id, updates)
        block = self.ledger.add_block("sanction_updated", sanction.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "sanction_updated", {"sanction_id": sanction.sanction_id, "bank_id": sanction.bank_id})
        return {"sanction": sanction.to_dict(), "block_hash": block.hash}

    def archive_sanction(self, sanction_id: str, actor: str = "system") -> dict[str, Any]:
        row = self.storage.fetch_one(
            "SELECT * FROM sanctions WHERE sanction_id = :sanction_id",
            {"sanction_id": sanction_id},
        )
        if row is None:
            raise NotFoundError(f"Sanction '{sanction_id}' does not exist.")
        sanction = Sanction(**{**row, "archived": bool(row["archived"])})
        if sanction.archived:
            raise ValidationError(f"Sanction '{sanction_id}' is already archived.")
        sanction.archived = True
        self.storage.update("sanctions", "sanction_id", sanction_id, {"archived": 1})
        block = self.ledger.add_block("sanction_archived", sanction.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "sanction_archived", {"sanction_id": sanction.sanction_id, "bank_id": sanction.bank_id})
        return {"sanction": sanction.to_dict(), "block_hash": block.hash}

    def list_sanctions(self) -> list[dict[str, Any]]:
        rows = self.storage.fetch_all("SELECT * FROM sanctions ORDER BY issued_at ASC")
        for row in rows:
            row["archived"] = bool(row["archived"])
        return rows

    def blockchain_state(self) -> list[dict[str, Any]]:
        return self.ledger.to_list()

    def verify_blockchain(self) -> dict[str, Any]:
        return self.ledger.verify()

    def dashboard(self) -> dict[str, Any]:
        transactions = self.list_transactions()
        audits = self.list_audits()
        sanctions = self.list_sanctions()
        flagged_count = sum(1 for txn in transactions if txn["flagged"])
        total_exposure = sum(float(txn["amount"]) for txn in transactions)
        open_audits = sum(1 for audit in audits if audit["status"] == "open")
        total_penalties = sum(float(s["penalty_amount"]) for s in sanctions)
        return {
            "banks_registered": len(self.list_banks()),
            "transactions_reported": len(transactions),
            "flagged_transactions": flagged_count,
            "open_audits": open_audits,
            "sanctions_issued": len(sanctions),
            "total_penalties": total_penalties,
            "reported_exposure": total_exposure,
            "blockchain_status": self.ledger.verify(),
        }

    def bank_oversight_summary(self, token: str | None) -> list[dict[str, Any]]:
        self.authorize(token, {"admin"})
        banks = self.list_banks()
        transactions = self.list_transactions()
        audits = self.list_audits()
        sanctions = self.list_sanctions()

        summary: list[dict[str, Any]] = []
        for bank in banks:
            bank_id = bank["bank_id"]
            bank_transactions = [item for item in transactions if item["bank_id"] == bank_id]
            bank_audits = [item for item in audits if item["bank_id"] == bank_id]
            bank_sanctions = [item for item in sanctions if item["bank_id"] == bank_id]
            flagged_count = sum(1 for item in bank_transactions if item["flagged"])
            flagged_exposure = sum(float(item["amount"]) for item in bank_transactions if item["flagged"])
            total_exposure = sum(float(item["amount"]) for item in bank_transactions)
            active_audits = [item for item in bank_audits if not item["archived"]]
            active_sanctions = [item for item in bank_sanctions if not item["archived"]]
            open_audits = sum(1 for item in active_audits if item["status"] == "open")
            total_penalties = sum(float(item["penalty_amount"]) for item in active_sanctions)
            risk_score = (flagged_count * 25) + (open_audits * 20) + (len(active_sanctions) * 15)
            if flagged_exposure >= 1_000_000:
                risk_score += 20
            summary.append(
                {
                    "bank_id": bank_id,
                    "name": bank["name"],
                    "bank_type": bank["bank_type"],
                    "country": bank["country"],
                    "capital_reserve": float(bank["capital_reserve"]),
                    "transactions_reported": len(bank_transactions),
                    "flagged_transactions": flagged_count,
                    "flagged_exposure": flagged_exposure,
                    "reported_exposure": total_exposure,
                    "open_audits": open_audits,
                    "total_audits": len(active_audits),
                    "sanctions_issued": len(active_sanctions),
                    "total_penalties": total_penalties,
                    "risk_score": min(risk_score, 100),
                }
            )
        summary.sort(key=lambda item: (-item["risk_score"], item["bank_id"]))
        return summary

    def bank_detail(self, token: str | None, bank_id: str) -> dict[str, Any]:
        self.authorize(token, {"admin"})
        bank = next((item for item in self.list_banks() if item["bank_id"] == bank_id), None)
        if bank is None:
            raise NotFoundError(f"Bank '{bank_id}' does not exist.")

        summary = next((item for item in self.bank_oversight_summary(token) if item["bank_id"] == bank_id), None)
        transactions = [item for item in self.list_transactions() if item["bank_id"] == bank_id]
        audits = [item for item in self.list_audits() if item["bank_id"] == bank_id]
        sanctions = [item for item in self.list_sanctions() if item["bank_id"] == bank_id]

        transaction_timeline: dict[str, int] = {}
        for item in transactions:
            bucket = item["reported_at"][:10]
            transaction_timeline[bucket] = transaction_timeline.get(bucket, 0) + 1

        recent_logs = [
            item for item in self.storage.load_logs(limit=200)
            if item["details"].get("bank_id") == bank_id
        ][:25]

        return {
            "bank": bank,
            "summary": summary,
            "transactions": transactions,
            "audits": audits,
            "sanctions": sanctions,
            "transaction_timeline": [
                {"date": key, "count": value}
                for key, value in sorted(transaction_timeline.items())
            ],
            "recent_logs": recent_logs,
        }

    def request_approval(
        self,
        token: str | None,
        action_type: str,
        target_id: str,
        target_bank_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self.authorize(token, {"admin"})
        allowed_actions = {"delete_transaction", "archive_audit", "archive_sanction", "close_audit"}
        if action_type not in allowed_actions:
            raise ValidationError(f"Unsupported approval action '{action_type}'.")
        if not target_id or not target_bank_id:
            raise ValidationError("target_id and target_bank_id are required.")

        request = {
            "requested_by": session["username"],
            "approved_by": None,
            "action_type": action_type,
            "target_id": target_id,
            "target_bank_id": target_bank_id,
            "payload_json": json.dumps(payload or {}, sort_keys=True),
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "decided_at": None,
            "decision_note": None,
        }
        self.storage.insert("approval_requests", request)
        row = self.storage.fetch_one("SELECT MAX(id) AS id FROM approval_requests")
        request_id = int(row["id"])
        self._log_event(
            session["username"],
            "approval_requested",
            {"request_id": request_id, "action_type": action_type, "target_id": target_id, "bank_id": target_bank_id},
        )
        return {"request_id": request_id, "status": "pending"}

    def list_approvals(self, token: str | None, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        self.authorize(token, {"admin"})
        safe_limit = max(1, min(limit, 200))
        if status and status not in {"pending", "approved", "rejected"}:
            raise ValidationError("status must be pending, approved, or rejected.")
        return self.storage.load_approvals(status=status, limit=safe_limit)

    def approve_request(self, token: str | None, request_id: int, decision_note: str = "") -> dict[str, Any]:
        session = self.authorize(token, {"admin"})
        request = self._get_approval_request(request_id)
        if request["status"] != "pending":
            raise ValidationError(f"Approval request '{request_id}' is already {request['status']}.")
        if request["requested_by"] == session["username"]:
            raise AuthorizationError("A second admin must approve this request.")

        payload = request["payload"]
        if request["action_type"] == "delete_transaction":
            result = self.delete_transaction(request["target_id"], actor=session["username"])
        elif request["action_type"] == "archive_audit":
            result = self.archive_audit(request["target_id"], actor=session["username"])
        elif request["action_type"] == "archive_sanction":
            result = self.archive_sanction(request["target_id"], actor=session["username"])
        elif request["action_type"] == "close_audit":
            result = self.close_audit(
                request["target_id"],
                str(payload.get("findings", "")),
                actor=session["username"],
            )
        else:
            raise ValidationError(f"Unsupported approval action '{request['action_type']}'.")

        self.storage.update(
            "approval_requests",
            "id",
            request_id,
            {
                "status": "approved",
                "approved_by": session["username"],
                "decided_at": datetime.now(timezone.utc).isoformat(),
                "decision_note": decision_note,
            },
        )
        self._log_event(
            session["username"],
            "approval_approved",
            {"request_id": request_id, "action_type": request["action_type"], "target_id": request["target_id"]},
        )
        return {"request_id": request_id, "status": "approved", "result": result}

    def reject_request(self, token: str | None, request_id: int, decision_note: str = "") -> dict[str, Any]:
        session = self.authorize(token, {"admin"})
        request = self._get_approval_request(request_id)
        if request["status"] != "pending":
            raise ValidationError(f"Approval request '{request_id}' is already {request['status']}.")
        if request["requested_by"] == session["username"]:
            raise AuthorizationError("A second admin must reject this request.")

        self.storage.update(
            "approval_requests",
            "id",
            request_id,
            {
                "status": "rejected",
                "approved_by": session["username"],
                "decided_at": datetime.now(timezone.utc).isoformat(),
                "decision_note": decision_note,
            },
        )
        self._log_event(
            session["username"],
            "approval_rejected",
            {"request_id": request_id, "action_type": request["action_type"], "target_id": request["target_id"]},
        )
        return {"request_id": request_id, "status": "rejected"}

    def create_user(self, payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        required = ["username", "password", "role"]
        self._require_fields(payload, required)
        username = payload["username"]
        role = payload["role"]
        if role not in {"admin", "auditor", "supervisor"}:
            raise ValidationError("role must be one of: admin, auditor, supervisor")
        if self.storage.fetch_one("SELECT username FROM users WHERE username = :username", {"username": username}):
            raise ValidationError(f"User '{username}' already exists.")

        user = RegulatorUser(
            username=username,
            password_hash=self._hash_password(payload["password"]),
            role=role,
        )
        self.storage.insert("users", asdict(user))
        block = self.ledger.add_block("user_created", user.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event(actor, "user_created", {"username": user.username, "role": user.role})
        return {"user": user.to_dict(), "block_hash": block.hash}

    def list_users(self) -> list[dict[str, Any]]:
        return self.storage.fetch_all(
            "SELECT username, role, created_at FROM users ORDER BY created_at ASC"
        )

    def login(self, payload: dict[str, Any]) -> dict[str, Any]:
        required = ["username", "password"]
        self._require_fields(payload, required)
        row = self.storage.fetch_one(
            "SELECT username, password_hash, role, created_at FROM users WHERE username = :username",
            {"username": payload["username"]},
        )
        if row is None or not self._verify_password(payload["password"], row["password_hash"]):
            raise AuthenticationError("Invalid username or password.")
        if self._is_legacy_hash(row["password_hash"]):
            self.storage.update(
                "users",
                "username",
                row["username"],
                {"password_hash": self._hash_password(payload["password"])},
            )

        self._delete_sessions_for_user(row["username"])
        token = secrets.token_hex(24)
        now = datetime.now(timezone.utc)
        session = {
            "token": token,
            "username": row["username"],
            "role": row["role"],
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=self.session_timeout_minutes)).isoformat(),
            "client_ip": str(payload.get("client_ip", "")),
            "user_agent": str(payload.get("user_agent", "")),
        }
        self.storage.upsert_session(session)
        self._log_event(
            row["username"],
            "login",
            {
                "role": row["role"],
                "expires_at": session["expires_at"],
                "client_ip": session["client_ip"],
                "user_agent": session["user_agent"],
            },
        )
        return {
            "token": token,
            "expires_at": session["expires_at"],
            "user": {"username": row["username"], "role": row["role"]},
        }

    def authenticate(self, token: str | None) -> dict[str, Any]:
        if not token:
            raise AuthenticationError("Missing authentication token.")
        self._purge_expired_sessions()
        session = self.storage.fetch_one(
            "SELECT token, username, role, created_at, expires_at, client_ip, user_agent FROM sessions WHERE token = :token",
            {"token": token},
        )
        if session is None:
            raise AuthenticationError("Invalid or expired authentication token.")
        return session

    def authorize(self, token: str | None, allowed_roles: set[str]) -> dict[str, Any]:
        session = self.authenticate(token)
        if session["role"] not in allowed_roles:
            raise AuthorizationError("User does not have permission for this action.")
        return session

    def logout(self, token: str | None) -> dict[str, Any]:
        session = self.authenticate(token)
        self.storage.execute(
            "DELETE FROM sessions WHERE token = :token",
            {"token": session["token"]},
        )
        self._log_event(session["username"], "logout", {"role": session["role"]})
        return {"message": f"User '{session['username']}' logged out successfully."}

    def refresh_session(self, token: str | None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        session = self.authenticate(token)
        payload = payload or {}
        now = datetime.now(timezone.utc)
        current_expiry = datetime.fromisoformat(session["expires_at"])
        base_time = current_expiry if current_expiry > now else now
        expires_at = (base_time + timedelta(minutes=self.session_timeout_minutes)).isoformat()
        client_ip = str(payload.get("client_ip", session.get("client_ip", "")))
        user_agent = str(payload.get("user_agent", session.get("user_agent", "")))
        self.storage.update(
            "sessions",
            "token",
            session["token"],
            {
                "created_at": now.isoformat(),
                "expires_at": expires_at,
                "client_ip": client_ip,
                "user_agent": user_agent,
            },
        )
        self._log_event(
            session["username"],
            "session_refreshed",
            {"expires_at": expires_at, "client_ip": client_ip, "user_agent": user_agent},
        )
        return {"token": session["token"], "expires_at": expires_at}

    def change_password(self, token: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        session = self.authenticate(token)
        required = ["current_password", "new_password"]
        self._require_fields(payload, required)
        row = self.storage.fetch_one(
            "SELECT username, password_hash FROM users WHERE username = :username",
            {"username": session["username"]},
        )
        if row is None or not self._verify_password(payload["current_password"], row["password_hash"]):
            raise AuthenticationError("Current password is incorrect.")
        self._validate_password_strength(payload["new_password"])
        self.storage.update(
            "users",
            "username",
            session["username"],
            {"password_hash": self._hash_password(payload["new_password"])},
        )
        self._delete_sessions_for_user(session["username"])
        block = self.ledger.add_block(
            "password_changed",
            {"username": session["username"], "changed_by": session["username"]},
        )
        self.storage.insert_block(block.to_dict())
        self._log_event(session["username"], "password_changed", {"changed_by": session["username"]})
        return {"message": f"Password updated for '{session['username']}'."}

    def reset_password(self, token: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        admin_session = self.authorize(token, {"admin"})
        required = ["username", "new_password"]
        self._require_fields(payload, required)
        username = payload["username"]
        if self.storage.fetch_one(
            "SELECT username FROM users WHERE username = :username",
            {"username": username},
        ) is None:
            raise NotFoundError(f"User '{username}' does not exist.")
        self._validate_password_strength(payload["new_password"])
        self.storage.update(
            "users",
            "username",
            username,
            {"password_hash": self._hash_password(payload["new_password"])},
        )
        self._delete_sessions_for_user(username)
        block = self.ledger.add_block(
            "password_reset",
            {"username": username, "changed_by": admin_session["username"]},
        )
        self.storage.insert_block(block.to_dict())
        self._log_event(admin_session["username"], "password_reset", {"username": username})
        return {"message": f"Password reset for '{username}'."}

    def list_logs(
        self,
        token: str | None,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        self.authorize(token, {"admin"})
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)
        return self.storage.load_logs(safe_limit, safe_offset, actor, action)

    def export_logs_csv(
        self,
        token: str | None,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
    ) -> str:
        logs = self.list_logs(token, limit=limit, offset=offset, actor=actor, action=action)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "timestamp", "actor", "action", "details"])
        for item in logs:
            writer.writerow(
                [
                    item["id"],
                    item["timestamp"],
                    item["actor"],
                    item["action"],
                    json.dumps(item["details"], sort_keys=True),
                ]
            )
        return output.getvalue()

    def seed_demo_data(self) -> None:
        if self.storage.count("banks") > 0:
            return
        self.register_bank(
            {
                "bank_id": "BANK001",
                "name": "National Forex Bank",
                "country": "India",
                "bank_type": "forex",
                "capital_reserve": 25_000_000,
            }
        )
        self.register_bank(
            {
                "bank_id": "BANK002",
                "name": "Central Trade Bank",
                "country": "India",
                "bank_type": "commercial",
                "capital_reserve": 40_000_000,
            }
        )
        self.record_transaction(
            {
                "txn_id": "TXN-1001",
                "bank_id": "BANK001",
                "counterparty_bank": "BANK002",
                "currency": "USD",
                "amount": 1_500_000,
                "txn_type": "cross_border_settlement",
            }
        )
        self.open_audit(
            {
                "audit_id": "AUD-1",
                "bank_id": "BANK001",
                "reason": "Large forex exposure mismatch",
            }
        )

    def _require_fields(self, payload: dict[str, Any], required: list[str]) -> None:
        missing = [field for field in required if field not in payload]
        if missing:
            raise ValidationError(f"Missing required fields: {', '.join(missing)}")

    def _get_bank(self, bank_id: str) -> Bank:
        row = self.storage.fetch_one("SELECT * FROM banks WHERE bank_id = :bank_id", {"bank_id": bank_id})
        if row is None:
            raise NotFoundError(f"Bank '{bank_id}' does not exist.")
        return Bank(**row)

    def _get_audit(self, audit_id: str) -> AuditCase:
        row = self.storage.fetch_one("SELECT * FROM audits WHERE audit_id = :audit_id", {"audit_id": audit_id})
        if row is None:
            raise NotFoundError(f"Audit '{audit_id}' does not exist.")
        row["archived"] = bool(row["archived"])
        return AuditCase(**row)

    def _get_approval_request(self, request_id: int) -> dict[str, Any]:
        row = self.storage.fetch_one(
            """
            SELECT id, requested_by, approved_by, action_type, target_id, target_bank_id,
                   payload_json, status, created_at, decided_at, decision_note
            FROM approval_requests
            WHERE id = :id
            """,
            {"id": request_id},
        )
        if row is None:
            raise NotFoundError(f"Approval request '{request_id}' does not exist.")
        row["payload"] = json.loads(row.pop("payload_json"))
        return row

    def _ensure_default_admin(self) -> None:
        if self.storage.count("users") > 0:
            return
        admin = RegulatorUser(
            username="admin",
            password_hash=self._hash_password("admin123"),
            role="admin",
        )
        self.storage.insert("users", asdict(admin))
        block = self.ledger.add_block("user_created", admin.to_dict())
        self.storage.insert_block(block.to_dict())
        self._log_event("system", "default_admin_created", {"username": admin.username})

    def _hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        iterations = 200_000
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"

    def _validate_password_strength(self, password: str) -> None:
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")

    def _delete_sessions_for_user(self, username: str) -> None:
        self.storage.execute(
            "DELETE FROM sessions WHERE username = :username",
            {"username": username},
        )

    def _purge_expired_sessions(self) -> None:
        self.storage.execute(
            "DELETE FROM sessions WHERE expires_at <> '' AND expires_at <= :now",
            {"now": datetime.now(timezone.utc).isoformat()},
        )

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        if self._is_legacy_hash(stored_hash):
            legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return hmac.compare_digest(legacy, stored_hash)
        try:
            algorithm, iterations_text, salt_hex, digest_hex = stored_hash.split("$", 3)
        except ValueError:
            return False
        if algorithm != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations_text),
        )
        return hmac.compare_digest(derived.hex(), digest_hex)

    def _is_legacy_hash(self, stored_hash: str) -> bool:
        return "$" not in stored_hash and len(stored_hash) == 64

    def _log_event(self, actor: str, action: str, details: dict[str, Any]) -> None:
        self.storage.insert_log(
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            details=details,
        )
