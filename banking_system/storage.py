from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class SQLiteStorage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS banks (
                    bank_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    country TEXT NOT NULL,
                    bank_type TEXT NOT NULL,
                    capital_reserve REAL NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS transactions (
                    txn_id TEXT PRIMARY KEY,
                    bank_id TEXT NOT NULL,
                    counterparty_bank TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    amount REAL NOT NULL,
                    txn_type TEXT NOT NULL,
                    reported_at TEXT NOT NULL,
                    flagged INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audits (
                    audit_id TEXT PRIMARY KEY,
                    bank_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    findings TEXT,
                    opened_at TEXT NOT NULL,
                    closed_at TEXT,
                    archived INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS sanctions (
                    sanction_id TEXT PRIMARY KEY,
                    bank_id TEXT NOT NULL,
                    penalty_amount REAL NOT NULL,
                    reason TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    archived INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    client_ip TEXT NOT NULL DEFAULT '',
                    user_agent TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS blockchain_blocks (
                    idx INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requested_by TEXT NOT NULL,
                    approved_by TEXT,
                    action_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_bank_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    decision_note TEXT
                );
                """
            )
            session_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()
            }
            audit_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(audits)").fetchall()
            }
            sanction_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(sanctions)").fetchall()
            }
            if "expires_at" not in session_columns:
                conn.execute(
                    "ALTER TABLE sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"
                )
            if "client_ip" not in session_columns:
                conn.execute(
                    "ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''"
                )
            if "user_agent" not in session_columns:
                conn.execute(
                    "ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''"
                )
            if "archived" not in audit_columns:
                conn.execute(
                    "ALTER TABLE audits ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
                )
            if "archived" not in sanction_columns:
                conn.execute(
                    "ALTER TABLE sanctions ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
                )

    def insert(self, table: str, data: dict[str, Any]) -> None:
        columns = ", ".join(data.keys())
        placeholders = ", ".join(f":{key}" for key in data)
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
                data,
            )

    def upsert_session(self, data: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (token, username, role, created_at, expires_at, client_ip, user_agent)
                VALUES (:token, :username, :role, :created_at, :expires_at, :client_ip, :user_agent)
                ON CONFLICT(token) DO UPDATE SET
                    username = excluded.username,
                    role = excluded.role,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    client_ip = excluded.client_ip,
                    user_agent = excluded.user_agent
                """,
                data,
            )

    def update(self, table: str, key_field: str, key_value: Any, data: dict[str, Any]) -> None:
        assignments = ", ".join(f"{column} = :{column}" for column in data)
        payload = dict(data)
        payload["_key_value"] = key_value
        with self._connect() as conn:
            conn.execute(
                f"UPDATE {table} SET {assignments} WHERE {key_field} = :_key_value",
                payload,
            )

    def fetch_all(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(query, params or {}).fetchall()
        return [dict(row) for row in rows]

    def fetch_one(self, query: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(query, params or {}).fetchone()
        return dict(row) if row else None

    def count(self, table: str) -> int:
        row = self.fetch_one(f"SELECT COUNT(*) AS count FROM {table}")
        return int(row["count"]) if row else 0

    def execute(self, query: str, params: dict[str, Any] | None = None) -> None:
        with self._connect() as conn:
            conn.execute(query, params or {})

    def insert_block(self, block_data: dict[str, Any]) -> None:
        data = {
            "idx": block_data["index"],
            "timestamp": block_data["timestamp"],
            "event_type": block_data["event_type"],
            "payload_json": json.dumps(block_data["payload"], sort_keys=True),
            "previous_hash": block_data["previous_hash"],
            "nonce": block_data["nonce"],
            "hash": block_data["hash"],
        }
        self.insert("blockchain_blocks", data)

    def insert_log(self, timestamp: str, actor: str, action: str, details: dict[str, Any]) -> None:
        self.insert(
            "system_logs",
            {
                "timestamp": timestamp,
                "actor": actor,
                "action": action,
                "details_json": json.dumps(details, sort_keys=True),
            },
        )

    def load_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT id, timestamp, actor, action, details_json FROM system_logs"
        filters: list[str] = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if actor:
            filters.append("actor = :actor")
            params["actor"] = actor
        if action:
            filters.append("action = :action")
            params["action"] = action
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY id DESC LIMIT :limit OFFSET :offset"
        rows = self.fetch_all(query, params)
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return rows

    def load_approvals(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = """
            SELECT id, requested_by, approved_by, action_type, target_id, target_bank_id,
                   payload_json, status, created_at, decided_at, decision_note
            FROM approval_requests
        """
        params: dict[str, Any] = {"limit": limit}
        if status:
            query += " WHERE status = :status"
            params["status"] = status
        query += " ORDER BY id DESC LIMIT :limit"
        rows = self.fetch_all(query, params)
        for row in rows:
            row["payload"] = json.loads(row.pop("payload_json"))
        return rows

    def load_blocks(self) -> list[dict[str, Any]]:
        rows = self.fetch_all("SELECT * FROM blockchain_blocks ORDER BY idx ASC")
        blocks: list[dict[str, Any]] = []
        for row in rows:
            blocks.append(
                {
                    "index": row["idx"],
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "payload": json.loads(row["payload_json"]),
                    "previous_hash": row["previous_hash"],
                    "nonce": row["nonce"],
                    "hash": row["hash"],
                }
            )
        return blocks
