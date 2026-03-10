import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from banking_system.services import (
    AuthenticationError,
    AuthorizationError,
    BankingRegulatorService,
    NotFoundError,
    ValidationError,
)


class BankingRegulatorServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        handle = NamedTemporaryFile(prefix="test_regulator_", suffix=".db", delete=False)
        handle.close()
        self.db_path = Path(handle.name)
        self.service = BankingRegulatorService(db_path=self.db_path, session_timeout_minutes=30)

    def test_register_bank_writes_to_blockchain(self) -> None:
        response = self.service.register_bank(
            {
                "bank_id": "BANK100",
                "name": "Supervision Bank",
                "country": "India",
                "bank_type": "forex",
                "capital_reserve": 5_000_000,
            }
        )

        self.assertEqual(response["bank"]["bank_id"], "BANK100")
        self.assertEqual(len(self.service.blockchain_state()), 3)
        self.assertTrue(self.service.verify_blockchain()["valid"])

    def test_large_transaction_is_flagged(self) -> None:
        self.service.register_bank(
            {
                "bank_id": "BANK100",
                "name": "Supervision Bank",
                "country": "India",
                "bank_type": "forex",
                "capital_reserve": 5_000_000,
            }
        )
        response = self.service.record_transaction(
            {
                "txn_id": "TXN-1",
                "bank_id": "BANK100",
                "counterparty_bank": "BANK200",
                "currency": "USD",
                "amount": 2_000_000,
                "txn_type": "cross_border_settlement",
            }
        )

        self.assertTrue(response["transaction"]["flagged"])

    def test_open_and_close_audit(self) -> None:
        self.service.register_bank(
            {
                "bank_id": "BANK100",
                "name": "Supervision Bank",
                "country": "India",
                "bank_type": "forex",
                "capital_reserve": 5_000_000,
            }
        )
        self.service.open_audit(
            {
                "audit_id": "AUD-100",
                "bank_id": "BANK100",
                "reason": "Suspicious activity",
            }
        )
        response = self.service.close_audit("AUD-100", "Issue confirmed and corrected.")

        self.assertEqual(response["audit"]["status"], "closed")
        self.assertEqual(response["audit"]["findings"], "Issue confirmed and corrected.")

    def test_sanction_requires_existing_bank(self) -> None:
        with self.assertRaises(NotFoundError):
            self.service.issue_sanction(
                {
                    "sanction_id": "S-1",
                    "bank_id": "MISSING",
                    "penalty_amount": 1000,
                    "reason": "Missing filing",
                }
            )

    def test_missing_required_field_raises_validation(self) -> None:
        with self.assertRaises(ValidationError):
            self.service.register_bank(
                {
                    "bank_id": "BANK100",
                    "name": "Incomplete Bank",
                }
            )

    def test_default_admin_can_login(self) -> None:
        response = self.service.login(
            {
                "username": "admin",
                "password": "admin123",
                "client_ip": "127.0.0.1",
                "user_agent": "unit-test",
            }
        )

        self.assertIn("token", response)
        self.assertEqual(response["user"]["role"], "admin")
        row = self.service.storage.fetch_one(
            "SELECT password_hash FROM users WHERE username = :username",
            {"username": "admin"},
        )
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_create_user_and_authorize(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.authorize(admin["token"], {"admin"})
        self.service.create_user(
            {
                "username": "auditor1",
                "password": "pass12345",
                "role": "auditor",
            }
        )
        auditor = self.service.login({"username": "auditor1", "password": "pass12345"})

        self.assertEqual(auditor["user"]["role"], "auditor")
        with self.assertRaises(AuthorizationError):
            self.service.authorize(auditor["token"], {"admin"})

    def test_invalid_login_raises_authentication_error(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.service.login({"username": "admin", "password": "wrong-password"})

    def test_data_persists_across_service_instances(self) -> None:
        self.service.register_bank(
            {
                "bank_id": "BANK900",
                "name": "Persistent Bank",
                "country": "India",
                "bank_type": "commercial",
                "capital_reserve": 7_000_000,
            }
        )

        another = BankingRegulatorService(db_path=self.db_path)
        banks = another.list_banks()

        self.assertEqual(len(banks), 1)
        self.assertEqual(banks[0]["bank_id"], "BANK900")
        self.assertTrue(another.verify_blockchain()["valid"])

    def test_user_can_change_password(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        response = self.service.change_password(
            admin["token"],
            {"current_password": "admin123", "new_password": "newadmin123"},
        )

        self.assertIn("Password updated", response["message"])
        with self.assertRaises(AuthenticationError):
            self.service.authenticate(admin["token"])
        fresh = self.service.login({"username": "admin", "password": "newadmin123"})
        self.assertEqual(fresh["user"]["username"], "admin")

    def test_admin_can_reset_password(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.create_user(
            {
                "username": "auditor1",
                "password": "pass12345",
                "role": "auditor",
            }
        )
        response = self.service.reset_password(
            admin["token"],
            {"username": "auditor1", "new_password": "reset12345"},
        )

        self.assertIn("Password reset", response["message"])
        auditor = self.service.login({"username": "auditor1", "password": "reset12345"})
        self.assertEqual(auditor["user"]["role"], "auditor")

    def test_logout_invalidates_session(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.logout(admin["token"])

        with self.assertRaises(AuthenticationError):
            self.service.authenticate(admin["token"])

    def test_session_can_be_refreshed(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        before = admin["expires_at"]

        refreshed = self.service.refresh_session(
            admin["token"],
            {"client_ip": "10.0.0.2", "user_agent": "refreshed-agent"},
        )

        self.assertEqual(refreshed["token"], admin["token"])
        self.assertGreater(refreshed["expires_at"], before)
        session = self.service.authenticate(admin["token"])
        self.assertEqual(session["client_ip"], "10.0.0.2")
        self.assertEqual(session["user_agent"], "refreshed-agent")

    def test_expired_session_is_rejected(self) -> None:
        short_lived = BankingRegulatorService(db_path=self.db_path, session_timeout_minutes=1)
        login = short_lived.login({"username": "admin", "password": "admin123"})
        short_lived.storage.update(
            "sessions",
            "token",
            login["token"],
            {"expires_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()},
        )

        with self.assertRaises(AuthenticationError):
            short_lived.authenticate(login["token"])

    def test_weak_password_is_rejected(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})

        with self.assertRaises(ValidationError):
            self.service.change_password(
                admin["token"],
                {"current_password": "admin123", "new_password": "short"},
            )

    def test_legacy_hash_is_migrated_on_login(self) -> None:
        legacy = hashlib.sha256("admin123".encode("utf-8")).hexdigest()
        self.service.storage.update(
            "users",
            "username",
            "admin",
            {"password_hash": legacy},
        )

        self.service.login({"username": "admin", "password": "admin123"})

        row = self.service.storage.fetch_one(
            "SELECT password_hash FROM users WHERE username = :username",
            {"username": "admin"},
        )
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_logs_are_admin_only(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.create_user(
            {
                "username": "auditor1",
                "password": "pass12345",
                "role": "auditor",
            }
        )
        auditor = self.service.login({"username": "auditor1", "password": "pass12345"})

        logs = self.service.list_logs(admin["token"])

        self.assertGreaterEqual(len(logs), 1)
        with self.assertRaises(AuthorizationError):
            self.service.list_logs(auditor["token"])

    def test_approval_requires_second_admin(self) -> None:
        self.service.create_user(
            {
                "username": "admin2",
                "password": "admin2345",
                "role": "admin",
            }
        )
        admin1 = self.service.login({"username": "admin", "password": "admin123"})
        admin2 = self.service.login({"username": "admin2", "password": "admin2345"})
        self.service.seed_demo_data()

        request = self.service.request_approval(
            admin1["token"],
            action_type="archive_audit",
            target_id="AUD-1",
            target_bank_id="BANK001",
            payload={},
        )

        with self.assertRaises(AuthorizationError):
            self.service.approve_request(admin1["token"], request["request_id"])

        result = self.service.approve_request(admin2["token"], request["request_id"], decision_note="Reviewed")
        approvals = self.service.list_approvals(admin2["token"], status="approved")

        self.assertEqual(result["status"], "approved")
        self.assertTrue(any(item["id"] == request["request_id"] for item in approvals))

    def test_approval_can_be_rejected(self) -> None:
        self.service.create_user(
            {
                "username": "admin2",
                "password": "admin2345",
                "role": "admin",
            }
        )
        admin1 = self.service.login({"username": "admin", "password": "admin123"})
        admin2 = self.service.login({"username": "admin2", "password": "admin2345"})
        self.service.seed_demo_data()

        request = self.service.request_approval(
            admin1["token"],
            action_type="delete_transaction",
            target_id="TXN-1001",
            target_bank_id="BANK001",
            payload={},
        )
        result = self.service.reject_request(admin2["token"], request["request_id"], decision_note="Rejected")

        self.assertEqual(result["status"], "rejected")

    def test_logs_support_filters_and_pagination(self) -> None:
        admin = self.service.login(
            {
                "username": "admin",
                "password": "admin123",
                "client_ip": "192.168.1.1",
                "user_agent": "agent-one",
            }
        )
        self.service.refresh_session(
            admin["token"],
            {"client_ip": "192.168.1.2", "user_agent": "agent-two"},
        )
        self.service.create_user(
            {
                "username": "auditor1",
                "password": "pass12345",
                "role": "auditor",
            }
        )

        login_logs = self.service.list_logs(admin["token"], limit=1, offset=0, action="login")
        all_logs = self.service.list_logs(admin["token"], limit=50, actor="admin")

        self.assertEqual(len(login_logs), 1)
        self.assertEqual(login_logs[0]["action"], "login")
        self.assertTrue(any(item["action"] == "session_refreshed" for item in all_logs))
        self.assertTrue(any(item["details"].get("client_ip") == "192.168.1.1" for item in all_logs))

    def test_logs_can_be_exported_as_csv(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})

        csv_text = self.service.export_logs_csv(admin["token"], limit=5, actor="admin")

        self.assertIn("id,timestamp,actor,action,details", csv_text)
        self.assertIn("admin", csv_text)

    def test_admin_dashboard_contains_summary_sections(self) -> None:
        dashboard = Path("banking_system/static/admin_logs.html").read_text(encoding="utf-8")

        self.assertIn("Loaded Entries", dashboard)
        self.assertIn("Action Volume", dashboard)
        self.assertIn("Actor Breakdown", dashboard)
        self.assertIn("Pending Approvals", dashboard)
        self.assertIn("Pending: 0", dashboard)
        self.assertIn("data-approval-filter", dashboard)
        self.assertIn("Auto Refresh", dashboard)
        self.assertIn("setInterval", dashboard)

    def test_bank_oversight_summary_ranks_banks(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.seed_demo_data()
        self.service.issue_sanction(
            {
                "sanction_id": "S-100",
                "bank_id": "BANK001",
                "penalty_amount": 500000,
                "reason": "AML reporting failure",
            }
        )

        summary = self.service.bank_oversight_summary(admin["token"])

        self.assertGreaterEqual(len(summary), 2)
        self.assertEqual(summary[0]["bank_id"], "BANK001")
        self.assertGreater(summary[0]["risk_score"], summary[1]["risk_score"])

    def test_admin_oversight_dashboard_contains_bank_sections(self) -> None:
        dashboard = Path("banking_system/static/admin_oversight.html").read_text(encoding="utf-8")

        self.assertIn("Bank Oversight Board", dashboard)
        self.assertIn("Risk Ranking", dashboard)
        self.assertIn("Bank Compliance Summary", dashboard)

    def test_bank_detail_contains_histories(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.seed_demo_data()
        self.service.issue_sanction(
            {
                "sanction_id": "S-101",
                "bank_id": "BANK001",
                "penalty_amount": 200000,
                "reason": "Late forex reporting",
            }
        )

        detail = self.service.bank_detail(admin["token"], "BANK001")

        self.assertEqual(detail["bank"]["bank_id"], "BANK001")
        self.assertGreaterEqual(len(detail["transactions"]), 1)
        self.assertGreaterEqual(len(detail["audits"]), 1)
        self.assertGreaterEqual(len(detail["sanctions"]), 1)
        self.assertIn("risk_score", detail["summary"])

    def test_update_audit_and_sanction(self) -> None:
        self.service.seed_demo_data()
        audit_response = self.service.update_audit("AUD-1", {"reason": "Updated audit reason"})
        self.service.issue_sanction(
            {
                "sanction_id": "S-200",
                "bank_id": "BANK001",
                "penalty_amount": 150000,
                "reason": "Original reason",
            }
        )
        sanction_response = self.service.update_sanction(
            "S-200",
            {"penalty_amount": 175000, "reason": "Updated sanction reason"},
        )

        self.assertEqual(audit_response["audit"]["reason"], "Updated audit reason")
        self.assertEqual(sanction_response["sanction"]["penalty_amount"], 175000)
        self.assertEqual(sanction_response["sanction"]["reason"], "Updated sanction reason")

    def test_archive_and_delete_flows_affect_active_summary(self) -> None:
        self.service.seed_demo_data()
        self.service.issue_sanction(
            {
                "sanction_id": "S-300",
                "bank_id": "BANK001",
                "penalty_amount": 150000,
                "reason": "Archive candidate",
            }
        )
        self.service.archive_audit("AUD-1", actor="admin")
        archived_sanction = self.service.archive_sanction("S-300", actor="admin")
        self.service.delete_transaction("TXN-1001", actor="admin")

        audits = self.service.list_audits()
        sanctions = self.service.list_sanctions()
        summary = self.service.bank_oversight_summary(self.service.login({"username": "admin", "password": "admin123"})["token"])

        self.assertTrue(any(item["audit_id"] == "AUD-1" and item["archived"] for item in audits))
        self.assertTrue(archived_sanction["sanction"]["archived"])
        self.assertEqual(summary[0]["transactions_reported"], 0)

    def test_admin_actor_appears_in_bank_activity_feed(self) -> None:
        admin = self.service.login({"username": "admin", "password": "admin123"})
        self.service.seed_demo_data()
        self.service.issue_sanction(
            {
                "sanction_id": "S-400",
                "bank_id": "BANK001",
                "penalty_amount": 125000,
                "reason": "Actor attribution test",
            },
            actor="admin",
        )

        detail = self.service.bank_detail(admin["token"], "BANK001")

        self.assertTrue(any(item["actor"] == "admin" and item["action"] == "sanction_issued" for item in detail["recent_logs"]))

    def test_admin_bank_dashboard_contains_drilldown_sections(self) -> None:
        dashboard = Path("banking_system/static/admin_bank_detail.html").read_text(encoding="utf-8")

        self.assertIn("Bank Drilldown Console", dashboard)
        self.assertIn("Transaction Timeline", dashboard)
        self.assertIn("Admin Activity Feed", dashboard)
        self.assertIn("Record Transaction", dashboard)
        self.assertIn("Open Audit", dashboard)
        self.assertIn("Issue Sanction", dashboard)
        self.assertIn("Close Audit", dashboard)


if __name__ == "__main__":
    unittest.main()
