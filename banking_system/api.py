from __future__ import annotations

import json
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from banking_system.services import (
    AuthenticationError,
    AuthorizationError,
    BankingRegulatorService,
    NotFoundError,
    ValidationError,
)


class RegulatorAPIHandler(BaseHTTPRequestHandler):
    service = BankingRegulatorService()
    service.seed_demo_data()
    dashboard_html = (Path(__file__).resolve().parent / "static" / "admin_logs.html").read_text(encoding="utf-8")
    oversight_html = (Path(__file__).resolve().parent / "static" / "admin_oversight.html").read_text(encoding="utf-8")
    bank_detail_html = (Path(__file__).resolve().parent / "static" / "admin_bank_detail.html").read_text(encoding="utf-8")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return
            if method == "GET" and path == "/admin/logs":
                self._send_html(HTTPStatus.OK, self.dashboard_html)
                return
            if method == "GET" and path == "/admin/oversight":
                self._send_html(HTTPStatus.OK, self.oversight_html)
                return
            if method == "GET" and path == "/admin/bank":
                self._send_html(HTTPStatus.OK, self.bank_detail_html)
                return
            if method == "POST" and path == "/auth/login":
                payload = self._read_json()
                payload.setdefault("client_ip", self.client_address[0] if self.client_address else "")
                payload.setdefault("user_agent", self.headers.get("User-Agent", ""))
                self._send_json(HTTPStatus.OK, self.service.login(payload))
                return

            token = self._get_token()
            if method == "POST" and path == "/auth/logout":
                self._send_json(HTTPStatus.OK, self.service.logout(token))
                return
            if method == "POST" and path == "/auth/refresh":
                payload = self._read_json()
                payload.setdefault("client_ip", self.client_address[0] if self.client_address else "")
                payload.setdefault("user_agent", self.headers.get("User-Agent", ""))
                self._send_json(HTTPStatus.OK, self.service.refresh_session(token, payload))
                return
            if method == "POST" and path == "/auth/change-password":
                self._send_json(HTTPStatus.OK, self.service.change_password(token, self._read_json()))
                return
            if method == "POST" and path == "/auth/reset-password":
                self._send_json(HTTPStatus.OK, self.service.reset_password(token, self._read_json()))
                return
            if method == "GET" and path == "/dashboard":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.dashboard())
                return
            if method == "GET" and path == "/oversight/banks":
                self._send_json(HTTPStatus.OK, self.service.bank_oversight_summary(token))
                return
            if method == "GET" and path.startswith("/oversight/banks/"):
                bank_id = path.split("/")[3]
                self._send_json(HTTPStatus.OK, self.service.bank_detail(token, bank_id))
                return
            if method == "GET" and path == "/banks":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.list_banks())
                return
            if method == "POST" and path == "/banks":
                session = self.service.authorize(token, {"admin", "supervisor"})
                self._send_json(HTTPStatus.CREATED, self.service.register_bank(self._read_json(), actor=session["username"]))
                return
            if method == "GET" and path == "/transactions":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.list_transactions())
                return
            if method == "POST" and path == "/transactions":
                session = self.service.authorize(token, {"admin", "supervisor"})
                self._send_json(HTTPStatus.CREATED, self.service.record_transaction(self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path.startswith("/transactions/") and path.endswith("/delete"):
                session = self.service.authorize(token, {"admin", "supervisor"})
                txn_id = path.split("/")[2]
                self._send_json(HTTPStatus.OK, self.service.delete_transaction(txn_id, actor=session["username"]))
                return
            if method == "GET" and path == "/audits":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.list_audits())
                return
            if method == "POST" and path == "/audits":
                session = self.service.authorize(token, {"admin", "auditor"})
                self._send_json(HTTPStatus.CREATED, self.service.open_audit(self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path.startswith("/audits/") and path.endswith("/close"):
                session = self.service.authorize(token, {"admin", "auditor"})
                audit_id = path.split("/")[2]
                payload = self._read_json()
                findings = payload.get("findings", "")
                self._send_json(HTTPStatus.OK, self.service.close_audit(audit_id, findings, actor=session["username"]))
                return
            if method == "POST" and path.startswith("/audits/") and path.endswith("/update"):
                session = self.service.authorize(token, {"admin", "auditor"})
                audit_id = path.split("/")[2]
                self._send_json(HTTPStatus.OK, self.service.update_audit(audit_id, self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path.startswith("/audits/") and path.endswith("/archive"):
                session = self.service.authorize(token, {"admin", "auditor"})
                audit_id = path.split("/")[2]
                self._send_json(HTTPStatus.OK, self.service.archive_audit(audit_id, actor=session["username"]))
                return
            if method == "GET" and path == "/sanctions":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.list_sanctions())
                return
            if method == "POST" and path == "/sanctions":
                session = self.service.authorize(token, {"admin", "supervisor"})
                self._send_json(HTTPStatus.CREATED, self.service.issue_sanction(self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path.startswith("/sanctions/") and path.endswith("/update"):
                session = self.service.authorize(token, {"admin", "supervisor"})
                sanction_id = path.split("/")[2]
                self._send_json(HTTPStatus.OK, self.service.update_sanction(sanction_id, self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path.startswith("/sanctions/") and path.endswith("/archive"):
                session = self.service.authorize(token, {"admin", "supervisor"})
                sanction_id = path.split("/")[2]
                self._send_json(HTTPStatus.OK, self.service.archive_sanction(sanction_id, actor=session["username"]))
                return
            if method == "GET" and path == "/users":
                self.service.authorize(token, {"admin"})
                self._send_json(HTTPStatus.OK, self.service.list_users())
                return
            if method == "GET" and path == "/approvals":
                self._send_json(
                    HTTPStatus.OK,
                    self.service.list_approvals(
                        token,
                        status=self._get_str_query(query, "status"),
                        limit=self._get_int_query(query, "limit", 100),
                    ),
                )
                return
            if method == "GET" and path == "/logs":
                self.service.authorize(token, {"admin"})
                self._send_json(
                    HTTPStatus.OK,
                    self.service.list_logs(
                        token,
                        limit=self._get_int_query(query, "limit", 100),
                        offset=self._get_int_query(query, "offset", 0),
                        actor=self._get_str_query(query, "actor"),
                        action=self._get_str_query(query, "action"),
                    ),
                )
                return
            if method == "GET" and path == "/logs/export.csv":
                self.service.authorize(token, {"admin"})
                self._send_csv(
                    HTTPStatus.OK,
                    self.service.export_logs_csv(
                        token,
                        limit=self._get_int_query(query, "limit", 100),
                        offset=self._get_int_query(query, "offset", 0),
                        actor=self._get_str_query(query, "actor"),
                        action=self._get_str_query(query, "action"),
                    ),
                    "system_logs.csv",
                )
                return
            if method == "POST" and path == "/users":
                session = self.service.authorize(token, {"admin"})
                self._send_json(HTTPStatus.CREATED, self.service.create_user(self._read_json(), actor=session["username"]))
                return
            if method == "POST" and path == "/approvals":
                payload = self._read_json()
                self._send_json(
                    HTTPStatus.CREATED,
                    self.service.request_approval(
                        token,
                        action_type=payload.get("action_type", ""),
                        target_id=payload.get("target_id", ""),
                        target_bank_id=payload.get("target_bank_id", ""),
                        payload=payload.get("payload", {}),
                    ),
                )
                return
            if method == "POST" and path.startswith("/approvals/") and path.endswith("/approve"):
                request_id = int(path.split("/")[2])
                payload = self._read_json()
                self._send_json(
                    HTTPStatus.OK,
                    self.service.approve_request(token, request_id, decision_note=payload.get("decision_note", "")),
                )
                return
            if method == "POST" and path.startswith("/approvals/") and path.endswith("/reject"):
                request_id = int(path.split("/")[2])
                payload = self._read_json()
                self._send_json(
                    HTTPStatus.OK,
                    self.service.reject_request(token, request_id, decision_note=payload.get("decision_note", "")),
                )
                return
            if method == "GET" and path == "/blockchain":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.blockchain_state())
                return
            if method == "GET" and path == "/blockchain/verify":
                self.service.authenticate(token)
                self._send_json(HTTPStatus.OK, self.service.verify_blockchain())
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found."})
        except AuthenticationError as exc:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except AuthorizationError as exc:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except ValidationError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except NotFoundError as exc:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body."})
        except Exception as exc:  # pragma: no cover
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: HTTPStatus, payload: str) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_csv(self, status: HTTPStatus, payload: str, filename: str) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_token(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header.removeprefix("Bearer ").strip()
        return None

    def _get_int_query(self, query: dict[str, list[str]], key: str, default: int) -> int:
        raw = query.get(key, [str(default)])[0]
        return int(raw)

    def _get_str_query(self, query: dict[str, list[str]], key: str) -> str | None:
        raw = query.get(key, [""])[0].strip()
        return raw or None


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), RegulatorAPIHandler)
