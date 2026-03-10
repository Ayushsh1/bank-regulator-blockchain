# Banking Supervision System with Blockchain

This project is a Python-based regulatory banking system intended for a reserve bank or forex regulator.
It allows the regulator to:

- register and monitor supervised banks
- record submitted interbank or forex transactions
- open and close compliance audits
- issue sanctions or regulatory actions
- preserve an immutable audit trail using a simple blockchain ledger
- persist supervision records in SQLite
- manage regulator officers using role-based authentication

## Why blockchain is used here

Each regulatory event is written to a block. That gives the regulator a tamper-evident chain of:

- bank onboarding
- transaction reporting
- audit activity
- sanctions and enforcement decisions

This is not a cryptocurrency system. It is an internal supervision ledger designed for traceability and verification.

## Project structure

```text
bank_regulator_blockchain/
  banking_system/
    api.py
    blockchain.py
    main.py
    models.py
    services.py
  tests/
    test_system.py
```

## Default admin account

On first run the system creates:

- username: `admin`
- password: `admin123`
- role: `admin`

Change or replace this account before using the system beyond local development.
Passwords must be at least 8 characters long.

## Run the server

```bash
cd C:\Users\ayush\bank_regulator_blockchain
python -m banking_system.main
```

The server starts on `http://127.0.0.1:8080`.
The SQLite database is created at `C:\Users\ayush\bank_regulator_blockchain\regulator.db`.

## Local run scripts

From the project folder on Windows you can use:

```bat
run_server.bat
```

That starts the API server at `http://127.0.0.1:8080`.

To run the test suite:

```bat
run_tests.bat
```

To start the server and open the admin dashboards in a browser:

```bat
launch_admin.bat
```

## API endpoints

### Health

- `GET /health`

### Authentication

- `POST /auth/login`
- `POST /auth/logout`
- `POST /auth/refresh`
- `POST /auth/change-password`
- `POST /auth/reset-password` (admin only)

Request body:

```json
{
  "username": "admin",
  "password": "admin123"
}
```

Use the returned token in the `Authorization` header:

```text
Authorization: Bearer <token>
```

Sessions expire automatically after 30 minutes. A new login invalidates the previous session for that user.
Passwords are stored using salted PBKDF2-SHA256 hashes.

Refresh session:

```json
{}
```

`login` and `refresh` also accept optional `client_ip` and `user_agent` fields. If omitted through the HTTP API, the server fills them from the request.

Change password body:

```json
{
  "current_password": "admin123",
  "new_password": "admin12345"
}
```

Reset password body:

```json
{
  "username": "auditor1",
  "new_password": "auditor1234"
}
```

### Users

- `GET /users` (admin only)
- `POST /users` (admin only)

### System Logs

- `GET /logs` (admin only)
- `GET /logs/export.csv` (admin only)
- `GET /admin/logs` (admin dashboard page)

This returns the most recent security and system activity, including login, logout, password operations, user creation, and regulatory events.
It supports query parameters:

- `limit`
- `offset`
- `actor`
- `action`

Example:

```text
GET /logs?limit=20&offset=0&actor=admin&action=login
```

CSV export example:

```text
GET /logs/export.csv?limit=100&actor=admin
```

Admin dashboard:

```text
http://127.0.0.1:8080/admin/logs
```

Paste an admin bearer token into the page, then load filtered logs or export them as CSV.
The same page now includes pending-approval badges and approval history filters for `pending`, `approved`, `rejected`, and `all`.
It also supports an `Auto Refresh` toggle that polls logs and approvals every 15 seconds while enabled.

### Oversight

- `GET /oversight/banks` (admin only)
- `GET /oversight/banks/{bank_id}` (admin only)
- `GET /admin/oversight` (admin oversight dashboard page)
- `GET /admin/bank` (admin bank drilldown page)

This provides bank-level compliance metrics including flagged exposure, open audits, sanctions, and a derived risk score.

Oversight dashboard:

```text
http://127.0.0.1:8080/admin/oversight
```

Bank drilldown page:

```text
http://127.0.0.1:8080/admin/bank
```

The bank drilldown page can now:

- record a new transaction for the loaded bank
- open a new audit for the loaded bank
- issue a sanction for the loaded bank
- close an open audit directly from the UI
- edit open-audit reasons and sanction details inline from the UI
- archive audits and sanctions with confirmation prompts
- delete transactions with a confirmation prompt

All admin-triggered actions now write actor-attributed entries into the activity feed, so the drilldown page shows which authenticated user made each change.

Request body:

```json
{
  "username": "auditor1",
  "password": "securepass",
  "role": "auditor"
}
```

### Banks

- `GET /banks` (authenticated)
- `POST /banks` (admin or supervisor)

Request body:

```json
{
  "bank_id": "BANK001",
  "name": "National Forex Bank",
  "country": "India",
  "bank_type": "forex",
  "capital_reserve": 25000000
}
```

### Transactions

- `GET /transactions` (authenticated)
- `POST /transactions` (admin or supervisor)

Request body:

```json
{
  "txn_id": "TXN-1001",
  "bank_id": "BANK001",
  "counterparty_bank": "BANK777",
  "currency": "USD",
  "amount": 1500000,
  "txn_type": "cross_border_settlement"
}
```

### Audits

- `GET /audits` (authenticated)
- `POST /audits` (admin or auditor)
- `POST /audits/{audit_id}/close` (admin or auditor)

Open audit body:

```json
{
  "audit_id": "AUD-1",
  "bank_id": "BANK001",
  "reason": "Large forex exposure mismatch"
}
```

Close audit body:

```json
{
  "findings": "Exposure mismatch confirmed and remediated."
}
```

### Sanctions

- `GET /sanctions` (authenticated)
- `POST /sanctions` (admin or supervisor)

Request body:

```json
{
  "sanction_id": "SANC-1",
  "bank_id": "BANK001",
  "penalty_amount": 500000,
  "reason": "AML reporting failure"
}
```

### Blockchain verification

- `GET /blockchain` (authenticated)
- `GET /blockchain/verify` (authenticated)

## Run tests

```bash
cd C:\Users\ayush\bank_regulator_blockchain
python -m unittest discover -s tests -v
```

## GitHub Actions

The repository includes a GitHub Actions workflow at `.github/workflows/python-tests.yml`.
It runs the unit test suite automatically on pushes and pull requests to `main`.
