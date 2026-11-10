# Auditor1XC

`cx_auditor.py` exports, from a single Checkmarx One **API key**:

| Output file | What it answers | Source API |
|---|---|---|
| `audit_trail.csv` | Every user action in the platform (who, what, when, from which IP) | `GET {base}/api/audit-events` (Audit Event Processor), optional legacy `GET {base}/api/audit` |
| `api_keys.csv` | Every API key: **which user created it**, when, when it was last used and from which IP | IAM: `users/{id}/offline-sessions/{ast-app}` + `users/{id}/consents` |
| `api_key_usage.csv` | Every time an API key was exchanged for a token: **which user used it**, from which IP, and whose key it was | IAM: `GET /events` (`REFRESH_TOKEN` events on `ast-app`) |
| `iam_admin_events.csv` | IAM admin changes (users, roles, groups, clients) and who made them | IAM: `GET /admin-events` |
| `iam_user_events.csv` | All IAM user events (logins, login failures, token refreshes) | IAM: `GET /events` |
| `summary.json` | Per-user rollup (keys created, key uses, key IPs, audit actions) and the status of each section | — |
| `raw.json` | Unmodified API responses | — |

Python 3.9+, standard library only.

## Usage

```bash
export CX_APIKEY='eyJhbGciOi...'
```

```bash
python3 cx_auditor.py --days 90 --out ./audit-out
```

The tenant, IAM URL (`https://<region.>iam.checkmarx.net`) and API URL
(`https://<region.>ast.checkmarx.net`) are read from the API key's `iss` claim.
You can override them with `--tenant`, `--iam-url` and `--base-url`.

| Option | Default | Notes |
|---|---|---|
| `--days` | 30 | Look-back window. `/api/audit-events` keeps 365 days, and its data starts on 2026-03-29 |
| `--legacy-audit` | off | Also pull the deprecated `/api/audit` trail (daily files) for older events. Duplicates are removed by `eventID` |
| `--out` | `./audit-out` | Output directory |

## How API keys are identified

A Checkmarx One API key is an IAM offline token issued to the `ast-app` client.
It always belongs to, and acts as, the user who generated it. So:

* **Created by**: the user who owns the offline session (`api_keys.csv`).
* **Used by**: the `userId` and IP on each `REFRESH_TOKEN` event for `ast-app`,
  matched to the key through the session ID (`api_key_usage.csv`). An IP that
  doesn't match the owner's usual addresses is the signal to look for.

The audit-events API has no "API key created" event type, which is why this
information comes from IAM.

## Required permissions

The API key inherits the roles of the user who generated it. For a full report
that user needs:

* Audit trail: access to the audit trail (tenant admin)
* IAM sections: `view-users` / `manage-users`, `view-events`, `view-clients` (IAM admin)
* IAM user and admin events are only stored if **event saving is enabled** for the
  tenant realm (IAM → Realm settings → Events). If it is off, the event sections
  come back empty.

If a section fails with 401/403 it is skipped and marked in `summary.json`. The
other sections still run.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests run the whole tool against a local mock of the Checkmarx One and IAM endpoints.
