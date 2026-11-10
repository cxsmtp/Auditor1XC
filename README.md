# Auditor1XC

Search Checkmarx One audit logs, API keys, and API key usage using a single API key.
It needs **Node.js 18+** and nothing from npm.

## GUI (recommended)

```bash
node cx_auditor_gui.mjs
```

or `npm start`. This opens `http://127.0.0.1:8787` in your browser. If that port is taken, it picks
a free one and prints the URL. Use `--port 9000` to choose a port and `--no-open` to skip opening
the browser. Stop it with Ctrl+C.

**1. Connect & fetch.**
* Paste the API key. The page shows which tenant and region the key belongs to, and warns if the key has expired.
* Pick a time range: 24 h, 7, 30, 90 or 365 days, or exact dates.
* Choose which data to fetch: audit trail, API keys, key usage, IAM admin events, IAM user events.
* Press **Fetch logs**. Progress is shown live, and **Cancel** stops the fetch.
* Advanced options: limit the API-key lookup to some users (faster on large tenants), include the legacy audit trail, or override the URLs and tenant.

**2. Work on the logs.** You fetch once, then every option below works instantly on that data.

| Feature | What it does |
|---|---|
| **Overview** | Count tiles per data set. **Things worth reviewing**: a key used from several IPs, keys of disabled users, keys unused for 90+ days, one IP failing sign-in for many users, users with repeated failed sign-ins, access-control changes, and deletions. Each one opens the matching rows. A **per-user summary** lists audit actions, deletes, API keys, key uses, key IPs, failed sign-ins and last activity. |
| **Global filters** (all tabs) | Users (username, email or ID, with suggestions), IPs, free text (searches event data too), a time window, and errors only. `,` = OR, filters combine with AND, `*` `?` are wildcards, and `!` excludes (e.g. `!10.0.*`). |
| **Facets** (left side of each tab) | Top values with counts for event type, action, resource, user, IP and so on. Click a value to include it, or ⊘ to exclude it. Several values can be combined. |
| **Column filters** | A filter box under every column header: contains, `=` exact, `!` exclude, wildcards. |
| **Sort / columns / paging** | Click a header to sort. Show or hide columns. 50 to 1000 rows per page. |
| **Group by** | Any column becomes a summary: row count, distinct users, distinct IPs, first and last seen. Click a group to see its rows. |
| **Activity chart** | Rows per day for the current filters. Hover for counts. Click a bar to zoom to that day. |
| **Row details** | Click a row to see every field, with event data shown as formatted JSON. One-click "filter to this user / IP", "exclude", "all uses of this key", and "copy as JSON". |
| **Saved views** | Save your filters, sorting and columns under a name. Views are stored in your browser and never include the data or the key. |
| **Export** | CSV or JSON of exactly the rows you are looking at. |
| **Save data / Open data** | Download the fetched data (without the key) and reopen it later, with no API key or network needed. |
| **Light / dark theme** | Follows your OS setting, or use the Theme button. |

**Security of the local app.** It listens only on `127.0.0.1` and rejects requests for any other
host name. Its API needs a random token that is created each time it starts and only the page
knows. The key is used only for the request and is never written to disk or logged; errors are
scrubbed of anything that looks like a token. "Save data" files contain no key, but they do
contain your audit data, so store them accordingly.

## Command line

`cx_auditor.mjs` does the same fetch for scripting, writing CSV and JSON files.
(`cx_auditor.py` is the original Python version. It exports the same data but has no search options.)

### Quick start

```bash
export CX_APIKEY='eyJhbGciOi...'
```

PowerShell: `$env:CX_APIKEY='eyJhbGciOi...'`

```bash
node cx_auditor.mjs --days 30
```

```bash
node cx_auditor.mjs --help
```

The tenant, IAM URL and API URL are read from the key's `iss` claim. Override them with
`--tenant`, `--iam-url` and `--base-url` if needed.

### Outputs (in `--out`, default `./audit-out`)

| File | Answers | Source |
|---|---|---|
| `audit_trail.csv` | Who did what, when, from which IP | `GET {base}/api/audit-events` (+ legacy `/api/audit` with `--legacy-audit`) |
| `api_keys.csv` | Each API key: **which user created it**, when, last used, last IP | IAM `users/{id}/offline-sessions/{ast-app}`, `users/{id}/consents` |
| `api_key_usage.csv` | Each use of a key: **which user used it**, the IP, and whose key it was | IAM `GET /events` (`REFRESH_TOKEN` on `ast-app`) |
| `iam_admin_events.csv` | IAM admin changes (users, roles, groups, clients) and who made them | IAM `GET /admin-events` |
| `iam_user_events.csv` | Logins, login failures, token refreshes | IAM `GET /events` |
| `summary.json` | Window, filters, rows fetched/matched per file, per-user rollup | |
| `raw.json` | Unfiltered API responses | |

### Searching (CLI)

Rules:

* Repeat a flag or comma-separate its values. Values within one flag are **OR**ed. Different flags are **AND**ed.
* `*` and `?` are wildcards. Matching is case-insensitive.
* Without a wildcard a value must match the whole field. `--ip 10.0.0.1` does not match `10.0.0.12`.

| Flag | Matches |
|---|---|
| `--user` | Username, email **or** user ID. An email is resolved to the user's ID, so it also matches audit rows that only carry the ID. It applies to the actor, the key creator and the key user. |
| `--ip` | Request IP. Example: `10.20.*` |
| `--event-type` | Audit `eventType` or IAM event type. Example: `projects.*`, `users.login`, `REFRESH_TOKEN` |
| `--action` | Audit `actionType` or IAM admin operation. Example: `delete`, `CREATE` |
| `--resource` | Audit resource, or IAM resource type or path. Example: `users*` |
| `--key-id` | API key session ID (from `api_keys.csv`) |
| `--text` | Substring anywhere in the row, including the event `data` payload |
| `--errors-only` | IAM events with an error, such as failed logins |
| `--from` / `--to` | Exact window, e.g. `2026-10-01` or `2026-10-01T08:00:00Z`. This overrides `--days`. |
| `--only` | Fetch only some sections: `audit,admin,events,keys,usage` |
| `--print` | Also print the matching rows as tables in the terminal |

A filter only applies to files that have that field. For example, `--event-type` doesn't
drop rows from `api_keys.csv`. `summary.json` lists which filters were applied to each file.

### Examples

What did two users delete in October, from outside the office network?

```bash
node cx_auditor.mjs --from 2026-10-01 --to 2026-10-31 --user alice@corp.com,bob --action delete --print
```

Who has API keys, and who used them from an unexpected IP?

```bash
node cx_auditor.mjs --only keys,usage --days 90 --print
```

Every use of one specific key:

```bash
node cx_auditor.mjs --only keys,usage --key-id 3f1c...-sess-id
```

Failed logins in the last 7 days:

```bash
node cx_auditor.mjs --only events --errors-only --days 7 --print
```

Any audit event that mentions a project name:

```bash
node cx_auditor.mjs --only audit --text payments-api
```

## How "created by" and "used by" are determined

A Checkmarx One API key is an IAM (Keycloak) offline token for the `ast-app` client. It always
belongs to, and acts as, the user who generated it.

* **Created by**: the owner of the offline session.
* **Used by**: the `userId` and IP on each `REFRESH_TOKEN` event, matched to the key by session ID.

A key that is "used by" someone other than its creator therefore shows up as **the creator's
identity coming from an unfamiliar IP**. Look at `api_key_ips` per user in `summary.json`.

## Limitations (please read)

* **Not yet run against a live tenant.** Every endpoint was checked against the Checkmarx One API
  reference, and the tests run the full flow against a mock server. Real responses may still differ.
  If a section fails, `summary.json` shows the HTTP status.
* **The audit trail has no "API key created" event.** The documented audit-events list doesn't
  include one. That is why key data comes from the IAM admin API.
* **API key names and expiry dates shown in the Checkmarx One UI aren't available.** No documented
  API exposes them. Keys are identified by session ID, creation time and owner.
* **IAM event data depends on tenant settings.** `iam_user_events`, `iam_admin_events` and
  `api_key_usage` are only populated if **event saving is enabled** for the realm, and only for
  that realm's event retention period. If saving is off, these files are empty, which doesn't mean
  there was no activity.
* **Filtering happens after download.** `/api/audit-events` only supports filtering by date on the
  server, so the whole time window is downloaded and then searched. On large tenants, narrow
  `--from`/`--to` and use `--only`. `--user` does cut the per-user API-key lookups down to the
  matching users.
* **Data range is limited.** `/api/audit-events` keeps 365 days, and its data starts on 2026-03-29.
  Use `--legacy-audit` for anything older.
* **Permissions.** The key inherits its creator's roles. The IAM sections need `manage-users` /
  `view-users`, `view-events` and `view-clients`. Sections the key can't read are skipped and
  marked in `summary.json`.
* **Corporate proxy.** Node's built-in `fetch` ignores `HTTPS_PROXY` unless you set
  `NODE_USE_ENV_PROXY=1` (supported in recent Node 22.x and 24.x).

## Tests

```bash
npm test
```

```bash
python3 -m unittest discover -s tests
```
