# Auditor1XC

Search Checkmarx One audit logs, API keys, and API key usage using a single API key.
It needs **Node.js 18+** and nothing from npm.

## GUI (recommended)

**Easiest: one file.** Download only `cx-auditor.mjs`, put it in any folder, and run:

```bash
node cx-auditor.mjs
```

This opens `http://127.0.0.1:8787` in your browser. If that port is taken, it picks a free one and
prints the URL. Use `--port 9000` to choose a port and `--no-open` to skip opening the browser.
Stop it with Ctrl+C.

`cx-auditor.mjs` is generated from the sources (`cx_auditor.mjs`, `cx_auditor_gui.mjs`, `gui/`) by
`npm run build`. If you work from the full repository instead, `npm start` runs the same GUI from the
sources. In that case `cx_auditor_gui.mjs` needs `cx_auditor.mjs` and the `gui` folder next to it.

> Behind a corporate proxy? Node only uses `HTTPS_PROXY` if you also set `NODE_USE_ENV_PROXY=1`
> (Windows: `set NODE_USE_ENV_PROXY=1` before running).

**1. Connect & fetch.**
* Paste the API key. The page shows which tenant and region the key belongs to, and warns if the key has expired.
* Pick a time range: 24 h, 7, 30, 90 or 365 days, or exact dates.
* Choose which data to fetch: audit trail, API keys, key usage, IAM admin events, IAM user events, AI credit usage.
* Press **Fetch logs**. Progress is shown live, and **Cancel** stops the fetch.
* Advanced options: limit the API-key lookup to some users (faster on large tenants), include the legacy audit trail, or override the URLs and tenant.

**2. Work on the logs.** You fetch once, then every option below works instantly on that data.
Every row names a **person** (name and email), not an ID. Actions show **how the person
authenticated** (browser, which API key, or which OAuth client), with a confidence level. See
[How people, API keys and credits are connected](#how-people-api-keys-and-credits-are-connected).

Tabs: **Who did what** (everything, as one timeline) · Audit trail · API keys (who created each key and what it did) · API key usage · **AI credit usage** · IAM admin events · IAM user events · People.

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
| `activity.csv` | **Everything as one timeline**: person, email, action, target, how they authenticated (API key / browser / OAuth client), confidence, evidence, IP | all of the below, joined |
| `audit_trail.csv` | Each action with the person's name and email, target, credential used, confidence | `GET {base}/api/audit-events` (+ legacy `/api/audit` with `--legacy-audit`) |
| `api_keys.csv` | Each API key: **who created it**, when, what it did (`actions_via_key`, `action_types`), last use and IP | IAM `users/{id}/offline-sessions/{ast-app}`, `users/{id}/consents` |
| `ai_runs.csv` | AI Triage/Remediation runs (AI credit use), with the person whose scan likely triggered each one | `GET {base}/api/ai-agents-coordinator/history` |
| `people.csv` | Every identity seen: name, email, username, type (user / OAuth client / deleted), ID | IAM users, clients, lookups |
| `api_key_usage.csv` | Each use of a key: **who used it** (name, email), the IP, and whose key it was | IAM `GET /events` (`REFRESH_TOKEN` on `ast-app`) |
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

## How people, API keys and credits are connected

Raw Checkmarx One logs only contain IDs. The auditor joins them so that every row names a person.

**1. Every ID becomes a person.** IDs are resolved in this order:

* IAM users, with full profiles: first and last name, email, username, enabled.
* OAuth clients. Each client acts through a service-account user, which is shown as `OAuth client: <name>`.
* IDs IAM no longer returns are looked up one by one. A 404 marks the user `(deleted)`. Any
  name or email found for that ID in event payloads is kept, so deleted users still have a name.
* Anything left is shown as `unknown user <id>` and flagged on the Overview.

**2. How each action was authenticated.** Checkmarx One access tokens expire after 30 minutes
(Authentication API). So an action at time *t* was made with a token the user received in the
30 minutes before *t*. The auditor reads that user's IAM token events in that window:

| Token event in the window | Shown as |
|---|---|
| Refresh of an offline session (= an API key) | **API key** + which key |
| Interactive `LOGIN` / browser session | **Browser sign-in** |
| `CLIENT_LOGIN`, or the actor is a service account | **OAuth client** |

Every attribution has a **confidence** and a **"How we know"** text:

| Confidence | Meaning |
|---|---|
| confirmed | The actor is an OAuth client's service account; there is only one way it can act |
| high | Exactly one credential issued tokens to this person in the window, from the action's IP |
| medium | Exactly one credential in the window, but from a different IP |
| low | Several credentials were active; the most recent before the action is shown, and the others are listed |
| none | No token events in the window: IAM event saving is off, or the event is older than its retention |

As a result, **API keys** shows, for each key: who created it, when, what it was used for (number
and types of actions), and when it was last used. **Who did what** shows each action with the
person, their email and the key they used.

**3. AI credit usage.** AI Triage and AI Remediation consume "Checkmarx Assist / AI credits". The
AI Agents Coordinator history (`/api/ai-agents-coordinator/history`) lists each run with project,
status and findings processed. It does **not** say who started a run or how many credits it used.
Each run is linked to the most recent scan of the same project in the 24 hours before it, and so
to that scan's person and credential. These links are labelled **likely**. Runs with no matching
scan, such as scheduled scans, are shown as not attributed.

**4. Who did what.** One timeline merges the audit trail, API key creation and use, sign-ins,
IAM admin changes and AI runs. Each row has: person · email · action · target (project names and
affected people resolved) · how they authenticated · confidence · IP.

## Limitations (please read)

* **Not yet run against a live tenant.** Every endpoint was checked against the Checkmarx One API
  reference, and the tests run the full flow against mock tenants. Real responses may still differ.
  If a section fails, the Overview (or `summary.json`) shows which one and the HTTP status.
* **Credential attribution needs IAM event saving.** If IAM event saving is off in the realm, or
  its retention is shorter than your time range, people are still named, but "Authenticated via"
  is `unknown` (confidence `none`). The Overview shows the share of events that could be attributed.
* **API keys act as their owner.** In Checkmarx One a key always acts as the user who created it.
  A key used by someone else therefore shows up as its owner acting from an unfamiliar IP. The
  "used from N IPs" finding and the per-key IP list are how to spot that.
* **Credits:** the API exposes no credit balance and no credits per run. "Findings processed" is
  the closest available measure. Manual AI requests made in the UI aren't in the documented
  audit-event list or the automation history, so they can't be shown.
* **The audit trail has no "API key created" event.** Key creation comes from the IAM offline
  session's start time.
* **API key names and expiry dates shown in the Checkmarx One UI aren't available.** No documented
  API exposes them. Keys are identified by session ID, creation time and owner.
* **Filtering happens after download.** `/api/audit-events` only supports filtering by date on the
  server. On large tenants, narrow the time range. Limiting the API-key check to some users also
  cuts the per-user lookups.
* **Data range is limited.** `/api/audit-events` keeps 365 days, and its data starts on 2026-03-29.
  Use the legacy audit option for older events.
* **Permissions.** The key inherits its creator's roles. Full results need tenant-level audit
  access, plus IAM `view-users` / `manage-users`, `view-events` and `view-clients`. Sections the
  key can't read are skipped and listed on the Overview.
* **Corporate proxy.** Node's built-in `fetch` ignores `HTTPS_PROXY` unless you set
  `NODE_USE_ENV_PROXY=1` (supported in recent Node 22.x and 24.x).

## Tests

`npm test` also checks that `cx-auditor.mjs` matches the sources.

```bash
npm test
```

```bash
python3 -m unittest discover -s tests
```
