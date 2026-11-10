#!/usr/bin/env python3
"""
cx_auditor - export Checkmarx One audit data using a single API key.

What it collects
  1. Audit trail of user actions          (GET /api/audit-events; legacy /api/audit)
  2. IAM admin events                      (who changed users/roles/clients)
  3. IAM user events (logins, token use)   (who used which credential, from where)
  4. API key inventory                     (which user created which API key, when,
                                            and when / from which IP it was last used)
  5. API key usage                         (token-refresh events tied to a key's session)

Checkmarx One API keys are IAM (Keycloak) offline tokens issued to the
"ast-app" client. The tenant and IAM host are read from the key itself, so
usually only the key is needed:

    export CX_APIKEY=eyJhbGciOi...
    python3 cx_auditor.py --days 30 --out ./audit-out

The account that owns the API key needs IAM admin rights (view-users,
view-events, view-clients) for sections 2-5; sections it cannot read are
skipped with a warning and the rest still run.

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

API_KEY_CLIENT_ID = "ast-app"
PAGE_SIZE = 100
# Keycloak user-event types that show a credential being exchanged/used.
TOKEN_USE_EVENTS = {"REFRESH_TOKEN", "CODE_TO_TOKEN", "CLIENT_LOGIN", "TOKEN_EXCHANGE"}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def decode_jwt_claims(token: str) -> dict:
    """Return the (unverified) payload of a JWT. Used only to locate the tenant."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("API key is not a JWT; pass --iam-url and --tenant explicitly") from exc


def derive_endpoints(api_key: str) -> tuple[str, str, str]:
    """From the key's `iss` claim, return (iam_url, tenant, ast_url).

    iss looks like https://<region.>iam.checkmarx.net/auth/realms/<tenant>
    """
    iss = decode_jwt_claims(api_key).get("iss", "")
    parsed = urllib.parse.urlparse(iss)
    parts = parsed.path.rstrip("/").split("/")
    if "realms" not in parts or not parsed.netloc:
        raise ValueError(f"cannot derive tenant from iss={iss!r}")
    tenant = parts[parts.index("realms") + 1]
    iam_url = f"{parsed.scheme}://{parsed.netloc}"
    ast_host = parsed.netloc.replace("iam.", "ast.", 1) if "iam." in parsed.netloc else parsed.netloc
    return iam_url, tenant, f"{parsed.scheme}://{ast_host}"


def ms_to_iso(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return dt.datetime.fromtimestamp(int(value) / 1000, tz=dt.timezone.utc).isoformat()
    except (TypeError, ValueError):
        return str(value)


def s_to_iso(value: Any) -> str:
    return ms_to_iso(int(value) * 1000) if value not in (None, "") else ""


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")
        self.status = status


class CxClient:
    def __init__(self, api_key: str, iam_url: str, tenant: str, ast_url: str, timeout: int = 60):
        self.api_key = api_key
        self.iam_url = iam_url.rstrip("/")
        self.tenant = tenant
        self.ast_url = ast_url.rstrip("/")
        self.timeout = timeout
        self._token: str | None = None

    # -- auth --------------------------------------------------------------- #
    def authenticate(self) -> None:
        url = f"{self.iam_url}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "client_id": API_KEY_CLIENT_ID,
            "refresh_token": self.api_key,
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
        self._token = self._send(req)["access_token"]

    # -- plumbing ----------------------------------------------------------- #
    def _send(self, req: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise HttpError(exc.code, req.full_url, exc.read().decode(errors="replace")) from None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw.decode(errors="replace")

    def get(self, url: str, params: dict | None = None, accept: str = "application/json",
            _retried: bool = False) -> Any:
        if params:
            q = {k: v for k, v in params.items() if v is not None}
            url = f"{url}?{urllib.parse.urlencode(q)}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token}",
                                                   "Accept": accept})
        try:
            return self._send(req)
        except HttpError as exc:
            if exc.status == 401 and not _retried:  # access token (30 min) expired mid-run
                self.authenticate()
                return self.get(url, None, accept, _retried=True)
            raise

    def admin(self, path: str) -> str:
        return f"{self.iam_url}/auth/admin/realms/{self.tenant}{path}"

    def paged_admin(self, path: str, params: dict | None = None) -> Iterable[dict]:
        first = 0
        while True:
            page = self.get(self.admin(path), {**(params or {}), "first": first, "max": PAGE_SIZE}) or []
            yield from page
            if len(page) < PAGE_SIZE:
                return
            first += PAGE_SIZE

    # -- data sources ------------------------------------------------------- #
    def audit_events(self, date_from: dt.datetime, date_to: dt.datetime) -> list[dict]:
        """Checkmarx One audit trail - current API (Audit Event Processor).

        GET /api/audit-events?offset&limit&startDate&endDate
        -> {"events": [...], "totalFilteredCount": N, "_links": {...}}
        Covers up to 365 days; data collection began 2026-03-29.
        """
        events: list[dict] = []
        offset, limit = 0, 1000
        params = {"startDate": _rfc3339(date_from), "endDate": _rfc3339(date_to)}
        while True:
            page = self.get(f"{self.ast_url}/api/audit-events",
                            {**params, "offset": offset, "limit": limit},
                            accept="application/json; version=1.0") or {}
            batch = page.get("events") or []
            events.extend(batch)
            total = page.get("totalFilteredCount")
            offset += len(batch)
            if not batch or len(batch) < limit or (total is not None and offset >= total):
                return events

    def audit_trail_legacy(self, date_from: dt.datetime, date_to: dt.datetime) -> list[dict]:
        """Deprecated GET /api/audit (still useful for events before 2026-03-29).

        Returns {"events": [...today...], "links": [{"eventDate", "url", "crc"}]}
        where each link is a pre-signed daily JSON file for an earlier date.
        """
        data = self.get(f"{self.ast_url}/api/audit",
                        {"from": date_from.strftime("%Y-%m-%d"), "to": date_to.strftime("%Y-%m-%d")},
                        accept="application/json; version=1.0")
        events: list[dict] = []
        if isinstance(data, list):
            events.extend(data)
        elif isinstance(data, dict):
            events.extend(data.get("events") or [])
            for link in data.get("links") or []:
                link_url = link.get("url") if isinstance(link, dict) else link
                if not link_url:
                    continue
                try:
                    chunk = self._fetch_link(link_url)
                except HttpError as exc:
                    log(f"  ! could not fetch audit file {link_url}: {exc}")
                    continue
                events.extend(chunk)
        return [e for e in events if _in_window(e.get("eventDate") or e.get("time"), date_from, date_to)]

    def _fetch_link(self, url: str) -> list[dict]:
        if url.startswith("/"):
            url = f"{self.ast_url}{url}"
        # Pre-signed storage URLs reject an Authorization header.
        presigned = "X-Amz-Signature" in url or "sig=" in url
        req = urllib.request.Request(url, headers={} if presigned else
                                     {"Authorization": f"Bearer {self._token}"})
        body = self._send(req)
        if isinstance(body, dict):
            return body.get("events") or []
        if isinstance(body, list):
            return body
        if isinstance(body, str):  # JSON lines
            return [json.loads(line) for line in body.splitlines() if line.strip()]
        return []

    def admin_events(self, date_from: dt.datetime, date_to: dt.datetime) -> list[dict]:
        return list(self.paged_admin("/admin-events", {
            "dateFrom": date_from.strftime("%Y-%m-%d"), "dateTo": date_to.strftime("%Y-%m-%d")}))

    def user_events(self, date_from: dt.datetime, date_to: dt.datetime) -> list[dict]:
        return list(self.paged_admin("/events", {
            "dateFrom": date_from.strftime("%Y-%m-%d"), "dateTo": date_to.strftime("%Y-%m-%d")}))

    def users(self) -> list[dict]:
        return list(self.paged_admin("/users", {"briefRepresentation": "true"}))

    def client_uuid(self, client_id: str) -> str | None:
        found = self.get(self.admin("/clients"), {"clientId": client_id}) or []
        return found[0]["id"] if found else None

    def user_consents(self, user_id: str) -> list[dict]:
        return self.get(self.admin(f"/users/{user_id}/consents")) or []

    def user_offline_sessions(self, user_id: str, client_uuid: str) -> list[dict]:
        return self.get(self.admin(f"/users/{user_id}/offline-sessions/{client_uuid}")) or []


def _rfc3339(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _in_window(value: Any, start: dt.datetime, end: dt.datetime) -> bool:
    if not value:
        return True
    try:
        if isinstance(value, (int, float)):
            ts = dt.datetime.fromtimestamp(value / 1000, tz=dt.timezone.utc)
        else:
            ts = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return True
    return start <= ts <= end


# --------------------------------------------------------------------------- #
# Report building
# --------------------------------------------------------------------------- #
def build_api_key_inventory(client: CxClient, users: list[dict]) -> list[dict]:
    """One row per API key (offline session) per user.

    created_by is the user the key belongs to: in Checkmarx One a key is always
    minted by, and acts as, the user who generated it.
    """
    uuid = client.client_uuid(API_KEY_CLIENT_ID)
    rows: list[dict] = []
    for u in users:
        uid, uname = u["id"], u.get("username", "")
        sessions = client.user_offline_sessions(uid, uuid) if uuid else []
        consent = next((c for c in client.user_consents(uid)
                        if c.get("clientId") == API_KEY_CLIENT_ID), None)
        grant_created = ms_to_iso(consent.get("createdDate")) if consent else ""
        grant_updated = ms_to_iso(consent.get("lastUpdatedDate")) if consent else ""
        for s in sessions:
            rows.append({
                "api_key_session_id": s.get("id", ""),
                "created_by_user": uname,
                "created_by_user_id": uid,
                "email": u.get("email", ""),
                "user_enabled": u.get("enabled", ""),
                "created_at": ms_to_iso(s.get("start")),
                "last_used_at": ms_to_iso(s.get("lastAccess")),
                "last_used_from_ip": s.get("ipAddress", ""),
                "offline_grant_first_created": grant_created,
                "offline_grant_last_updated": grant_updated,
            })
        if not sessions and consent and any(
                g.get("key") == "Offline Token" for g in consent.get("additionalGrants") or []):
            # Key exists but no live session is visible (e.g. idle-expired view).
            rows.append({
                "api_key_session_id": "",
                "created_by_user": uname, "created_by_user_id": uid,
                "email": u.get("email", ""), "user_enabled": u.get("enabled", ""),
                "created_at": grant_created, "last_used_at": grant_updated,
                "last_used_from_ip": "",
                "offline_grant_first_created": grant_created,
                "offline_grant_last_updated": grant_updated,
            })
    return rows


def build_api_key_usage(user_events: list[dict], keys: list[dict],
                        users_by_id: dict[str, str]) -> list[dict]:
    """Token-use events, tied back to the API key (offline session) that was used."""
    key_owner = {k["api_key_session_id"]: k["created_by_user"] for k in keys if k["api_key_session_id"]}
    rows = []
    for e in user_events:
        if e.get("clientId") != API_KEY_CLIENT_ID or e.get("type") not in TOKEN_USE_EVENTS:
            continue
        sid = e.get("sessionId", "")
        rows.append({
            "time": ms_to_iso(e.get("time")),
            "event_type": e.get("type", ""),
            "used_by_user": users_by_id.get(e.get("userId", ""), e.get("details", {}).get("username", "")),
            "used_by_user_id": e.get("userId", ""),
            "ip_address": e.get("ipAddress", ""),
            "api_key_session_id": sid,
            "api_key_created_by": key_owner.get(sid, ""),
            "is_api_key": sid in key_owner or e.get("details", {}).get("refresh_token_type") == "Offline",
            "error": e.get("error", ""),
        })
    return rows


def flatten_admin_event(e: dict, users_by_id: dict[str, str]) -> dict:
    auth = e.get("authDetails") or {}
    return {
        "time": ms_to_iso(e.get("time")),
        "operation": e.get("operationType", ""),
        "resource_type": e.get("resourceType", ""),
        "resource_path": e.get("resourcePath", ""),
        "actor_user": users_by_id.get(auth.get("userId", ""), ""),
        "actor_user_id": auth.get("userId", ""),
        "actor_client": auth.get("clientId", ""),
        "actor_ip": auth.get("ipAddress", ""),
        "error": e.get("error", ""),
        "representation": e.get("representation", ""),
    }


def flatten_user_event(e: dict, users_by_id: dict[str, str]) -> dict:
    return {
        "time": ms_to_iso(e.get("time")),
        "type": e.get("type", ""),
        "user": users_by_id.get(e.get("userId", ""), (e.get("details") or {}).get("username", "")),
        "user_id": e.get("userId", ""),
        "client": e.get("clientId", ""),
        "ip_address": e.get("ipAddress", ""),
        "session_id": e.get("sessionId", ""),
        "error": e.get("error", ""),
        "details": json.dumps(e.get("details") or {}, sort_keys=True),
    }


def flatten_audit_event(e: dict, users_by_id: dict[str, str]) -> dict:
    uid = e.get("actionUserId", "")
    data = e.get("data") if isinstance(e.get("data"), dict) else {}
    return {
        "time": e.get("eventDate", ""),
        "event_id": e.get("eventID", ""),
        "event_type": e.get("eventType", ""),
        "audit_resource": e.get("auditResource", ""),
        "action": e.get("actionType", ""),
        "actor_user": users_by_id.get(uid) or data.get("username", ""),
        "actor_user_id": uid,
        "ip_address": e.get("ipAddress") or "",
        "source": e.get("_source", ""),
        "data": json.dumps(e.get("data") or {}, sort_keys=True, default=str),
    }


def write_csv(path: str, rows: list[dict]) -> None:
    fields: list[str] = []
    for r in rows:
        fields.extend(k for k in r if k not in fields)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields or ["empty"])
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run(args: argparse.Namespace) -> int:
    api_key = args.api_key or os.environ.get("CX_APIKEY")
    if not api_key:
        log("error: provide the API key via --api-key or CX_APIKEY")
        return 2

    iam_url, tenant, ast_url = args.iam_url, args.tenant, args.base_url
    if not (iam_url and tenant and ast_url):
        d_iam, d_tenant, d_ast = derive_endpoints(api_key)
        iam_url, tenant, ast_url = iam_url or d_iam, tenant or d_tenant, ast_url or d_ast
    log(f"tenant={tenant}  iam={iam_url}  api={ast_url}")

    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=args.days)
    os.makedirs(args.out, exist_ok=True)

    client = CxClient(api_key, iam_url, tenant, ast_url)
    client.authenticate()
    log("authenticated")

    report: dict[str, Any] = {"tenant": tenant, "from": start.isoformat(), "to": end.isoformat(),
                              "sections": {}}

    def section(name: str, fn):
        log(f"- {name} ...")
        try:
            result = fn()
            report["sections"][name] = {"status": "ok", "count": len(result)}
            log(f"  {len(result)} records")
            return result
        except HttpError as exc:
            hint = " (API key owner lacks permission)" if exc.status in (401, 403) else ""
            report["sections"][name] = {"status": f"failed: HTTP {exc.status}{hint}"}
            log(f"  ! skipped: {exc}{hint}")
            return []

    users = section("users", client.users)
    users_by_id = {u["id"]: u.get("username", "") for u in users}

    def collect_audit() -> list[dict]:
        events: list[dict] = []
        try:
            events = [{**e, "_source": "audit-events"} for e in client.audit_events(start, end)]
        except HttpError as exc:
            if exc.status != 404:
                raise
            log("  /api/audit-events not available on this tenant; using legacy /api/audit")
            args.legacy_audit = True
        if args.legacy_audit:
            seen = {e.get("eventID") for e in events if e.get("eventID")}
            for e in client.audit_trail_legacy(start, end):
                if not e.get("eventID") or e["eventID"] not in seen:
                    events.append({**e, "_source": "audit-legacy"})
        return sorted(events, key=lambda e: str(e.get("eventDate", "")))

    audit = section("audit_trail", collect_audit)
    admin_ev = section("iam_admin_events", lambda: client.admin_events(start, end))
    user_ev = section("iam_user_events", lambda: client.user_events(start, end))
    keys = section("api_keys", lambda: build_api_key_inventory(client, users)) if users else []
    usage = build_api_key_usage(user_ev, keys, users_by_id)
    report["sections"]["api_key_usage"] = {"status": "ok", "count": len(usage)}

    outputs = {
        "audit_trail.csv": [flatten_audit_event(e, users_by_id) for e in audit],
        "iam_admin_events.csv": [flatten_admin_event(e, users_by_id) for e in admin_ev],
        "iam_user_events.csv": [flatten_user_event(e, users_by_id) for e in user_ev],
        "api_keys.csv": keys,
        "api_key_usage.csv": usage,
    }
    for name, rows in outputs.items():
        write_csv(os.path.join(args.out, name), rows)

    # Per-user rollup: keys created, key uses, actions performed.
    summary: dict[str, dict] = {}
    for k in keys:
        summary.setdefault(k["created_by_user"], {}).setdefault("api_keys_created", 0)
        summary[k["created_by_user"]]["api_keys_created"] += 1
    for u in usage:
        s = summary.setdefault(u["used_by_user"] or u["used_by_user_id"], {})
        s["api_key_uses"] = s.get("api_key_uses", 0) + 1
        s.setdefault("api_key_ips", set()).add(u["ip_address"])
    for a in outputs["audit_trail.csv"]:
        s = summary.setdefault(a["actor_user"], {})
        s["audit_actions"] = s.get("audit_actions", 0) + 1
    for s in summary.values():
        if "api_key_ips" in s:
            s["api_key_ips"] = sorted(i for i in s["api_key_ips"] if i)
    report["per_user"] = summary

    raw = {"audit_trail": audit, "iam_admin_events": admin_ev, "iam_user_events": user_ev,
           "api_keys": keys, "api_key_usage": usage}
    with open(os.path.join(args.out, "raw.json"), "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, default=str)
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    log(f"done -> {os.path.abspath(args.out)}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export Checkmarx One audit logs and API key usage.")
    p.add_argument("--api-key", help="Checkmarx One API key (default: $CX_APIKEY)")
    p.add_argument("--base-url", help="Checkmarx One API URL, e.g. https://ast.checkmarx.net "
                                      "(default: derived from the key)")
    p.add_argument("--iam-url", help="IAM URL, e.g. https://iam.checkmarx.net (default: from the key)")
    p.add_argument("--tenant", help="tenant name (default: from the key)")
    p.add_argument("--days", type=int, default=30, help="look-back window in days (default 30)")
    p.add_argument("--out", default="audit-out", help="output directory (default ./audit-out)")
    p.add_argument("--legacy-audit", action="store_true",
                   help="also pull the deprecated /api/audit trail (events before 2026-03-29)")
    return p.parse_args(argv)


if __name__ == "__main__":
    sys.exit(run(parse_args()))
