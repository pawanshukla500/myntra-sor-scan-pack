#!/usr/bin/env python3
"""Run one Myntra Partner packing job from a local network.

The script is intentionally manual and read-only against the Consignment DB:
it reads the exact carton/barcode quantities, opens a visible local Chrome
window, and waits for the operator to complete Myntra sign-in if required.
It never marks the source consignment complete and only records a local
success marker after every carton has been closed in the portal.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from dotenv import load_dotenv
except ImportError:  # optional; the script also works with exported env vars
    load_dotenv = None

try:
    import psycopg  # psycopg 3
except ImportError:  # pragma: no cover - fallback for older local setups
    psycopg = None

try:
    import psycopg2  # psycopg2 fallback
except ImportError:  # pragma: no cover
    psycopg2 = None

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Playwright is required. Install dependencies with: "
        "python -m pip install -r myntra_requirements.txt && "
        "python -m playwright install chromium"
    ) from exc


SCAN_PACK_URL = os.getenv(
    "MYNTRA_PARTNER_SCANPACK_URL",
    "https://partners.myntrainfo.com/Manufacturing/scanpack",
)
# Myntra's bare /login endpoint returns "Invalid client Id". Starting from
# Scan & Pack creates the partner-specific SSO URL (cidx + return URL), then
# the runner completes the requested email/password flow on that redirect.
LOGIN_URL = os.getenv("MYNTRA_PARTNER_LOGIN_URL", SCAN_PACK_URL)
def application_dir() -> Path:
    # PyInstaller one-file executables run from a temporary extraction folder;
    # user configuration must live beside the executable instead. When the
    # source is run directly, keep its state beside the script too so the
    # source and EXE can be maintained together in one folder.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


DEFAULT_CONFIG = application_dir() / "myntra_manual_config.json"
DEFAULT_STATE = application_dir() / "data" / "myntra-manual-state.json"


def _dpapi_blob(data: bytes):
    """Return a Windows DATA_BLOB for DPAPI calls."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    buffer = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect_secret(value: str) -> str:
    """Encrypt a local secret with the current Windows user profile."""
    if not value:
        return ""
    if os.name != "nt":
        raise RuntimeError("Encrypted local configuration requires Windows DPAPI")
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.windll.crypt32
    source, source_buffer = _dpapi_blob(value.encode("utf-8"))
    target = type(source)()
    if not crypt32.CryptProtectData(ctypes.byref(source), "MyntraPartnerManual", None, None, None, 0, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        raw = ctypes.string_at(target.pbData, target.cbData)
        return base64.b64encode(raw).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(target.pbData)


def unprotect_secret(value: str) -> str:
    if not value:
        return ""
    if os.name != "nt":
        raise RuntimeError("Encrypted local configuration requires Windows DPAPI")
    import ctypes

    crypt32 = ctypes.windll.crypt32
    raw = base64.b64decode(value.encode("ascii"))
    source, source_buffer = _dpapi_blob(raw)
    target = type(source)()
    if not crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(target.pbData)


def obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def number(value: Any, fallback: int = 0) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return fallback
    return result


def normalize(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def account_id(value: Any) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return result[:49] or "myntra-account"


def db_url() -> str:
    value = str(os.getenv("CONSIGMENT_APP_DATABASE_URL", "")).strip()
    if not value:
        raise RuntimeError("CONSIGMENT_APP_DATABASE_URL is not configured")
    # Cockroach local runs normally have no CA bundle. Keep TLS enabled while
    # avoiding a local certificate-file requirement, matching the Node worker.
    parts = urlsplit(value)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["sslmode"] = "require"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def load_runtime_config(path: Path, consignment_override: str | None) -> dict[str, Any]:
    config: dict[str, Any] = {}
    if path.exists():
        try:
            config = obj(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read config file {path}: {exc}") from exc
    # Decrypt values that were saved by this Windows app. Environment values
    # always win, allowing a team member to use an injected secret instead.
    decrypted: dict[str, str] = {}
    for plain, encrypted in {
        "consignment_database_url": "consignment_database_url_encrypted",
        "myntra_email": "myntra_email_encrypted",
        "myntra_password": "myntra_password_encrypted",
        "proxy": "proxy_encrypted",
    }.items():
        encrypted_value = config.get(encrypted)
        if encrypted_value:
            decrypted[plain] = unprotect_secret(str(encrypted_value))
        elif config.get(plain):
            decrypted[plain] = str(config.get(plain))
    values = {
        "CONSIGMENT_APP_DATABASE_URL": decrypted.get("consignment_database_url"),
        "MYNTRA_PARTNER_EMAIL": decrypted.get("myntra_email"),
        "MYNTRA_PARTNER_PASSWORD": decrypted.get("myntra_password"),
        "MYNTRA_PARTNER_PROXY": decrypted.get("proxy"),
    }
    for key, value in values.items():
        if not os.getenv(key) and value:
            os.environ[key] = str(value)
    config.update(decrypted)
    # Migrate a hand-filled/legacy JSON file to encrypted DPAPI storage once.
    if path.exists() and any(config.get(key) for key in decrypted) and not config.get("consignment_database_url_encrypted"):
        save_runtime_config(path, config)
    return config


def save_runtime_config(path: Path, config: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    saved = {key: value for key, value in config.items() if key not in {
        "consignment_database_url", "myntra_email", "myntra_password", "proxy",
    }}
    for plain, encrypted in {
        "consignment_database_url": "consignment_database_url_encrypted",
        "myntra_email": "myntra_email_encrypted",
        "myntra_password": "myntra_password_encrypted",
        "proxy": "proxy_encrypted",
    }.items():
        value = str(config.get(plain) or "")
        if value:
            saved[encrypted] = protect_secret(value)
        elif config.get(encrypted):
            saved[encrypted] = config[encrypted]
    path.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    try:
        # Best effort: restrict the config file to the current Windows user.
        if os.name == "nt":
            import subprocess
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{os.getenv('USERNAME')}:F"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            path.chmod(0o600)
    except Exception:
        pass


def load_app_environment(env_file: str | None = None) -> None:
    """Load the local build environment or the EXE's embedded DB setting."""
    if not load_dotenv:
        return
    candidates: list[Path] = []
    if env_file:
        candidates.append(Path(env_file))
    if getattr(sys, "frozen", False):
        candidates.append(Path(getattr(sys, "_MEIPASS", application_dir())) / ".embedded.env")
    candidates.append(Path(__file__).resolve().parent.parent / ".env")
    for candidate in candidates:
        if candidate.exists():
            load_dotenv(candidate, override=False)


def first_run_setup(path: Path, config: dict[str, Any], consignment_override: str | None) -> dict[str, Any]:
    if os.getenv("CONSIGMENT_APP_DATABASE_URL"):
        return config
    print(f"No database configuration found. Creating protected local config: {path}")
    db = input("Consignment database URL: ").strip()
    if not db:
        raise RuntimeError("A Consignment database URL is required")
    email = input("Myntra partner email (optional; saved encrypted): ").strip()
    password = getpass.getpass("Myntra partner password (optional; saved encrypted): ") if email else ""
    config.update({
        "consignment_database_url": db,
        "myntra_email": email,
        "myntra_password": password,
        "auto_login": False,
        "consignment": consignment_override or config.get("consignment") or "MYNJ-VBXOEO240726-16",
    })
    save_runtime_config(path, config)
    os.environ["CONSIGMENT_APP_DATABASE_URL"] = db
    if email:
        os.environ["MYNTRA_PARTNER_EMAIL"] = email
        os.environ["MYNTRA_PARTNER_PASSWORD"] = password
    return config


def connect_db():
    url = db_url()
    if psycopg is not None:
        return psycopg.connect(url, connect_timeout=15, options="-c default_transaction_read_only=on")
    if psycopg2 is not None:
        return psycopg2.connect(url, connect_timeout=15, options="-c default_transaction_read_only=on")
    raise RuntimeError("Install psycopg[binary] or psycopg2-binary before running this script")


def has_confirmed(data: dict[str, Any], stage: str) -> bool:
    return bool(obj(obj(data).get("stageConfirmations")).get(stage, {}).get("confirmedAt"))


def consignment_scenario(data: dict[str, Any]) -> str:
    """Return the operator-facing scenario derived from Consignment DB fields."""
    status_keys = (
        "derivedStatus", "workflowBucket", "priorityBucket", "listPriorityBucket",
        "workflowStatus", "packingStatus", "currentStatus", "currentStage", "state", "status",
    )
    statuses = [normalize_status(data.get(key)) for key in status_keys]
    statuses = [value for value in statuses if value]
    shipment = normalize_status(data.get("shipmentStatus"))
    workflow_stage = normalize_status(data.get("currentWorkflowStage") or data.get("workflowStage"))
    pending_action = normalize_status(data.get("pendingAction"))

    # pendingAction is the clearest signal for records whose generic status is
    # already "completed". It must take precedence over shipmentStatus, which
    # can still say "Under Packing" while the invoice action is pending.
    if (
        any("pending invoice" in value for value in statuses)
        or "invoice number" in pending_action
        or "enter invoice" in pending_action
        or workflow_stage == "invoice created"
    ):
        return "Packed · pending invoice"
    if (
        any(value == "ready for dispatch" for value in statuses)
        or shipment == "ready"
        or "mark dispatched" in pending_action
        or "docket" in pending_action
    ):
        return "Ready for dispatch"
    if shipment == "under packing" or any(value in {"in progress", "under packing"} for value in statuses):
        return "Under packing"
    if shipment:
        return shipment.title()
    if statuses:
        return statuses[0].title()
    if workflow_stage:
        return workflow_stage.title()
    return "Scenario not set"


def is_packed_pending_invoice(data: dict[str, Any]) -> bool:
    configured = normalize_status(os.getenv("MYNTRA_PARTNER_ELIGIBLE_STATUS", "packed pending invoice"))
    status_keys = (
        "status", "workflowStatus", "packingStatus", "currentStatus", "currentStage", "state",
        "shipmentStatus", "workflowBucket", "priorityBucket", "listPriorityBucket", "derivedStatus",
    )
    statuses = [normalize_status(data.get(key)) for key in status_keys]
    statuses = [value for value in statuses if value]
    if configured in statuses or any("pending invoice" in value for value in statuses):
        return True
    packing_done = has_confirmed(data, "packing_completed") or normalize_status(data.get("status")) == "completed"
    invoice_ready = has_confirmed(data, "ready_for_invoice")
    invoice_done = has_confirmed(data, "invoice_created")
    shipment = normalize_status(data.get("shipmentStatus"))
    dispatched = has_confirmed(data, "dispatched") or shipment in {"in transit", "forwarded"}
    inwarded = has_confirmed(data, "inward_completed") or bool(str(data.get("dateOfInward") or "").strip())
    ready_dispatch = has_confirmed(data, "ready_for_dispatch") or shipment == "ready"
    if inwarded or dispatched or (ready_dispatch and invoice_done):
        return False
    # In the Consignment app, the visible “PACKED · PENDING INVOICE” group is
    # represented by status=completed plus currentWorkflowStage=invoice_created
    # and a pending invoice action. This is the authoritative read-only
    # workflow signal; status=completed alone is not enough.
    workflow_stage = normalize_status(data.get("currentWorkflowStage") or data.get("workflowStage"))
    pending_action = normalize_status(data.get("pendingAction"))
    invoice_stage = (
        workflow_stage in {"invoice created", "ready for invoice"}
        or "invoice number" in pending_action
        or (invoice_ready and not invoice_done)
    )
    if invoice_stage and packing_done and not invoice_done:
        return True
    # A plain packed/completed/dispatched record is not eligible. The source
    # app uses a separate “Packed · pending invoice” bucket for records that
    # still need partner-portal packing, so do not re-offer terminal rows.
    terminal = {
        "packed", "completed", "invoiced", "invoice created", "ready for dispatch",
        "dispatched", "in transit", "forwarded", "inward completed", "archived", "cancelled",
    }
    if any(value in terminal for value in statuses):
        return False
    return False


def read_eligible_consignments(limit: int | None = None, state_path: Path | None = None) -> list[dict[str, Any]]:
    """Return all consignments for the configured Myntra SOR marketplace."""
    max_rows = None if limit is None else max(int(limit), 1)
    # Keep state_path in the public signature for older callers. Local run
    # history is deliberately ignored: every database row is always runnable.
    _ = state_path
    target_marketplace = normalize_status(os.getenv("MYNTRA_PARTNER_MARKETPLACE", "Myntra SOR"))
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id::text, data FROM documents WHERE collection = 'marketplaces'")
            marketplaces: dict[str, dict[str, Any]] = {}
            for source_id, raw in cur.fetchall():
                data = obj(raw)
                label = str(data.get("name") or data.get("label") or data.get("code") or source_id).strip()
                code = str(data.get("code") or data.get("name") or "").strip()
                marketplaces[str(source_id)] = {
                    "sourceId": str(source_id), "label": label, "code": code,
                    "accountId": account_id(code or label or source_id),
                }
            target_ids = [
                source_id for source_id, marketplace in marketplaces.items()
                if target_marketplace in {
                    normalize_status(marketplace.get("label")),
                    normalize_status(marketplace.get("code")),
                }
            ]
            if not target_ids:
                return []
            placeholders = ", ".join(["%s"] * len(target_ids))
            cur.execute(
                f"""SELECT id::text, data FROM documents
                    WHERE collection = 'consignments'
                      AND (data->>'marketplaceId' IN ({placeholders})
                        OR data->>'marketplaceID' IN ({placeholders}))
                    ORDER BY id::text ASC""",
                tuple(target_ids + target_ids),
            )
            results: list[dict[str, Any]] = []
            for row_id, raw in cur.fetchall():
                data = obj(raw)
                marketplace = marketplaces.get(str(data.get("marketplaceId") or data.get("marketplaceID") or ""))
                if not marketplace:
                    continue
                code = str(
                    data.get("id") or data.get("consignmentNo") or data.get("internalShipmentNo")
                    or data.get("shipmentNo") or row_id or ""
                ).strip()
                if not code:
                    continue
                results.append({
                    "code": code,
                    "shipment": data.get("shipmentNo") or data.get("internalShipmentNo") or "",
                    "marketplace": marketplace["label"],
                    "accountId": marketplace["accountId"],
                    "warehouse": data.get("warehouse") or data.get("warehouseName") or "",
                    "scenario": consignment_scenario(data),
                    "status": data.get("status") or "",
                    "shipmentStatus": data.get("shipmentStatus") or "",
                    "packedQty": number(data.get("totalPackedQty", data.get("packedQty"))),
                    "requiredQty": number(data.get("totalRequiredQty", data.get("requiredQty"))),
                })
                if max_rows is not None and len(results) >= max_rows:
                    break
    return results


def normalize_status(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def read_plan(code: str) -> dict[str, Any]:
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id::text, data FROM documents
                   WHERE collection = 'consignments'
                     AND (id::text = %s OR data->>'id' = %s
                       OR data->>'consignmentNo' = %s
                       OR data->>'internalShipmentNo' = %s
                       OR data->>'shipmentNo' = %s)
                   LIMIT 1""",
                (code, code, code, code, code),
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError(f"Consignment not found: {code}")
            consignment_row_id, data = row
            data = obj(data)

            cur.execute("SELECT id::text, data FROM documents WHERE collection = 'marketplaces'")
            marketplaces = {}
            for marketplace_id, marketplace_data in cur.fetchall():
                marketplace_data = obj(marketplace_data)
                label = str(
                    marketplace_data.get("name")
                    or marketplace_data.get("label")
                    or marketplace_data.get("code")
                    or marketplace_id
                ).strip()
                marketplaces[str(marketplace_id)] = {
                    "sourceId": str(marketplace_id),
                    "code": str(marketplace_data.get("code") or marketplace_data.get("name") or "").strip(),
                    "label": label,
                    "accountId": account_id(marketplace_data.get("code") or label or marketplace_id),
                }
            marketplace = marketplaces.get(str(data.get("marketplaceId", "")))

            box_ids = [str(value) for value in data.get("boxIds", []) if str(value).strip()]
            if box_ids:
                cur.execute(
                    """SELECT id::text, data FROM documents
                       WHERE collection = 'boxes'
                         AND (data->>'consignmentId' = %s OR id::text = ANY(%s))""",
                    (str(consignment_row_id), box_ids),
                )
            else:
                cur.execute(
                    """SELECT id::text, data FROM documents
                       WHERE collection = 'boxes' AND data->>'consignmentId' = %s""",
                    (str(consignment_row_id),),
                )
            box_rows = cur.fetchall()

    if not box_rows:
        raise RuntimeError(f"No cartons found for consignment {code}")

    boxes = []
    for box_id, box_data in box_rows:
        box_data = obj(box_data)
        box_no = str(box_data.get("boxNo", box_data.get("cartonNo", ""))).strip()
        if not box_no:
            raise RuntimeError(f"Carton {box_id} has no carton number")
        items = []
        for raw_item in box_data.get("items", []):
            item = obj(raw_item)
            barcode = str(item.get("barcode") or item.get("marketplaceBarcode") or item.get("sku") or "").strip()
            qty = number(item.get("qty", item.get("quantity")))
            if not barcode or qty < 1:
                raise RuntimeError(f"Invalid barcode/quantity in carton {box_no}")
            items.append({"barcode": barcode, "qty": qty})
        total = sum(item["qty"] for item in items)
        declared = number(box_data.get("totalQty", box_data.get("originalTotalQty")))
        if not total:
            raise RuntimeError(f"Carton {box_no} has no barcode items")
        if declared and declared != total:
            raise RuntimeError(f"Carton {box_no} quantity mismatch: declared {declared}, items {total}")
        boxes.append({"id": str(box_id), "boxNo": box_no, "items": items, "totalUnits": total})
    boxes.sort(key=lambda box: (number(box["boxNo"], 0), box["boxNo"]))
    total_units = sum(box["totalUnits"] for box in boxes)
    expected = number(data.get("totalPackedQty", data.get("packedQty")))
    if expected and expected != total_units:
        raise RuntimeError(f"Consignment {code} quantity mismatch: boxes {total_units}, packed {expected}")
    return {
        "consignment": {
            "code": str(data.get("id") or consignment_row_id or code),
            "warehouse": data.get("warehouse") or data.get("warehouseName"),
            "marketplace": (marketplace or {}).get("label") or data.get("marketplaceId"),
        },
        "boxes": boxes,
        "totalUnits": total_units,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def empty_state() -> dict[str, Any]:
    return {"version": 2, "completed": [], "active": None}


def read_state(path: Path) -> dict[str, Any]:
    """Read durable packing state and migrate the original list format.

    Older builds wrote a JSON array containing completed consignment IDs. The
    current format retains legacy history plus optional run progress, but this
    data never controls whether a consignment may be started again. A malformed
    or missing file is treated as empty.
    """
    source_path = path
    if not path.exists() and path.name == "myntra-manual-state.json":
        # One-time compatibility with builds that used the old filename.
        legacy = path.with_name("myntra-manual-completed.json")
        if legacy.exists():
            source_path = legacy
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return empty_state()
    if isinstance(raw, list):
        completed = sorted({str(value).strip().lower() for value in raw if str(value).strip()})
        return {"version": 2, "completed": completed, "active": None}
    if not isinstance(raw, dict):
        return empty_state()
    completed = sorted({str(value).strip().lower() for value in raw.get("completed", []) if str(value).strip()})
    active = raw.get("active") if isinstance(raw.get("active"), dict) else None
    if active:
        code = str(active.get("code") or "").strip().lower()
        active = dict(active) if code else None
        if active:
            active["code"] = code
    return {"version": 2, "completed": completed, "active": active}


def write_state(path: Path, state: dict[str, Any]) -> None:
    """Atomically persist state so a process stop cannot leave half-written JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = {
        "version": 2,
        "completed": sorted({str(value).strip().lower() for value in state.get("completed", []) if str(value).strip()}),
        "active": state.get("active") if isinstance(state.get("active"), dict) else None,
    }
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def active_code(state: dict[str, Any]) -> str | None:
    active = state.get("active") if isinstance(state.get("active"), dict) else None
    code = str(active.get("code") or "").strip().lower() if active else ""
    return code or None


def visible_text(page, text: str, exact: bool = True) -> bool:
    wanted = normalize(text)
    try:
        return bool(
            page.evaluate(
                """([wanted, exact]) => Array.from(document.querySelectorAll('button,[role=button],a,li,div,span'))
                  .some((el) => { const s=getComputedStyle(el), r=el.getBoundingClientRect();
                    const value=(el.innerText||el.textContent||'').replace(/\\s+/g,' ').trim().toLowerCase();
                    return value && (exact ? value===wanted : value.includes(wanted)) &&
                      s.display!=='none' && s.visibility!=='hidden' && r.width>0 && r.height>0; })""",
                [wanted, exact],
            )
        )
    except PlaywrightError:
        # Myntra redirects between SSO and the partner portal; a page can
        # navigate between the URL read and this DOM check.
        return False


def click_text(page, text: str, exact: bool = True, timeout: int = 60_000) -> None:
    wanted = normalize(text)
    page.wait_for_function(
        """([wanted, exact]) => Array.from(document.querySelectorAll('button,[role=button],a,li,div,span'))
          .some((el) => { const s=getComputedStyle(el), r=el.getBoundingClientRect();
            const value=(el.innerText||el.textContent||'').replace(/\\s+/g,' ').trim().toLowerCase();
            return value && (exact ? value===wanted : value.includes(wanted)) &&
              s.display!=='none' && s.visibility!=='hidden' && r.width>0 && r.height>0; })""",
        arg=[wanted, exact],
        timeout=timeout,
    )
    marker = "data-codex-click-target"
    marked = False
    try:
        marked = bool(page.evaluate(
            """([wanted, exact, marker]) => {
              const visible=(el)=>{ const s=getComputedStyle(el), r=el.getBoundingClientRect();
                return s.display!=='none' && s.visibility!=='hidden' && r.width>0 && r.height>0; };
              const nodes=Array.from(document.querySelectorAll('button,[role=button],a,li,div,span'))
                .filter((node)=>{ const value=(node.innerText||node.textContent||'').replace(/\\s+/g,' ').trim().toLowerCase();
                  return value && (exact ? value===wanted : value.includes(wanted)) && visible(node); })
                .sort((a,b)=>((/^(BUTTON|A|LI)$/.test(b.tagName)||b.getAttribute('role')==='button')-
                             (/^(BUTTON|A|LI)$/.test(a.tagName)||a.getAttribute('role')==='button')) ||
                        (a.innerText||'').length-(b.innerText||'').length);
              if (!nodes.length) return false;
              nodes[0].setAttribute(marker, '1');
              return true;
            }""",
            [wanted, exact, marker],
        ))
        if not marked:
            raise RuntimeError(f"Could not click portal control: {text}")
        target = page.locator(f"[{marker}='1']").first
        target.scroll_into_view_if_needed()
        target.click(timeout=timeout)
    finally:
        try:
            page.evaluate("(marker) => document.querySelectorAll(`[${marker}='1']`).forEach((el) => el.removeAttribute(marker))", marker)
        except PlaywrightError:
            pass


def choose_dropdown(page, label: str, value: str) -> None:
    click_text(page, label, exact=False)
    page.wait_for_timeout(300)
    click_text(page, value, exact=True)


def confirm_dialogs(page) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            buttons = page.locator("button,[role=button]")
            for index in range(buttons.count() - 1, -1, -1):
                button = buttons.nth(index)
                if not button.is_visible():
                    continue
                if normalize(button.inner_text()) != "confirm":
                    continue
                # Use Playwright's real click so Myntra's React handler
                # receives the confirmation, rather than DOM .click().
                button.scroll_into_view_if_needed()
                button.click(timeout=5_000)
                page.wait_for_timeout(350)
                break
            else:
                return
        except PlaywrightError:
            # The modal can re-render between the count and click. Retry with
            # a fresh locator until the short confirmation window expires.
            page.wait_for_timeout(150)


def portal_count(page) -> int | None:
    match = re.search(r"TOTAL\s+ITEMS\s*:?\s*(\d+)", page.locator("body").inner_text(), re.I)
    return int(match.group(1)) if match else None


def ready_portal_page(context, preferred=None):
    """Return the live portal page after Myntra swaps pages during SSO."""
    candidates = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend(reversed(list(context.pages)))
    seen = set()
    for candidate in candidates:
        marker = id(candidate)
        if marker in seen or candidate.is_closed():
            continue
        seen.add(marker)
        try:
            if "partners.myntrainfo.com" in candidate.url and visible_text(candidate, "START PACKING", False):
                return candidate
        except PlaywrightError:
            continue
    return None


def live_portal_page(context, preferred=None):
    """Return any open Myntra partner page, even when a modal is active."""
    candidates = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend(reversed(list(context.pages)))
    seen = set()
    seen.clear()
    for candidate in candidates:
        marker = id(candidate)
        if marker in seen or candidate.is_closed():
            continue
        seen.add(marker)
        try:
            if "partners.myntrainfo.com" in candidate.url:
                return candidate
        except PlaywrightError:
            continue
    return None


def live_login_page(context, preferred=None):
    """Return the current Myntra SSO page, including pages opened by redirects."""
    candidates = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend(reversed(list(context.pages)))
    seen = set()
    # Prefer the credential form. Myntra can leave the method selector open
    # while mounting /emaillogin in another page or frame.
    for candidate in candidates:
        marker = id(candidate)
        if marker in seen or candidate.is_closed():
            continue
        seen.add(marker)
        try:
            if "accounts.myntra.com" in candidate.url and login_form_frame(candidate) is not None:
                return candidate
        except PlaywrightError:
            continue
    seen.clear()
    for candidate in candidates:
        marker = id(candidate)
        if marker in seen or candidate.is_closed():
            continue
        seen.add(marker)
        try:
            if "accounts.myntra.com" in candidate.url:
                return candidate
        except PlaywrightError:
            continue
    return None


def login_form_frame(page):
    """Find the Myntra email/password form in the page or an embedded frame."""
    try:
        for frame in page.frames:
            if frame.locator("#email").count() and frame.locator("#password").count():
                return frame
    except PlaywrightError:
        return None
    return None


def chrome_executable(playwright) -> Path:
    """Return an installed Chrome executable for the operator-driven login."""
    configured = str(os.getenv("MYNTRA_PARTNER_CHROME_PATH") or "").strip()
    candidates = [
        Path(configured) if configured else None,
        Path(os.getenv("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.getenv("PROGRAMFILES(X86)", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.getenv("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
        Path(playwright.chromium.executable_path),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("Google Chrome was not found. Install Chrome or set MYNTRA_PARTNER_CHROME_PATH.")


def human_login_debug_port() -> int:
    """Use a stable local port so an intentionally left-open login can be resumed."""
    try:
        port = int(os.getenv("MYNTRA_PARTNER_CHROME_DEBUG_PORT", "9331"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("MYNTRA_PARTNER_CHROME_DEBUG_PORT must be a number") from exc
    if not 1024 <= port <= 65535:
        raise RuntimeError("MYNTRA_PARTNER_CHROME_DEBUG_PORT must be between 1024 and 65535")
    return port


def launch_human_login_browser(playwright, log_callback=None):
    """Launch normal Chrome with a persistent profile, then attach for packing.

    Chrome—not Playwright—owns the browser process and profile. Playwright is
    attached only to observe completion and to run the existing packing flow;
    it never fills, clicks, or submits the Myntra authentication form.
    """
    import subprocess

    def progress(message: str) -> None:
        if log_callback:
            log_callback(message)
        else:
            print(message)

    port = human_login_debug_port()
    endpoint = f"http://127.0.0.1:{port}"
    browser = None
    try:
        browser = playwright.chromium.connect_over_cdp(endpoint, timeout=1_500)
        progress("Reusing the dedicated Myntra Chrome session")
    except PlaywrightError:
        chrome = chrome_executable(playwright)
        profile = Path(os.getenv("LOCALAPPDATA") or application_dir()) / "MyntraPartnerManual" / "ChromeProfile"
        profile.mkdir(parents=True, exist_ok=True)
        command = [
            str(chrome),
            "--remote-debugging-address=127.0.0.1",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--profile-directory=Default",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-notifications",
            "--window-size=1366,900",
            "--new-window",
            LOGIN_URL,
        ]
        proxy = str(os.getenv("MYNTRA_PARTNER_PROXY") or "").strip()
        if proxy:
            command.insert(-2, f"--proxy-server={proxy}")
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                browser = playwright.chromium.connect_over_cdp(endpoint, timeout=1_500)
                break
            except PlaywrightError:
                time.sleep(0.35)
        if browser is None:
            raise RuntimeError(
                "Could not connect to the dedicated Myntra Chrome window. "
                "Close any existing Myntra login Chrome window and try again."
            )
        progress("Opened a dedicated Chrome profile for manual Myntra sign-in")

    if not browser.contexts:
        raise RuntimeError("The dedicated Myntra Chrome session has no browser context")
    context = browser.contexts[0]
    pages = [candidate for candidate in context.pages if not candidate.is_closed()]
    page = next(
        (candidate for candidate in reversed(pages) if "myntra" in candidate.url.lower()),
        pages[-1] if pages else context.new_page(),
    )
    return browser, context, page


def close_human_login_browser(browser, context) -> None:
    """Close the external Chrome process, not only Playwright's CDP connection."""
    try:
        pages = [candidate for candidate in context.pages if not candidate.is_closed()]
        if pages:
            session = context.new_cdp_session(pages[0])
            session.send("Browser.close")
            return
    except PlaywrightError:
        pass
    browser.close()


def emit(args: argparse.Namespace, message: str) -> None:
    print(message)
    callback = getattr(args, "log_callback", None)
    if callback:
        callback(message)


def wait_for_portal(
    context,
    login_page,
    auto_login: bool,
    email: str | None,
    password: str | None,
    gui: bool = False,
    log_callback=None,
):
    """Complete Myntra SSO, then return the ready Scan & Pack page."""
    def progress(message: str) -> None:
        if log_callback:
            log_callback(message)
        elif not gui:
            print(message)

    try:
        login_timeout = max(60, float(os.getenv("MYNTRA_PARTNER_LOGIN_TIMEOUT_S", "600")))
    except (TypeError, ValueError):
        login_timeout = 600.0
    deadline = time.monotonic() + login_timeout
    mode_clicked = False
    submitted = False
    submit_attempts = 0
    last_submit_at = 0.0
    prompted = False
    try:
        progress("Opening Myntra partner SSO")
        login_page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60_000)
    except PlaywrightError:
        # The SSO page may continue redirecting after the initial navigation.
        pass

    while time.monotonic() < deadline:
        url = ""
        try:
            current_login = live_login_page(context, login_page)
            if current_login is not None:
                login_page = current_login
            elif login_page.is_closed():
                open_pages = [p for p in context.pages if not p.is_closed()]
                if open_pages:
                    login_page = open_pages[-1]
            url = login_page.url
            portal = ready_portal_page(context, login_page)
            if portal is not None:
                progress("Myntra Scan & Pack is ready")
                return portal
            if "accounts.myntra.com" in url:
                if not mode_clicked and visible_text(login_page, "Use Email And Password", False):
                    try:
                        click_text(login_page, "Use Email And Password", exact=False, timeout=15_000)
                        mode_clicked = True
                        progress("Selected Use Email And Password")
                    except PlaywrightError:
                        pass

                form_frame = login_form_frame(login_page)
                form = form_frame if form_frame is not None else login_page
                email_field = form.locator("#email").first
                password_field = form.locator("#password").first
                fields_ready = False
                if email_field.count() and password_field.count():
                    try:
                        email_field.wait_for(state="visible", timeout=2_000)
                        password_field.wait_for(state="visible", timeout=2_000)
                        fields_ready = True
                    except PlaywrightError:
                        fields_ready = False

                if fields_ready:
                    can_retry = submitted and submit_attempts < 2 and (time.monotonic() - last_submit_at) >= 8
                    if auto_login and email and password and (not submitted or can_retry):
                        progress("Myntra login form is ready; entering saved credentials")
                        email_field.fill(email)
                        password_field.fill(password)
                        login_button = form.locator(
                            "button.global_actionButton__L2wUb, "
                            "button.global_actionButton__rKxIQ, "
                            "button:has-text('LOG IN'), button[type='submit'], input[type='submit']"
                        ).first
                        login_button.wait_for(state="visible", timeout=10_000)
                        login_button.click()
                        submitted = True
                        submit_attempts += 1
                        last_submit_at = time.monotonic()
                        progress("Submitted Myntra login; waiting for partner portal")
                    elif (not auto_login or not email or not password) and not prompted:
                        progress(
                            "Complete Myntra sign-in in Chrome. "
                            "The app will continue automatically when Scan & Pack is ready."
                        )
                        prompted = True
        except PlaywrightError:
            # A redirect can destroy the execution context for one polling tick.
            pass
        try:
            # Do not treat a transient SSO callback URL as a completed login.
            # Myntra can briefly expose partners.myntrainfo.com while the app
            # is still booting, or immediately redirect back to the login form.
            # Only leave this loop once the actual Scan & Pack control is visible.
            login_page.wait_for_timeout(700)
        except PlaywrightError:
            time.sleep(0.7)

    try:
        last_url = login_page.url
    except PlaywrightError:
        last_url = url or "closed page"
    raise RuntimeError(f"Myntra Scan & Pack page did not become ready (current URL: {last_url})")


def run(args: argparse.Namespace) -> None:
    load_app_environment(args.env_file)
    config_path = Path(args.config_file)
    runtime_config = load_runtime_config(config_path, args.consignment)
    if not os.getenv("CONSIGMENT_APP_DATABASE_URL"):
        runtime_config = first_run_setup(config_path, runtime_config, args.consignment)
    code = (args.consignment or runtime_config.get("consignment") or "").strip()
    if not code:
        code = input("Consignment ID: ").strip()
    if not code:
        raise RuntimeError("Consignment ID is required")
    state_path = Path(args.state_file)
    state = read_state(state_path)
    normalized_code = code.lower()
    plan = read_plan(code)
    boxes = plan["boxes"][: args.max_boxes] if args.max_boxes else plan["boxes"]
    units = sum(box["totalUnits"] for box in boxes)
    if args.plan_only:
        print(f"PLAN OK: {code} | {len(boxes)} cartons | {units} units")
        for box in boxes:
            print(f"  Carton {box['boxNo']}: {box['totalUnits']} units, {len(box['items'])} barcodes")
        return
    emit(args, f"Consignment: {code}")
    emit(args, f"Marketplace: {plan['consignment']['marketplace']} | Warehouse: {plan['consignment']['warehouse']}")
    emit(args, f"Cartons: {len(boxes)} | Units: {units}")
    for box in boxes:
        emit(args, f"  Carton {box['boxNo']}: {box['totalUnits']} units, {len(box['items'])} barcodes")
    if not args.yes and not getattr(args, "gui", False):
        answer = input("Type PACK to open Myntra and start this run: ").strip()
        if answer != "PACK":
            print("Cancelled before opening the portal.")
            return

    email = os.getenv("MYNTRA_PARTNER_EMAIL") or None
    password = os.getenv("MYNTRA_PARTNER_PASSWORD") or None
    auto_login = args.auto_login or bool(runtime_config.get("auto_login"))
    if auto_login and not email:
        email = input("Myntra partner email: ").strip()
    if auto_login and not password:
        password = getpass.getpass("Myntra partner password: ")

    # Progress is retained for recovery and diagnostics only. It never locks a
    # consignment or prevents any shipment from being started again.
    tracking_run = not bool(args.portal_only)
    tracking_full_run = tracking_run and not bool(args.max_boxes)
    if tracking_run:
        previous_active = (
            dict(state.get("active") or {})
            if active_code(state) == normalized_code
            else {}
        )
        active = {
            **previous_active,
            "code": normalized_code,
            "startedAt": previous_active.get("startedAt") or _now_iso(),
            "updatedAt": _now_iso(),
            "cartonsTotal": len(plan["boxes"]),
            "unitsTotal": plan["totalUnits"],
            "mode": "full" if tracking_full_run else "test",
            "cartonsClosed": number(previous_active.get("cartonsClosed")),
            "currentCarton": previous_active.get("currentCarton"),
            "currentCartonIndex": number(previous_active.get("currentCartonIndex")),
            "lastEvent": "run started",
        }
        state["active"] = active
        write_state(state_path, state)
        emit(args, f"Saved run progress: {code}")

    with sync_playwright() as playwright:
        browser, context, page = launch_human_login_browser(
            playwright,
            log_callback=getattr(args, "log_callback", None),
        )
        success = False

        def portal_click(text: str, exact: bool = True) -> None:
            """Click a control and recover if SSO swapped the active page."""
            nonlocal page
            try:
                click_text(page, text, exact=exact)
            except PlaywrightError:
                recovered = live_portal_page(context, page)
                if recovered is None:
                    raise
                page = recovered
                click_text(page, text, exact=exact)

        try:
            page = wait_for_portal(
                context,
                page,
                auto_login,
                email,
                password,
                gui=getattr(args, "gui", False),
                log_callback=getattr(args, "log_callback", None),
            )
            page = ready_portal_page(context, page) or page
            if getattr(args, "portal_only", False):
                emit(args, "LOGIN VERIFIED: Myntra Scan & Pack is ready; packing was not started.")
                return
            emit(args, "Opening Myntra Start Packing form")
            portal_click("START PACKING", exact=False)
            page = live_portal_page(context, page) or page
            choose_dropdown(page, "SELECT PACKING OPTION", "PO")
            choose_dropdown(page, "SELECT BARCODE", code)
            choose_dropdown(page, "MODE OF TRANSPORT", "Road")
            portal_click("START NEW", exact=True)
            page.wait_for_timeout(800)
            for index, box in enumerate(boxes, 1):
                if tracking_run:
                    active = dict(state.get("active") or {})
                    active.update({
                        "code": normalized_code,
                        "updatedAt": _now_iso(),
                        "currentCarton": box["boxNo"],
                        "currentCartonIndex": index,
                        "currentItemIndex": 0,
                        "currentItemScanned": 0,
                        "lastEvent": f"opening carton {box['boxNo']}",
                    })
                    state["active"] = active
                    write_state(state_path, state)
                portal_click("OPEN NEW CARTON", exact=False)
                emit(args, f"Opened carton {box['boxNo']} ({index}/{len(boxes)})")
                item_position = 0
                for item in box["items"]:
                    for _item_copy in range(item["qty"]):
                        scanner = page.locator("#scanner-input")
                        scanner.click()
                        scanner.fill(item["barcode"])
                        scanner.press("Enter")
                        page.wait_for_timeout(max(100, int(os.getenv("MYNTRA_PARTNER_SCAN_DELAY_MS", "250"))))
                        confirm_dialogs(page)
                        item_position += 1
                        if tracking_run:
                            active = dict(state.get("active") or {})
                            active.update({
                                "updatedAt": _now_iso(),
                                "currentItemIndex": item_position,
                                "currentItemScanned": item_position,
                                "lastEvent": f"confirmed item {item_position}/{box['totalUnits']} in carton {box['boxNo']}",
                            })
                            state["active"] = active
                            write_state(state_path, state)
                actual = portal_count(page)
                if actual is not None and actual != box["totalUnits"]:
                    raise RuntimeError(f"Carton {box['boxNo']} count mismatch: portal {actual}, expected {box['totalUnits']}")
                portal_click("CLOSE CARTON", exact=False)
                emit(args, f"Closed carton {box['boxNo']}: {box['totalUnits']} units")
                if tracking_run:
                    active = dict(state.get("active") or {})
                    active.update({
                        "updatedAt": _now_iso(),
                        "cartonsClosed": index,
                        "currentCarton": None,
                        "currentCartonIndex": index,
                        "currentItemIndex": 0,
                        "currentItemScanned": 0,
                        "lastEvent": f"closed carton {box['boxNo']}",
                    })
                    state["active"] = active
                    write_state(state_path, state)
                page.wait_for_timeout(500)
            success = len(boxes) == len(plan["boxes"])
            if success:
                state["active"] = None
                write_state(state_path, state)
                emit(args, f"COMPLETED: {code} ({units} units)")
            elif tracking_run and args.max_boxes:
                state["active"] = None
                write_state(state_path, state)
                emit(args, f"TEST COMPLETED: {code} ({units} units); this shipment remains runnable")
            else:
                emit(args, "PARTIAL RUN FINISHED; this shipment remains runnable.")
        except Exception:
            try:
                page.screenshot(path=str(Path(args.screenshot_dir) / f"{code}-failure.png"), full_page=True)
            except Exception:
                pass
            print("The browser was left open for inspection.", file=sys.stderr)
            raise
        finally:
            if getattr(args, "gui", False) and success:
                close_human_login_browser(browser, context)
            elif args.close_on_success and success:
                close_human_login_browser(browser, context)
            elif getattr(args, "portal_only", False):
                close_human_login_browser(browser, context)
            elif not getattr(args, "gui", False):
                input("Press Enter to close the local Myntra browser: ")
                close_human_login_browser(browser, context)


def run_gui(args: argparse.Namespace) -> None:
    """Windows app view for selecting any Myntra SOR consignment scenario."""
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError as exc:
        raise RuntimeError("Tkinter is required for the app view; use the Python command-line mode instead") from exc

    load_app_environment(args.env_file)
    root = tk.Tk()
    root.title("Myntra SOR Scan & Pack")
    root.geometry("1320x740")
    root.minsize(1080, 600)
    config_path = Path(args.config_file)
    try:
        runtime_config = load_runtime_config(config_path, None)
    except Exception as exc:
        runtime_config = {}
        messagebox.showerror("Configuration error", str(exc), parent=root)

    status_var = tk.StringVar(value="Ready")
    scenario_filter_var = tk.StringVar(value="All scenarios")
    result_summary_var = tk.StringVar(value="No orders loaded")
    auto_login_var = tk.BooleanVar(value=bool(runtime_config.get("auto_login")))
    db_var = tk.StringVar(value=str(runtime_config.get("consignment_database_url") or os.getenv("CONSIGMENT_APP_DATABASE_URL") or ""))
    email_var = tk.StringVar(value=str(runtime_config.get("myntra_email") or ""))
    password_var = tk.StringVar(value=str(runtime_config.get("myntra_password") or ""))
    rows: list[dict[str, Any]] = []

    header = ttk.Frame(root, padding=(16, 12))
    header.pack(fill="x")
    ttk.Label(header, text="Myntra SOR Scan & Pack", font=("Segoe UI", 18, "bold")).pack(side="left")
    ttk.Label(header, textvariable=status_var).pack(side="right")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    packing_tab = ttk.Frame(notebook, padding=12)
    settings_tab = ttk.Frame(notebook, padding=12)
    activity_tab = ttk.Frame(notebook, padding=12)
    notebook.add(packing_tab, text="Myntra SOR orders")
    notebook.add(settings_tab, text="Settings")
    notebook.add(activity_tab, text="Activity")

    log_box = tk.Text(activity_tab, height=24, state="disabled", wrap="word", bg="#101827", fg="#d7e3f4")
    log_box.pack(fill="both", expand=True)

    def log(message: str) -> None:
        def append() -> None:
            log_box.configure(state="normal")
            log_box.insert("end", message + "\n")
            log_box.see("end")
            log_box.configure(state="disabled")
            status_var.set(message)
        root.after(0, append)

    filters = ttk.Frame(packing_tab)
    filters.pack(fill="x", pady=(0, 8))
    ttk.Label(filters, text="Scenario:").pack(side="left")
    scenario_filter = ttk.Combobox(
        filters, textvariable=scenario_filter_var, values=("All scenarios",),
        state="readonly", width=28,
    )
    scenario_filter.pack(side="left", padx=(6, 12))
    ttk.Label(filters, textvariable=result_summary_var).pack(side="right")

    columns = ("code", "shipment", "warehouse", "scenario", "db_status", "packed")
    tree_frame = ttk.Frame(packing_tab)
    tree_frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse", height=18)
    headings = {
        "code": "Consignment", "shipment": "Shipment / order", "warehouse": "Warehouse",
        "scenario": "Scenario from DB", "db_status": "DB status", "packed": "Packed qty",
    }
    widths = {
        "code": 225, "shipment": 125, "warehouse": 190, "scenario": 190,
        "db_status": 135, "packed": 85,
    }
    for column in columns:
        tree.heading(column, text=headings[column])
        tree.column(column, width=widths[column], anchor="w")
    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    def render_rows(*_args) -> None:
        tree.delete(*tree.get_children())
        selected_scenario = scenario_filter_var.get()
        displayed = [
            row for row in rows
            if selected_scenario == "All scenarios" or row["scenario"] == selected_scenario
        ]
        for row in displayed:
            database_status = " / ".join(
                str(value) for value in (row.get("status"), row.get("shipmentStatus")) if value
            )
            tree.insert(
                "", "end", iid=row["code"],
                values=(
                    row["code"], row.get("shipment", ""), row["warehouse"], row["scenario"],
                    database_status, row["packedQty"] or "",
                ),
            )
        result_summary_var.set(f"{len(displayed)} shown · {len(rows)} total Myntra SOR orders")

    scenario_filter.bind("<<ComboboxSelected>>", render_rows)

    def refresh() -> None:
        nonlocal rows
        try:
            rows = read_eligible_consignments(state_path=Path(args.state_file))
            scenarios = sorted({row["scenario"] for row in rows})
            filter_values = ("All scenarios", *scenarios)
            scenario_filter.configure(values=filter_values)
            if scenario_filter_var.get() not in filter_values:
                scenario_filter_var.set("All scenarios")
            render_rows()
            scenario_counts: dict[str, int] = {}
            for row in rows:
                scenario_counts[row["scenario"]] = scenario_counts.get(row["scenario"], 0) + 1
            scenario_summary = ", ".join(
                f"{scenario}: {count}" for scenario, count in sorted(scenario_counts.items())
            )
            status_var.set(f"{len(rows)} SOR order(s) · all runnable")
            log(f"Loaded all {len(rows)} runnable Myntra SOR order(s) from Consignment DB ({scenario_summary or 'no scenarios'})")
        except Exception as exc:
            status_var.set("Database unavailable")
            log(f"ERROR: {exc}")
            messagebox.showerror("Could not load consignments", str(exc), parent=root)

    def selected() -> str | None:
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Select an order", "Choose one Myntra SOR consignment first.", parent=root)
            return None
        return str(selection[0])

    def validate() -> None:
        code = selected()
        if not code:
            return
        try:
            plan = read_plan(code)
            messagebox.showinfo("Plan validated", f"{code}\n\n{len(plan['boxes'])} cartons\n{plan['totalUnits']} units\nAll barcode quantities are valid.", parent=root)
            log(f"Validated {code}: {len(plan['boxes'])} cartons / {plan['totalUnits']} units")
        except Exception as exc:
            log(f"ERROR validating {code}: {exc}")
            messagebox.showerror("Plan validation failed", str(exc), parent=root)

    def start(mode: str) -> None:
        code = selected()
        if not code:
            return
        try:
            plan = read_plan(code)
        except Exception as exc:
            messagebox.showerror("Plan validation failed", str(exc), parent=root)
            return
        worker_args = argparse.Namespace(
            consignment=code, max_boxes=1 if mode == "test" else None, auto_login=auto_login_var.get(),
            yes=True, force=False, close_on_success=True, plan_only=False, portal_only=False, env_file=None,
            config_file=str(config_path), state_file=str(Path(args.state_file)), screenshot_dir="downloads/myntra-manual",
            gui=True, log_callback=log,
        )
        log(f"Starting {'one-carton test' if mode == 'test' else 'full'} for {code} ({len(plan['boxes'])} cartons / {plan['totalUnits']} units)")
        notebook.select(activity_tab)
        threading.Thread(target=lambda: run_background(worker_args), daemon=True).start()

    def run_background(worker_args: argparse.Namespace) -> None:
        try:
            run(worker_args)
            root.after(0, refresh)
        except Exception as exc:
            log(f"ERROR: {exc}")

    def save_settings() -> None:
        db = db_var.get().strip()
        if not db:
            messagebox.showerror("Database URL required", "Enter the Consignment CockroachDB URL once. It will be encrypted for this Windows user.", parent=root)
            return
        new_config = dict(runtime_config)
        new_config.update({
            "consignment_database_url": db,
            "myntra_email": email_var.get().strip(),
            "myntra_password": password_var.get(),
            "auto_login": bool(auto_login_var.get()),
        })
        try:
            save_runtime_config(config_path, new_config)
            os.environ["CONSIGMENT_APP_DATABASE_URL"] = db
            if new_config.get("myntra_email"):
                os.environ["MYNTRA_PARTNER_EMAIL"] = str(new_config["myntra_email"])
            else:
                os.environ.pop("MYNTRA_PARTNER_EMAIL", None)
            if new_config.get("myntra_password"):
                os.environ["MYNTRA_PARTNER_PASSWORD"] = str(new_config["myntra_password"])
            else:
                os.environ.pop("MYNTRA_PARTNER_PASSWORD", None)
            load_runtime_config(config_path, None)
            runtime_config.update(new_config)
            status_var.set("Encrypted settings saved")
            log("Encrypted database and portal settings saved")
            refresh()
            notebook.select(packing_tab)
        except Exception as exc:
            messagebox.showerror("Could not save settings", str(exc), parent=root)

    ttk.Label(settings_tab, text="Consignment database URL (saved encrypted with Windows DPAPI)").pack(anchor="w")
    ttk.Entry(settings_tab, textvariable=db_var, width=110, show="•").pack(fill="x", pady=(4, 12))
    ttk.Label(settings_tab, text="Myntra partner email (saved encrypted)").pack(anchor="w")
    ttk.Entry(settings_tab, textvariable=email_var, width=70).pack(fill="x", pady=(4, 12))
    ttk.Label(settings_tab, text="Myntra partner password (saved encrypted)").pack(anchor="w")
    ttk.Entry(settings_tab, textvariable=password_var, width=70, show="•").pack(fill="x", pady=(4, 12))
    ttk.Checkbutton(
        settings_tab,
        text="Use saved credentials for automatic sign-in",
        variable=auto_login_var,
    ).pack(anchor="w", pady=(0, 12))
    ttk.Button(settings_tab, text="Save encrypted settings", command=save_settings).pack(anchor="w")
    ttk.Label(
        settings_tab,
        text="Myntra opens in a dedicated visible Chrome profile. If automatic sign-in is disabled or Myntra asks for verification, complete it in Chrome.",
        foreground="#555",
    ).pack(anchor="w", pady=(16, 0))
    ttk.Label(settings_tab, text="The database URL and credentials are never written in plaintext to the config file.", foreground="#555").pack(anchor="w", pady=(6, 0))

    controls = ttk.Frame(packing_tab)
    controls.pack(fill="x", pady=(10, 0))
    ttk.Button(controls, text="Refresh", command=refresh).pack(side="left")
    ttk.Button(controls, text="Validate selected", command=validate).pack(side="left", padx=8)
    ttk.Button(controls, text="Test first carton", command=lambda: start("test")).pack(side="right")
    ttk.Button(controls, text="Start full Scan & Pack", command=lambda: start("full")).pack(side="right", padx=8)
    ttk.Label(
        packing_tab,
        text="Every Myntra SOR shipment can be started again at any time; local run history never blocks Scan & Pack.",
        foreground="#555",
    ).pack(anchor="w", pady=(8, 0))
    tree.bind("<Double-1>", lambda _event: start("full"))
    if os.getenv("CONSIGMENT_APP_DATABASE_URL"):
        root.after(100, refresh)
    else:
        notebook.select(settings_tab)
        status_var.set("Setup required: save the encrypted database URL")
        root.after(150, lambda: log("Enter the Consignment database URL once in Settings; it will be encrypted locally."))
    root.mainloop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manually pack one Myntra consignment from the local network")
    parser.add_argument("--consignment", help="Exact consignment code; defaults to the config file")
    parser.add_argument("--max-boxes", type=int, help="Test only the first 1 or 2 cartons; never writes completion")
    parser.add_argument("--auto-login", action="store_true", help="Deprecated compatibility option; sign-in is always manual")
    parser.add_argument("--yes", action="store_true", help="Skip the final PACK confirmation")
    parser.add_argument("--force", action="store_true", help="Deprecated compatibility option; repeat runs are always allowed")
    parser.add_argument("--close-on-success", action="store_true", help="Close Chrome after all cartons finish")
    parser.add_argument("--plan-only", action="store_true", help="Read and validate the plan without opening Chrome")
    parser.add_argument("--portal-only", action="store_true", help="Verify Myntra SSO and Scan & Pack readiness without packing")
    parser.add_argument("--env-file", help="Optional dotenv file; defaults to project .env")
    parser.add_argument("--config-file", default=str(DEFAULT_CONFIG), help="Config file beside the executable")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE), help="Local completion marker JSON path")
    parser.add_argument("--screenshot-dir", default="downloads/myntra-manual", help="Failure screenshot directory")
    parser.add_argument("--app", action="store_true", help="Open the app-style consignment selector")
    return parser.parse_args()


if __name__ == "__main__":
    parsed_args = parse_args()
    try:
        cli_requested = any((parsed_args.consignment, parsed_args.max_boxes, parsed_args.plan_only, parsed_args.portal_only, parsed_args.yes, parsed_args.force, parsed_args.auto_login, parsed_args.env_file))
        if parsed_args.app or not cli_requested:
            run_gui(parsed_args)
        else:
            run(parsed_args)
    except KeyboardInterrupt:
        raise SystemExit("Interrupted; no completion marker was written.")
    except Exception as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
