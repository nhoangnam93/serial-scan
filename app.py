#!/usr/bin/env python3
"""
NAB Serial Scanner v3.0 – Multi-User Real-Time
WebSocket-powered barcode scanner with live dashboard.
Multiple users scan simultaneously; all see results in real time.
"""

import os
import csv
import json
import sqlite3
import socket
import ssl
import base64
import hashlib
import hmac
import logging
import platform
import re
import secrets
import shutil
import sys
import threading
import time
import webbrowser
import io
import tempfile
import uuid
from collections import deque
from datetime import datetime
from io import StringIO, BytesIO
from flask import Flask, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from src.vision import recognize_text_from_binary, infer_best_rotation_deg
from serial_parser import (
    extract_serial_from_text,
    is_likely_dell_service_tag,
    normalize_serial_candidate,
    normalize_serial_profile,
    is_likely_macbook_serial,
    is_valid_serial_candidate_for_profile,
)

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# --- PyObjC Apple Vision Setup ---
import Cocoa
import Vision

# Rate limiting for PIN attempts
auth_attempts = {} # ip -> {count, last_attempt}

def check_auth_rate_limit(ip):
    now = time.time()
    record = auth_attempts.get(ip, {"count": 0, "last_attempt": 0})
    if record["count"] >= 5 and (now - record["last_attempt"]) < 60:
        return False
    if (now - record["last_attempt"]) > 300:
        record["count"] = 0
    return True

def record_auth_failure(ip):
    now = time.time()
    record = auth_attempts.get(ip, {"count": 0, "last_attempt": 0})
    record["count"] += 1
    record["last_attempt"] = now
    auth_attempts[ip] = record

def record_auth_success(ip):
    auth_attempts.pop(ip, None)

def get_active_scanner_count():
    return sum(1 for state in client_ocr_state.values() if state.get("scanning"))


def allow_serial(serial, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    normalized = normalize_serial_candidate(serial or "", profile=profile)
    if not normalized:
        return False
    if profile == "dell":
        return is_likely_dell_service_tag(normalized) and is_valid_serial_candidate_for_profile(normalized, "dell")
    if not STRICT_MACBOOK_ONLY:
        return True
    return is_likely_macbook_serial(normalized) and is_valid_serial_candidate_for_profile(normalized, "apple")


def has_strong_serial_context(text, serial, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    if not text or not serial:
        return False
    up = str(text).upper()
    compact = re.sub(r"[^A-Z0-9]", "", up)
    target = re.sub(r"[^A-Z0-9]", "", str(serial).upper())
    if not target or target not in compact:
        return False
    if profile == "dell":
        return bool(re.search(r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG|ST\s*[:#-])\s*[A-Z0-9]{5,12}", up))
    return bool(re.search(r"(?:SERIAL\s*NO\.?|SERIAL|SERIA|S/N|SN)\s*[:#-]?\s*[A-Z0-9\s]{6,24}", up))


def has_label_marker(text, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    up = str(text or "").upper()
    if not up.strip():
        return False
    if profile == "dell":
        return bool(re.search(r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG|ST\s*[:#-])", up))
    return bool(re.search(r"(?:SERIAL\s*NO\.?|SERIAL|SERIA|S/N|SN)\s*[:#-]?", up))


def has_dell_marker_match(text, serial):
    up = str(text or "").upper()
    if not up or not serial:
        return False
    target = normalize_serial_candidate(serial, "dell")
    if len(target) != 7:
        return False
    patterns = [
        r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG|ST)\s*[:#-]\s*([A-Z0-9]{6,12})",
        r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG)\s+([A-Z0-9]{6,12})",
    ]
    for pat in patterns:
        for m in re.finditer(pat, up, re.IGNORECASE):
            cand = normalize_serial_candidate(m.group(1), "dell")
            if len(cand) > 7:
                cand = cand[:7]
            if cand == target:
                return True
    return False


def extract_serial_from_strong_context(text, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    up = str(text or "").upper()
    if not up:
        return ""
    if profile == "dell":
        m = re.search(r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG|ST)\s*[:#-]\s*([A-Z0-9]{6,12})", up, re.IGNORECASE)
        if not m:
            return ""
        cand = normalize_serial_candidate(m.group(1), "dell")
        if len(cand) > 7:
            cand = cand[:7]
        return cand if allow_serial(cand, "dell") else ""

    m = re.search(r"(?:SERIAL\s*NO\.?|SERIAL|SERIA|S/N|SN)\s*[:#-]?\s*([A-Z0-9\s]{8,20})", up, re.IGNORECASE)
    if not m:
        return ""
    tail = re.sub(r"[^A-Z0-9]", "", m.group(1))
    cand = normalize_serial_candidate(tail, "apple")
    return cand if allow_serial(cand, "apple") else ""


def get_sid_serial_profile(sid, incoming=None):
    incoming_profile = normalize_serial_profile(incoming) if incoming else ""
    if incoming_profile:
        return incoming_profile
    user_profile = normalize_serial_profile((connected_users.get(sid) or {}).get("serial_profile", DEFAULT_SERIAL_PROFILE))
    return user_profile or DEFAULT_SERIAL_PROFILE


def normalize_lane_name(name):
    lane = (name or "").strip()
    if not lane:
        return "General"
    lane = re.sub(r"\s+", " ", lane[:32]).strip()
    return lane or "General"


def lane_csv_filename(lane_name):
    lane = normalize_lane_name(lane_name)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", lane).strip("_")
    if not safe:
        safe = "General"
    return f"{safe}.csv"


def write_lane_csv_files(rows):
    os.makedirs(LANE_CSV_DIR, exist_ok=True)
    grouped = {}
    for row in rows:
        lane = normalize_lane_name(row.get("Lane", "General"))
        grouped.setdefault(lane, []).append(row)

    keep_files = {lane_csv_filename(lane) for lane in grouped.keys()}
    for filename in os.listdir(LANE_CSV_DIR):
        if not filename.endswith(".csv"):
            continue
        if filename not in keep_files:
            try:
                os.remove(os.path.join(LANE_CSV_DIR, filename))
            except OSError:
                pass

    for lane, lane_rows in grouped.items():
        lane_path = os.path.join(LANE_CSV_DIR, lane_csv_filename(lane))
        with open(lane_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)
            for r in lane_rows:
                writer.writerow([
                    r.get("Timestamp", ""),
                    r.get("Hostname", ""),
                    r.get("Serial Number", ""),
                    r.get("Scanned By", ""),
                    r.get("User", ""),
                    normalize_lane_name(r.get("Lane", lane)),
                ])


def sync_lane_state_from_rows(rows):
    counts = {}
    lanes_in_rows = set()
    for row in rows:
        lane = normalize_lane_name(row.get("Lane", "General"))
        lanes_in_rows.add(lane)
        counts[lane] = int(counts.get(lane, 0)) + 1

    for lane in lanes_in_rows:
        shared_lanes.setdefault(lane, [])

    for lane in list(shared_lanes.keys()):
        counts.setdefault(lane, 0)

    if "General" not in shared_lanes:
        shared_lanes["General"] = []
    counts.setdefault("General", 0)

    lane_scanned_counts.clear()
    lane_scanned_counts.update(counts)


def ensure_lane(lane_name):
    lane = normalize_lane_name(lane_name)
    if lane not in shared_lanes:
        shared_lanes[lane] = []
    if lane not in lane_scanned_counts:
        lane_scanned_counts[lane] = 0
    return lane


def lanes_snapshot():
    output = []
    for lane_name in sorted(shared_lanes.keys()):
        items = shared_lanes[lane_name]
        current = items[-1] if items else None
        output.append({
            "name": lane_name,
            "count": len(items),
            "scanned_count": int(lane_scanned_counts.get(lane_name, 0)),
            "current": {
                "id": current["id"],
                "serial": current["serial"],
                "user": current["user"],
                "created_at": current["created_at"],
                "updated_at": current["updated_at"],
            } if current else None,
            "items": [
                {
                    "id": q["id"],
                    "serial": q["serial"],
                    "user": q["user"],
                    "created_at": q["created_at"],
                    "updated_at": q["updated_at"],
                }
                for q in items[-12:]
            ],
        })
    return output


def broadcast_queue():
    payload = lanes_snapshot()
    for sid, user in list(connected_users.items()):
        if not user.get("verified"):
            continue
        socketio.emit("lanes_data", payload, to=sid)
        socketio.emit("queue_data", payload, to=sid)


def is_priority_scanner(state):
    if not state or not state.get("scanning"):
        return False
    started_at = state.get("started_scanning_at", 0.0)
    return started_at > 0 and (time.time() - started_at) <= OCR_PRIORITY_WINDOW_SEC


def get_priority_scanner_count():
    return sum(1 for state in client_ocr_state.values() if is_priority_scanner(state))


def get_recommended_ocr_interval_ms(extra_penalty=0):
    active = max(1, get_active_scanner_count())
    dynamic = OCR_BASE_INTERVAL_MS + (active - 1) * 140 + ocr_inflight * 220 + extra_penalty
    return max(OCR_BASE_INTERVAL_MS, min(OCR_MAX_INTERVAL_MS, dynamic))


def get_client_ocr_interval_ms(state, extra_penalty=0):
    delay = get_recommended_ocr_interval_ms(extra_penalty)
    if is_priority_scanner(state):
        delay -= OCR_PRIORITY_BONUS_MS
    return max(180, delay)


def emit_ocr_policy(sid, status="ready", next_delay_ms=None, accepted=None, source=None, ocr_confidence=None):
    state = client_ocr_state.get(sid)
    if next_delay_ms is None:
        next_delay_ms = get_client_ocr_interval_ms(state)
    payload = {
        "status": status,
        "next_delay_ms": int(next_delay_ms),
        "accepted": accepted if accepted is not None else status == "accepted",
        "active_scanners": get_active_scanner_count(),
        "priority_scanners": get_priority_scanner_count(),
        "inflight": ocr_inflight,
        "capacity": OCR_MAX_INFLIGHT,
    }
    if source:
        payload["source"] = source
    if ocr_confidence is not None:
        payload["ocr_confidence"] = round(float(ocr_confidence), 4)
    socketio.emit("ocr_policy", payload, to=sid)


def emit_ocr_success(
    sid,
    serial,
    source=None,
    next_delay_ms=None,
    ocr_confidence=None,
    serial_profile=None,
    ocr_rotation=None,
):
    state = client_ocr_state.get(sid)
    if next_delay_ms is None:
        next_delay_ms = get_client_ocr_interval_ms(state)
    payload = {
        "serial": serial,
        "next_delay_ms": int(next_delay_ms),
        "status": "accepted",
        "active_scanners": get_active_scanner_count(),
        "priority_scanners": get_priority_scanner_count(),
        "inflight": ocr_inflight,
        "capacity": OCR_MAX_INFLIGHT,
    }
    if source:
        payload["source"] = source
    if ocr_confidence is not None:
        payload["ocr_confidence"] = round(float(ocr_confidence), 4)
    if ocr_rotation is not None:
        try:
            payload["ocr_rotation"] = int(ocr_rotation) % 360
        except Exception:
            payload["ocr_rotation"] = 0
    profile = normalize_serial_profile(serial_profile or ((state or {}).get("serial_profile")) or DEFAULT_SERIAL_PROFILE)
    payload["serial_profile"] = profile
    socketio.emit("ocr_success", payload, to=sid)


def get_ocr_dashboard_snapshot():
    prune_stale_sessions()
    latencies = list(ocr_metrics["latency_samples"])
    confidences = list(ocr_metrics["confidence_samples"])
    avg_latency_ms = int(sum(latencies) / len(latencies)) if latencies else 0
    avg_confidence_pct = int((sum(confidences) / len(confidences)) * 100) if confidences else 0
    match_rate = int((ocr_metrics["matches"] / ocr_metrics["frames_accepted"]) * 100) if ocr_metrics["frames_accepted"] else 0
    return {
        "active_scanners": get_active_scanner_count(),
        "priority_scanners": get_priority_scanner_count(),
        "connected_users": len(connected_users),
        "inflight": ocr_inflight,
        "capacity": OCR_MAX_INFLIGHT,
        "recommended_delay_ms": get_recommended_ocr_interval_ms(),
        "avg_latency_ms": avg_latency_ms,
        "avg_confidence_pct": avg_confidence_pct,
        "min_confidence_pct": int(OCR_MIN_CONFIDENCE * 100),
        "frames_accepted": ocr_metrics["frames_accepted"],
        "matches": ocr_metrics["matches"],
        "match_rate": match_rate,
        "busy_rejects": ocr_metrics["busy_rejects"],
        "errors": ocr_metrics["errors"],
    }


def broadcast_ocr_dashboard():
    socketio.emit("ocr_dashboard", get_ocr_dashboard_snapshot())


def process_single_image_for_sid(sid, img_data, source="live_photo", serial_profile="apple"):
    state = client_ocr_state.get(sid)
    if state is None:
        emit_ocr_policy(sid, status="idle", accepted=False, next_delay_ms=get_recommended_ocr_interval_ms(250))
        return

    try:
        ocr_result = recognize_text_from_binary(img_data, serial_profile)
    except Exception as e:
        print(f"-> OCR Photo Crash for {sid}:", e)
        ocr_metrics["errors"] += 1
        emit_ocr_policy(
            sid,
            status="error",
            next_delay_ms=get_client_ocr_interval_ms(state, 450),
            accepted=False,
            source=source,
        )
        broadcast_ocr_dashboard()
        return

    text = (ocr_result or {}).get("text", "") if isinstance(ocr_result, dict) else (ocr_result or "")
    confidence = float((ocr_result or {}).get("confidence", 0.0)) if isinstance(ocr_result, dict) else 0.0
    serial_hint = normalize_serial_candidate((ocr_result or {}).get("serial_hint", ""), serial_profile) if isinstance(ocr_result, dict) else ""
    ocr_rotation = int((ocr_result or {}).get("rotation_deg", 0) or 0) if isinstance(ocr_result, dict) else 0
    if confidence > 0:
        ocr_metrics["confidence_samples"].append(confidence)

    if text and text.strip():
        print(f"-> OCR Photo Text from {sid}: '{text.strip()}'")
    parsed_serial = extract_serial_from_text(text or "", serial_profile)
    context_serial = extract_serial_from_strong_context(text or "", serial_profile)
    hint_serial = serial_hint if allow_serial(serial_hint, serial_profile) else ""
    parsed_valid = parsed_serial if allow_serial(parsed_serial, serial_profile) else ""
    context_valid = context_serial if allow_serial(context_serial, serial_profile) else ""
    if serial_profile == "apple":
        possible_serial = parsed_valid or hint_serial or context_valid
    else:
        possible_serial = hint_serial or parsed_valid or context_valid
    has_marker = has_label_marker(text or "", serial_profile)
    dell_marker_match = has_dell_marker_match(text or "", possible_serial) if serial_profile == "dell" else False
    context_strong = has_strong_serial_context(text or "", possible_serial, serial_profile)
    required_conf = OCR_ACCEPT_CONTEXT_MIN_CONFIDENCE if context_strong else OCR_ACCEPT_VALID_MIN_CONFIDENCE
    if serial_profile == "dell":
        required_conf = max(required_conf, 0.62 if dell_marker_match else 0.86)
    # Label-only gate for photo flow: require marker, unless OCR is very strong on direct serial.
    if not has_marker and not (
        possible_serial
        and allow_serial(possible_serial, serial_profile)
        and confidence >= max(0.9, OCR_ACCEPT_VALID_MIN_CONFIDENCE)
    ):
        ocr_metrics["no_match"] += 1
        emit_ocr_policy(
            sid,
            status="no_match",
            next_delay_ms=get_client_ocr_interval_ms(state, 120),
            accepted=True,
            source=source,
            ocr_confidence=confidence,
        )
        broadcast_ocr_dashboard()
        return
    if (
        possible_serial
        and allow_serial(possible_serial, serial_profile)
        and confidence >= required_conf
    ):
        if confidence < OCR_POPUP_MIN_CONFIDENCE:
            emit_ocr_policy(
                sid,
                status="low_confidence",
                next_delay_ms=get_client_ocr_interval_ms(state, 220),
                accepted=False,
                source=source,
                ocr_confidence=confidence,
            )
            broadcast_ocr_dashboard()
            return
        preview_rotation = int(ocr_rotation or 0) % 360
        if preview_rotation == 0:
            preview_rotation = infer_best_rotation_deg(img_data, serial_profile)
        ocr_metrics["matches"] += 1
        emit_ocr_success(
            sid,
            possible_serial,
            source=source,
            ocr_confidence=confidence,
            serial_profile=serial_profile,
            ocr_rotation=preview_rotation,
        )
        broadcast_ocr_dashboard()
        return

    if text and confidence <= OCR_MIN_CONFIDENCE:
        emit_ocr_policy(
            sid,
            status="low_confidence",
            next_delay_ms=get_client_ocr_interval_ms(state, 220),
            accepted=False,
            source=source,
            ocr_confidence=confidence,
        )
        broadcast_ocr_dashboard()
        return

    if text and text.strip():
        ocr_metrics["no_match"] += 1
        status = "no_match"
    else:
        ocr_metrics["no_text"] += 1
        status = "no_text"

    emit_ocr_policy(
        sid,
        status=status,
        next_delay_ms=get_client_ocr_interval_ms(state),
        accepted=True,
        source=source,
        ocr_confidence=confidence,
    )
    broadcast_ocr_dashboard()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE_DIR, ".scanner_secret")


def load_or_create_secret_key():
    from_env = str(os.environ.get("SECRET_KEY") or "").strip()
    if from_env:
        return from_env
    try:
        if os.path.isfile(SECRET_FILE):
            with open(SECRET_FILE, "r") as f:
                value = (f.read() or "").strip()
            if len(value) >= 32:
                return value
    except Exception:
        pass
    value = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, "w") as f:
            f.write(value)
        os.chmod(SECRET_FILE, 0o600)
    except Exception:
        pass
    return value


app = Flask(__name__)
app.config["SECRET_KEY"] = load_or_create_secret_key()
socketio = SocketIO(app, async_mode="gevent")

CSV_FILE = os.path.join(BASE_DIR, "serial_numbers.csv")
LANE_CSV_DIR = os.path.join(BASE_DIR, "lane_csv")
CHECK_FILE = os.path.join(BASE_DIR, "check.csv")
CSV_HEADERS = ["Timestamp", "Hostname", "Serial Number", "Scanned By", "User", "Lane"]
CROPS_DIR = os.path.join(BASE_DIR, "cropped_scans")
CROPS_MANIFEST_FILE = os.path.join(BASE_DIR, "cropped_manifest.csv")
CROPS_MANIFEST_HEADERS = ["Timestamp", "Serial", "Confidence", "User", "Method", "File", "LatestFile"]
OCR_MAX_INFLIGHT = max(2, min(4, (os.cpu_count() or 4) // 2))
OCR_BASE_INTERVAL_MS = 450
OCR_MAX_INTERVAL_MS = 1800
OCR_PRIORITY_WINDOW_SEC = 8
OCR_PRIORITY_BONUS_MS = 220
OCR_MIN_CONFIDENCE = float(os.environ.get("OCR_MIN_CONFIDENCE", "0.92"))
OCR_ACCEPT_VALID_MIN_CONFIDENCE = float(os.environ.get("OCR_ACCEPT_VALID_MIN_CONFIDENCE", "0.82"))
OCR_ACCEPT_CONTEXT_MIN_CONFIDENCE = float(os.environ.get("OCR_ACCEPT_CONTEXT_MIN_CONFIDENCE", "0.50"))
OCR_POPUP_MIN_CONFIDENCE = float(os.environ.get("OCR_POPUP_MIN_CONFIDENCE", "1.0"))
OCR_MATCH_CONFIRM_STREAK = max(1, int(os.environ.get("OCR_MATCH_CONFIRM_STREAK", "2")))
OCR_MATCH_CONFIRM_STREAK_DELL = max(1, int(os.environ.get("OCR_MATCH_CONFIRM_STREAK_DELL", "1")))
OCR_MATCH_CONFIRM_WINDOW_SEC = float(os.environ.get("OCR_MATCH_CONFIRM_WINDOW_SEC", "2.0"))
STRICT_MACBOOK_ONLY = os.environ.get("STRICT_MACBOOK_ONLY", "1").lower() in {"1", "true", "yes", "on"}
DEFAULT_SERIAL_PROFILE = normalize_serial_profile(os.environ.get("DEFAULT_SERIAL_PROFILE", "apple"))
_ENV_JOIN_PIN = str(os.environ.get("JOIN_PIN", "")).strip()
JOIN_PIN = _ENV_JOIN_PIN if _ENV_JOIN_PIN else "2026"
JOIN_PIN_DEFAULTED = not bool(_ENV_JOIN_PIN)
JOIN_PIN_HASH = os.environ.get("JOIN_PIN_HASH", "").strip()
USERS_FILE = os.path.join(BASE_DIR, "users.json")
DB_FILE = os.path.join(BASE_DIR, "scanner.db")
user_registry = {}  # client_id -> {name, pin_hash}
MAX_OCR_IMAGE_DATA_URL_CHARS = int(os.environ.get("MAX_OCR_IMAGE_DATA_URL_CHARS", "7000000"))
MAX_CROP_BYTES = int(os.environ.get("MAX_CROP_BYTES", "6000000"))
PIN_MIN_LEN = int(os.environ.get("PIN_MIN_LEN", "4"))
PIN_MAX_LEN = int(os.environ.get("PIN_MAX_LEN", "16"))
PIN_HASH_PREFIX = "scrypt$"
DATA_FILE_MODE = 0o600
APP_BUILD_ID = datetime.now().strftime("%Y%m%d%H%M%S")
SESSION_TOKEN_TTL_SECONDS = int(os.environ.get("SESSION_TOKEN_TTL_SECONDS", "1209600"))
DEFAULT_USER_SETTINGS = {
    "active_function": "inventory",
    "serial_profile": DEFAULT_SERIAL_PROFILE,
    "camera_pref": "environment",
    "camera_tuning_profile": "auto",
    "camera_tuning_overrides": {},
    "autosave_pref": "1",
    "auto_scan_start": "1",
    "selected_box_id": "",
}
ALLOWED_FUNCTIONS = {"inventory", "box", "import"}

# Track connected users: sid -> {name, ip, connected_at}
connected_users = {}
client_session_index = {}
ocr_inflight = 0
client_ocr_state = {}
ocr_metrics = {
    "frames_accepted": 0,
    "matches": 0,
    "no_text": 0,
    "no_match": 0,
    "busy_rejects": 0,
    "empty_frames": 0,
    "errors": 0,
    "latency_samples": deque(maxlen=50),
    "confidence_samples": deque(maxlen=80),
}
shared_lanes = {"General": []}
lane_scanned_counts = {"General": 0}
lane_next_id = 1
check_serials_cache = set()
check_serials_cache_raw = set()
check_serials_cache_by_profile = {"apple": set(), "dell": set()}
check_serials_mtime = None
SESSION_STALE_SECONDS = 90
BOXES_FILE = os.path.join(BASE_DIR, "boxes.json")
BCK_DIR = os.path.join(BASE_DIR, "backups")
BCK_MIN_INTERVAL_SEC = int(os.environ.get("BACKUP_MIN_INTERVAL_SEC", "900") or 900)
BCK_RETENTION = int(os.environ.get("BACKUP_RETENTION", "24") or 24)
SCAN_IDEMPOTENCY_TTL_SEC = float(os.environ.get("SCAN_IDEMPOTENCY_TTL_SEC", "25") or 25)
box_registry = {}  # box_id -> {name, target: [], scanned: [], user, last_active}
box_live_presence = {}  # box_id -> {sid -> member}
sid_box_membership = {}  # sid -> box_id
data_lock = threading.Lock()
backup_lock = threading.Lock()
idempotency_lock = threading.Lock()
recent_scan_idempotency = {}  # key -> expire_ts
last_backup_at = 0.0


def db_connect():
    conn = sqlite3.connect(DB_FILE, timeout=7.5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_database():
    os.makedirs(BASE_DIR, exist_ok=True)
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    client_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    pin_hash TEXT NOT NULL,
                    session_version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                )
                """
            )
            # Backward-compatible migration for older DBs.
            cols = conn.execute("PRAGMA table_info(users)").fetchall()
            col_names = {str(row["name"]) for row in cols}
            if "session_version" not in col_names:
                conn.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_settings (
                    client_id TEXT PRIMARY KEY,
                    settings_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(client_id) REFERENCES users(client_id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS boxes (
                    box_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()
    secure_chmod(DB_FILE)


def sanitize_user_settings(raw):
    incoming = raw if isinstance(raw, dict) else {}
    cleaned = dict(DEFAULT_USER_SETTINGS)
    mode = str(incoming.get("active_function", cleaned["active_function"])).strip().lower()
    cleaned["active_function"] = mode if mode in ALLOWED_FUNCTIONS else DEFAULT_USER_SETTINGS["active_function"]
    cleaned["serial_profile"] = normalize_serial_profile(incoming.get("serial_profile", cleaned["serial_profile"]))
    camera_pref = str(incoming.get("camera_pref", cleaned["camera_pref"])).strip().lower()
    if camera_pref in {"environment", "user"}:
        cleaned["camera_pref"] = camera_pref
    elif re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", camera_pref):
        cleaned["camera_pref"] = camera_pref
    else:
        cleaned["camera_pref"] = DEFAULT_USER_SETTINGS["camera_pref"]
    tuning_profile = str(incoming.get("camera_tuning_profile", cleaned.get("camera_tuning_profile", "auto"))).strip().lower()
    cleaned["camera_tuning_profile"] = tuning_profile if tuning_profile in {"auto", "iphone", "android", "desktop", "aggressive"} else "auto"
    overrides = incoming.get("camera_tuning_overrides", {}) if isinstance(incoming, dict) else {}
    if not isinstance(overrides, dict):
        overrides = {}
    clean_overrides = {}
    try:
        if "minLight" in overrides:
            clean_overrides["minLight"] = max(28.0, min(72.0, float(overrides.get("minLight"))))
        if "minEdge" in overrides:
            clean_overrides["minEdge"] = max(0.020, min(0.090, float(overrides.get("minEdge"))))
        if "minVariance" in overrides:
            clean_overrides["minVariance"] = max(90.0, min(360.0, float(overrides.get("minVariance"))))
        if "centerY" in overrides:
            clean_overrides["centerY"] = max(0.48, min(0.66, float(overrides.get("centerY"))))
        if "heightRatio" in overrides:
            clean_overrides["heightRatio"] = max(0.22, min(0.38, float(overrides.get("heightRatio"))))
        if "widthRatio" in overrides:
            clean_overrides["widthRatio"] = max(0.86, min(0.99, float(overrides.get("widthRatio"))))
    except Exception:
        clean_overrides = {}
    cleaned["camera_tuning_overrides"] = clean_overrides
    autosave_pref = str(incoming.get("autosave_pref", cleaned["autosave_pref"])).strip()
    cleaned["autosave_pref"] = "0" if autosave_pref == "0" else "1"
    auto_scan_start = str(incoming.get("auto_scan_start", cleaned.get("auto_scan_start", "1"))).strip()
    cleaned["auto_scan_start"] = "0" if auto_scan_start == "0" else "1"
    selected_box_id = str(incoming.get("selected_box_id", cleaned["selected_box_id"])).strip()
    cleaned["selected_box_id"] = selected_box_id[:64] if re.fullmatch(r"[A-Za-z0-9._:-]{0,64}", selected_box_id) else ""
    return cleaned


def db_list_users():
    with db_connect() as conn:
        try:
            rows = conn.execute(
                "SELECT client_id, name, pin_hash, session_version FROM users ORDER BY updated_at DESC"
            ).fetchall()
        except sqlite3.OperationalError:
            rows = conn.execute(
                "SELECT client_id, name, pin_hash FROM users ORDER BY updated_at DESC"
            ).fetchall()
    return [
        {
            "client_id": r["client_id"],
            "name": r["name"],
            "pin_hash": r["pin_hash"],
            "session_version": int((r["session_version"] if "session_version" in r.keys() else 0) or 0),
        }
        for r in rows
    ]


def db_get_user(client_id):
    if not client_id:
        return None
    with db_connect() as conn:
        try:
            row = conn.execute(
                "SELECT client_id, name, pin_hash, session_version FROM users WHERE client_id = ?",
                (str(client_id),),
            ).fetchone()
        except sqlite3.OperationalError:
            row = conn.execute(
                "SELECT client_id, name, pin_hash FROM users WHERE client_id = ?",
                (str(client_id),),
            ).fetchone()
    if not row:
        return None
    return {
        "client_id": row["client_id"],
        "name": row["name"],
        "pin_hash": row["pin_hash"],
        "session_version": int((row["session_version"] if "session_version" in row.keys() else 0) or 0),
    }


def db_upsert_user(client_id, name, pin_hash):
    cid = str(client_id or "").strip()
    if not cid:
        return False
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO users (client_id, name, pin_hash, created_at, updated_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(client_id) DO UPDATE SET
                    name=excluded.name,
                    pin_hash=excluded.pin_hash,
                    updated_at=excluded.updated_at
                """,
                (cid, (name or "Anonymous")[:64], pin_hash, now, now, now),
            )
            conn.commit()
    return True


def db_update_user_name(client_id, name):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                "UPDATE users SET name = ?, updated_at = ? WHERE client_id = ?",
                ((name or "Anonymous")[:64], now, str(client_id or "")),
            )
            conn.commit()


def db_update_user_pin(client_id, pin_hash):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                "UPDATE users SET pin_hash = ?, session_version = session_version + 1, updated_at = ? WHERE client_id = ?",
                (pin_hash, now, str(client_id or "")),
            )
            conn.commit()


def db_bump_session_version(client_id):
    cid = str(client_id or "").strip()
    if not cid:
        return
    with data_lock:
        with db_connect() as conn:
            try:
                conn.execute(
                    "UPDATE users SET session_version = session_version + 1, updated_at = ? WHERE client_id = ?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cid),
                )
            except sqlite3.OperationalError:
                # Legacy DB without session_version; migration in init_database() will add it.
                conn.execute(
                    "UPDATE users SET updated_at = ? WHERE client_id = ?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cid),
                )
            conn.commit()


def db_touch_login(client_id):
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE client_id = ?",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), str(client_id or "")),
            )
            conn.commit()


def db_get_user_settings(client_id):
    cid = str(client_id or "").strip()
    if not cid:
        return dict(DEFAULT_USER_SETTINGS)
    with db_connect() as conn:
        row = conn.execute(
            "SELECT settings_json FROM user_settings WHERE client_id = ?",
            (cid,),
        ).fetchone()
    if not row:
        return dict(DEFAULT_USER_SETTINGS)
    try:
        payload = json.loads(row["settings_json"] or "{}")
    except Exception:
        payload = {}
    return sanitize_user_settings(payload)


def db_save_user_settings(client_id, incoming):
    cid = str(client_id or "").strip()
    if not cid:
        return dict(DEFAULT_USER_SETTINGS)
    current = db_get_user_settings(cid)
    merged = dict(current)
    merged.update(incoming if isinstance(incoming, dict) else {})
    clean = sanitize_user_settings(merged)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = json.dumps(clean, separators=(",", ":"), ensure_ascii=True)
    with data_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO user_settings (client_id, settings_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(client_id) DO UPDATE SET
                    settings_json=excluded.settings_json,
                    updated_at=excluded.updated_at
                """,
                (cid, payload, now),
            )
            conn.commit()
    return clean


def db_ensure_user_settings(client_id):
    cid = str(client_id or "").strip()
    if not cid:
        return dict(DEFAULT_USER_SETTINGS)
    with db_connect() as conn:
        row = conn.execute(
            "SELECT settings_json FROM user_settings WHERE client_id = ?",
            (cid,),
        ).fetchone()
    if row:
        try:
            return sanitize_user_settings(json.loads(row["settings_json"] or "{}"))
        except Exception:
            pass
    return db_save_user_settings(cid, DEFAULT_USER_SETTINGS)


def migrate_users_json_to_db():
    if not os.path.isfile(USERS_FILE):
        return
    try:
        with open(USERS_FILE, "r") as f:
            legacy = json.load(f) or {}
    except Exception:
        return
    if not isinstance(legacy, dict):
        return
    for cid, profile in legacy.items():
        if not isinstance(profile, dict):
            continue
        client_id = str(cid or "").strip()
        if not client_id:
            continue
        name = str(profile.get("name") or "Anonymous").strip() or "Anonymous"
        pin_hash = str(profile.get("pin_hash") or "").strip()
        plain_pin = str(profile.get("pin") or "").strip()
        if plain_pin and not pin_hash:
            pin_hash = hash_pin(plain_pin)
        if not pin_hash:
            continue
        existing = db_get_user(client_id)
        if existing and existing.get("pin_hash"):
            continue
        db_upsert_user(client_id, name, pin_hash)


def db_load_boxes():
    result = {}
    with db_connect() as conn:
        rows = conn.execute("SELECT box_id, payload_json FROM boxes").fetchall()
    for row in rows:
        box_id = str(row["box_id"] or "").strip()
        if not box_id:
            continue
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            result[box_id] = payload
    return result


def db_save_boxes(registry):
    data = registry if isinstance(registry, dict) else {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with data_lock:
        with db_connect() as conn:
            conn.execute("BEGIN")
            existing_ids = {r["box_id"] for r in conn.execute("SELECT box_id FROM boxes").fetchall()}
            incoming_ids = set()
            for box_id, payload in data.items():
                bid = str(box_id or "").strip()
                if not bid:
                    continue
                incoming_ids.add(bid)
                payload_json = json.dumps(payload if isinstance(payload, dict) else {}, separators=(",", ":"), ensure_ascii=True)
                conn.execute(
                    """
                    INSERT INTO boxes (box_id, payload_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(box_id) DO UPDATE SET
                        payload_json=excluded.payload_json,
                        updated_at=excluded.updated_at
                    """,
                    (bid, payload_json, now),
                )
            stale_ids = existing_ids - incoming_ids
            if stale_ids:
                conn.executemany("DELETE FROM boxes WHERE box_id = ?", [(sid,) for sid in stale_ids])
            conn.commit()


def migrate_boxes_json_to_db():
    with db_connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM boxes").fetchone()
    if row and int(row["cnt"] or 0) > 0:
        return
    if not os.path.isfile(BOXES_FILE):
        return
    try:
        with open(BOXES_FILE, "r") as f:
            payload = json.load(f) or {}
    except Exception:
        return
    if isinstance(payload, dict) and payload:
        db_save_boxes(payload)


def secure_chmod(path, mode=DATA_FILE_MODE):
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _backup_file_list():
    base_files = [
        CSV_FILE,
        CHECK_FILE,
        USERS_FILE,
        BOXES_FILE,
        CROPS_MANIFEST_FILE,
        DB_FILE,
        DB_FILE + "-wal",
        DB_FILE + "-shm",
    ]
    return [p for p in base_files if os.path.isfile(p)]


def run_backup(reason="periodic", force=False):
    global last_backup_at
    now = time.time()
    if not force and (now - last_backup_at) < max(60, BCK_MIN_INTERVAL_SEC):
        return None
    with backup_lock:
        now = time.time()
        if not force and (now - last_backup_at) < max(60, BCK_MIN_INTERVAL_SEC):
            return None
        os.makedirs(BCK_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r"[^a-z0-9_-]+", "_", str(reason).lower())[:24]
        folder = os.path.join(BCK_DIR, f"{stamp}_{slug or 'backup'}")
        os.makedirs(folder, exist_ok=True)
        copied = []
        for src in _backup_file_list():
            try:
                dst = os.path.join(folder, os.path.basename(src))
                shutil.copy2(src, dst)
                secure_chmod(dst)
                copied.append(os.path.basename(src))
            except Exception:
                continue
        meta_path = os.path.join(folder, "_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "reason": str(reason),
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "files": copied,
                },
                f,
                ensure_ascii=True,
                separators=(",", ":"),
            )
        secure_chmod(meta_path)
        try:
            dirs = [
                os.path.join(BCK_DIR, name)
                for name in os.listdir(BCK_DIR)
                if os.path.isdir(os.path.join(BCK_DIR, name))
            ]
            dirs.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            for stale in dirs[max(1, BCK_RETENTION):]:
                shutil.rmtree(stale, ignore_errors=True)
        except Exception:
            pass
        last_backup_at = now
        return folder


def _prune_idempotency_cache(now_ts=None):
    now_ts = now_ts or time.time()
    stale = [k for k, exp in recent_scan_idempotency.items() if exp <= now_ts]
    for k in stale:
        recent_scan_idempotency.pop(k, None)


def claim_scan_idempotency_key(key):
    token = str(key or "").strip()
    if not token:
        return True
    now_ts = time.time()
    with idempotency_lock:
        _prune_idempotency_cache(now_ts)
        if token in recent_scan_idempotency:
            return False
        recent_scan_idempotency[token] = now_ts + max(5.0, SCAN_IDEMPOTENCY_TTL_SEC)
    return True


def atomic_write_json(path, payload):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        secure_chmod(path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def is_reasonable_pin(pin):
    p = str(pin or "").strip()
    return PIN_MIN_LEN <= len(p) <= PIN_MAX_LEN


def join_pin_matches(pin):
    candidate = str(pin or "").strip()
    if not candidate:
        return False
    if JOIN_PIN_HASH:
        return verify_pin(candidate, JOIN_PIN_HASH)
    if not JOIN_PIN:
        return True
    return hmac.compare_digest(candidate, JOIN_PIN)


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(data: str) -> bytes:
    raw = str(data or "")
    pad = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw + pad)


def issue_session_token(client_id):
    cid = str(client_id or "").strip()
    if not cid:
        return ""
    user = db_get_user(cid)
    session_version = int((user or {}).get("session_version", 0) or 0)
    now = int(time.time())
    payload = {
        "cid": cid,
        "ver": session_version,
        "iat": now,
        "exp": now + max(300, SESSION_TOKEN_TTL_SECONDS),
    }
    body = _b64u_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    secret = str(app.config.get("SECRET_KEY") or "").encode("utf-8")
    sig = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_session_token(token):
    raw = str(token or "").strip()
    if not raw or "." not in raw:
        return None
    body, sig = raw.split(".", 1)
    if not body or not sig:
        return None
    secret = str(app.config.get("SECRET_KEY") or "").encode("utf-8")
    expected = hmac.new(secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        payload = json.loads(_b64u_decode(body).decode("utf-8"))
    except Exception:
        return None
    cid = str((payload or {}).get("cid") or "").strip()
    if not cid or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", cid):
        return None
    expected_version = int((db_get_user(cid) or {}).get("session_version", 0) or 0)
    token_version = int((payload or {}).get("ver", 0) or 0)
    if token_version != expected_version:
        return None
    exp = int((payload or {}).get("exp") or 0)
    if exp <= int(time.time()):
        return None
    return cid


def extract_http_session_token():
    authz = str(request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    header = str(request.headers.get("X-Session-Token") or "").strip()
    if header:
        return header
    query = str(request.args.get("st") or "").strip()
    if query:
        return query
    return ""


def require_http_session():
    token = extract_http_session_token()
    if not token:
        return None
    return verify_session_token(token)


def hash_pin(pin, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    key = hashlib.scrypt(str(pin).encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"{PIN_HASH_PREFIX}16384$8$1${salt.hex()}${key.hex()}"


def verify_pin(pin, stored):
    raw = str(stored or "").strip()
    if not raw:
        return False
    # Backward compatibility with old plaintext pin records.
    if not raw.startswith(PIN_HASH_PREFIX):
        return hmac.compare_digest(str(pin or "").strip(), raw)
    try:
        _, n_s, r_s, p_s, salt_hex, key_hex = raw.split("$", 5)
        key = hashlib.scrypt(
            str(pin or "").encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(bytes.fromhex(key_hex)),
        )
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


def ensure_crop_storage():
    os.makedirs(CROPS_DIR, exist_ok=True)
    if not os.path.isfile(CROPS_MANIFEST_FILE):
        with open(CROPS_MANIFEST_FILE, "w", newline="") as f:
            csv.writer(f).writerow(CROPS_MANIFEST_HEADERS)


def decode_data_url_image(data_url):
    if not data_url or not isinstance(data_url, str):
        return None, None
    if len(data_url) > MAX_OCR_IMAGE_DATA_URL_CHARS:
        return None, None
    if "," not in data_url:
        return None, None
    header, b64 = data_url.split(",", 1)
    ext = "jpg"
    if "image/png" in header:
        ext = "png"
    elif "image/webp" in header:
        ext = "webp"
    elif "image/jpeg" in header or "image/jpg" in header:
        ext = "jpg"
    try:
        payload = base64.b64decode(b64, validate=True)
        if not payload or len(payload) > MAX_CROP_BYTES:
            return None, None
        return payload, ext
    except Exception:
        return None, None


def save_crop_image(serial, crop_data_url, confidence=0.0, user="Anonymous", method="camera", timestamp_str=None):
    payload, ext = decode_data_url_image(crop_data_url)
    if not payload or not ext:
        return None

    ensure_crop_storage()
    serial_safe = re.sub(r"[^A-Z0-9]+", "", normalize_serial_candidate(serial or ""))
    if not serial_safe:
        return None

    if timestamp_str:
        try:
            ts = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = datetime.now()
    else:
        ts = datetime.now()
    stamp = ts.strftime("%Y%m%d_%H%M%S_%f")[:-3]
    unique_name = f"{serial_safe}__{stamp}.{ext}"
    latest_name = f"{serial_safe}.{ext}"
    unique_path = os.path.join(CROPS_DIR, unique_name)
    latest_path = os.path.join(CROPS_DIR, latest_name)

    with data_lock:
        with open(unique_path, "wb") as f:
            f.write(payload)
        with open(latest_path, "wb") as f:
            f.write(payload)
        secure_chmod(unique_path)
        secure_chmod(latest_path)

        with open(CROPS_MANIFEST_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                (timestamp_str or datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                serial_safe,
                f"{float(confidence or 0.0):.4f}",
                (user or "Anonymous"),
                (method or "camera"),
                unique_name,
                latest_name,
            ])
        secure_chmod(CROPS_MANIFEST_FILE)

    return {
        "serial": serial_safe,
        "file": unique_name,
        "latest_file": latest_name,
        "path": unique_path,
    }


def get_qr_base64(url):
    if not HAS_QRCODE:
        return ""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=1)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()
    except Exception as e:
        print(f"-> QR gen error: {e}")
        return ""


def load_box_registry():
    global box_registry
    try:
        init_database()
        migrate_boxes_json_to_db()
        box_registry = db_load_boxes()
    except Exception as e:
        print(f"-> Error loading box registry from db: {e}")
        box_registry = {}
    normalize_box_registry()


def save_box_registry():
    try:
        db_save_boxes(box_registry)
        # Keep a JSON mirror for compatibility/debugging.
        with data_lock:
            atomic_write_json(BOXES_FILE, box_registry)
    except Exception as e:
        print(f"-> Error saving box registry: {e}")


def load_user_registry():
    global user_registry
    init_database()
    migrate_users_json_to_db()
    user_registry = {}
    try:
        for row in db_list_users():
            user_registry[row["client_id"]] = {
                "name": row["name"],
                "pin_hash": row["pin_hash"],
                "session_version": int(row.get("session_version", 0) or 0),
            }
            db_ensure_user_settings(row["client_id"])
    except Exception as e:
        print(f"-> Error loading users from db: {e}")
        user_registry = {}


def save_user_to_registry(client_id, name, pin):
    global user_registry
    cid = str(client_id or "").strip()
    if not cid:
        return
    pin_hash = hash_pin(str(pin or "").strip())
    if not db_upsert_user(cid, name, pin_hash):
        return
    user_registry[cid] = {"name": name, "pin_hash": pin_hash, "session_version": 0}
    db_ensure_user_settings(cid)


def ensure_session_identity_row(client_id, display_name="Session"):
    cid = str(client_id or "").strip()
    if not cid:
        return None
    existing = db_get_user(cid)
    if existing:
        if cid not in user_registry:
            user_registry[cid] = {
                "name": existing.get("name", display_name) or display_name,
                "pin_hash": existing.get("pin_hash", ""),
                "session_version": int(existing.get("session_version", 0) or 0),
            }
        return existing
    # Create a non-loginable random hash row so session tokens can be versioned/revoked.
    random_hash = hash_pin(secrets.token_urlsafe(24))
    db_upsert_user(cid, (display_name or "Session")[:64], random_hash)
    created = db_get_user(cid) or {"client_id": cid, "name": display_name, "pin_hash": random_hash, "session_version": 0}
    user_registry[cid] = {
        "name": created.get("name", display_name) or display_name,
        "pin_hash": created.get("pin_hash", random_hash),
        "session_version": int(created.get("session_version", 0) or 0),
    }
    db_ensure_user_settings(cid)
    return created


def find_user_by_pin(pin, exclude_client_id=None):
    target = str(pin or "").strip()
    if not target:
        return None, None
    for row in db_list_users():
        cid = row["client_id"]
        if exclude_client_id and cid == exclude_client_id:
            continue
        if verify_pin(target, row.get("pin_hash")):
            return cid, {"name": row.get("name", "Anonymous"), "pin_hash": row.get("pin_hash", "")}
    return None, None


def now_hms():
    return datetime.now().strftime("%H:%M:%S")


def box_room_name(box_id):
    return f"box:{box_id}"


def normalize_box_record(box_id, raw):
    data = raw if isinstance(raw, dict) else {}
    box_profile = normalize_serial_profile(data.get("serial_profile", DEFAULT_SERIAL_PROFILE))
    target_raw = data.get("target") or []
    scanned_raw = data.get("scanned") or []
    audit_raw = data.get("audit") or []

    target = []
    seen_target = set()
    for item in target_raw:
        serial = normalize_serial_candidate(item, box_profile)
        if serial and serial not in seen_target:
            seen_target.add(serial)
            target.append(serial)

    scanned = []
    seen_scanned = set()
    for item in scanned_raw:
        serial = normalize_serial_candidate(item, box_profile)
        if serial and serial not in seen_scanned:
            seen_scanned.add(serial)
            scanned.append(serial)

    audit = []
    if isinstance(audit_raw, list):
        for row in audit_raw[-1200:]:
            if not isinstance(row, dict):
                continue
            serial = normalize_serial_candidate(row.get("serial"), box_profile)
            if not serial:
                continue
            audit.append({
                "serial": serial,
                "serial_profile": normalize_serial_profile(row.get("serial_profile", box_profile)),
                "user": (row.get("user") or "Anonymous")[:48],
                "method": (row.get("method") or "camera")[:16],
                "lane": normalize_lane_name(row.get("lane")),
                "timestamp": row.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "in_target": bool(row.get("in_target")),
                "duplicate_in_box": bool(row.get("duplicate_in_box")),
                "sid": (row.get("sid") or "")[:64],
                "ip": (row.get("ip") or "")[:64],
            })

    return {
        "id": str(box_id),
        "name": (data.get("name") or f"Box {box_id}")[:64],
        "serial_profile": box_profile,
        "target": target,
        "scanned": scanned,
        "user": (data.get("user") or "Anon")[:48],
        "last_active": data.get("last_active") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "closed": bool(data.get("closed", False)),
        "audit": audit,
    }


def normalize_box_registry():
    global box_registry
    normalized = {}
    for raw_id, raw in (box_registry or {}).items():
        box_id = str(raw_id)
        normalized[box_id] = normalize_box_record(box_id, raw)
    box_registry = normalized


def box_collaborators(box_id):
    members = list((box_live_presence.get(box_id) or {}).values())
    members.sort(
        key=lambda m: (
            0 if m.get("session_state") == "scanning" else 1,
            -(float(m.get("last_seen_ts") or 0.0)),
            (m.get("name") or "").lower(),
        )
    )
    return [
        {
            "sid": m.get("sid"),
            "name": m.get("name", "Anonymous"),
            "ip": m.get("ip", "unknown"),
            "joined_at": m.get("joined_at", ""),
            "last_active_at": m.get("last_active_at", ""),
            "session_state": m.get("session_state", "idle"),
        }
        for m in members
    ]


def box_payload_for(sid=None):
    payload = {}
    for box_id in sorted(
        box_registry.keys(),
        key=lambda key: (box_registry[key].get("last_active", ""), box_registry[key].get("name", "")),
        reverse=True,
    ):
        box = box_registry[box_id]
        box_profile = normalize_serial_profile(box.get("serial_profile", DEFAULT_SERIAL_PROFILE))
        target = box.get("target") or []
        scanned = box.get("scanned") or []
        progress = int((len(scanned) / len(target)) * 100) if target else 0
        collaborators = box_collaborators(box_id)
        payload[box_id] = {
            "id": box_id,
            "name": box.get("name") or f"Box {box_id}",
            "target": target,
            "scanned": scanned,
            "user": box.get("user", "Anon"),
            "last_active": box.get("last_active", ""),
            "closed": bool(box.get("closed")),
            "serial_profile": box_profile,
            "audit_count": len(box.get("audit") or []),
            "recent_scans": [
                {
                    "serial": normalize_serial_candidate(row.get("serial"), box_profile),
                    "serial_profile": normalize_serial_profile(row.get("serial_profile", box_profile)),
                    "timestamp": row.get("timestamp") or "",
                    "user": row.get("user") or "Anonymous",
                    "method": row.get("method") or "camera",
                    "lane": normalize_lane_name(row.get("lane")),
                    "in_target": bool(row.get("in_target")),
                    "duplicate_in_box": bool(row.get("duplicate_in_box")),
                    "crop_latest_file": (row.get("crop_latest_file") or ""),
                }
                for row in (box.get("audit") or [])[-400:]
                if normalize_serial_candidate(row.get("serial"), box_profile)
            ],
            "progress_pct": progress,
            "active_users": len(collaborators),
            "collaborators": collaborators,
            "joined": sid is not None and sid_box_membership.get(sid) == box_id,
        }
    return payload


def emit_boxes_updated(target_sid=None):
    if target_sid:
        if not connected_users.get(target_sid, {}).get("verified"):
            return
        socketio.emit("boxes_updated", box_payload_for(target_sid), to=target_sid)
        return
    for sid in list(connected_users.keys()):
        if not connected_users.get(sid, {}).get("verified"):
            continue
        socketio.emit("boxes_updated", box_payload_for(sid), to=sid)


def is_verified_session(sid):
    return bool(connected_users.get(sid, {}).get("verified"))


def is_user_authenticated_session(sid):
    user = connected_users.get(sid, {}) or {}
    return bool(user.get("authenticated_user"))


def require_verified_session(require_user=True):
    if not is_verified_session(request.sid):
        emit("auth_error", {"reason": "not_verified"}, to=request.sid)
        return False
    if require_user and not is_user_authenticated_session(request.sid):
        emit("auth_error", {"reason": "user_auth_required"}, to=request.sid)
        emit("session_status", {
            "verified": True,
            "authenticated_user": False,
            "requires_user_auth": True,
        }, to=request.sid)
        return False
    if is_verified_session(request.sid):
        return True
    return False


def emit_initial_data_for_sid(sid):
    if not is_verified_session(sid):
        return
    rows = read_csv_rows()
    sync_lane_state_from_rows(rows)
    history = [{
        "serial": r.get("Serial Number", ""),
        "timestamp": r.get("Timestamp", ""),
        "method": r.get("Scanned By", ""),
        "user": r.get("User", ""),
        "lane": r.get("Lane", "General") or "General",
        "checked": matches_checklist_any(r.get("Serial Number", "")),
    } for r in rows]
    history.reverse()
    socketio.emit("history_data", history, to=sid)
    socketio.emit("lanes_data", lanes_snapshot(), to=sid)
    emit_boxes_updated(sid)


def leave_box_for_sid(sid, notify=True):
    current = sid_box_membership.pop(sid, None)
    if not current:
        return False
    members = box_live_presence.get(current)
    if members and sid in members:
        members.pop(sid, None)
        if not members:
            box_live_presence.pop(current, None)
    try:
        leave_room(box_room_name(current), sid=sid)
    except Exception:
        pass
    if notify:
        emit_boxes_updated()
    return True


def join_box_for_sid(sid, box_id):
    if not box_id or box_id not in box_registry:
        return False
    leave_box_for_sid(sid, notify=False)
    try:
        join_room(box_room_name(box_id), sid=sid)
    except Exception:
        return False
    user = connected_users.get(sid, {})
    sid_box_membership[sid] = box_id
    box_live_presence.setdefault(box_id, {})[sid] = {
        "sid": sid,
        "name": user.get("name", "Anonymous"),
        "ip": user.get("ip", "unknown"),
        "joined_at": now_hms(),
        "last_active_at": user.get("last_active_at", now_hms()),
        "last_seen_ts": user.get("last_seen_ts", time.time()),
        "session_state": user.get("session_state", "idle"),
    }
    emit_boxes_updated()
    return True


def set_user_session_state(sid, session_state=None, touch=False):
    user = connected_users.get(sid)
    if not user:
        return
    if session_state is not None:
        user["session_state"] = session_state
    if touch:
        user["last_active_at"] = now_hms()
        user["last_seen_ts"] = time.time()
    box_id = sid_box_membership.get(sid)
    if box_id and box_id in box_live_presence and sid in box_live_presence[box_id]:
        member = box_live_presence[box_id][sid]
        member["session_state"] = user.get("session_state", "idle")
        member["last_active_at"] = user.get("last_active_at", now_hms())
        member["last_seen_ts"] = user.get("last_seen_ts", time.time())


def prune_stale_sessions():
    cutoff = time.time() - SESSION_STALE_SECONDS
    stale_sids = [
        sid for sid, user in connected_users.items()
        if user.get("last_seen_ts", time.time()) < cutoff
    ]
    changed = False
    for sid in stale_sids:
        changed = remove_session(sid) or changed
    return changed


def remove_session(sid):
    user = connected_users.pop(sid, None)
    client_ocr_state.pop(sid, None)
    left_box = leave_box_for_sid(sid, notify=False)
    if not user:
        if left_box:
            emit_boxes_updated()
        return False
    client_id = user.get("client_id")
    if client_id and client_session_index.get(client_id) == sid:
        client_session_index.pop(client_id, None)
    if left_box:
        emit_boxes_updated()
    return True


# ============================================
# HTML Template
# ============================================

INDEX_TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "index.html")

def render_index_html():
    with open(INDEX_TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()
    return template.replace("__APP_BUILD_ID__", APP_BUILD_ID)

# ============================================
# CSV Helpers
# ============================================

def read_csv_rows():
    rows = []
    if os.path.isfile(CSV_FILE):
        with open(CSV_FILE, newline="") as f:
            for row in csv.DictReader(f):
                lane = normalize_lane_name(row.get("Lane", "General"))
                row["Lane"] = lane
                rows.append(row)
    return rows


def write_csv_rows(rows):
    with data_lock:
        with open(CSV_FILE, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADERS)
            for r in rows:
                w.writerow([r.get("Timestamp",""), r.get("Hostname",""),
                            r.get("Serial Number",""), r.get("Scanned By",""),
                            r.get("User",""), r.get("Lane","General")])
        secure_chmod(CSV_FILE)


def ensure_csv_schema():
    if not os.path.isfile(CSV_FILE):
        return
    try:
        with open(CSV_FILE, newline="") as f:
            reader = csv.reader(f)
            header = next(reader, [])
    except Exception:
        header = []
    if header == CSV_HEADERS:
        return
    rows = read_csv_rows()
    write_csv_rows(rows)


def load_check_serials():
    global check_serials_cache, check_serials_cache_raw, check_serials_cache_by_profile, check_serials_mtime
    if not os.path.isfile(CHECK_FILE):
        check_serials_cache = set()
        check_serials_cache_raw = set()
        check_serials_cache_by_profile = {"apple": set(), "dell": set()}
        check_serials_mtime = None
        return check_serials_cache

    try:
        mtime = os.path.getmtime(CHECK_FILE)
    except OSError:
        check_serials_cache = set()
        check_serials_cache_raw = set()
        check_serials_cache_by_profile = {"apple": set(), "dell": set()}
        check_serials_mtime = None
        return check_serials_cache

    if check_serials_mtime == mtime:
        return check_serials_cache

    loaded_raw = set()
    try:
        with open(CHECK_FILE, newline="") as f:
            for row in csv.reader(f):
                for cell in row:
                    raw = re.sub(r"[^A-Z0-9]", "", (cell or "").upper())
                    if raw:
                        loaded_raw.add(raw)
        secure_chmod(CHECK_FILE)
    except Exception:
        loaded_raw = set()

    apple_set = set(
        n for n in (normalize_serial_candidate(v, "apple") for v in loaded_raw)
        if n and is_valid_serial_candidate_for_profile(n, "apple")
    )
    dell_set = set(
        n for n in (normalize_serial_candidate(v, "dell") for v in loaded_raw)
        if n and is_valid_serial_candidate_for_profile(n, "dell")
    )
    check_serials_cache_raw = loaded_raw
    check_serials_cache_by_profile = {"apple": apple_set, "dell": dell_set}
    check_serials_cache = apple_set
    check_serials_mtime = mtime
    return check_serials_cache


def matches_checklist(serial, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    serial = normalize_serial_candidate(serial or "", profile)
    if not serial:
        return False
    load_check_serials()
    allowed = check_serials_cache_by_profile.get(profile, set())
    if not allowed:
        return False
    return serial in allowed


def matches_checklist_any(serial):
    return matches_checklist(serial, "apple") or matches_checklist(serial, "dell")


def add_serial_to_checklist(serial, approved=False, confidence=0.0, manual=False, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    normalized = normalize_serial_candidate(serial or "", profile)
    if not normalized:
        return False, "invalid_serial"
    if not approved:
        return False, "not_approved"
    if (not manual) and float(confidence or 0.0) <= 0.99:
        return False, "low_confidence"
    if not allow_serial(normalized, profile):
        return False, f"non_{profile}_serial"

    load_check_serials()
    allowed = check_serials_cache_by_profile.get(profile, set())
    if normalized in allowed:
        return False, "already_exists"

    os.makedirs(os.path.dirname(CHECK_FILE) or ".", exist_ok=True)
    with data_lock:
        with open(CHECK_FILE, "a", newline="") as f:
            f.write(normalized + "\n")
        secure_chmod(CHECK_FILE)

    # force cache refresh
    global check_serials_mtime
    check_serials_mtime = None
    load_check_serials()
    return True, "added"


# ============================================
# Routes
# ============================================

@app.route("/")
def index():
    return render_index_html()


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Local scanner UI should never be cached by intermediaries.
    if (
        request.path == "/"
        or request.path.startswith("/checkset")
        or request.path.startswith("/qr-data")
        or request.path.startswith("/health")
    ):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/download")
def download():
    if not require_http_session():
        return Response("Unauthorized", status=401)
    if not os.path.isfile(CSV_FILE):
        return "No data", 404
    with open(CSV_FILE) as f:
        content = f.read()
    return Response(content, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=serial_numbers.csv"})


@app.route("/checkset")
def checkset():
    if not require_http_session():
        return Response("Unauthorized", status=401)
    profile = normalize_serial_profile(request.args.get("profile", DEFAULT_SERIAL_PROFILE))
    load_check_serials()
    serials = sorted(check_serials_cache_by_profile.get(profile, set()))
    return jsonify({"count": len(serials), "serials": serials})


@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "build": APP_BUILD_ID,
        "users_online": len(connected_users),
        "active_scanners": get_active_scanner_count(),
        "ocr_inflight": ocr_inflight,
        "ocr_capacity": OCR_MAX_INFLIGHT,
        "boxes": len(box_registry),
    })


def build_network_url():
    local_ip = get_local_ip()
    port = 5000
    force_http = os.environ.get("DISABLE_SSL", "").lower() in {"1", "true", "yes", "on"}
    cert = os.path.join(BASE_DIR, "cert.pem")
    key = os.path.join(BASE_DIR, "key.pem")
    has_ssl = (not force_http) and os.path.isfile(cert) and os.path.isfile(key)
    scheme = "https" if has_ssl else "http"
    return f"{scheme}://{local_ip}:{port}/"


@app.route("/qr-data")
def qr_data():
    url = build_network_url()
    qr_b64 = get_qr_base64(url)
    reason = "" if qr_b64 else "QR image unavailable on server; use URL copy."
    return jsonify({"url": url, "b64": qr_b64, "reason": reason})


@app.route("/download/lane/<path:lane_name>")
def download_lane(lane_name):
    if not require_http_session():
        return Response("Unauthorized", status=401)
    rows = read_csv_rows()
    lane = normalize_lane_name(lane_name)
    lane_rows = [r for r in rows if normalize_lane_name(r.get("Lane", "General")) == lane]
    if not lane_rows:
        return "No data for lane", 404

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADERS)
    for r in lane_rows:
        writer.writerow([
            r.get("Timestamp", ""),
            r.get("Hostname", ""),
            r.get("Serial Number", ""),
            r.get("Scanned By", ""),
            r.get("User", ""),
            normalize_lane_name(r.get("Lane", lane)),
        ])
    filename = lane_csv_filename(lane)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/download/crops-manifest")
def download_crops_manifest():
    if not require_http_session():
        return Response("Unauthorized", status=401)
    ensure_crop_storage()
    if not os.path.isfile(CROPS_MANIFEST_FILE):
        return "No cropped scans", 404
    return send_file(
        CROPS_MANIFEST_FILE,
        mimetype="text/csv",
        as_attachment=True,
        download_name="cropped_manifest.csv",
    )


@app.route("/download/crop/<path:filename>")
def download_crop_file(filename):
    if not require_http_session():
        return Response("Unauthorized", status=401)
    ensure_crop_storage()
    safe_name = os.path.basename(filename)
    path = os.path.join(CROPS_DIR, safe_name)
    if not os.path.isfile(path):
        return "Crop not found", 404
    ext = (safe_name.rsplit(".", 1)[-1] if "." in safe_name else "jpg").lower()
    mimetype = "image/jpeg"
    if ext == "png":
        mimetype = "image/png"
    elif ext == "webp":
        mimetype = "image/webp"
    return send_file(path, mimetype=mimetype, as_attachment=True, download_name=safe_name)


@app.route("/download/box/<path:box_id>")
def download_box_summary(box_id):
    if not require_http_session():
        return Response("Unauthorized", status=401)
    load_box_registry()
    box_id = str(box_id)
    box = box_registry.get(box_id)
    if not box:
        return "Box not found", 404
    box_profile = normalize_serial_profile(box.get("serial_profile", DEFAULT_SERIAL_PROFILE))

    target = [normalize_serial_candidate(s, box_profile) for s in box.get("target", []) if normalize_serial_candidate(s, box_profile)]
    scanned = [normalize_serial_candidate(s, box_profile) for s in box.get("scanned", []) if normalize_serial_candidate(s, box_profile)]
    scanned_set = set(scanned)
    target_set = set(target)

    latest_by_serial = {}
    for row in box.get("audit", []):
        serial = normalize_serial_candidate(row.get("serial"), box_profile)
        if not serial:
            continue
        latest_by_serial[serial] = row

    ordered_serials = target + [s for s in scanned if s not in target_set]
    seen = set()
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Box ID",
        "Box Name",
        "Serial",
        "In Target List",
        "Scanned",
        "Scanned At",
        "Scanned By",
        "Method",
        "Lane",
    ])

    for serial in ordered_serials:
        if serial in seen:
            continue
        seen.add(serial)
        latest = latest_by_serial.get(serial, {})
        writer.writerow([
            box_id,
            box.get("name", f"Box {box_id}"),
            serial,
            "YES" if serial in target_set else "NO",
            "YES" if serial in scanned_set else "NO",
            latest.get("timestamp", ""),
            latest.get("user", ""),
            latest.get("method", ""),
            latest.get("lane", ""),
        ])

    filename = f"box_{re.sub(r'[^A-Za-z0-9._-]+', '_', box.get('name', box_id)).strip('_') or box_id}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/cert")
def download_cert():
    cert_path = os.path.join(BASE_DIR, "cert.pem")
    if not os.path.isfile(cert_path):
        return "Certificate not found", 404
    return send_file(
        cert_path,
        mimetype="application/x-x509-ca-cert",
        as_attachment=True,
        download_name="nab-serial-scanner-cert.pem",
    )


@app.route("/cert.cer")
def download_cert_cer():
    cert_path = os.path.join(BASE_DIR, "cert.pem")
    if not os.path.isfile(cert_path):
        return "Certificate not found", 404
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            pem_data = f.read()
        der_bytes = ssl.PEM_cert_to_DER_cert(pem_data)
    except Exception:
        return "Certificate conversion failed", 500
    return Response(
        der_bytes,
        mimetype="application/pkix-cert",
        headers={
            "Content-Disposition": "attachment; filename=nab-serial-scanner-cert.cer",
        },
    )


@app.route("/cert.mobileconfig")
def download_cert_mobileconfig():
    cert_path = os.path.join(BASE_DIR, "cert.pem")
    if not os.path.isfile(cert_path):
        return "Certificate not found", 404
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            pem_data = f.read()
        der_bytes = ssl.PEM_cert_to_DER_cert(pem_data)
        cert_b64 = base64.b64encode(der_bytes).decode("ascii")
        profile_uuid = str(uuid.uuid4()).upper()
        cert_uuid = str(uuid.uuid4()).upper()
        profile_name = "NAB Serial Scanner Local Trust"
        profile = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>nab-serial-scanner-cert.cer</string>
      <key>PayloadContent</key>
      <data>{cert_b64}</data>
      <key>PayloadDescription</key>
      <string>Installs local HTTPS trust certificate for NAB Serial Scanner.</string>
      <key>PayloadDisplayName</key>
      <string>NAB Scanner Certificate</string>
      <key>PayloadIdentifier</key>
      <string>com.nab.serialscanner.cert.{cert_uuid.lower()}</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{cert_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Install certificate to trust local scanner HTTPS endpoint.</string>
  <key>PayloadDisplayName</key>
  <string>{profile_name}</string>
  <key>PayloadIdentifier</key>
  <string>com.nab.serialscanner.profile.{profile_uuid.lower()}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""
    except Exception:
        return "Profile generation failed", 500
    return Response(
        profile,
        mimetype="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": "attachment; filename=nab-serial-scanner-cert.mobileconfig",
        },
    )


# ============================================
# Socket.IO Events
# ============================================

@socketio.on("connect")
def on_connect(auth=None):
    ip = request.remote_addr or "unknown"
    if not check_auth_rate_limit(ip):
        raise ConnectionRefusedError("rate_limited")
    auth = auth or {}
    client_id = re.sub(r"[^A-Za-z0-9._:-]", "", (auth.get("client_id") or "").strip())[:64]
    if not client_id:
        client_id = f"cli-{int(time.time() * 1000)}-{request.sid[:6]}"
    join_pin = str(auth.get("pin", "")).strip()
    auth_session_token = str(auth.get("session_token", "")).strip()
    serial_profile = normalize_serial_profile(auth.get("serial_profile", DEFAULT_SERIAL_PROFILE))
    token_client_id = verify_session_token(auth_session_token)
    if token_client_id:
        client_id = token_client_id
    load_user_registry()
    pin_user_client_id = None
    pin_user_profile = None
    is_join_pin = False
    if (not token_client_id) and join_pin:
        # Priority: existing user PIN first, then session join PIN.
        pin_user_client_id, pin_user_profile = find_user_by_pin(join_pin)
        if not pin_user_client_id:
            is_join_pin = join_pin_matches(join_pin)
    if not token_client_id and not pin_user_client_id and not is_join_pin:
        record_auth_failure(ip)
        raise ConnectionRefusedError("unauthorized")
    record_auth_success(ip)

    if pin_user_client_id:
        client_id = pin_user_client_id

    authenticated_user = bool(
        (token_client_id and token_client_id in user_registry)
        or pin_user_client_id
    )
    if pin_user_profile and isinstance(pin_user_profile, dict):
        profile = pin_user_profile
    else:
        profile = user_registry.get(client_id, {}) if (client_id and authenticated_user) else {}
    display_name = ((profile.get("name") or "Anonymous").strip() or "Anonymous") if authenticated_user else "Anonymous"
    user_settings = db_ensure_user_settings(client_id) if client_id else dict(DEFAULT_USER_SETTINGS)
    serial_profile = normalize_serial_profile(user_settings.get("serial_profile", serial_profile))

    if client_id:
        previous_sid = client_session_index.get(client_id)
        if previous_sid and previous_sid != request.sid:
            remove_session(previous_sid)

    connected_users[request.sid] = {
        "name": display_name,
        "ip": ip,
        "connected_at": now_hms(),
        "last_active_at": now_hms(),
        "last_seen_ts": time.time(),
        "client_id": client_id,
        "serial_profile": serial_profile,
        "session_state": "idle",
        "verified": True,
        "authenticated_user": authenticated_user,
        "settings": user_settings,
    }
    
    if client_id:
        if authenticated_user:
            client_session_index[client_id] = request.sid
            db_touch_login(client_id)
        
    client_ocr_state[request.sid] = {
        "scanning": False,
        "started_scanning_at": 0.0,
        "pending": False,
        "last_submit": 0.0,
        "last_result": "",
        "last_result_at": 0.0,
        "candidate_serial": "",
        "candidate_count": 0,
        "candidate_seen_at": 0.0,
        "recent_latencies": deque(maxlen=6),
        "serial_profile": serial_profile,
    }

    emit("identity_status", {
        "verified": True,
        "name": display_name,
        "client_id": client_id,
        "authenticated_user": authenticated_user,
        "session_token": issue_session_token(client_id) if client_id else "",
        "settings": user_settings,
    }, to=request.sid)

    broadcast_users()
    emit_initial_data_for_sid(request.sid)
    emit_ocr_policy(request.sid, status="ready", accepted=True)
    emit("session_registered", {"sid": request.sid}, to=request.sid)
    emit("ocr_dashboard", get_ocr_dashboard_snapshot())
    broadcast_ocr_dashboard()


@socketio.on("authenticate_pin")
def on_authenticate_pin(data):
    data = data or {}
    ip = request.remote_addr or "unknown"
    pin = str(data.get("pin", "")).strip()
    if not is_reasonable_pin(pin):
        emit("auth_result", {"success": False, "reason": "invalid_pin"}, to=request.sid)
        return
    
    if not check_auth_rate_limit(ip):
        emit("auth_result", {"success": False, "reason": "rate_limit"}, to=request.sid)
        return

    # Check for User Profile PIN first.
    load_user_registry()
    matched_client_id, matched_profile = find_user_by_pin(pin)
    if matched_client_id:
        record_auth_success(ip)
        user_settings = db_ensure_user_settings(matched_client_id)
        if request.sid in connected_users:
            connected_users[request.sid]["name"] = matched_profile.get("name", "Anonymous")
            connected_users[request.sid]["verified"] = True
            connected_users[request.sid]["client_id"] = matched_client_id
            connected_users[request.sid]["authenticated_user"] = True
            connected_users[request.sid]["settings"] = user_settings
            connected_users[request.sid]["serial_profile"] = normalize_serial_profile(
                user_settings.get("serial_profile", connected_users[request.sid].get("serial_profile", DEFAULT_SERIAL_PROFILE))
            )
        client_session_index[matched_client_id] = request.sid
        emit_initial_data_for_sid(request.sid)
        emit("auth_result", {
            "success": True, 
            "type": "user",
            "user": {"name": matched_profile.get("name", "Anonymous")},
            "session_token": issue_session_token(matched_client_id),
            "settings": user_settings,
        }, to=request.sid)
        broadcast_users()
        return

    # Then allow Session JOIN PIN.
    if join_pin_matches(pin):
        record_auth_success(ip)
        if request.sid in connected_users:
            connected_users[request.sid]["verified"] = True
            connected_users[request.sid]["authenticated_user"] = is_user_authenticated_session(request.sid)
        emit_initial_data_for_sid(request.sid)
        emit("auth_result", {"success": True, "type": "session"}, to=request.sid)
        emit("session_status", {
            "verified": True,
            "authenticated_user": bool(connected_users.get(request.sid, {}).get("authenticated_user")),
            "requires_user_auth": not bool(connected_users.get(request.sid, {}).get("authenticated_user")),
            "session_token": issue_session_token(connected_users.get(request.sid, {}).get("client_id")) if connected_users.get(request.sid, {}).get("client_id") else "",
        }, to=request.sid)
        broadcast_users()
        return

    record_auth_failure(ip)
    emit("auth_result", {"success": False, "reason": "invalid_pin"}, to=request.sid)


@socketio.on("register_client")
def on_register_client(data):
    # Backward-compatible no-op now that client_id is registered during connect.
    if request.sid in connected_users:
        emit("session_registered", {"sid": request.sid}, to=request.sid)


@socketio.on("disconnect")
def on_disconnect():
    remove_session(request.sid)
    broadcast_users()
    broadcast_ocr_dashboard()


@socketio.on("set_name")
def on_set_name(data):
    if not require_verified_session(require_user=False):
        return
    # This is now mostly handled via register_user
    name = data.get("name", "Anonymous").strip()
    if request.sid in connected_users:
        connected_users[request.sid]["name"] = name
        connected_users[request.sid]["last_active_at"] = now_hms()
        box_id = sid_box_membership.get(request.sid)
        if box_id and box_id in box_live_presence and request.sid in box_live_presence[box_id]:
            box_live_presence[box_id][request.sid]["name"] = name
    broadcast_users()
    emit_boxes_updated()


@socketio.on("register_user")
def on_register_user(data):
    data = data or {}
    ip = request.remote_addr or "unknown"
    if not check_auth_rate_limit(ip):
        emit("auth_error", {"reason": "rate_limit"}, to=request.sid)
        return
    client_id = re.sub(r"[^A-Za-z0-9._:-]", "", str((data or {}).get("client_id") or "").strip())[:64]
    name = data.get("name", "Anonymous").strip()
    pin = str(data.get("pin", "")).strip()
    if not client_id:
        client_id = f"cli-{int(time.time() * 1000)}-{request.sid[:6]}"
    if not name or not pin:
        record_auth_failure(ip)
        emit("auth_error", {"reason": "missing_fields"}, to=request.sid)
        return
    if not is_reasonable_pin(pin):
        record_auth_failure(ip)
        emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
        return
    if join_pin_matches(pin):
        record_auth_failure(ip)
        emit("auth_error", {"reason": "pin_reserved"}, to=request.sid)
        return
    existing_client_id, _ = find_user_by_pin(pin, exclude_client_id=client_id)
    if existing_client_id:
        record_auth_failure(ip)
        emit("auth_error", {"reason": "pin_in_use"}, to=request.sid)
        return
    
    save_user_to_registry(client_id, name, pin)
    record_auth_success(ip)
    user_settings = db_ensure_user_settings(client_id)
    if request.sid in connected_users:
        connected_users[request.sid]["name"] = name
        connected_users[request.sid]["verified"] = True
        connected_users[request.sid]["client_id"] = client_id
        connected_users[request.sid]["authenticated_user"] = True
        connected_users[request.sid]["settings"] = user_settings
        connected_users[request.sid]["serial_profile"] = normalize_serial_profile(
            user_settings.get("serial_profile", connected_users[request.sid].get("serial_profile", DEFAULT_SERIAL_PROFILE))
        )
        box_id = sid_box_membership.get(request.sid)
        if box_id and box_id in box_live_presence and request.sid in box_live_presence[box_id]:
            box_live_presence[box_id][request.sid]["name"] = name
    client_session_index[client_id] = request.sid
    
    emit("identity_status", {"verified": True, "name": name, "client_id": client_id, "authenticated_user": True, "session_token": issue_session_token(client_id), "settings": user_settings}, to=request.sid)
    emit_initial_data_for_sid(request.sid)
    broadcast_users()
    emit_boxes_updated()


@socketio.on("login_with_pin")
def on_login_with_pin(data):
    data = data or {}
    ip = request.remote_addr or "unknown"
    if not check_auth_rate_limit(ip):
        emit("auth_error", {"reason": "rate_limit"}, to=request.sid)
        return
    pin = str((data or {}).get("pin", "")).strip()
    if not pin:
        record_auth_failure(ip)
        emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
        return
    if not is_reasonable_pin(pin):
        record_auth_failure(ip)
        emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
        return
    load_user_registry()
    matched_client_id, matched_profile = find_user_by_pin(pin)
    if not matched_client_id or not matched_profile:
        record_auth_failure(ip)
        emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
        return
    record_auth_success(ip)
    previous_sid = client_session_index.get(matched_client_id)
    if previous_sid and previous_sid != request.sid:
        remove_session(previous_sid)
    if request.sid in connected_users:
        connected_users[request.sid]["name"] = matched_profile.get("name", "Anonymous")
        connected_users[request.sid]["verified"] = True
        connected_users[request.sid]["client_id"] = matched_client_id
        connected_users[request.sid]["authenticated_user"] = True
        user_settings = db_ensure_user_settings(matched_client_id)
        connected_users[request.sid]["settings"] = user_settings
        connected_users[request.sid]["serial_profile"] = normalize_serial_profile(
            user_settings.get("serial_profile", connected_users[request.sid].get("serial_profile", DEFAULT_SERIAL_PROFILE))
        )
    client_session_index[matched_client_id] = request.sid
    db_touch_login(matched_client_id)
    emit("identity_status", {
        "verified": True,
        "name": matched_profile.get("name", "Anonymous"),
        "client_id": matched_client_id,
        "authenticated_user": True,
        "session_token": issue_session_token(matched_client_id),
        "settings": db_ensure_user_settings(matched_client_id),
    }, to=request.sid)
    emit_initial_data_for_sid(request.sid)
    broadcast_users()
    emit_boxes_updated()


@socketio.on("update_profile")
def on_update_profile(data):
    data = data or {}
    if request.sid not in connected_users or not connected_users[request.sid].get("verified"):
        return
    
    client_id = connected_users[request.sid].get("client_id")
    if not client_id:
        return

    name = data.get("name", "").strip()
    pin = str(data.get("pin", "")).strip()
    
    load_user_registry()
    if client_id in user_registry:
        if name:
            db_update_user_name(client_id, name)
            user_registry[client_id]["name"] = name
            connected_users[request.sid]["name"] = name
        if pin:
            if not is_reasonable_pin(pin):
                emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
                return
            if join_pin_matches(pin):
                emit("auth_error", {"reason": "pin_reserved"}, to=request.sid)
                return
            existing_client_id, _ = find_user_by_pin(pin, exclude_client_id=client_id)
            if existing_client_id:
                emit("auth_error", {"reason": "pin_in_use"}, to=request.sid)
                return
            new_hash = hash_pin(pin)
            db_update_user_pin(client_id, new_hash)
            user_registry[client_id]["pin_hash"] = new_hash

        emit("identity_status", {
            "verified": True,
            "name": user_registry[client_id]["name"],
            "client_id": client_id,
            "authenticated_user": True,
            "session_token": issue_session_token(client_id),
            "settings": db_ensure_user_settings(client_id),
        }, to=request.sid)
        broadcast_users()
        emit_boxes_updated()
        emit("profile_updated", {"success": True}, to=request.sid)


@socketio.on("session_heartbeat")
def on_session_heartbeat():
    if request.sid in connected_users:
        connected_users[request.sid]["last_seen_ts"] = time.time()
        box_id = sid_box_membership.get(request.sid)
        if box_id and box_id in box_live_presence and request.sid in box_live_presence[box_id]:
            box_live_presence[box_id][request.sid]["last_seen_ts"] = connected_users[request.sid]["last_seen_ts"]
            box_live_presence[box_id][request.sid]["last_active_at"] = connected_users[request.sid].get("last_active_at", now_hms())
    if prune_stale_sessions():
        broadcast_users()
        broadcast_ocr_dashboard()
        emit_boxes_updated()


@socketio.on("get_session_status")
def on_get_session_status():
    user = connected_users.get(request.sid, {}) or {}
    authenticated_user = is_user_authenticated_session(request.sid)
    if request.sid in connected_users:
        connected_users[request.sid]["authenticated_user"] = authenticated_user
    emit("session_status", {
        "verified": bool(user.get("verified")),
        "authenticated_user": authenticated_user,
        "requires_user_auth": bool(user.get("verified")) and not authenticated_user,
        "name": user.get("name", "Anonymous"),
        "client_id": user.get("client_id", ""),
        "session_token": issue_session_token(user.get("client_id", "")) if user.get("client_id") else "",
    }, to=request.sid)


@socketio.on("logout_session")
def on_logout_session():
    user = connected_users.get(request.sid) or {}
    client_id = str(user.get("client_id") or "").strip()
    if client_id and user.get("authenticated_user"):
        db_bump_session_version(client_id)
        cached = user_registry.get(client_id)
        if isinstance(cached, dict):
            cached["session_version"] = int(cached.get("session_version", 0) or 0) + 1
    if request.sid in connected_users:
        emit("logged_out", {"ok": True}, to=request.sid)
    remove_session(request.sid)
    broadcast_users()
    broadcast_ocr_dashboard()
    disconnect(sid=request.sid)


@socketio.on("load_user_settings")
def on_load_user_settings():
    if not require_verified_session(require_user=False):
        return
    user = connected_users.get(request.sid) or {}
    client_id = str(user.get("client_id") or "").strip()
    settings = db_ensure_user_settings(client_id) if client_id else dict(DEFAULT_USER_SETTINGS)
    if request.sid in connected_users:
        connected_users[request.sid]["settings"] = settings
        connected_users[request.sid]["serial_profile"] = normalize_serial_profile(
            settings.get("serial_profile", connected_users[request.sid].get("serial_profile", DEFAULT_SERIAL_PROFILE))
        )
    emit("user_settings", {"ok": True, "settings": settings}, to=request.sid)


@socketio.on("save_user_settings")
def on_save_user_settings(data):
    if not require_verified_session(require_user=False):
        return
    user = connected_users.get(request.sid) or {}
    client_id = str(user.get("client_id") or "").strip()
    if not client_id:
        emit("user_settings", {"ok": False, "reason": "missing_client"}, to=request.sid)
        return
    incoming = (data or {}).get("settings") or {}
    settings = db_save_user_settings(client_id, incoming)
    if request.sid in connected_users:
        connected_users[request.sid]["settings"] = settings
        connected_users[request.sid]["serial_profile"] = normalize_serial_profile(
            settings.get("serial_profile", connected_users[request.sid].get("serial_profile", DEFAULT_SERIAL_PROFILE))
        )
    state = client_ocr_state.get(request.sid)
    if state is not None:
        state["serial_profile"] = connected_users[request.sid].get("serial_profile", state.get("serial_profile", DEFAULT_SERIAL_PROFILE))
    emit("user_settings", {"ok": True, "settings": settings}, to=request.sid)


@socketio.on("scanner_state")
def on_scanner_state(data):
    data = data or {}
    if not require_verified_session(require_user=False):
        return
    state = client_ocr_state.get(request.sid)
    if state is None:
        return
    serial_profile = get_sid_serial_profile(request.sid, data.get("serial_profile"))
    state["serial_profile"] = serial_profile
    if request.sid in connected_users:
        connected_users[request.sid]["serial_profile"] = serial_profile
    scanning = bool(data.get("scanning"))
    state["scanning"] = scanning
    set_user_session_state(request.sid, "scanning" if scanning else "idle", touch=True)
    if scanning:
        state["started_scanning_at"] = time.time()
    else:
        state["started_scanning_at"] = 0.0
        state["pending"] = False
        state["candidate_serial"] = ""
        state["candidate_count"] = 0
        state["candidate_seen_at"] = 0.0
    emit_ocr_policy(request.sid, status="ready" if scanning else "idle", accepted=True)
    broadcast_ocr_dashboard()


@socketio.on("process_photo_capture")
def on_process_photo_capture(data):
    global ocr_inflight
    data = data or {}
    if not require_verified_session(require_user=False):
        return
    state = client_ocr_state.get(request.sid)
    if state is None:
        emit_ocr_policy(
            request.sid,
            status="idle",
            accepted=False,
            next_delay_ms=get_recommended_ocr_interval_ms(250),
            source="photo",
        )
        return

    set_user_session_state(request.sid, "photo", touch=True)
    serial_profile = get_sid_serial_profile(request.sid, data.get("serial_profile") or state.get("serial_profile"))
    state["serial_profile"] = serial_profile
    if request.sid in connected_users:
        connected_users[request.sid]["serial_profile"] = serial_profile
    img_data = data.get("image")
    if not img_data:
        ocr_metrics["empty_frames"] += 1
        emit_ocr_policy(
            request.sid,
            status="empty",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 200),
            source="photo",
        )
        broadcast_ocr_dashboard()
        return
    if not isinstance(img_data, str) or len(img_data) > MAX_OCR_IMAGE_DATA_URL_CHARS:
        ocr_metrics["errors"] += 1
        emit_ocr_policy(
            request.sid,
            status="error",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 300),
            source="photo",
        )
        broadcast_ocr_dashboard()
        return

    if state.get("pending"):
        emit_ocr_policy(
            request.sid,
            status="client_pending",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 200),
            source="photo",
        )
        return

    if ocr_inflight >= OCR_MAX_INFLIGHT:
        ocr_metrics["busy_rejects"] += 1
        emit_ocr_policy(
            request.sid,
            status="server_busy",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 350),
            source="photo",
        )
        broadcast_ocr_dashboard()
        return

    state["pending"] = True
    state["last_submit"] = time.time()
    ocr_inflight += 1
    ocr_metrics["frames_accepted"] += 1
    emit("photo_received", {"ok": True}, to=request.sid)
    try:
        process_single_image_for_sid(request.sid, img_data, source="photo", serial_profile=serial_profile)
    finally:
        latency_ms = int((time.time() - state["last_submit"]) * 1000)
        state["recent_latencies"].append(latency_ms)
        ocr_metrics["latency_samples"].append(latency_ms)
        state["pending"] = False
        ocr_inflight = max(0, ocr_inflight - 1)


@socketio.on("save_scan")
def on_save_scan(data):
    data = data or {}
    if not require_verified_session(require_user=False):
        return
    ensure_csv_schema()
    serial_profile = get_sid_serial_profile(request.sid, data.get("serial_profile"))
    function_mode = str(data.get("function_mode") or "").strip().lower()
    if request.sid in connected_users:
        connected_users[request.sid]["serial_profile"] = serial_profile
    serial = normalize_serial_candidate(data.get("serial", "").strip(), serial_profile)
    method = data.get("method", "manual")
    user = data.get("user", "Anonymous")
    idempotency_key = str(data.get("idempotency_key") or "").strip()[:128]
    ocr_confidence = float(data.get("ocr_confidence", 0.0) or 0.0)
    crop_image = data.get("crop_image")
    active_box = str(data.get("box_id") or "").strip()
    if active_box:
        if active_box not in box_registry:
            emit("save_rejected", {"serial": serial, "reason": "box_not_found"}, to=request.sid)
            return
        if box_registry[active_box].get("closed"):
            emit("save_rejected", {"serial": serial, "reason": "box_closed"}, to=request.sid)
            return
    if active_box and active_box in box_registry:
        box_name = (box_registry[active_box].get("name") or f"Box-{active_box}").strip()
        lane = ensure_lane(data.get("lane") or box_name)
    else:
        lane = ensure_lane(data.get("lane"))
    if idempotency_key and not claim_scan_idempotency_key(idempotency_key):
        emit("save_rejected", {
            "serial": serial,
            "reason": "duplicate_submit",
        }, to=request.sid)
        return
    if not allow_serial(serial, serial_profile):
        emit("save_rejected", {
            "serial": serial,
            "reason": f"non_{serial_profile}_serial" if serial_profile in {"apple", "dell"} else "invalid_serial",
        }, to=request.sid)
        return
    enforce_checklist = function_mode != "box" and not bool(active_box)
    if enforce_checklist and not matches_checklist(serial, serial_profile):
        emit("save_rejected", {
            "serial": serial,
            "reason": "not_in_checklist",
        }, to=request.sid)
        return
    set_user_session_state(request.sid, "manual" if method == "manual" else "scanning", touch=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = platform.node()
    crop_saved = None

    existing = read_csv_rows()
    duplicate = any(r.get("Serial Number") == serial for r in existing)

    with data_lock:
        file_exists = os.path.isfile(CSV_FILE) and os.path.getsize(CSV_FILE) > 0
        with open(CSV_FILE, "a", newline="") as f:
            w = csv.writer(f)
            if not file_exists:
                w.writerow(CSV_HEADERS)
            w.writerow([timestamp, hostname, serial, method, user, lane])
        secure_chmod(CSV_FILE)

    if crop_image:
        try:
            crop_saved = save_crop_image(
                serial=serial,
                crop_data_url=crop_image,
                confidence=ocr_confidence,
                user=user,
                method=method,
                timestamp_str=timestamp,
            )
        except Exception as e:
            print(f"-> crop save warning: {e}")

    # Update box if active
    box_duplicate = False
    box_in_target = False
    if active_box and active_box in box_registry:
        box = box_registry[active_box]
        scanned = box.setdefault("scanned", [])
        target = box.setdefault("target", [])
        audit = box.setdefault("audit", [])
        box_duplicate = serial in scanned
        box_in_target = serial in target
        if not box_duplicate:
            scanned.append(serial)
        box["last_active"] = timestamp
        audit.append({
            "serial": serial,
            "serial_profile": serial_profile,
            "user": user,
            "method": method,
            "lane": lane,
            "timestamp": timestamp,
            "in_target": box_in_target,
            "duplicate_in_box": box_duplicate,
            "sid": request.sid,
            "ip": request.remote_addr or "unknown",
            "crop_file": crop_saved["file"] if crop_saved else "",
            "crop_latest_file": crop_saved["latest_file"] if crop_saved else "",
        })
        if len(audit) > 1200:
            box["audit"] = audit[-1200:]
        save_box_registry()
        emit_boxes_updated()
        socketio.emit("box_scan_update", {
            "box_id": active_box,
            "serial": serial,
            "in_target": box_in_target,
            "duplicate_in_box": box_duplicate,
            "user": user,
            "timestamp": timestamp,
        }, to=box_room_name(active_box))

    # Broadcast to ALL connected clients
    scan_data = {
        "serial": serial,
        "timestamp": timestamp,
        "method": method,
        "user": user,
        "lane": lane,
        "checked": True,
        "duplicate": duplicate,
        "box_id": active_box or None,
        "box_in_target": box_in_target,
        "box_duplicate": box_duplicate,
        "ocr_confidence": ocr_confidence,
        "crop_file": crop_saved["file"] if crop_saved else None,
        "crop_latest_file": crop_saved["latest_file"] if crop_saved else None,
        "serial_profile": serial_profile,
    }
    socketio.emit("new_scan", scan_data)
    rows = read_csv_rows()
    sync_lane_state_from_rows(rows)
    broadcast_queue()
    write_lane_csv_files(rows)
    run_backup(reason="save_scan")


@socketio.on("queue_add")
def on_queue_add(data):
    global lane_next_id
    if not require_verified_session(require_user=False):
        return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    serial = normalize_serial_candidate((data or {}).get("serial", "").strip(), serial_profile)
    user = ((data or {}).get("user") or connected_users.get(request.sid, {}).get("name") or "Anonymous").strip()
    lane = ensure_lane((data or {}).get("lane"))
    if not allow_serial(serial, serial_profile):
        emit("queue_rejected", {"reason": f"non_{serial_profile}_serial"}, to=request.sid)
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    shared_lanes[lane].append({
        "id": lane_next_id,
        "serial": serial,
        "user": user,
        "lane": lane,
        "created_at": now,
        "updated_at": now,
    })
    lane_next_id += 1
    broadcast_queue()


@socketio.on("queue_update_current")
def on_queue_update_current(data):
    if not require_verified_session(require_user=False):
        return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    serial = normalize_serial_candidate((data or {}).get("serial", "").strip(), serial_profile)
    user = ((data or {}).get("user") or connected_users.get(request.sid, {}).get("name") or "Anonymous").strip()
    lane = ensure_lane((data or {}).get("lane"))
    if not allow_serial(serial, serial_profile):
        emit("queue_rejected", {"reason": f"non_{serial_profile}_serial"}, to=request.sid)
        return
    if not shared_lanes[lane]:
        emit("queue_rejected", {"reason": "no_current_queue"}, to=request.sid)
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current = shared_lanes[lane][-1]
    current["serial"] = serial
    current["user"] = user
    current["updated_at"] = now
    broadcast_queue()


@socketio.on("lane_create")
def on_lane_create(data):
    if not require_verified_session(require_user=False):
        return
    lane = normalize_lane_name((data or {}).get("lane"))
    if not lane:
        emit("queue_rejected", {"reason": "invalid_lane"}, to=request.sid)
        return
    ensure_lane(lane)
    broadcast_queue()


@socketio.on("add_to_checklist")
def on_add_to_checklist(data):
    if not require_verified_session(require_user=False):
        return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    serial = normalize_serial_candidate((data or {}).get("serial", "").strip(), serial_profile)
    approved = bool((data or {}).get("approved"))
    confidence = float((data or {}).get("confidence", 0.0) or 0.0)
    manual = bool((data or {}).get("manual")) or str((data or {}).get("source", "")).lower() == "manual"
    ok, status = add_serial_to_checklist(
        serial,
        approved=approved,
        confidence=confidence,
        manual=manual,
        serial_profile=serial_profile,
    )
    emit("checklist_update", {"status": status, "serial": serial}, to=request.sid)
    if ok:
        socketio.emit("checklist_changed")


@socketio.on("delete_scan")
def on_delete_scan(data):
    if not require_verified_session(require_user=False):
        return
    serial = data.get("serial", "")
    timestamp = data.get("timestamp", "")
    rows = read_csv_rows()
    new_rows = []
    removed = False
    for r in rows:
        if not removed and r.get("Serial Number") == serial and r.get("Timestamp") == timestamp:
            removed = True
            continue
        new_rows.append(r)
    write_csv_rows(new_rows)
    sync_lane_state_from_rows(new_rows)
    write_lane_csv_files(new_rows)
    broadcast_queue()
    socketio.emit("entry_deleted", {"serial": serial, "timestamp": timestamp})


@socketio.on("clear_all")
def on_clear_all():
    if not require_verified_session(require_user=False):
        return
    with data_lock:
        with open(CSV_FILE, "w", newline="") as f:
            csv.writer(f).writerow(CSV_HEADERS)
        secure_chmod(CSV_FILE)
    sync_lane_state_from_rows([])
    broadcast_queue()
    write_lane_csv_files([])
    run_backup(reason="clear_all", force=True)
    socketio.emit("all_cleared")

@socketio.on("bulk_import_checklist")
def on_bulk_import_checklist(data):
    if not require_verified_session(require_user=False):
        return
    text = (data or {}).get("text", "").strip()
    if not text:
        return
    
    # Split by newline or comma
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    raw_list = re.split(r"[\n,\s]+", text)
    added_count = 0
    errors = []
    
    for raw in raw_list:
        serial = normalize_serial_candidate(raw.strip(), serial_profile)
        if not serial:
            continue
        ok, status = add_serial_to_checklist(serial, approved=True, manual=True, serial_profile=serial_profile)
        if ok:
            added_count += 1
        elif status != "already_exists":
            errors.append(f"{serial}: {status}")

    emit("bulk_import_result", {
        "added": added_count,
        "total": len(set(filter(None, [normalize_serial_candidate(r.strip(), serial_profile) for r in raw_list]))),
        "errors": errors[:5] # limit error list
    }, to=request.sid)
    
    if added_count > 0:
        socketio.emit("checklist_changed")


@socketio.on("get_qr_code")
def on_get_qr_code():
    if not require_verified_session(require_user=False):
        return
    net_url = build_network_url()
    qr_b64 = get_qr_base64(net_url)
    if qr_b64:
        emit("qr_code_data", {"url": net_url, "b64": qr_b64}, to=request.sid)
        return
    emit("qr_code_data", {
        "url": net_url,
        "b64": "",
        "reason": "QR image unavailable on server; use URL copy.",
    }, to=request.sid)


@socketio.on("box_create")
def on_box_create(data):
    if not require_verified_session(require_user=False):
        return
    raw_name = str((data or {}).get("name", "")).strip()
    if not raw_name:
        emit("box_rejected", {"reason": "name_required"}, to=request.sid)
        return
    name = re.sub(r"\s+", " ", raw_name)[:64].strip()
    if not name:
        emit("box_rejected", {"reason": "name_required"}, to=request.sid)
        return
    # Reuse existing box by name (case-insensitive) to avoid accidental duplicates.
    for existing_id, existing_box in box_registry.items():
        existing_name = str(existing_box.get("name") or "").strip().lower()
        if existing_name and existing_name == name.lower():
            join_box_for_sid(request.sid, existing_id)
            emit("box_joined", {"ok": True, "box_id": existing_id}, to=request.sid)
            return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    # Millisecond timestamps can collide under concurrent creates; use random id.
    box_id = f"box_{int(time.time() * 1000)}_{secrets.token_hex(3)}"
    box_registry[box_id] = normalize_box_record(box_id, {
        "name": name,
        "serial_profile": serial_profile,
        "target": [],
        "scanned": [],
        "user": connected_users.get(request.sid, {}).get("name", "Anon"),
        "last_active": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "closed": False,
        "audit": [],
    })
    save_box_registry()
    join_box_for_sid(request.sid, box_id)
    emit("box_joined", {"ok": True, "box_id": box_id}, to=request.sid)


@socketio.on("box_import_target")
def on_box_import_target(data):
    if not require_verified_session(require_user=False):
        return
    box_id = str((data or {}).get("box_id") or "").strip()
    text = (data or {}).get("text", "").strip()
    if not box_id or box_id not in box_registry:
        emit("box_rejected", {"reason": "box_not_found", "box_id": box_id}, to=request.sid)
        return
    if not text:
        emit("box_rejected", {"reason": "empty_import", "box_id": box_id}, to=request.sid)
        return
    if box_registry[box_id].get("closed"):
        emit("box_rejected", {"reason": "box_closed", "box_id": box_id}, to=request.sid)
        return
    
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    raw_list = re.split(r"[\n,\s]+", text)
    new_targets = []
    batch_seen = set()
    ignored_count = 0
    for raw in raw_list:
        serial = normalize_serial_candidate(raw.strip(), serial_profile)
        if serial and serial not in box_registry[box_id]["target"] and serial not in batch_seen:
            new_targets.append(serial)
            batch_seen.add(serial)
        elif raw.strip():
            ignored_count += 1
    if not new_targets:
        emit("box_rejected", {"reason": "no_valid_serials", "box_id": box_id}, to=request.sid)
        return
    
    box_registry[box_id]["target"].extend(new_targets)
    box_registry[box_id]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_box_registry()
    emit_boxes_updated()
    emit("box_imported", {
        "ok": True,
        "box_id": box_id,
        "added_count": len(new_targets),
        "ignored_count": ignored_count,
    }, to=request.sid)


@socketio.on("box_delete")
def on_box_delete(data):
    if not require_verified_session(require_user=False):
        return
    box_id = str((data or {}).get("box_id") or "").strip()
    if not box_id or box_id not in box_registry:
        emit("box_rejected", {"reason": "box_not_found", "box_id": box_id}, to=request.sid)
        return
    if box_id in box_registry:
        for sid, joined_box in list(sid_box_membership.items()):
            if joined_box == box_id:
                leave_box_for_sid(sid, notify=False)
                socketio.emit("box_joined", {"ok": True, "box_id": None}, to=sid)
        del box_registry[box_id]
        save_box_registry()
        emit_boxes_updated()
        emit("box_deleted", {"ok": True, "box_id": box_id}, to=request.sid)


@socketio.on("box_join")
def on_box_join(data):
    if not require_verified_session(require_user=False):
        return
    box_id = str((data or {}).get("box_id") or "").strip()
    if not box_id or box_id not in box_registry:
        emit("box_joined", {"ok": False, "reason": "box_not_found"}, to=request.sid)
        return
    if sid_box_membership.get(request.sid) == box_id:
        emit("box_joined", {"ok": True, "box_id": box_id}, to=request.sid)
        return
    if join_box_for_sid(request.sid, box_id):
        emit("box_joined", {"ok": True, "box_id": box_id}, to=request.sid)
    else:
        emit("box_joined", {"ok": False, "reason": "join_failed"}, to=request.sid)


@socketio.on("box_leave")
def on_box_leave():
    if not require_verified_session(require_user=False):
        return
    leave_box_for_sid(request.sid, notify=True)
    emit("box_joined", {"ok": True, "box_id": None}, to=request.sid)


@socketio.on("box_set_closed")
def on_box_set_closed(data):
    if not require_verified_session(require_user=False):
        return
    box_id = str((data or {}).get("box_id") or "").strip()
    closed = bool((data or {}).get("closed"))
    if not box_id or box_id not in box_registry:
        emit("box_rejected", {"reason": "box_not_found", "box_id": box_id}, to=request.sid)
        return
    box_registry[box_id]["closed"] = closed
    box_registry[box_id]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_box_registry()
    emit_boxes_updated()
    emit("box_state_changed", {"ok": True, "box_id": box_id, "closed": closed}, to=request.sid)


@socketio.on("get_boxes")
def on_get_boxes():
    if not require_verified_session(require_user=False):
        return
    load_box_registry()
    emit_boxes_updated(request.sid)


@socketio.on('debug_log')
def handle_debug_log(data):
    print(f"-> CLIENT DEBUG [{request.sid}]:", data)

frame_counts = {}

@socketio.on('process_ocr_frame')
def handle_ocr_frame(data):
    global ocr_inflight
    data = data or {}
    sid = request.sid
    if not require_verified_session(require_user=False):
        return
    state = client_ocr_state.get(sid)
    if state is None:
        emit_ocr_policy(sid, status="idle", accepted=False, next_delay_ms=get_recommended_ocr_interval_ms(250))
        return

    if not state.get("scanning"):
        emit_ocr_policy(sid, status="idle", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 250))
        return
    serial_profile = get_sid_serial_profile(sid, data.get("serial_profile") or state.get("serial_profile"))
    state["serial_profile"] = serial_profile
    if sid in connected_users:
        connected_users[sid]["serial_profile"] = serial_profile

    if state.get("pending"):
        emit_ocr_policy(sid, status="client_pending", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 200))
        return

    if ocr_inflight >= OCR_MAX_INFLIGHT:
        ocr_metrics["busy_rejects"] += 1
        emit_ocr_policy(sid, status="server_busy", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 350))
        broadcast_ocr_dashboard()
        return

    frame_counts[sid] = frame_counts.get(sid, 0) + 1
    state["pending"] = True
    state["last_submit"] = time.time()
    ocr_inflight += 1
    ocr_metrics["frames_accepted"] += 1

    img_data = data.get('image')
    if not img_data:
        state["pending"] = False
        ocr_inflight = max(0, ocr_inflight - 1)
        ocr_metrics["empty_frames"] += 1
        print(f"-> OCR Frame #{frame_counts[sid]} from {sid} dropped: No image data")
        emit_ocr_policy(sid, status="empty", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 200))
        broadcast_ocr_dashboard()
        return
    if not isinstance(img_data, str) or len(img_data) > MAX_OCR_IMAGE_DATA_URL_CHARS:
        state["pending"] = False
        ocr_inflight = max(0, ocr_inflight - 1)
        ocr_metrics["errors"] += 1
        emit_ocr_policy(sid, status="error", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 300))
        broadcast_ocr_dashboard()
        return
        
    if frame_counts[sid] % 10 == 1:
        print(f"-> OCR Frame #{frame_counts[sid]} received from {sid} (Size: {len(img_data)} chars)")
        
    try:
        ocr_result = recognize_text_from_binary(img_data, serial_profile)
        text = (ocr_result or {}).get("text", "") if isinstance(ocr_result, dict) else (ocr_result or "")
        confidence = float((ocr_result or {}).get("confidence", 0.0)) if isinstance(ocr_result, dict) else 0.0
        serial_hint = normalize_serial_candidate((ocr_result or {}).get("serial_hint", ""), serial_profile) if isinstance(ocr_result, dict) else ""
        ocr_rotation = int((ocr_result or {}).get("rotation_deg", 0) or 0) if isinstance(ocr_result, dict) else 0
        ocr_variant = (ocr_result or {}).get("variant", "primary") if isinstance(ocr_result, dict) else "primary"
        if confidence > 0:
            ocr_metrics["confidence_samples"].append(confidence)
        if text and text.strip():
            print(f"-> OCR Raw Text from {sid} [{ocr_variant}]: '{text.strip()}'")
    except Exception as e:
        print(f"-> TPool Crash for {sid}:", e)
        state["pending"] = False
        ocr_inflight = max(0, ocr_inflight - 1)
        ocr_metrics["errors"] += 1
        emit_ocr_policy(sid, status="error", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 450))
        broadcast_ocr_dashboard()
        return

    latency_ms = int((time.time() - state["last_submit"]) * 1000)
    state["recent_latencies"].append(latency_ms)
    ocr_metrics["latency_samples"].append(latency_ms)
    state["pending"] = False
    ocr_inflight = max(0, ocr_inflight - 1)

    next_delay_ms = get_client_ocr_interval_ms(state)

    if not text:
        state["candidate_serial"] = ""
        state["candidate_count"] = 0
        state["candidate_seen_at"] = 0.0
        ocr_metrics["no_text"] += 1
        emit_ocr_policy(sid, status="no_text", accepted=True, next_delay_ms=next_delay_ms, ocr_confidence=0.0)
        broadcast_ocr_dashboard()
        return

    parsed_serial = extract_serial_from_text(text, serial_profile)
    context_serial = extract_serial_from_strong_context(text or "", serial_profile)
    hint_serial = serial_hint if allow_serial(serial_hint, serial_profile) else ""
    parsed_valid = parsed_serial if allow_serial(parsed_serial, serial_profile) else ""
    context_valid = context_serial if allow_serial(context_serial, serial_profile) else ""
    if serial_profile == "apple":
        possible_serial = parsed_valid or hint_serial or context_valid
    else:
        possible_serial = hint_serial or parsed_valid or context_valid
    has_marker = has_label_marker(text or "", serial_profile)
    dell_marker_match = has_dell_marker_match(text or "", possible_serial) if serial_profile == "dell" else False
    context_strong = has_strong_serial_context(text or "", possible_serial, serial_profile)
    required_conf = OCR_ACCEPT_CONTEXT_MIN_CONFIDENCE if context_strong else OCR_ACCEPT_VALID_MIN_CONFIDENCE
    if serial_profile == "dell":
        required_conf = max(required_conf, 0.62 if dell_marker_match else 0.86)
    # Label-only gate for live flow: require marker unless direct serial is high-confidence.
    if not has_marker and not (
        possible_serial
        and allow_serial(possible_serial, serial_profile)
        and confidence >= max(0.9, OCR_ACCEPT_VALID_MIN_CONFIDENCE)
    ):
        state["candidate_serial"] = ""
        state["candidate_count"] = 0
        state["candidate_seen_at"] = 0.0
        ocr_metrics["no_match"] += 1
        emit_ocr_policy(
            sid,
            status="no_match",
            accepted=True,
            next_delay_ms=get_client_ocr_interval_ms(state, 120),
            ocr_confidence=confidence,
        )
        broadcast_ocr_dashboard()
        return
    if (
        possible_serial
        and allow_serial(possible_serial, serial_profile)
        and confidence >= required_conf
    ):
        if confidence < OCR_POPUP_MIN_CONFIDENCE:
            state["candidate_serial"] = ""
            state["candidate_count"] = 0
            state["candidate_seen_at"] = 0.0
            emit_ocr_policy(
                sid,
                status="low_confidence",
                accepted=False,
                next_delay_ms=get_client_ocr_interval_ms(state, 220),
                ocr_confidence=confidence,
            )
            broadcast_ocr_dashboard()
            return
        required_streak = OCR_MATCH_CONFIRM_STREAK_DELL if serial_profile == "dell" else OCR_MATCH_CONFIRM_STREAK
        if serial_profile == "dell" and not dell_marker_match:
            required_streak = max(required_streak, 2)
        now_ts = time.time()
        prev_candidate = state.get("candidate_serial", "")
        prev_seen_at = float(state.get("candidate_seen_at", 0.0) or 0.0)
        if prev_candidate == possible_serial and (now_ts - prev_seen_at) <= OCR_MATCH_CONFIRM_WINDOW_SEC:
            state["candidate_count"] = int(state.get("candidate_count", 0) or 0) + 1
        else:
            state["candidate_serial"] = possible_serial
            state["candidate_count"] = 1
        state["candidate_seen_at"] = now_ts

        if state["candidate_count"] < required_streak:
            emit_ocr_policy(
                sid,
                status="stabilizing",
                accepted=True,
                next_delay_ms=get_client_ocr_interval_ms(state, 80),
                ocr_confidence=confidence,
            )
            broadcast_ocr_dashboard()
            return

        duplicate_gap_ok = (
            possible_serial != state.get("last_result")
            or (time.time() - state.get("last_result_at", 0.0)) > 2.0
        )
        if duplicate_gap_ok:
            state["last_result"] = possible_serial
            state["last_result_at"] = time.time()
            ocr_metrics["matches"] += 1
            preview_rotation = int(ocr_rotation or 0) % 360
            if preview_rotation == 0:
                preview_rotation = infer_best_rotation_deg(img_data, serial_profile)
            print(f"-> OCR MATCH: '{possible_serial}' for client {sid} in {latency_ms}ms")
            emit_ocr_success(
                sid,
                possible_serial,
                next_delay_ms=next_delay_ms,
                ocr_confidence=confidence,
                serial_profile=serial_profile,
                ocr_rotation=preview_rotation,
            )
            broadcast_ocr_dashboard()
            return

    if confidence <= OCR_MIN_CONFIDENCE:
        state["candidate_serial"] = ""
        state["candidate_count"] = 0
        state["candidate_seen_at"] = 0.0
        emit_ocr_policy(
            sid,
            status="low_confidence",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 220),
            ocr_confidence=confidence,
        )
        broadcast_ocr_dashboard()
        return

    state["candidate_serial"] = ""
    state["candidate_count"] = 0
    state["candidate_seen_at"] = 0.0
    ocr_metrics["no_match"] += 1
    emit_ocr_policy(sid, status="no_match", accepted=True, next_delay_ms=next_delay_ms, ocr_confidence=confidence)
    broadcast_ocr_dashboard()


def broadcast_users():
    prune_stale_sessions()
    ordered = sorted(
        connected_users.items(),
        key=lambda item: (
            0 if item[1].get("session_state") == "scanning" else 1,
            -float(item[1].get("last_seen_ts", 0.0)),
            (item[1].get("name") or "").lower(),
        ),
    )
    users = [{
        "sid": sid,
        "name": u["name"],
        "ip": u["ip"],
        "connected_at": u["connected_at"],
        "last_active_at": u.get("last_active_at", u["connected_at"]),
        "session_state": u.get("session_state", "idle"),
        "box_id": sid_box_membership.get(sid),
    } for sid, u in ordered]
    socketio.emit("users_update", users)


# ============================================
# Startup helpers
# ============================================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_qr_terminal(url):
    if not HAS_QRCODE:
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    for r in range(0, len(matrix) - 1, 2):
        line = "  "
        for c in range(len(matrix[r])):
            top = matrix[r][c]
            bot = matrix[r + 1][c] if r + 1 < len(matrix) else False
            if top and bot: line += "\u2588"
            elif top: line += "\u2580"
            elif bot: line += "\u2584"
            else: line += " "
        print(line)
    if len(matrix) % 2 == 1:
        line = "  "
        for c in range(len(matrix[-1])):
            line += "\u2580" if matrix[-1][c] else " "
        print(line)


def open_browser_delayed(url, delay=1.5):
    def _open():
        import time; time.sleep(delay)
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()


if __name__ == "__main__":
    PORT = 5000
    CERT = os.path.join(BASE_DIR, "cert.pem")
    KEY = os.path.join(BASE_DIR, "key.pem")
    local_ip = get_local_ip()
    force_http = os.environ.get("DISABLE_SSL", "").lower() in {"1", "true", "yes", "on"}
    has_ssl = (not force_http) and os.path.isfile(CERT) and os.path.isfile(KEY)
    scheme = "https" if has_ssl else "http"
    local_url = f"{scheme}://127.0.0.1:{PORT}"
    net_url = f"{scheme}://{local_ip}:{PORT}"

    print()
    print("  \033[1;31m★\033[0m  \033[1mNAB Serial Scanner v3.0 — Multi-User Real-Time\033[0m")
    print("  " + "─" * 48)
    print(f"  \033[1;32m→  Local:\033[0m    {local_url}")
    print(f"  \033[1;36m→  Network:\033[0m  {net_url}")
    print(f"  \033[1;33m→  CSV:\033[0m      {CSV_FILE}")
    if JOIN_PIN_HASH:
        print(f"  \033[1;34m→  Join PIN:\033[0m  configured via JOIN_PIN_HASH")
    else:
        print(f"  \033[1;34m→  Join PIN:\033[0m  {JOIN_PIN}")
    if has_ssl:
        print(f"  \033[1;35m→  SSL:\033[0m      ✅ HTTPS enabled")
    print("  " + "─" * 48)

    if has_ssl:
        print()
        print("  \033[1;33m💡 Accept certificate warning on first visit.\033[0m")
    else:
        print()
        print("  \033[1;33m💡 HTTP mode enabled. Use a trusted tunnel for phone camera access.\033[0m")
    if JOIN_PIN_DEFAULTED and not JOIN_PIN_HASH:
        print("  \033[1;33mℹ JOIN_PIN not set in environment; using local default PIN 2026.\033[0m")

    if HAS_QRCODE:
        print()
        print("  \033[1mScan QR to open on phone/tablet:\033[0m")
        print()
        print_qr_terminal(net_url)
    print()

    try:
        ensure_csv_schema()
        init_database()
        load_check_serials()
        ensure_crop_storage()
        load_user_registry()
        load_box_registry()
        rows = read_csv_rows()
        sync_lane_state_from_rows(rows)
        write_lane_csv_files(rows)
        for p in (CSV_FILE, CHECK_FILE, USERS_FILE, DB_FILE, BOXES_FILE, CROPS_MANIFEST_FILE):
            if os.path.isfile(p):
                secure_chmod(p)
        run_backup(reason="startup", force=True)
    except Exception as e:
        print(f"-> Lane CSV sync warning: {e}")

    open_browser_delayed(local_url)

    if has_ssl:
        socketio.run(
            app,
            host="0.0.0.0",
            port=PORT,
            debug=False,
            use_reloader=False,
            keyfile=KEY,
            certfile=CERT,
        )
    else:
        socketio.run(
            app,
            host="0.0.0.0",
            port=PORT,
            debug=False,
            use_reloader=False,
        )
