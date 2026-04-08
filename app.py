#!/usr/bin/env python3
"""
NAB Serial Scanner v3.0 – Multi-User Real-Time
WebSocket-powered barcode scanner with live dashboard.
Multiple users scan simultaneously; all see results in real time.
"""

import eventlet
eventlet.monkey_patch()
from eventlet import tpool

import os
import csv
import json
import socket
import base64
import hashlib
import hmac
import logging
import platform
import re
import secrets
import sys
import threading
import time
import webbrowser
import io
import tempfile
from collections import deque
from datetime import datetime
from io import StringIO, BytesIO
from flask import Flask, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from src.vision import recognize_text_from_binary
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
    socketio.emit("lanes_data", payload)
    socketio.emit("queue_data", payload)


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


def emit_ocr_success(sid, serial, source=None, next_delay_ms=None, ocr_confidence=None, serial_profile=None):
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
        ocr_result = tpool.execute(recognize_text_from_binary, img_data, serial_profile)
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
    if confidence > 0:
        ocr_metrics["confidence_samples"].append(confidence)

    if text and text.strip():
        print(f"-> OCR Photo Text from {sid}: '{text.strip()}'")
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

    possible_serial = serial_hint or extract_serial_from_text(text or "", serial_profile)
    if possible_serial and allow_serial(possible_serial, serial_profile):
        ocr_metrics["matches"] += 1
        emit_ocr_success(sid, possible_serial, source=source, ocr_confidence=confidence, serial_profile=serial_profile)
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

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
socketio = SocketIO(app, async_mode="eventlet")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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
OCR_MIN_CONFIDENCE = float(os.environ.get("OCR_MIN_CONFIDENCE", "0.99"))
STRICT_MACBOOK_ONLY = os.environ.get("STRICT_MACBOOK_ONLY", "1").lower() in {"1", "true", "yes", "on"}
DEFAULT_SERIAL_PROFILE = normalize_serial_profile(os.environ.get("DEFAULT_SERIAL_PROFILE", "apple"))
JOIN_PIN = os.environ.get("JOIN_PIN", "2026")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
user_registry = {}  # client_id -> {name, pin_hash}
MAX_OCR_IMAGE_DATA_URL_CHARS = int(os.environ.get("MAX_OCR_IMAGE_DATA_URL_CHARS", "7000000"))
MAX_CROP_BYTES = int(os.environ.get("MAX_CROP_BYTES", "6000000"))
PIN_MIN_LEN = int(os.environ.get("PIN_MIN_LEN", "4"))
PIN_MAX_LEN = int(os.environ.get("PIN_MAX_LEN", "16"))
PIN_HASH_PREFIX = "scrypt$"
DATA_FILE_MODE = 0o600

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
box_registry = {}  # box_id -> {name, target: [], scanned: [], user, last_active}
box_live_presence = {}  # box_id -> {sid -> member}
sid_box_membership = {}  # sid -> box_id
data_lock = threading.Lock()


def secure_chmod(path, mode=DATA_FILE_MODE):
    try:
        os.chmod(path, mode)
    except Exception:
        pass


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
    if not os.path.isfile(BOXES_FILE):
        box_registry = {}
        return
    try:
        with open(BOXES_FILE, "r") as f:
            box_registry = json.load(f)
        secure_chmod(BOXES_FILE)
    except Exception as e:
        print(f"-> Error loading box registry: {e}")
        box_registry = {}
    normalize_box_registry()


def save_box_registry():
    try:
        with data_lock:
            atomic_write_json(BOXES_FILE, box_registry)
    except Exception as e:
        print(f"-> Error saving box registry: {e}")


def load_user_registry():
    global user_registry
    if not os.path.isfile(USERS_FILE):
        user_registry = {}
        return
    try:
        with open(USERS_FILE, "r") as f:
            user_registry = json.load(f)
        secure_chmod(USERS_FILE)
    except Exception as e:
        print(f"-> Error loading user registry: {e}")
        user_registry = {}
    migrated = False
    for cid, profile in list((user_registry or {}).items()):
        if not isinstance(profile, dict):
            user_registry.pop(cid, None)
            migrated = True
            continue
        plain_pin = str(profile.get("pin", "")).strip()
        pin_hash = str(profile.get("pin_hash", "")).strip()
        if plain_pin and not pin_hash:
            profile["pin_hash"] = hash_pin(plain_pin)
            profile.pop("pin", None)
            migrated = True
        elif pin_hash and profile.get("pin"):
            profile.pop("pin", None)
            migrated = True
    if migrated:
        try:
            with data_lock:
                atomic_write_json(USERS_FILE, user_registry)
        except Exception as e:
            print(f"-> Error migrating user registry pins: {e}")


def save_user_to_registry(client_id, name, pin):
    global user_registry
    user_registry[client_id] = {"name": name, "pin_hash": hash_pin(str(pin or "").strip())}
    try:
        with data_lock:
            atomic_write_json(USERS_FILE, user_registry)
    except Exception as e:
        print(f"-> Error saving user registry: {e}")


def find_user_by_pin(pin, exclude_client_id=None):
    target = str(pin or "").strip()
    if not target:
        return None, None
    for cid, profile in (user_registry or {}).items():
        if exclude_client_id and cid == exclude_client_id:
            continue
        if verify_pin(target, (profile or {}).get("pin_hash") or (profile or {}).get("pin")):
            return cid, profile
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
        socketio.emit("boxes_updated", box_payload_for(target_sid), to=target_sid)
        return
    for sid in list(connected_users.keys()):
        socketio.emit("boxes_updated", box_payload_for(sid), to=sid)


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

LEGACY_INDEX_HTML = """
  .grid { grid-template-columns:1fr; gap:12px; }
  .card-body { padding:12px; }
  .card-head { padding:12px 14px; }
  /* Bigger scanner on mobile */
  #reader { min-height: 300px; }
  /* Bigger touch targets */
  .btn { padding:14px 16px; font-size:13px; min-height:48px; }
  .btn-sm { padding:10px 14px; font-size:11px; min-height:40px; }
  .input-f { padding:14px; font-size:16px; /* 16px prevents iOS zoom */ }
  .input-f::placeholder { font-size:14px; }
  .search { padding:12px 12px 12px 36px; font-size:14px; }
  .modal { padding:24px 20px; }
  .modal input { font-size:18px; padding:14px; }
  .modal .btn { padding:16px; font-size:15px; }
  /* Feed items bigger for touch */
  .feed-item { padding:12px; gap:10px; }
  .feed-avatar { width:36px; height:36px; font-size:13px; }
  .feed-serial { font-size:14px; }
  .feed-meta { font-size:11px; gap:5px; }
  .feed-delete { opacity:0.4; padding:8px 12px; font-size:16px; }
  .feed { max-height:50vh; -webkit-overflow-scrolling:touch; }
  /* User list */
  .user-row { padding:10px 12px; }
  .user-name { font-size:13px; }
  /* Toasts */
  .toasts { bottom:12px; right:12px; left:12px; }
  .toast-msg { font-size:13px; }
  /* Camera selector */
  .camera-sel { font-size:12px; padding:8px 10px; max-width:none; flex:1; }
  .user-pill { font-size:12px; padding:8px 14px; }
  .conn-pill { font-size:12px; padding:8px 12px; }
}

/* iOS safe area */
@supports (padding-bottom: env(safe-area-inset-bottom)) {
  .app { padding-bottom: calc(40px + env(safe-area-inset-bottom)); }
}

/* Cards */
.card {
  background:var(--bg-card); border:1px solid var(--border);
  border-radius:var(--radius); overflow:hidden;
  box-shadow:0 10px 28px rgba(0,0,0,0.22);
  transition:transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.card:hover {
  transform:translateY(-1px);
  box-shadow:0 14px 34px rgba(0,0,0,0.28);
  border-color:rgba(255,255,255,0.12);
}
.card-head {
  display:flex; align-items:center; justify-content:space-between;
  padding:14px 16px; border-bottom:1px solid var(--border);
  background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.005));
}
.card-title {
  display:flex; align-items:center; gap:6px;
  font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.6px;
}
.card-body { padding:16px; }
.head-actions {
  display:flex;
  align-items:center;
  gap:6px;
  flex-wrap:wrap;
}

/* Scanner */
#reader { width:100%; border-radius:var(--radius-sm); overflow:hidden; background:#000; }
#reader video { border-radius:var(--radius-sm) !important; object-fit:cover; }
#reader__dashboard_section { display:none !important; }
#reader a[href*="scanapp"] { display:none !important; }
#reader img[alt="Info icon"] { display:none !important; }
#qr-shaded-region { border-color:rgba(0,0,0,0.55) !important; }
/* Ensure video fills on iOS */
#reader video { -webkit-playsinline:true; playsinline:true; }

.controls { display:flex; gap:6px; margin-top:12px; }
.func-tabs {
  display:flex;
  gap:6px;
  margin-top:10px;
}
.func-tab {
  flex:1;
  padding:8px 10px;
  border-radius:8px;
  border:1px solid var(--border);
  background:rgba(255,255,255,0.04);
  color:var(--text2);
  font-size:11px;
  font-weight:700;
  cursor:pointer;
}
.func-tab.active {
  color:#fff;
  background:linear-gradient(135deg,var(--nab-red),var(--nab-red-dark));
  border-color:transparent;
}
.serial-profile-switch {
  margin-top:8px;
  display:flex;
  gap:6px;
}
.serial-profile-btn {
  flex:1;
  padding:8px 10px;
  border-radius:8px;
  border:1px solid var(--border);
  background:rgba(255,255,255,0.03);
  color:var(--text2);
  font-size:11px;
  font-weight:700;
  cursor:pointer;
}
.serial-profile-btn.active {
  color:#fff;
  border-color:rgba(16,185,129,0.35);
  background:rgba(16,185,129,0.18);
}
.btn {
  flex:1; padding:10px 12px; border-radius:var(--radius-sm); border:none;
  font-family:'Inter',sans-serif; font-size:11px; font-weight:700;
  cursor:pointer; transition:all 0.25s; text-transform:uppercase;
  display:flex; align-items:center; justify-content:center; gap:5px;
}
.btn-red { background:linear-gradient(135deg,var(--nab-red),var(--nab-red-dark)); color:#fff; box-shadow:0 4px 16px var(--nab-red-glow); }
.btn-red:hover { transform:translateY(-1px); box-shadow:0 6px 24px var(--nab-red-glow); }
.btn-ghost { background:rgba(255,255,255,0.05); color:var(--text); border:1px solid var(--border); }
.btn-ghost:hover { background:rgba(255,255,255,0.08); }
.btn-green { background:var(--success-bg); color:var(--success); border:1px solid rgba(16,185,129,0.2); }
.btn-danger { background:var(--danger-bg); color:var(--danger); border:1px solid rgba(239,68,68,0.2); }
.btn-sm { flex:0; padding:7px 12px; font-size:10px; }
.btn:disabled { opacity:0.35; cursor:not-allowed; transform:none !important; animation:none !important; box-shadow:none !important; }

@keyframes pulseBtn {
  0% { box-shadow: 0 0 0 0 rgba(200,16,46,0.6); }
  70% { box-shadow: 0 0 0 12px rgba(200,16,46,0); }
  100% { box-shadow: 0 0 0 0 rgba(200,16,46,0); }
}
.btn-pulse { animation: pulseBtn 2s infinite; }

.input-row { display:flex; gap:6px; margin-top:10px; }
.input-f {
  flex:1; padding:10px 12px; border-radius:var(--radius-sm);
  border:1px solid var(--border); background:var(--bg-input);
  color:var(--text); font-family:'JetBrains Mono',monospace; font-size:13px;
  outline:none; transition:all 0.2s;
}
.input-f:focus { border-color:var(--nab-red); box-shadow:0 0 0 3px rgba(200,16,46,0.12); }
.input-f::placeholder { color:var(--text3); font-family:'Inter',sans-serif; font-size:12px; }

.banner {
  margin-top:10px; padding:10px 14px; border-radius:var(--radius-sm);
  display:none; align-items:center; gap:8px;
  font-size:12px; font-weight:600;
  animation: bannerIn 0.35s cubic-bezier(0.34,1.56,0.64,1);
}
.banner.show { display:flex; }
.banner.success { background:var(--success-bg); color:var(--success); }
.banner.warning { background:var(--warning-bg); color:var(--warning); }
.banner.info { background:var(--info-bg); color:var(--info); }
.banner .mono { font-family:'JetBrains Mono',monospace; font-weight:700; letter-spacing:0.5px; }
@keyframes bannerIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:translateY(0); } }

/* Live feed */
.feed { max-height:380px; overflow-y:auto; }
.feed::-webkit-scrollbar { width:3px; }
.feed::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.08); border-radius:4px; }

.feed-item {
  display:flex; align-items:flex-start; gap:10px;
  padding:10px 12px; border-radius:var(--radius-sm); margin-bottom:4px;
  border:1px solid transparent; transition:all 0.2s;
  animation: feedIn 0.3s ease;
}
.feed-item:hover { background:var(--bg-card-hover); border-color:var(--border); }
@keyframes feedIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:translateX(0); } }

.feed-avatar {
  width:32px; height:32px; border-radius:8px;
  display:grid; place-items:center;
  font-size:12px; font-weight:800; flex-shrink:0;
  text-transform:uppercase;
}
.feed-content { flex:1; min-width:0; }
.feed-thumb {
  width:52px;
  height:34px;
  object-fit:cover;
  border-radius:8px;
  border:1px solid var(--border);
  background:#000;
  flex-shrink:0;
  cursor:zoom-in;
}
.feed-serial {
  font-family:'JetBrains Mono',monospace;
  font-size:13px; font-weight:700; letter-spacing:0.3px;
}
.feed-meta {
  font-size:10px; color:var(--text3); margin-top:2px;
  display:flex; gap:6px; align-items:center; flex-wrap:wrap;
}
.feed-badge {
  font-size:9px; font-weight:700; padding:1px 5px;
  border-radius:3px; text-transform:uppercase; letter-spacing:0.3px;
}
.fb-camera { background:var(--info-bg); color:var(--info); }
.fb-manual { background:rgba(255,255,255,0.05); color:var(--text2); }
.fb-dupe { background:var(--warning-bg); color:var(--warning); }
.fb-check { background:var(--success-bg); color:var(--success); }

.feed-delete {
  opacity:0; border:none; background:none; color:var(--danger);
  cursor:pointer; padding:4px 8px; font-size:14px; transition:opacity 0.2s;
  -webkit-tap-highlight-color:transparent;
}
.feed-item:hover .feed-delete { opacity:0.5; }
.feed-delete:hover { opacity:1 !important; }
/* On touch devices, always show delete btn faintly */
@media (hover:none) { .feed-delete { opacity:0.35; } }

.feed-empty { text-align:center; padding:40px 16px; color:var(--text3); font-size:12px; }
.feed-empty .icon { font-size:32px; margin-bottom:8px; opacity:0.2; }
.feed-count {
  margin:-2px 0 8px;
  font-size:11px;
  color:var(--text2);
}

/* Online users */
.users-list { display:flex; flex-direction:column; gap:4px; }
.user-row {
  display:flex; align-items:center; gap:8px;
  padding:8px 10px; border-radius:var(--radius-sm);
  transition:all 0.2s; animation: feedIn 0.3s ease;
}
.user-row:hover { background:var(--bg-card-hover); }
.user-dot { width:7px; height:7px; border-radius:50%; background:var(--success); animation: blink 2s infinite; flex-shrink:0; }
@keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
.user-name { font-size:12px; font-weight:600; display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.user-info { font-size:10px; color:var(--text3); }
.user-you {
  font-size:9px; font-weight:700; background:var(--purple-bg); color:var(--purple);
  padding:1px 5px; border-radius:3px; margin-left:4px;
}
.user-badge {
  font-size:9px; font-weight:700; padding:1px 5px;
  border-radius:999px; letter-spacing:0.2px; text-transform:uppercase;
}
.ub-scanning { background:var(--success-bg); color:var(--success); }
.ub-photo { background:var(--info-bg); color:var(--info); }
.ub-idle { background:rgba(255,255,255,0.05); color:var(--text2); }
.ub-manual { background:var(--warning-bg); color:var(--warning); }

.mini-stats { display:grid; grid-template-columns:repeat(2,1fr); gap:8px; }
.mini-stat {
  border:1px solid var(--border); border-radius:10px; padding:10px 12px;
  background:rgba(255,255,255,0.02);
}
.mini-stat-label {
  font-size:10px; color:var(--text3); text-transform:uppercase; letter-spacing:0.5px; font-weight:700;
}
.mini-stat-value {
  margin-top:4px; font-family:'JetBrains Mono',monospace; font-size:18px; font-weight:700; color:var(--text);
}
.mini-note { margin-top:10px; font-size:11px; color:var(--text2); line-height:1.4; }
.engine-status {
  margin-top:10px; display:flex; align-items:center; justify-content:space-between; gap:10px;
}
.status-pill {
  font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px;
  padding:4px 8px; border-radius:999px; border:1px solid var(--border);
}
.status-idle { background:rgba(255,255,255,0.04); color:var(--text2); }
.status-active { background:var(--success-bg); color:var(--success); border-color:rgba(16,185,129,0.25); }
.status-busy { background:var(--warning-bg); color:var(--warning); border-color:rgba(245,158,11,0.25); }
.meter-wrap { margin-top:8px; display:flex; flex-direction:column; gap:6px; }
.meter-row { display:flex; align-items:center; justify-content:space-between; gap:10px; font-size:10px; color:var(--text2); }
.meter-track {
  width:100%; height:6px; border-radius:999px; background:rgba(255,255,255,0.08); overflow:hidden;
}
.meter-fill {
  height:100%; width:0%; border-radius:999px; transition:width 0.25s ease;
}
.meter-pool { background:linear-gradient(90deg, #06B6D4, #3B82F6); }
.meter-hit { background:linear-gradient(90deg, #10B981, #22C55E); }

/* Search */
.search {
  width:100%; padding:9px 12px 9px 32px; border-radius:var(--radius-sm);
  border:1px solid var(--border); background:var(--bg-input);
  color:var(--text); font-size:12px; outline:none; transition:all 0.2s;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' fill='%234B5563' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E");
  background-repeat:no-repeat; background-position:10px center;
  margin-bottom:10px;
}
.search:focus { border-color:var(--nab-red); }

/* Flash */
.scan-flash {
  position:fixed; inset:0; z-index:9999; pointer-events:none;
  opacity:0; transition:opacity 0.1s;
}
.scan-flash.on { opacity:1; }

/* Toast */
.toasts { position:fixed; bottom:16px; right:16px; z-index:999; display:flex; flex-direction:column; gap:6px; }
.toast-msg {
  background:var(--bg-card); border:1px solid var(--border);
  color:var(--text); padding:10px 16px; border-radius:var(--radius-sm);
  font-size:12px; font-weight:500; box-shadow:0 8px 32px rgba(0,0,0,0.4);
  animation: toastIn 0.3s ease, toastOut 0.3s ease 2.5s forwards;
}
@keyframes toastIn { from { opacity:0; transform:translateX(16px); } to { opacity:1; transform:translateX(0); } }
@keyframes toastOut { to { opacity:0; transform:translateX(16px); } }

/* Name modal */
.modal-bg {
  position:fixed; inset:0; z-index:10000;
  background:rgba(0,0,0,0.7); backdrop-filter:blur(8px);
  display:grid; place-items:center;
}
.modal {
  background: rgba(17, 22, 33, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.12);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-radius: 24px; padding: 36px; width: 380px; max-width: 92vw;
  text-align: center; 
  box-shadow: 
    0 4px 6px -1px rgba(0, 0, 0, 0.1), 
    0 2px 4px -1px rgba(0, 0, 0, 0.06),
    0 20px 40px -10px rgba(0, 0, 0, 0.5);
  animation: modalScale 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
}
@keyframes modalScale {
  from { opacity: 0; transform: scale(0.9) translateY(10px); }
  to { opacity: 1; transform: scale(1) translateY(0); }
}
.modal h2 { font-size:18px; font-weight:800; margin-bottom:6px; }
.modal p { font-size:13px; color:var(--text2); margin-bottom:20px; }
.modal input {
  width:100%; padding:12px 14px; border-radius:var(--radius-sm);
  border:1px solid var(--border); background:var(--bg-input);
  color:var(--text); font-size:15px; font-weight:600;
  outline:none; text-align:center; margin-bottom:12px;
}
.modal input:focus { border-color:var(--nab-red); }
.modal .btn { width:100%; }

.camera-sel {
  padding:6px 8px; border-radius:6px; border:1px solid var(--border);
  background:var(--bg-input); color:var(--text);
  font-size:10px; outline:none; cursor:pointer; max-width:140px;
}

.perf-note {
  margin-top:10px; font-size:11px; color:var(--text2);
  display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;
}
.proc-note {
  margin-top:6px;
  font-size:11px;
  color:var(--text2);
  min-height:16px;
}
.proc-note.active {
  color: var(--info);
}
.hold-card {
  position:fixed;
  left:50%;
  top:50%;
  transform:translate(-50%, -50%);
  width:min(92vw, 420px);
  padding:12px;
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  background:var(--bg-card);
  box-shadow:0 20px 60px rgba(0,0,0,0.55);
  z-index:10020;
  display:none;
}
.hold-card.show {
  display:block;
  animation:bannerIn 0.25s ease;
}
.hold-title {
  font-size:12px;
  font-weight:700;
  color:var(--text);
  margin-bottom:6px;
}
.hold-check-icon {
  display:inline-flex;
  align-items:center;
  gap:5px;
  margin-bottom:8px;
  font-size:11px;
  font-weight:700;
  color:var(--success);
  background:var(--success-bg);
  border:1px solid rgba(16,185,129,0.24);
  border-radius:999px;
  padding:3px 8px;
}
.feed-check-icon {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:16px;
  height:16px;
  border-radius:999px;
  margin-right:6px;
  color:var(--success);
  background:var(--success-bg);
  border:1px solid rgba(16,185,129,0.22);
  font-size:10px;
  font-weight:800;
  vertical-align:middle;
}
.hold-serial {
  font-family:'JetBrains Mono',monospace;
  font-size:16px;
  font-weight:700;
  color:var(--text);
  letter-spacing:0.4px;
}
.hold-meta {
  margin-top:6px;
  font-size:11px;
  color:var(--text2);
}
.hold-actions {
  margin-top:10px;
  display:flex;
  gap:8px;
}
.hold-overlay {
  position:fixed;
  inset:0;
  background:rgba(0,0,0,0.46);
  backdrop-filter:blur(3px);
  z-index:10010;
  display:none;
}
.hold-overlay.show {
  display:block;
}
.queue-box {
  margin-top:10px;
  padding:10px;
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  background:rgba(255,255,255,0.02);
}
.queue-box.import-mode {
  background:rgba(16,185,129,0.05);
  border-color:rgba(16,185,129,0.2);
}
.queue-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
  font-size:11px;
  font-weight:700;
  color:var(--text2);
  text-transform:uppercase;
  letter-spacing:0.4px;
}
.queue-controls {
  margin-top:8px;
  display:flex;
  gap:6px;
}
.queue-link {
  margin-top:8px;
  font-size:11px;
  color:var(--text2);
  display:flex;
  align-items:center;
  gap:6px;
}
.queue-select {
  flex:1;
  min-width:120px;
  padding:8px;
  border-radius:8px;
  border:1px solid var(--border);
  background:var(--bg-input);
  color:var(--text);
  font-size:11px;
}
.queue-input {
  flex:1;
  min-width:100px;
  padding:8px;
  border-radius:8px;
  border:1px solid var(--border);
  background:var(--bg-input);
  color:var(--text);
  font-size:11px;
}
.queue-current {
  margin-top:6px;
  font-family:'JetBrains Mono',monospace;
  font-size:13px;
  color:var(--text);
}
.queue-list {
  margin-top:8px;
  display:flex;
  flex-direction:column;
  gap:4px;
  max-height:88px;
  overflow:auto;
}
.queue-item {
  font-size:11px;
  color:var(--text2);
  display:flex;
  justify-content:space-between;
  gap:8px;
}
.check-box {
  margin-top:10px;
  padding-top:10px;
  border-top:1px dashed var(--border);
}
#checkBox {
  border:1px solid rgba(16,185,129,0.18);
  border-radius:10px;
  padding:10px;
  background:rgba(16,185,129,0.06);
}
.mode-summary {
  margin-top:10px;
  border:1px solid var(--border);
  border-radius:10px;
  background:rgba(255,255,255,0.03);
  padding:8px 10px;
}
.mode-title {
  font-size:11px;
  font-weight:700;
  color:var(--text);
  letter-spacing:0.3px;
}
.mode-sub {
  margin-top:4px;
  font-size:11px;
  color:var(--text2);
}
.import-actions {
  margin-top:8px;
  display:flex;
  gap:6px;
}
.import-actions .btn {
  flex:1;
}
.import-note {
  margin-top:6px;
  font-size:11px;
  color:var(--text2);
}
.check-title {
  font-size:11px;
  font-weight:700;
  color:var(--text);
  margin-bottom:6px;
}
.check-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:6px;
  font-size:11px;
  color:var(--text2);
}
.check-preview {
  margin-top:6px;
  max-height:82px;
  overflow:auto;
  font-size:11px;
  color:var(--text2);
  font-family:'JetBrains Mono',monospace;
}
.check-form {
  margin-top:8px;
  display:flex;
  gap:6px;
}
.box-lobby {
  margin-bottom:10px;
  display:flex;
  flex-direction:column;
  gap:6px;
  max-height:140px;
  overflow:auto;
}
.box-lobby-item {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
  padding:8px 10px;
  border-radius:10px;
  border:1px solid var(--border);
  background:rgba(255,255,255,0.02);
  cursor:pointer;
}
.box-lobby-item.active {
  border-color:rgba(59,130,246,0.35);
  background:rgba(59,130,246,0.1);
}
.box-lobby-meta {
  font-size:10px;
  color:var(--text2);
}
.box-collabs {
  margin-bottom:8px;
  font-size:11px;
  color:var(--text2);
}
.box-found {
  margin-bottom:10px;
  border:1px dashed var(--border);
  border-radius:8px;
  padding:6px 8px;
  font-size:11px;
  color:var(--text2);
}
.box-found.show {
  color:var(--success);
  border-color:rgba(16,185,129,0.45);
  background:rgba(16,185,129,0.12);
  animation:foundPulse 0.55s ease;
}
@keyframes foundPulse {
  from { transform:scale(0.98); opacity:0.5; }
  to { transform:scale(1); opacity:1; }
}
@media (max-width:760px) {
  .controls, .input-row, .check-form, .queue-controls, .import-actions, .head-actions, .serial-profile-switch {
    flex-wrap:wrap;
  }
  .controls .btn, .import-actions .btn {
    min-width:120px;
  }
  .check-head {
    flex-wrap:wrap;
  }
}
</style>
</head>
<body>

<div class="scan-flash" id="scanFlash"></div>

<!-- PIN Modal -->
<div class="modal-bg" id="pinModal" style="display:none;">
  <div class="modal">
    <div style="font-size:36px; margin-bottom:12px;">🔐</div>
    <h2>Join Scanner</h2>
    <p>Enter join PIN to access this session</p>
    <input type="password" id="pinInput" placeholder="PIN"
           onkeydown="if(event.key==='Enter') submitPin()" autofocus>
    <button class="btn btn-red" onclick="submitPin()">Join</button>
  </div>
</div>

<!-- Name Modal (Registration) -->
<div class="modal-bg" id="nameModal" style="display:none;">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">👤</div>
    <h2>Create New User</h2>
    <p>Set display name and unique personal PIN</p>
    <div style="display:flex; flex-direction:column; gap:12px; margin-bottom:20px;">
      <input type="text" id="nameInput" placeholder="Enter your name" 
             style="margin-bottom:0;" onkeydown="if(event.key==='Enter') document.getElementById('regPinInput').focus()">
      <input type="password" id="regPinInput" placeholder="Set a personal PIN" 
             style="margin-bottom:0;" onkeydown="if(event.key==='Enter') document.getElementById('regPinConfirmInput').focus()">
      <input type="password" id="regPinConfirmInput" placeholder="Confirm PIN" 
             style="margin-bottom:0;" onkeydown="if(event.key==='Enter') registerUser()">
    </div>
    <div style="margin-bottom:12px; font-size:12px; color:var(--text3);">
      Have an existing PIN? <a href="#" onclick="showAuthChoiceModal(); return false;" style="color:var(--info); text-decoration:none;">Use Existing PIN</a>
    </div>
    <button class="btn btn-red" onclick="registerUser()">Create Profile</button>
  </div>
</div>

<div class="modal-bg" id="authChoiceModal" style="display:none;">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">🔐</div>
    <h2>Sign In</h2>
    <p>Choose how you want to continue</p>
    <div style="display:flex; flex-direction:column; gap:10px;">
      <button class="btn btn-red" onclick="showUserPinModal()">Use Existing PIN</button>
      <button class="btn btn-ghost" onclick="showNameModal()">Create New User</button>
    </div>
  </div>
</div>

<!-- QR Modal -->
<div class="modal-bg" id="qrModal" style="display:none;" onclick="if(event.target===this) closeQr()">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">📱</div>
    <h2>Quick Connect</h2>
    <p>Scan this QR code with your phone to open the scanner instantly. PIN is pre-filled.</p>
    <div id="qrContainer" style="background:white; padding:12px; border-radius:12px; display:inline-block; margin-bottom:20px;">
      <img id="qrImage" src="" style="width:200px; height:200px; display:block;">
    </div>
    <div style="margin-bottom:20px;">
      <code id="netUrlText" style="display:block; font-size:11px; color:var(--text3); word-break:break-all; margin-bottom:8px;"></code>
      <button class="btn btn-ghost btn-sm" onclick="copyUrl()">📋 Copy URL</button>
    </div>
    <button class="btn btn-red" onclick="closeQr()">Done</button>
  </div>
</div>

<!-- Box Create Modal -->
<div class="modal-bg" id="boxCreateModal" style="display:none;" onclick="if(event.target===this) closeBoxCreate()">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">📦</div>
    <h2>Create New Box</h2>
    <p>Give this box/container a name to start tracking</p>
    <input type="text" id="boxNameInput" placeholder="Box Name (e.g. Pallet A)" 
           style="margin-bottom:20px;" onkeydown="if(event.key==='Enter') submitBoxCreate()">
    <div style="display:flex; gap:10px;">
      <button class="btn btn-ghost" onclick="closeBoxCreate()">Cancel</button>
      <button class="btn btn-red" onclick="submitBoxCreate()">Create Box</button>
    </div>
  </div>
</div>

<!-- Box Import Modal -->
<div class="modal-bg" id="boxImportModal" style="display:none;" onclick="if(event.target===this) closeBoxImport()">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">📄</div>
    <h2>Import Target List</h2>
    <p>Paste the list of serials expected in this box</p>
    <textarea id="boxImportInput" placeholder="Serial numbers..."
              style="width:100%; height:160px; border-radius:12px; border:1px solid var(--border); background:var(--bg-input); color:var(--text); padding:12px; font-family:'JetBrains Mono',monospace; font-size:13px; outline:none; margin-bottom:18px;"></textarea>
    <div style="display:flex; gap:10px;">
      <button class="btn btn-ghost" onclick="closeBoxImport()">Cancel</button>
      <button class="btn btn-red" id="boxImportSubmitBtn" onclick="submitBoxImport()">Import List</button>
    </div>
  </div>
</div>
<div class="modal-bg" id="userPinModal" style="display:none;">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">👋</div>
    <h2 id="userPinTitle">Use Existing PIN</h2>
    <p>Enter PIN to load that user profile</p>
    <input type="password" id="userPinInput" placeholder="Your PIN" 
           style="margin-bottom:20px;" onkeydown="if(event.key==='Enter') submitUserPin()">
    <button class="btn btn-red" onclick="submitUserPin()">Unlock</button>
    <div style="margin-top:16px; font-size:12px; color:var(--text3);">
      No profile yet? <a href="#" onclick="showNameModal(); return false;" style="color:var(--info); text-decoration:none;">Create new user</a>
    </div>
  </div>
</div>

<!-- Profile Modal (Edit User Info) -->
<div class="modal-bg" id="profileModal" style="display:none;" onclick="if(event.target===this) closeProfile()">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">👤</div>
    <h2>Edit Profile</h2>
    <p>Update your scanner identity</p>
    <div style="display:flex; flex-direction:column; gap:12px; margin-bottom:20px; text-align:left;">
      <div>
        <label style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase; margin-left:4px;">Full Name</label>
        <input type="text" id="profNameInput" placeholder="Name" style="margin-top:4px; margin-bottom:0;">
      </div>
      <div>
        <label style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase; margin-left:4px;">Change PIN (Leave blank to keep)</label>
        <input type="password" id="profPinInput" placeholder="New PIN" style="margin-top:4px; margin-bottom:0;">
      </div>
    </div>
    <div style="display:flex; gap:10px;">
      <button class="btn btn-ghost" onclick="closeProfile()">Cancel</button>
      <button class="btn btn-red" onclick="updateProfile()">Save Changes</button>
    </div>
  </div>
</div>

<!-- Bulk Import Modal -->
<div class="modal-bg" id="bulkImportModal" style="display:none;" onclick="if(event.target===this) closeBulkImport()">
  <div class="modal">
    <div style="font-size:42px; margin-bottom:16px;">📥</div>
    <h2>Bulk Import serials</h2>
    <p>Paste a list of serials to add to check.csv (one per line or separated by spaces/commas)</p>
    <textarea id="bulkImportInput" placeholder="S001, S002, S003..." 
              style="width:100%; height:160px; border-radius:12px; border:1px solid var(--border); background:var(--bg-input); color:var(--text); padding:12px; font-family:'JetBrains Mono',monospace; font-size:13px; outline:none; margin-bottom:18px;"></textarea>
    <div style="display:flex; gap:10px;">
      <button class="btn btn-ghost" onclick="closeBulkImport()">Cancel</button>
      <button class="btn btn-red" onclick="submitBulkImport()">Import All</button>
    </div>
  </div>
</div>

<div class="app">
  <header class="header">
    <div class="logo">
      <div class="logo-icon">★</div>
      <div>
        <h1>NAB Serial Scanner</h1>
        <small>Multi-User Real-Time &bull; v3.0</small>
      </div>
    </div>
    <div class="header-right">
      <button class="btn btn-ghost btn-sm" style="padding:4px 8px; font-size:14px;" onclick="showQr()">📱 QR</button>
      <select class="camera-sel" id="cameraSel" onchange="switchCamera()">
        <option>Loading…</option>
      </select>
      <div class="user-pill" id="userPill" onclick="changeName()">👤 —</div>
      <div class="conn-pill" id="connPill" style="background:var(--success-bg); color:var(--success);">
        <span style="width:6px;height:6px;border-radius:50%;background:var(--success);animation:blink 2s infinite;"></span>
        <span id="connCount">0</span> online
      </div>
    </div>
  </header>

  <!-- Stats -->
  <div class="stats">
    <div class="stat red"><div class="stat-label">Total Scans</div><div class="stat-val" id="sTotal">0</div></div>
    <div class="stat green"><div class="stat-label">Today</div><div class="stat-val" id="sToday">0</div></div>
    <div class="stat blue"><div class="stat-label">Unique</div><div class="stat-val" id="sUnique">0</div></div>
    <div class="stat yellow"><div class="stat-label">Duplicates</div><div class="stat-val" id="sDupes">0</div></div>
    <div class="stat purple"><div class="stat-label">Users Online</div><div class="stat-val" id="sOnline">0</div></div>
  </div>

  <!-- Grid -->
  <div class="grid">
    <!-- Scanner -->
    <div>
      <div class="card">
        <div class="card-head">
          <div class="card-title">📷 Scanner</div>
          <label style="display:flex;align-items:center;gap:5px;font-size:10px;color:var(--text2);cursor:pointer;">
            <input type="checkbox" id="autosave" checked onchange="onAutosaveChange()" style="accent-color:var(--nab-red);">
            Auto-save
          </label>
        </div>
        <div class="card-body">
          <div id="reader"></div>
          <div class="func-tabs">
            <button class="func-tab active" id="funcInventoryBtn" onclick="setFunctionMode('inventory')">Check Inventory</button>
            <button class="func-tab" id="funcBoxBtn" onclick="setFunctionMode('box')">Box Counting</button>
            <button class="func-tab" id="funcImportBtn" onclick="setFunctionMode('import')">Import check.csv</button>
          </div>
          <div class="mode-summary">
            <div class="mode-title" id="modeTitle">Mode: Check Inventory</div>
            <div class="mode-sub" id="modeSub">Scan only serials that match check.csv, then save to the selected lane.</div>
          </div>
          <div class="serial-profile-switch">
            <button class="serial-profile-btn active" id="profileAppleBtn" onclick="setSerialProfile('apple')">Apple Serial</button>
            <button class="serial-profile-btn" id="profileDellBtn" onclick="setSerialProfile('dell')">Dell Service Tag</button>
          </div>
          <div class="controls">
            <button class="btn btn-red btn-pulse" id="startBtn" onclick="startScanner()">▶ Start</button>
            <button class="btn btn-ghost" id="stopBtn" onclick="stopScanner()" disabled>⏹ Stop</button>
            <button class="btn btn-ghost" id="photoBtn" onclick="capturePhoto()" disabled>📸 Take Photo</button>
          </div>
          <div class="input-row">
            <input class="input-f" id="manualInput" placeholder="Type serial…" onkeydown="if(event.key==='Enter') saveManual()">
            <button class="btn btn-red btn-sm" id="manualSaveBtn" onclick="saveManual()">Save</button>
          </div>
          <div class="perf-note">
            <span id="perfMode">Smart OCR session idle</span>
            <span id="perfLoad">M4 OCR pool 0/0</span>
          </div>
          <div class="proc-note" id="procNote">Ready.</div>
          <div class="queue-box">
            <div class="check-box" id="checkBox" style="margin-top:0;padding-top:0;border-top:none;">
              <div class="check-title">Import to check.csv</div>
              <div class="import-actions" id="importActions">
                <button class="btn btn-ghost btn-sm" onclick="startImportLive()">📹 Use Live Camera</button>
                <button class="btn btn-ghost btn-sm" onclick="capturePhotoForImport()">📸 Capture Add</button>
              </div>
              <div class="import-note">Use camera in Import mode, then tap Continue on popup to add.</div>
              <div class="check-head">
                <span>check.csv loaded: <strong id="checkCount">0</strong></span>
                <button class="btn btn-ghost btn-sm" onclick="loadCheckset(true)">Load check.csv</button>
                <button class="btn btn-ghost btn-sm" onclick="showBulkImport()">Bulk Import</button>
              </div>
              <div class="check-preview" id="checkPreview">-</div>
              <div class="check-form">
                <input class="queue-input" id="checkAddInput" placeholder="Serial to add">
                <button class="btn btn-ghost btn-sm" onclick="addChecklistFromForm()">Add</button>
              </div>
              <label class="queue-link">
                <input type="checkbox" id="checkApprove"> Approve add to check.csv
                <span id="checkConfLabel">conf 0%</span>
              </label>
            </div>

            <!-- Box Box -->
            <div class="check-box" id="boxContainer" style="display:none; margin-top:0; padding-top:0; border-top:none;">
              <div class="check-title">Box Inventory</div>
              <div class="box-controls" style="display:flex; gap:10px; margin-bottom:12px;">
                <select class="queue-select" id="boxSel" style="flex:1;" onchange="onBoxChange()"></select>
                <button class="btn btn-ghost btn-sm" onclick="showBoxCreate()">+ New Box</button>
              </div>
              <div class="box-lobby" id="boxLobbyList"></div>
              <div id="boxStatusCard" style="display:none;">
                <div class="meter-row" style="font-size:11px; margin-bottom:4px;">
                  <span id="boxStatsText">0/0 scanned</span>
                  <span id="boxPercentText">0%</span>
                </div>
                <div class="meter-track" style="height:10px; margin-bottom:12px;"><div class="meter-fill meter-pool" id="boxProgressFill" style="width:0%;"></div></div>
                <div class="box-collabs" id="boxCollabs">No collaborators yet.</div>
                <div class="box-found" id="boxFoundFlash">Waiting for matched serial…</div>
                <div style="display:flex; gap:8px; margin-bottom:12px;">
                  <button class="btn btn-ghost btn-sm" style="flex:1;" onclick="showBoxImport()">📄 Import Target</button>
                  <button class="btn btn-ghost btn-sm" style="flex:1;" id="boxCloseBtn" onclick="toggleBoxClosed()">🔒 Close Box</button>
                </div>
                <div style="display:flex; gap:8px; margin-bottom:12px;">
                  <button class="btn btn-ghost btn-sm" style="flex:1;" onclick="downloadBoxSummary()">⬇ Box CSV</button>
                  <button class="btn btn-danger btn-sm" onclick="deleteActiveBox()">✕ Delete</button>
                </div>
                <div class="check-head">
                  <span id="boxMissingTitle">Missing Serials</span>
                  <button class="btn btn-ghost btn-sm" id="boxMissingToggleBtn" onclick="toggleBoxMissing()">Show List</button>
                </div>
                <div class="check-preview" id="boxMissingList" style="display:none; max-height:120px; overflow-y:auto; text-align:left; font-size:11px;">-</div>
              </div>
            </div>
            <div class="queue-head" id="queueHead"><span>Serial Lanes</span><span id="qCount">0</span></div>
            <div class="queue-controls" id="laneControls">
              <select class="queue-select" id="laneSel" onchange="onLaneChange()"></select>
              <input class="queue-input" id="laneInput" placeholder="New lane" onkeydown="if(event.key==='Enter') createLane()">
              <button class="btn btn-ghost btn-sm" onclick="createLane()">Add</button>
            </div>
            <label class="queue-link" id="laneAutoAssignWrap">
              <input type="checkbox" id="laneAutoAssign" onchange="onLaneAutoAssignChange()">
              Link scans to selected lane
            </label>
            <div class="queue-current" id="qCurrent">No active queue item</div>
            <div class="queue-list" id="qList"></div>
          </div>
          <div class="banner" id="banner"></div>
        </div>
      </div>
    </div>

    <!-- Live Feed -->
    <div>
      <div class="card">
        <div class="card-head">
          <div class="card-title" id="feedTitle">⚡ Live Feed</div>
          <div class="head-actions">
            <button class="btn btn-green btn-sm" onclick="downloadCSV()">⬇ CSV</button>
            <button class="btn btn-green btn-sm" onclick="downloadLaneCSV()">⬇ Lane CSV</button>
            <button class="btn btn-green btn-sm" onclick="downloadCropManifest()">⬇ Crops CSV</button>
            <button class="btn btn-danger btn-sm" onclick="clearAll()">✕ Clear</button>
          </div>
        </div>
        <div class="card-body">
          <input class="search" id="searchBox" placeholder="Search…" oninput="renderFeed()">
          <div class="feed-count" id="feedCount">0 items</div>
          <div class="feed" id="feedList">
            <div class="feed-empty"><div class="icon">📡</div>Waiting for scans…</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Online Users -->
    <div>
      <div class="card">
        <div class="card-head">
          <div class="card-title">👥 Online Users</div>
        </div>
        <div class="card-body">
          <div class="users-list" id="usersList">
            <div class="feed-empty"><div class="icon">👤</div>No users connected</div>
          </div>
        </div>
      </div>
    </div>

    <!-- OCR Performance -->
    <div>
      <div class="card">
        <div class="card-head">
          <div class="card-title">🧠 M4 OCR Engine</div>
          <div class="status-pill status-idle" id="mStatus">Idle</div>
        </div>
        <div class="card-body">
          <div class="mini-stats">
            <div class="mini-stat">
              <div class="mini-stat-label">Scanning Now</div>
              <div class="mini-stat-value" id="mActive">0</div>
            </div>
            <div class="mini-stat">
              <div class="mini-stat-label">Workers Busy</div>
              <div class="mini-stat-value" id="mPool">0/0</div>
            </div>
            <div class="mini-stat">
              <div class="mini-stat-label">Avg OCR</div>
              <div class="mini-stat-value" id="mLatency">0ms</div>
            </div>
            <div class="mini-stat">
              <div class="mini-stat-label">OCR Confidence</div>
              <div class="mini-stat-value" id="mMatch">0%</div>
            </div>
          </div>
          <div class="meter-wrap">
            <div class="meter-row">
              <span>Worker Utilization</span>
              <span id="mUtilText">0%</span>
            </div>
            <div class="meter-track"><div class="meter-fill meter-pool" id="mUtilFill"></div></div>
            <div class="meter-row">
              <span>OCR Confidence</span>
              <span id="mHitText">0%</span>
            </div>
            <div class="meter-track"><div class="meter-fill meter-hit" id="mHitFill"></div></div>
          </div>
          <div class="mini-note" id="mNote">Waiting for scan sessions…</div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="hold-overlay" id="scanHoldOverlay" onclick="ignoreScanHold()"></div>
<div class="hold-card" id="scanHold">
  <div class="hold-title">Scan Complete</div>
  <div class="hold-check-icon" id="holdCheckIcon" style="display:none;">✔ Listed in CSV</div>
  <img id="holdCropImage" src="" alt="Cropped scan preview" style="display:none; width:100%; border-radius:10px; border:1px solid var(--border); margin-bottom:8px; max-height:180px; object-fit:contain; background:#000;">
  <div class="hold-serial" id="holdSerial">-</div>
  <div class="hold-meta" id="holdMeta">Review result, then continue scanning.</div>
  <div class="hold-actions">
    <button class="btn btn-red" onclick="continueAfterScan()">Continue</button>
    <button class="btn btn-ghost" onclick="ignoreScanHold()">Ignore</button>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<div class="modal-bg" id="cropPreviewModal" style="display:none;" onclick="if(event.target===this) closeCropPreview()">
  <div class="modal" style="max-width:min(96vw, 900px); width:min(96vw,900px);">
    <h2 style="margin-bottom:8px;">Cropped Preview</h2>
    <p id="cropPreviewMeta" style="margin-bottom:12px;">-</p>
    <img id="cropPreviewImage" src="" alt="Crop preview" style="display:block; width:100%; max-height:72vh; object-fit:contain; border-radius:12px; border:1px solid var(--border); background:#000;">
    <div style="display:flex; gap:10px; margin-top:14px;">
      <button class="btn btn-ghost" onclick="closeCropPreview()">Close</button>
      <button class="btn btn-red" onclick="downloadCropPreview()">Download</button>
    </div>
  </div>
</div>

<script>
// ============================================
// State
// ============================================
let sock = null;
let scanner = null;
let isScanning = false;
let scanHistory = [];
let cameras = [];
let selectedCam = null;
let userName = localStorage.getItem('nab_scanner_name') || '';
let userPin = localStorage.getItem('nab_scanner_user_pin') || '';
let clientId = localStorage.getItem('nab_scanner_client_id') || '';
let joinPin = '';
let appBootstrapped = false;
let currentSessionId = '';
let lastCode = '';
let lastCodeTime = 0;
const userColors = {};
const colorPalette = [
  '#C8102E','#3B82F6','#10B981','#F59E0B','#8B5CF6',
  '#EC4899','#06B6D4','#F97316','#14B8A6','#6366F1'
];
let colorIdx = 0;

let ocrRunning = false;
let ocrTimer = null;
let ocrAwaitingServer = false;
let photoProcessing = false;
let photoOnlyStream = null;
const DEFAULT_OCR_DELAY_MS = 700;
let ocrDelayMs = 700;
let latestOcrSerial = '';
let latestOcrAt = 0;
let latestOcrConfidence = 0;
let latestOcrCropImage = '';
let lastSubmittedCropImage = '';
let processingMode = '';
let scanHoldActive = false;
let holdSerialValue = '';
let holdScanPending = null;
let sharedLanes = [];
let selectedLane = localStorage.getItem('nab_selected_lane') || 'General';
let allBoxes = {};
let selectedBoxId = '';
let boxMissingVisible = false;
let boxFoundFlashTimer = null;
let lastBoxFoundSerial = '';
let pendingBoxJoinId = '';
let laneAutoAssign = localStorage.getItem('nab_lane_auto_assign') !== '0';
let allowedCheckSet = new Set();
let checksetLastLoadedAt = 0;
let activeFunction = localStorage.getItem('nab_active_function') || 'inventory';
let serialProfile = (localStorage.getItem('nab_serial_profile') || 'apple').toLowerCase();
if (serialProfile !== 'apple' && serialProfile !== 'dell') serialProfile = 'apple';
let lastConnectErrorToastAt = 0;
let cameraPreference = localStorage.getItem('nab_camera_pref') || 'environment';
let autosavePref = localStorage.getItem('nab_autosave_pref');
if (autosavePref !== '0' && autosavePref !== '1') autosavePref = '1';
let previewCropFilename = '';

function setCookie(name, value, days = 90) {
  const expires = new Date(Date.now() + (days * 24 * 60 * 60 * 1000)).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value || '')}; expires=${expires}; path=/; SameSite=Lax`;
}

function getCookie(name) {
  const key = `${name}=`;
  const parts = (document.cookie || '').split(';');
  for (const part of parts) {
    const p = part.trim();
    if (p.startsWith(key)) return decodeURIComponent(p.slice(key.length));
  }
  return '';
}

function saveJoinPin(pin) {
  const val = String(pin || '').trim();
  joinPin = val;
  if (!val) return;
  localStorage.setItem('nab_scanner_pin', val);
  setCookie('nab_scanner_pin', val, 180);
}

function clearJoinPinCache() {
  joinPin = '';
  localStorage.removeItem('nab_scanner_pin');
  setCookie('nab_scanner_pin', '', -1);
}

function loadJoinPinCache() {
  const fromLocal = (localStorage.getItem('nab_scanner_pin') || '').trim();
  if (fromLocal) {
    joinPin = fromLocal;
    return fromLocal;
  }
  const fromCookie = (getCookie('nab_scanner_pin') || '').trim();
  if (fromCookie) {
    joinPin = fromCookie;
    localStorage.setItem('nab_scanner_pin', fromCookie);
    return fromCookie;
  }
  joinPin = '';
  return '';
}

function saveSelectedBox(boxId) {
  const id = String(boxId || '').trim();
  selectedBoxId = id;
  if (id) localStorage.setItem('nab_selected_box_id', id);
  else localStorage.removeItem('nab_selected_box_id');
}

function loadSelectedBoxCache() {
  const cached = (localStorage.getItem('nab_selected_box_id') || '').trim();
  if (cached) selectedBoxId = cached;
}

function setProcessingState(mode, active, detail = '') {
  processingMode = active ? mode : '';
  const el = document.getElementById('procNote');
  if (!el) return;
  el.classList.toggle('active', active);
  if (!active) {
    el.textContent = 'Ready.';
    return;
  }
  const label = mode === 'photo' ? 'Processing photo' : 'Processing live frame';
  el.textContent = detail ? `${label} • ${detail}` : `${label}...`;
}

function showScanHold(serial, isDupe, autosaved, cropImage = '', isListed = null) {
  scanHoldActive = true;
  holdSerialValue = serial;
  holdScanPending = {
    serial,
    isDupe,
    autosaved,
    confidence: latestOcrConfidence,
    crop_image: cropImage || latestOcrCropImage || '',
    is_listed: typeof isListed === 'boolean' ? isListed : null,
  };
  const hold = document.getElementById('scanHold');
  const overlay = document.getElementById('scanHoldOverlay');
  const serialEl = document.getElementById('holdSerial');
  const metaEl = document.getElementById('holdMeta');
  const imgEl = document.getElementById('holdCropImage');
  const checkIconEl = document.getElementById('holdCheckIcon');
  if (serialEl) serialEl.textContent = serial;
  if (imgEl) {
    const src = holdScanPending?.crop_image || '';
    if (src) {
      imgEl.src = src;
      imgEl.style.display = 'block';
    } else {
      imgEl.src = '';
      imgEl.style.display = 'none';
    }
  }
  if (metaEl) {
    const fallbackListed = (() => {
      const inCheckCsv = allowedCheckSet.size > 0 && allowedCheckSet.has(serial);
      const inBoxCsv = (
        activeFunction === 'box'
        && !!selectedBoxId
        && !!allBoxes[selectedBoxId]
        && Array.isArray(allBoxes[selectedBoxId].target)
        && allBoxes[selectedBoxId].target.includes(serial)
      );
      return inCheckCsv || inBoxCsv;
    })();
    const isListed = typeof holdScanPending?.is_listed === 'boolean' ? holdScanPending.is_listed : fallbackListed;
    if (checkIconEl) checkIconEl.style.display = isListed ? 'inline-flex' : 'none';
    const checkedText = isListed ? '✓ listed in CSV' : 'Not listed in CSV';
    const confText = `confidence ${Math.round((holdScanPending?.confidence || 0) * 100)}%`;
    if (autosaved) {
      metaEl.textContent = isDupe
        ? `Duplicate detected. ${checkedText}. ${confText}. Continue or ignore.`
        : `${checkedText}. ${confText}. Continue or ignore.`;
    } else {
      metaEl.textContent = isDupe
        ? `Duplicate detected. ${checkedText}. ${confText}. Continue or ignore.`
        : `${checkedText}. ${confText}. Continue or ignore.`;
    }
  }
  const addInput = document.getElementById('checkAddInput');
  const confLabel = document.getElementById('checkConfLabel');
  if (addInput) addInput.value = serial;
  if (confLabel) confLabel.textContent = `conf ${Math.round((holdScanPending?.confidence || 0) * 100)}%`;
  if (overlay) overlay.classList.add('show');
  if (hold) hold.classList.add('show');
}

function hideScanHold() {
  scanHoldActive = false;
  holdSerialValue = '';
  holdScanPending = null;
  const imgEl = document.getElementById('holdCropImage');
  const checkIconEl = document.getElementById('holdCheckIcon');
  if (imgEl) {
    imgEl.src = '';
    imgEl.style.display = 'none';
  }
  if (checkIconEl) checkIconEl.style.display = 'none';
  const hold = document.getElementById('scanHold');
  const overlay = document.getElementById('scanHoldOverlay');
  if (overlay) overlay.classList.remove('show');
  if (hold) hold.classList.remove('show');
}

function resumeScanFlow() {
  hideScanHold();
  if (scanner && isScanning) {
    try { scanner.resume(); } catch(e) {}
    queueNextOcr(180);
  }
}

function continueAfterScan() {
  if (holdScanPending) {
    if (activeFunction === 'import') {
      const approved = !!document.getElementById('checkApprove')?.checked;
      const confidence = holdScanPending?.confidence || 0;
      sock.emit('add_to_checklist', { serial: holdScanPending.serial, approved, confidence, serial_profile: serialProfile });
    } else {
      const payload = { 
        serial: holdScanPending.serial, 
        method: 'camera', 
        lane: selectedLane, 
        user: userName,
        box_id: activeFunction === 'box' ? selectedBoxId : null,
        ocr_confidence: holdScanPending?.confidence || 0,
        crop_image: holdScanPending?.crop_image || ''
      };
      payload.serial_profile = serialProfile;
      sock.emit('save_scan', payload);
    }
  }
  resumeScanFlow();
}

function ignoreScanHold() {
  resumeScanFlow();
}

function addChecklistFromForm() {
  if (!sock) return;
  const serial = (document.getElementById('checkAddInput')?.value || '').trim();
  const approved = !!document.getElementById('checkApprove')?.checked;
  const confidence = holdScanPending?.confidence || 0;
  if (!serial) return;
  sock.emit('add_to_checklist', { serial, approved, confidence, manual: true, serial_profile: serialProfile });
}

function normalizeSerialProfile(profile) {
  const p = String(profile || '').toLowerCase();
  return p === 'dell' ? 'dell' : 'apple';
}

function setSerialProfile(profile) {
  const next = normalizeSerialProfile(profile);
  if (serialProfile === next) return;
  serialProfile = next;
  localStorage.setItem('nab_serial_profile', serialProfile);
  allowedCheckSet = new Set();
  checksetLastLoadedAt = 0;
  updateFunctionModeUI();
  loadCheckset(true);
  if (sock) {
    sock.emit('scanner_state', { scanning: !!isScanning, serial_profile: serialProfile });
  }
}

function setFunctionMode(mode) {
  if (mode === 'import' || mode === 'box' || mode === 'inventory') activeFunction = mode;
  else activeFunction = 'inventory';
  localStorage.setItem('nab_active_function', activeFunction);
  updateFunctionModeUI();
}

function onAutosaveChange() {
  const cb = document.getElementById('autosave');
  autosavePref = (cb && cb.checked) ? '1' : '0';
  localStorage.setItem('nab_autosave_pref', autosavePref);
}

function startImportLive() {
  setFunctionMode('import');
  if (!isScanning) startScanner();
  showBanner('Import mode live camera ready. Scan then tap Continue to add.', 'info');
}

function capturePhotoForImport() {
  setFunctionMode('import');
  capturePhoto();
}

function updateFunctionModeUI() {
  const invBtn = document.getElementById('funcInventoryBtn');
  const boxTabBtn = document.getElementById('funcBoxBtn');
  const impBtn = document.getElementById('funcImportBtn');
  const queueBox = document.querySelector('.queue-box');
  const queueHead = document.getElementById('queueHead');
  const laneControls = document.getElementById('laneControls');
  const laneWrap = document.getElementById('laneAutoAssignWrap');
  const qCurrent = document.getElementById('qCurrent');
  const qList = document.getElementById('qList');
  const checkBox = document.getElementById('checkBox');
  const boxContainer = document.getElementById('boxContainer');
  const modeTitle = document.getElementById('modeTitle');
  const modeSub = document.getElementById('modeSub');
  const profileAppleBtn = document.getElementById('profileAppleBtn');
  const profileDellBtn = document.getElementById('profileDellBtn');
  const manualInput = document.getElementById('manualInput');
  const manualSaveBtn = document.getElementById('manualSaveBtn');
  const photoBtn = document.getElementById('photoBtn');
  const importActions = document.getElementById('importActions');
  const autosaveCb = document.getElementById('autosave');

  const mode = activeFunction;
  if (invBtn) invBtn.classList.toggle('active', mode === 'inventory');
  if (boxTabBtn) boxTabBtn.classList.toggle('active', mode === 'box');
  if (impBtn) impBtn.classList.toggle('active', mode === 'import');
  if (profileAppleBtn) profileAppleBtn.classList.toggle('active', serialProfile === 'apple');
  if (profileDellBtn) profileDellBtn.classList.toggle('active', serialProfile === 'dell');

  if (queueBox) queueBox.classList.toggle('import-mode', mode !== 'inventory');
  if (queueHead) queueHead.style.display = mode === 'inventory' ? '' : 'none';
  if (laneControls) laneControls.style.display = mode === 'inventory' ? '' : 'none';
  if (laneWrap) laneWrap.style.display = mode === 'inventory' ? '' : 'none';
  if (qCurrent) qCurrent.style.display = mode === 'inventory' ? '' : 'none';
  if (qList) qList.style.display = mode === 'inventory' ? '' : 'none';
  
  if (checkBox) checkBox.style.display = mode === 'import' ? '' : 'none';
  if (boxContainer) boxContainer.style.display = mode === 'box' ? '' : 'none';
  if (importActions) importActions.style.display = mode === 'import' ? 'flex' : 'none';

  if (modeTitle) {
    if (mode === 'inventory') modeTitle.textContent = 'Mode: Check Inventory';
    else if (mode === 'box') modeTitle.textContent = 'Mode: Box Counting';
    else modeTitle.textContent = 'Mode: Import check.csv';
  }
  
  if (modeSub) {
    const profileLabel = serialProfile === 'dell' ? 'Dell Service Tag' : 'Apple Serial';
    if (mode === 'inventory') modeSub.textContent = `Scan only ${profileLabel} values that match check.csv, then save to lane.`;
    else if (mode === 'box') modeSub.textContent = `Scan ${profileLabel} values into a specific box. Track missing vs counted.`;
    else modeSub.textContent = `Add ${profileLabel} values to the global check.csv list.`;
  }
  
  if (manualInput) {
    const tokenLabel = serialProfile === 'dell' ? 'service tag' : 'serial';
    manualInput.placeholder = mode === 'inventory' ? `Type ${tokenLabel}…` : (mode === 'box' ? `Type ${tokenLabel} for box…` : `Type ${tokenLabel} to import…`);
  }
  if (manualSaveBtn) {
    manualSaveBtn.textContent = mode === 'inventory' ? 'Save' : (mode === 'box' ? 'Check-in' : 'Add');
  }
  if (photoBtn) {
    photoBtn.textContent = mode === 'inventory' ? '📸 Take Photo' : '📸 Capture Scan';
  }
  if (autosaveCb) {
    autosaveCb.disabled = mode !== 'inventory';
    if (mode === 'inventory') autosaveCb.checked = autosavePref !== '0';
  }
  
  if (mode === 'box') {
    if (sock) sock.emit('get_boxes');
  } else if (sock && selectedBoxId) {
    pendingBoxJoinId = '';
    sock.emit('box_leave');
  }
}

function renderQueue() {
  const countEl = document.getElementById('qCount');
  const currentEl = document.getElementById('qCurrent');
  const listEl = document.getElementById('qList');
  const laneSel = document.getElementById('laneSel');
  const laneAutoAssignEl = document.getElementById('laneAutoAssign');
  if (!countEl || !currentEl || !listEl || !laneSel) return;
  if (laneAutoAssignEl) laneAutoAssignEl.checked = laneAutoAssign;

  countEl.textContent = sharedLanes.length;
  if (!sharedLanes.length) {
    laneSel.innerHTML = '';
    currentEl.textContent = 'No lane available';
    listEl.innerHTML = '';
    return;
  }

  laneSel.innerHTML = sharedLanes.map((lane) => (
    `<option value="${esc(lane.name)}">${esc(lane.name)} • q:${lane.count || 0} • s:${lane.scanned_count || 0}</option>`
  )).join('');
  if (!sharedLanes.some((lane) => lane.name === selectedLane)) {
    selectedLane = sharedLanes[0].name;
    localStorage.setItem('nab_selected_lane', selectedLane);
  }
  laneSel.value = selectedLane;
  const lane = sharedLanes.find((x) => x.name === selectedLane) || sharedLanes[0];

  if (!lane || !lane.current) {
    currentEl.textContent = `Lane ${selectedLane}: no current item • scanned ${lane ? (lane.scanned_count || 0) : 0}`;
    listEl.innerHTML = '';
    return;
  }

  currentEl.textContent = `${lane.current.serial} • ${lane.current.user || 'anon'} • lane ${lane.name} • scanned ${lane.scanned_count || 0}`;
  listEl.innerHTML = (lane.items || []).slice(-6).reverse().map((q) => (
    `<div class="queue-item"><span>${esc(q.serial)}</span><span>${esc(q.updated_at || q.created_at || '')}</span></div>`
  )).join('');
}

function onLaneChange() {
  const laneSel = document.getElementById('laneSel');
  if (!laneSel) return;
  selectedLane = laneSel.value || 'General';
  localStorage.setItem('nab_selected_lane', selectedLane);
  renderQueue();
  renderFeed();
}

function onLaneAutoAssignChange() {
  const cb = document.getElementById('laneAutoAssign');
  laneAutoAssign = !!(cb && cb.checked);
  localStorage.setItem('nab_lane_auto_assign', laneAutoAssign ? '1' : '0');
}

function createLane() {
  if (!sock) return;
  const input = document.getElementById('laneInput');
  if (!input) return;
  const lane = (input.value || '').trim();
  if (!lane) return;
  selectedLane = lane;
  localStorage.setItem('nab_selected_lane', selectedLane);
  sock.emit('lane_create', { lane });
  input.value = '';
  renderFeed();
}

function showPinModal() {
  document.getElementById('pinModal').style.display = 'grid';
  setTimeout(() => document.getElementById('pinInput').focus(), 100);
}

function submitPin() {
  const input = document.getElementById('pinInput');
  const pin = (input.value || '').trim();
  if (!pin) {
    input.value = '';
    toast('Enter PIN');
    return;
  }
  saveJoinPin(pin);
  document.getElementById('pinModal').style.display = 'none';
  bootstrapApp();
}

function updatePerfNote(data) {
  if (!data) return;
  const mode = document.getElementById('perfMode');
  const load = document.getElementById('perfLoad');
  if (typeof data.next_delay_ms === 'number') {
    ocrDelayMs = data.next_delay_ms;
  }
  const status = data.status || 'ready';
  const label = {
    ready: 'Smart OCR ready',
    accepted: 'Frame accepted',
    server_busy: 'Queue balancing active',
    client_pending: 'Waiting on prior frame',
    no_text: 'Reading label…',
    no_match: 'Looking for serial…',
    low_confidence: 'Low confidence, rescanning…',
    idle: 'Smart OCR session idle',
    error: 'OCR retrying…',
    empty: 'Frame dropped'
  }[status] || 'Smart OCR active';
  const confText = typeof data.ocr_confidence === 'number'
    ? ` • conf ${Math.round(data.ocr_confidence * 100)}%`
    : '';
  mode.textContent = `${label}${confText} • next ${ocrDelayMs}ms`;
  load.textContent = `M4 OCR pool ${data.inflight || 0}/${data.capacity || 0} • ${data.active_scanners || 0} users • ${data.priority_scanners || 0} priority`;
}

function renderOcrDashboard(data) {
  if (!data) return;
  const active = data.active_scanners || 0;
  const inflight = data.inflight || 0;
  const capacity = data.capacity || 0;
  const matchRate = data.match_rate || 0;
  const confidencePct = data.avg_confidence_pct || 0;
  const utilization = capacity > 0 ? Math.min(100, Math.round((inflight / capacity) * 100)) : 0;

  document.getElementById('mActive').textContent = active;
  document.getElementById('mPool').textContent = `${inflight}/${capacity}`;
  document.getElementById('mLatency').textContent = `${data.avg_latency_ms || 0}ms`;
  document.getElementById('mMatch').textContent = `${confidencePct}%`;
  document.getElementById('mUtilText').textContent = `${utilization}%`;
  document.getElementById('mHitText').textContent = `${confidencePct}%`;
  document.getElementById('mUtilFill').style.width = `${utilization}%`;
  document.getElementById('mHitFill').style.width = `${confidencePct}%`;

  const status = document.getElementById('mStatus');
  if (!active) {
    status.className = 'status-pill status-idle';
    status.textContent = 'Idle';
  } else if (inflight >= capacity && capacity > 0) {
    status.className = 'status-pill status-busy';
    status.textContent = 'High Load';
  } else {
    status.className = 'status-pill status-active';
    status.textContent = 'Active';
  }

  const note = document.getElementById('mNote');
  const sessions = active;
  const priority = data.priority_scanners || 0;
  const users = data.connected_users || 0;
  const delay = data.recommended_delay_ms || 0;
  const frames = data.frames_accepted || 0;
  const matches = data.matches || 0;
  if (!users) {
    note.textContent = 'No live sessions connected.';
  } else if (!sessions) {
    note.textContent = `${users} live session${users === 1 ? '' : 's'} connected. Waiting for a scanner to start.`;
  } else {
    note.textContent = `${sessions} scanning, OCR ${confidencePct}% avg (min ${data.min_confidence_pct || 0}%), ${matches}/${frames} matches, pacing ${delay}ms.`;
  }
}

function drawOcrCropToCanvas(video, canvas, opts = {}) {
  const sourceWidth = video.videoWidth;
  const sourceHeight = video.videoHeight;
  const widthRatio = opts.widthRatio || 0.94;
  const heightRatio = opts.heightRatio || 0.32;
  const centerY = opts.centerY || 0.57;
  const qualityWidth = opts.qualityWidth || 1400;
  const adaptiveCenter = opts.adaptiveCenter !== false;

  const cropWidth = Math.floor(sourceWidth * widthRatio);
  const cropHeight = Math.floor(sourceHeight * heightRatio);
  const cropX = Math.floor((sourceWidth - cropWidth) / 2);
  const cropY = Math.max(0, Math.floor(sourceHeight * centerY - cropHeight / 2));
  const scale = Math.min(1, qualityWidth / cropWidth);

  const outW = Math.max(1, Math.floor(cropWidth * scale));
  const outH = Math.max(1, Math.floor(cropHeight * scale));
  canvas.width = outW;
  canvas.height = outH;

  const temp = document.createElement('canvas');
  temp.width = outW;
  temp.height = outH;
  const tctx = temp.getContext('2d', { willReadFrequently: true });
  tctx.drawImage(
    video,
    cropX, cropY, cropWidth, cropHeight,
    0, 0, outW, outH
  );

  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  // Auto-center serial text vertically within the crop band.
  if (adaptiveCenter && outH >= 48 && outW >= 160) {
    try {
      const img = tctx.getImageData(0, 0, outW, outH);
      const data = img.data;
      const rowScore = new Float32Array(outH);
      for (let y = 0; y < outH - 1; y++) {
        let score = 0;
        for (let x = 0; x < outW - 1; x += 2) {
          const i = (y * outW + x) * 4;
          const j = ((y + 1) * outW + x) * 4;
          const r = data[i], g = data[i + 1], b = data[i + 2];
          const r2 = data[j], g2 = data[j + 1], b2 = data[j + 2];
          const l1 = 0.299 * r + 0.587 * g + 0.114 * b;
          const l2 = 0.299 * r2 + 0.587 * g2 + 0.114 * b2;
          score += Math.abs(l1 - l2);
        }
        rowScore[y] = score;
      }
      // Smooth scores to avoid noisy spikes.
      const smooth = new Float32Array(outH);
      for (let y = 2; y < outH - 2; y++) {
        smooth[y] = rowScore[y - 2] * 0.12 + rowScore[y - 1] * 0.2 + rowScore[y] * 0.36 + rowScore[y + 1] * 0.2 + rowScore[y + 2] * 0.12;
      }
      let bestY = Math.floor(outH / 2);
      let best = -1;
      for (let y = Math.floor(outH * 0.12); y < Math.floor(outH * 0.88); y++) {
        if (smooth[y] > best) {
          best = smooth[y];
          bestY = y;
        }
      }
      const bandH = Math.max(Math.floor(outH * 0.62), 56);
      const top = Math.max(0, Math.min(outH - bandH, Math.floor(bestY - bandH / 2)));
      ctx.drawImage(temp, 0, top, outW, bandH, 0, 0, outW, outH);
    } catch (e) {
      ctx.drawImage(temp, 0, 0, outW, outH);
    }
  } else {
    ctx.drawImage(temp, 0, 0, outW, outH);
  }

  // Aggressive filters for metallic MacBook surfaces.
  ctx.filter = 'grayscale(1) contrast(1.9) brightness(1.08) saturate(0)';
  ctx.drawImage(canvas, 0, 0);

  // Adaptive thresholding emulation via high-contrast passes.
  ctx.filter = 'contrast(2.5) brightness(0.92)';
  ctx.drawImage(canvas, 0, 0);
  ctx.filter = 'contrast(1.6) brightness(1.02)';
  ctx.drawImage(canvas, 0, 0);
  ctx.filter = 'none';
}

function getUserColor(name) {
  if (!userColors[name]) {
    userColors[name] = colorPalette[colorIdx % colorPalette.length];
    colorIdx++;
  }
  return userColors[name];
}

if (!clientId) {
  clientId = (crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));
  localStorage.setItem('nab_scanner_client_id', clientId);
}

// ============================================
// Audio
// ============================================
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;
function beep(freq = 1200) {
  if (!audioCtx) audioCtx = new AudioCtx();
  const o = audioCtx.createOscillator();
  const g = audioCtx.createGain();
  o.connect(g); g.connect(audioCtx.destination);
  o.frequency.value = freq; g.gain.value = 0.12;
  o.start(); g.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.18);
  o.stop(audioCtx.currentTime + 0.18);
}
function beepDupe() { beep(400); setTimeout(() => beep(300), 150); }

// ============================================
// Socket.IO
// ============================================
function initSocket() {
  sock = io({
    auth: {
      client_id: clientId,
      name: userName || 'Anonymous',
      pin: joinPin || '',
      serial_profile: serialProfile
    }
  });

  sock.on('identity_status', (data) => {
    if (!data || !data.verified) {
      if (data && data.has_profile_on_device) showUserPinModal();
      else showAuthChoiceModal();
      return;
    }
    userName = data.name || 'Anonymous';
    if (data.client_id) {
      clientId = data.client_id;
      localStorage.setItem('nab_scanner_client_id', clientId);
    }
    localStorage.setItem('nab_scanner_name', userName);
    document.getElementById('userPill').innerHTML = '👤 ' + esc(userName);
    hideAllIdentityModals();
  });

  sock.on('auth_error', (data) => {
    const reason = data && data.reason ? data.reason : 'auth_error';
    if (reason === 'invalid_pin') {
      toast('PIN not found. Try again or create new user.');
      showUserPinModal();
      return;
    }
    if (reason === 'pin_in_use') {
      toast('PIN already used by another user. Choose different PIN.');
      showNameModal();
      return;
    }
    if (reason === 'missing_fields') {
      toast('Name and PIN are required.');
      showNameModal();
      return;
    }
    if (reason === 'rate_limit') {
      toast('Too many attempts. Wait 1 minute and try again.');
      return;
    }
    toast('Authentication failed.');
    showAuthChoiceModal();
  });

  sock.on('profile_updated', (data) => {
    if (data.success) {
      toast('✅ Profile updated');
      closeProfile();
    }
  });

  sock.on('bulk_import_result', (data) => {
    toast(`✅ Imported ${data.added}/${data.total} serials`);
    if (data.errors && data.errors.length > 0) {
      console.warn('Import errors:', data.errors);
    }
    loadCheckset();
  });

  sock.on('connect', () => {
    const connPill = document.getElementById('connPill');
    if (connPill) {
      connPill.style.background = 'var(--success-bg)';
      connPill.style.color = 'var(--success)';
    }
    sock.emit('session_heartbeat');
    sock.emit('scanner_state', { scanning: !!isScanning, serial_profile: serialProfile });
  });

  sock.on('connect_error', (err) => {
    const connPill = document.getElementById('connPill');
    if (connPill) {
      connPill.style.background = 'var(--warning-bg)';
      connPill.style.color = 'var(--warning)';
    }
    appBootstrapped = false;
    const msg = String((err && (err.message || err.data || '')) || '').toLowerCase();
    const invalidPin = msg.includes('unauthorized') || msg.includes('invalid') || msg.includes('rejected');
    if (invalidPin) {
      clearJoinPinCache();
      showPinModal();
      toast('Join PIN invalid. Enter PIN again.');
      return;
    }
    if (!joinPin) {
      showPinModal();
      const now = Date.now();
      if ((now - lastConnectErrorToastAt) > 4000) {
        toast('Join PIN required');
        lastConnectErrorToastAt = now;
      }
      return;
    }
    // Keep previously successful join PIN; do not force re-entry on transient network issues.
    const now = Date.now();
    if ((now - lastConnectErrorToastAt) > 6000) {
      toast('Connection lost. Retrying with saved join PIN…');
      lastConnectErrorToastAt = now;
    }
  });

  sock.on('disconnect', () => {
    const connPill = document.getElementById('connPill');
    if (connPill) {
      connPill.style.background = 'var(--danger-bg)';
      connPill.style.color = 'var(--danger)';
    }
  });

  sock.on('boxes_updated', (data) => {
    allBoxes = (data && typeof data === 'object') ? data : {};
    if (selectedBoxId && !allBoxes[selectedBoxId]) saveSelectedBox('');
    if (!selectedBoxId) {
      const joined = Object.values(allBoxes).find((b) => b && b.joined);
      if (joined && joined.id) saveSelectedBox(joined.id);
      else {
        const firstId = Object.keys(allBoxes)[0] || '';
        if (firstId) saveSelectedBox(firstId);
      }
    }
    if (pendingBoxJoinId && allBoxes[pendingBoxJoinId] && allBoxes[pendingBoxJoinId].joined) {
      pendingBoxJoinId = '';
    }
    renderBoxes();
    renderFeed();
  });

  sock.on('box_joined', (data) => {
    if (!data || !data.ok) {
      showBanner('Cannot join box right now.', 'warning');
      return;
    }
    pendingBoxJoinId = '';
    saveSelectedBox(data.box_id || '');
    renderBoxes();
    renderFeed();
  });

  sock.on('box_scan_update', (data) => {
    if (!data || !data.box_id) return;
    if (data.box_id === selectedBoxId && data.in_target) {
      flashFoundSerial(data.serial);
    }
  });

  sock.on('box_rejected', (data) => {
    const reason = data && data.reason ? data.reason : 'error';
    if (reason === 'box_closed') {
      showBanner('This box is closed. Reopen it to continue scanning.', 'warning');
      return;
    }
    if (reason === 'box_not_found') {
      showBanner('Selected box was removed.', 'warning');
      return;
    }
    showBanner('Box action rejected.', 'warning');
  });

  sock.on('qr_code_data', (data) => {
    document.getElementById('qrImage').src = 'data:image/png;base64,' + data.b64;
    document.getElementById('netUrlText').textContent = data.url;
  });

  // Real-time scan from any user
  sock.on('new_scan', (data) => {
    scanHistory.unshift(data);
    renderFeed();
    updateStats();
    if (data && data.box_id && data.box_id === selectedBoxId && data.box_in_target) {
      flashFoundSerial(data.serial);
    }

    // Flash + sound if from another user
    if (data.user !== userName) {
      flash('info');
      beep(800);
    }
  });

  sock.on('ocr_success', (data) => {
    if (!data || !data.serial) return;
    latestOcrSerial = data.serial;
    latestOcrAt = Date.now();
    latestOcrConfidence = typeof data.ocr_confidence === 'number' ? data.ocr_confidence : latestOcrConfidence;
    latestOcrCropImage = lastSubmittedCropImage || latestOcrCropImage || '';
    ocrAwaitingServer = false;
    photoProcessing = false;
    setProcessingState(processingMode || (data && data.source === 'photo' ? 'photo' : 'live'), false);
    if (data.source === 'photo' && !isScanning) stopPhotoOnlyStream();
    if (typeof data.next_delay_ms === 'number') ocrDelayMs = data.next_delay_ms;
    updatePerfNote({ status: 'accepted', ...data, accepted: true });
    onScan(data.serial, { confidence: latestOcrConfidence, source: 'ocr', cropImage: latestOcrCropImage });
    queueNextOcr();
  });

  sock.on('ocr_policy', (data) => {
    ocrAwaitingServer = false;
    setProcessingState(processingMode || (data && data.source === 'photo' ? 'photo' : 'live'), false);
    if (data && data.status === 'low_confidence') {
      maybeAutoRefocusByConfidence(data.ocr_confidence);
    }
    if (data && data.source === 'photo') {
      photoProcessing = false;
      if (!isScanning) stopPhotoOnlyStream();
      if (data.status === 'no_match' || data.status === 'no_text') {
        showBanner('📸 Photo uploaded but no serial found', 'warning');
      } else if (data.status === 'low_confidence') {
        const conf = typeof data.ocr_confidence === 'number' ? Math.round(data.ocr_confidence * 100) : 0;
        showBanner(`📸 Low OCR confidence ${conf}%, please rescan`, 'warning');
      } else if (data.status === 'error') {
        showBanner('⚠️ Photo processing failed', 'warning');
      }
    }
    updatePerfNote(data);
    queueNextOcr();
  });

  sock.on('save_rejected', (data) => {
    if (data && data.reason === 'non_apple_serial') {
      showBanner('Invalid Apple serial format (expect 10 or 12 chars).', 'warning');
      return;
    }
    if (data && data.reason === 'non_dell_serial') {
      showBanner('Invalid Dell Service Tag format (expect 7 chars).', 'warning');
      return;
    }
    if (data && data.reason === 'not_in_checklist') {
      showBanner('Serial not found in check.csv. Not added to list.', 'warning');
      return;
    }
    if (data && data.reason === 'box_closed') {
      showBanner('Box is closed. Reopen to add new scans.', 'warning');
      return;
    }
    if (data && data.reason === 'box_not_found') {
      showBanner('Box not found. Please reselect a box.', 'warning');
      return;
    }
    showBanner('Invalid serial number.', 'warning');
  });

  sock.on('lanes_data', (data) => {
    sharedLanes = Array.isArray(data) ? data : [];
    renderQueue();
  });

  sock.on('queue_data', (data) => {
    sharedLanes = Array.isArray(data) ? data : [];
    renderQueue();
  });

  sock.on('queue_rejected', (data) => {
    const reason = data && data.reason ? data.reason : 'invalid';
    if (reason === 'no_current_queue') {
      showBanner('No current queue item. Use Add Queue first.', 'warning');
      return;
    }
    if (reason === 'invalid_lane') {
      showBanner('Invalid lane name.', 'warning');
      return;
    }
    if (reason === 'non_apple_serial') {
      showBanner('Queue expects Apple serial format.', 'warning');
      return;
    }
    if (reason === 'non_dell_serial') {
      showBanner('Queue expects Dell Service Tag format.', 'warning');
      return;
    }
    showBanner('Queue update rejected.', 'warning');
  });

  sock.on('checklist_update', (data) => {
    const status = data && data.status ? data.status : 'invalid';
    if (status === 'added') {
      showBanner('Added to check.csv', 'success');
      loadCheckset();
      return;
    }
    if (status === 'already_exists') {
      showBanner('Already exists in check.csv', 'info');
      return;
    }
    if (status === 'non_apple_serial') {
      showBanner('Invalid Apple serial (expect 10 or 12 chars)', 'warning');
      return;
    }
    if (status === 'non_dell_serial') {
      showBanner('Invalid Dell Service Tag (expect 7 chars)', 'warning');
      return;
    }
    if (status === 'not_approved') {
      showBanner('Approve checkbox required before add', 'warning');
      return;
    }
    if (status === 'low_confidence') {
      showBanner('Need confidence > 99% to add', 'warning');
      return;
    }
    showBanner('Cannot add to check.csv', 'warning');
  });

  sock.on('checklist_changed', () => {
    loadCheckset();
  });

  sock.on('ocr_dashboard', (data) => {
    renderOcrDashboard(data);
  });

  sock.on('session_registered', (data) => {
    currentSessionId = data && data.sid ? data.sid : '';
  });

  // User list updates
  sock.on('users_update', (users) => {
    renderUsers(users);
    document.getElementById('connCount').textContent = users.length;
    document.getElementById('sOnline').textContent = users.length;
  });

  setInterval(() => {
    if (sock && sock.connected) sock.emit('session_heartbeat');
  }, 20000);

  // History load
  sock.on('history_data', (data) => {
    scanHistory = data;
    renderFeed();
    updateStats();
  });

  // Entry deleted
  sock.on('entry_deleted', (data) => {
    scanHistory = scanHistory.filter(h =>
      !(h.serial === data.serial && h.timestamp === data.timestamp)
    );
    renderFeed();
    updateStats();
  });

  // All cleared
  sock.on('all_cleared', () => {
    scanHistory = [];
    renderFeed();
    updateStats();
  });
}

// ============================================
// Identity & Profile
// ============================================
function showNameModal() {
  hideAllIdentityModals();
  const p1 = document.getElementById('regPinInput');
  const p2 = document.getElementById('regPinConfirmInput');
  if (p1) p1.value = '';
  if (p2) p2.value = '';
  document.getElementById('nameModal').style.display = 'grid';
  setTimeout(() => document.getElementById('nameInput').focus(), 150);
}

function showAuthChoiceModal() {
  hideAllIdentityModals();
  document.getElementById('authChoiceModal').style.display = 'grid';
}

function showUserPinModal() {
  hideAllIdentityModals();
  document.getElementById('userPinModal').style.display = 'grid';
  setTimeout(() => document.getElementById('userPinInput').focus(), 150);
}

function showProfileModal() {
  document.getElementById('profNameInput').value = userName;
  document.getElementById('profPinInput').value = '';
  document.getElementById('profileModal').style.display = 'grid';
  setTimeout(() => document.getElementById('profNameInput').focus(), 150);
}

function closeProfile() {
  document.getElementById('profileModal').style.display = 'none';
}

function hideAllIdentityModals() {
  document.getElementById('authChoiceModal').style.display = 'none';
  document.getElementById('nameModal').style.display = 'none';
  document.getElementById('userPinModal').style.display = 'none';
  document.getElementById('pinModal').style.display = 'none';
}

function registerUser() {
  const name = document.getElementById('nameInput').value.trim();
  const pin = document.getElementById('regPinInput').value.trim();
  const pinConfirm = (document.getElementById('regPinConfirmInput')?.value || '').trim();
  if (!name || !pin || !pinConfirm) {
    toast('Name and PIN required');
    return;
  }
  if (pin !== pinConfirm) {
    toast('PIN confirmation does not match');
    return;
  }
  
  if (sock) {
    sock.emit('register_user', { client_id: clientId, name, pin });
  }
}

function submitUserPin() {
  const input = document.getElementById('userPinInput');
  const pin = input.value.trim();
  if (!pin) return;
  
  userPin = pin;
  if (sock) {
    sock.emit('login_with_pin', { pin });
  }
}

function resetIdentity() {
  if (!confirm('Switch user? This will clear your current identity on this device.')) return;
  localStorage.removeItem('nab_scanner_name');
  localStorage.removeItem('nab_scanner_user_pin');
  userName = '';
  userPin = '';
  showAuthChoiceModal();
}

function updateProfile() {
  const name = document.getElementById('profNameInput').value.trim();
  const pin = document.getElementById('profPinInput').value.trim();
  if (!name) {
    toast('Name cannot be empty');
    return;
  }
  
  const payload = { name };
  if (pin) {
    payload.pin = pin;
    userPin = pin;
    localStorage.setItem('nab_scanner_user_pin', pin);
  }
  
  if (sock) {
    sock.emit('update_profile', payload);
  }
}

function changeName() {
  showProfileModal();
}

// Bulk Import
function showBulkImport() {
  document.getElementById('bulkImportInput').value = '';
  document.getElementById('bulkImportModal').style.display = 'grid';
  setTimeout(() => document.getElementById('bulkImportInput').focus(), 150);
}

function closeBulkImport() {
  document.getElementById('bulkImportModal').style.display = 'none';
}

function submitBulkImport() {
  const text = document.getElementById('bulkImportInput').value.trim();
  if (!text) return;
  if (!sock) return;
    sock.emit('bulk_import_checklist', { text, serial_profile: serialProfile });
  closeBulkImport();
  toast('Processing bulk import...');
}

// ============================================
// OCR (Text Recognition) Backend Relay
// ============================================
async function doOcrFrame() {
  if (!isScanning || ocrRunning || !sock || ocrAwaitingServer || scanHoldActive) return;
  const video = document.querySelector('#reader video');
  if (!video || video.readyState < 2) return;

  ocrRunning = true;
  try {
    const canvas = document.createElement('canvas');
    drawOcrCropToCanvas(video, canvas, {
      widthRatio: 0.94,
      heightRatio: 0.30,
      centerY: 0.56,
      qualityWidth: 1500
    });

    const b64 = canvas.toDataURL('image/jpeg', 0.72);
    lastSubmittedCropImage = b64;
    setProcessingState('live', true);
    ocrAwaitingServer = true;
    sock.emit('process_ocr_frame', { image: b64, serial_profile: serialProfile });
  } catch(e) {
    sock.emit('debug_log', { msg: 'ocr_canvas_error: ' + e.message });
    setProcessingState('live', false);
    ocrAwaitingServer = false;
  }

  ocrRunning = false;
}

function stopPhotoOnlyStream() {
  if (!photoOnlyStream) return;
  photoOnlyStream.getTracks().forEach(track => track.stop());
  photoOnlyStream = null;
}

async function getVideoElementForPhoto() {
  const activeVideo = document.querySelector('#reader video');
  if (activeVideo && activeVideo.readyState >= 2) return activeVideo;

  const reader = document.getElementById('reader');
  reader.innerHTML = '';
  const video = document.createElement('video');
  video.setAttribute('playsinline', 'true');
  video.muted = true;
  video.autoplay = true;
  video.style.width = '100%';
  video.style.borderRadius = '10px';
  reader.appendChild(video);

  photoOnlyStream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: currentFacingMode || 'environment' },
    audio: false
  });
  video.srcObject = photoOnlyStream;
  await video.play();
  await new Promise(resolve => setTimeout(resolve, 500));
  return video;
}

async function capturePhoto() {
  if (!sock || photoProcessing) return;

  try {
    const video = await getVideoElementForPhoto();
    if (!video || video.readyState < 2) {
      toast('⚠️ Camera not ready');
      return;
    }

    const canvas = document.createElement('canvas');
    drawOcrCropToCanvas(video, canvas, {
      widthRatio: 0.96,
      heightRatio: 0.24,
      centerY: 0.54,
      qualityWidth: 1700
    });

    photoProcessing = true;
    flash('info');
    lastSubmittedCropImage = canvas.toDataURL('image/jpeg', 0.82);
    setProcessingState('photo', true);
    showBanner('📸 Photo captured, processing on server…', 'info');
    sock.emit('process_photo_capture', { image: lastSubmittedCropImage, serial_profile: serialProfile });
  } catch (e) {
    photoProcessing = false;
    setProcessingState('photo', false);
    toast('⚠️ Photo capture failed');
  }
}

function queueNextOcr(delay = ocrDelayMs) {
  if (ocrTimer) clearTimeout(ocrTimer);
  if (!isScanning || scanHoldActive) return;
  ocrTimer = setTimeout(doOcrFrame, Math.max(150, delay || DEFAULT_OCR_DELAY_MS));
}

// ============================================
// Camera
// ============================================
let useFacingMode = false;
let currentFacingMode = 'environment';
let lastAutoRefocusAt = 0;

function getActiveVideoTrack() {
  const video = document.querySelector('#reader video');
  const stream = video && video.srcObject ? video.srcObject : photoOnlyStream;
  if (!stream || !stream.getVideoTracks) return null;
  const tracks = stream.getVideoTracks();
  return tracks && tracks.length ? tracks[0] : null;
}

async function refocusCamera(silent = false) {
  const track = getActiveVideoTrack();
  if (!track || typeof track.applyConstraints !== 'function') return false;
  try {
    const caps = typeof track.getCapabilities === 'function' ? (track.getCapabilities() || {}) : {};
    const advanced = [];
    if (Array.isArray(caps.focusMode) && caps.focusMode.includes('continuous')) {
      advanced.push({ focusMode: 'continuous' });
    } else if (Array.isArray(caps.focusMode) && caps.focusMode.includes('single-shot')) {
      advanced.push({ focusMode: 'single-shot' });
    }
    if (caps.zoom && typeof caps.zoom.max === 'number' && typeof caps.zoom.min === 'number') {
      const zoom = Math.max(caps.zoom.min, Math.min(caps.zoom.max, (caps.zoom.min + caps.zoom.max) / 2));
      advanced.push({ zoom });
    }
    if (!advanced.length) return false;
    await track.applyConstraints({ advanced });
    if (!silent) showBanner('Lens refocused', 'info');
    return true;
  } catch (e) {
    if (!silent) showBanner('Refocus not supported on this camera', 'warning');
    return false;
  }
}

function maybeAutoRefocusByConfidence(confidence) {
  const conf = typeof confidence === 'number' ? confidence : 0;
  if (conf >= 0.95) return;
  const now = Date.now();
  if ((now - lastAutoRefocusAt) < 2500) return;
  lastAutoRefocusAt = now;
  refocusCamera(true);
}

async function loadCameras() {
  try {
    cameras = await Html5Qrcode.getCameras();
    const sel = document.getElementById('cameraSel');
    if (cameras && cameras.length > 0) {
      // Add standard options first just in case
      let html = '<option value="environment">Back Camera</option><option value="user">Front Camera</option>';
      html += cameras.map((c,i) => `<option value="${c.id}">${c.label || 'Lens '+(i+1)}</option>`).join('');
      sel.innerHTML = html;
      const wants = cameraPreference || 'environment';
      if (wants === 'environment' || wants === 'user') {
        useFacingMode = true;
        currentFacingMode = wants;
        sel.value = wants;
      } else if (cameras.some((c) => c.id === wants)) {
        useFacingMode = false;
        selectedCam = wants;
        sel.value = wants;
      } else {
        useFacingMode = true;
        currentFacingMode = 'environment';
        sel.value = 'environment';
      }
    } else {
      throw new Error("No cameras");
    }
  } catch(e) { 
    // Fallback if permission rejected or unsupported before start
    const sel = document.getElementById('cameraSel');
    sel.innerHTML = '<option value="environment">Back Camera</option><option value="user">Front Camera</option>';
    useFacingMode = true;
    currentFacingMode = (cameraPreference === 'user') ? 'user' : 'environment';
    sel.value = currentFacingMode;
  }
}

function switchCamera() {
  const val = document.getElementById('cameraSel').value;
  if (val === 'environment' || val === 'user') {
    useFacingMode = true;
    currentFacingMode = val;
  } else {
    useFacingMode = false;
    selectedCam = val;
  }
  cameraPreference = val;
  localStorage.setItem('nab_camera_pref', cameraPreference);
  if (isScanning) stopScanner().then(() => setTimeout(startScanner, 300));
}

function isMobile() {
  return /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || window.innerWidth < 600;
}

function startScanner() {
  document.getElementById('reader').innerHTML = '';
  scanner = new Html5Qrcode('reader');
  
  let cfg;
  if (useFacingMode) {
      cfg = { facingMode: currentFacingMode };
  } else {
      cfg = selectedCam ? { deviceId: { exact: selectedCam } } : { facingMode: 'environment' };
  }
  
  // Adapt scan region proportionally 
  const mobile = isMobile();
  const qrboxFn = function(viewfinderWidth, viewfinderHeight) {
      let minEdgePercentage = 0.85; // 85% width
      let w = Math.floor(viewfinderWidth * minEdgePercentage);
      let h = 130; // Ideal height for 1D barcodes
      return { width: w, height: h };
  };
  
  scanner.start(cfg,
    { fps: mobile ? 10 : 15, 
      qrbox: qrboxFn,
      disableFlip: false,
      experimentalFeatures:{ useBarCodeDetectorIfSupported:true }
    },
    (decoded) => onScan(decoded, { confidence: 1, source: 'barcode' }), ()=>{}
  ).then(() => {
    isScanning = true;
    hideScanHold();
    ocrAwaitingServer = false;
    stopPhotoOnlyStream();
    const sBtn = document.getElementById('startBtn');
    sBtn.disabled = true;
    sBtn.classList.remove('btn-pulse');
    document.getElementById('stopBtn').disabled = false;
    document.getElementById('photoBtn').disabled = false;
    if (sock) sock.emit('scanner_state', { scanning: true, serial_profile: serialProfile });
    refocusCamera(true);
    queueNextOcr(200);
  }).catch(e => toast('⚠️ Camera: ' + e));
}

function stopScanner() {
  return new Promise(r => {
    if (ocrTimer) { clearTimeout(ocrTimer); ocrTimer = null; }
    hideScanHold();
    ocrAwaitingServer = false;
    setProcessingState('live', false);
    if (scanner && isScanning) {
      scanner.stop().then(() => {
        isScanning = false;
        if (sock) sock.emit('scanner_state', { scanning: false, serial_profile: serialProfile });
        const sBtn = document.getElementById('startBtn');
        sBtn.disabled = false;
        sBtn.classList.add('btn-pulse');
        document.getElementById('stopBtn').disabled = true;
        document.getElementById('photoBtn').disabled = false;
        r();
      }).catch(() => {
        isScanning = false;
        if (sock) sock.emit('scanner_state', { scanning: false, serial_profile: serialProfile });
        document.getElementById('photoBtn').disabled = false;
        r();
      });
    } else {
      document.getElementById('photoBtn').disabled = false;
      stopPhotoOnlyStream();
      r();
    }
  });
}

// ============================================
// Scan handler
// ============================================
function onScan(decoded, meta = {}) {
  if (typeof meta.confidence === 'number') {
    latestOcrConfidence = meta.confidence;
  }
  if (meta && typeof meta.cropImage === 'string' && meta.cropImage) {
    latestOcrCropImage = meta.cropImage;
  }
  refreshChecksetIfStale();
  if (scanHoldActive) return;
  const normalized = normalizeClientSerial(decoded, serialProfile);
  if (!isLikelySerialForProfile(normalized, serialProfile)) return;
  if (activeFunction === 'inventory' && allowedCheckSet.size > 0 && !allowedCheckSet.has(normalized)) {
    showBanner('Not in check.csv. Ignored.', 'warning');
    return;
  }

  const now = Date.now();
  if (normalized === lastCode && (now - lastCodeTime) < 3000) return;
  lastCode = normalized; lastCodeTime = now;

  const dupeCount = scanHistory.filter(h => h.serial === normalized).length;
  const isDupe = dupeCount > 0;
  const listedInCheckCsv = allowedCheckSet.size > 0 && allowedCheckSet.has(normalized);
  const listedInBoxCsv = (
    activeFunction === 'box'
    && !!selectedBoxId
    && !!allBoxes[selectedBoxId]
    && Array.isArray(allBoxes[selectedBoxId].target)
    && allBoxes[selectedBoxId].target.includes(normalized)
  );
  const isListedInCsv = listedInCheckCsv || listedInBoxCsv;

  if (isDupe) {
    beepDupe();
    flash('warning');
    if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
    showBanner('⚠️ Duplicate ×' + (dupeCount+1) + ': <span class="mono">' + esc(normalized) + '</span>', 'warning');
  } else {
    beep();
    flash('success');
    if (navigator.vibrate) navigator.vibrate(100);
    showBanner('🔍 Scanned: <span class="mono">' + esc(normalized) + '</span>', 'info');
  }

  if (scanner && isScanning) {
    scanner.pause(true);
  }

  const autosaveEnabled = !!document.getElementById('autosave')?.checked;
  if (autosaveEnabled && activeFunction === 'inventory') {
    emitSave(normalized, meta.source === 'barcode' ? 'camera' : 'camera', selectedLane, true);
    if (scanner && isScanning) {
      try { scanner.resume(); } catch(e) {}
      queueNextOcr(180);
    }
    return;
  }

  showScanHold(normalized, isDupe, true, latestOcrCropImage, isListedInCsv);
}

function emitSave(serial, method, lane = null, forceLane = false) {
  if (!sock) return;
  const payload = { 
    serial: serial.trim(), 
    method, 
    user: userName,
    box_id: activeFunction === 'box' ? selectedBoxId : null,
    ocr_confidence: latestOcrConfidence || 0,
    crop_image: latestOcrCropImage || '',
    serial_profile: serialProfile
  };
  if (forceLane && lane) payload.lane = lane;
  else if (laneAutoAssign) payload.lane = selectedLane;
  sock.emit('save_scan', payload);
}

function saveManual() {
  const input = document.getElementById('manualInput');
  const serial = (input.value || '').trim();
  if (!serial) return;
  
  if (activeFunction === 'import') {
    sock.emit('add_to_checklist', { serial, manual: true, serial_profile: serialProfile });
  } else {
    const payload = { 
      serial, 
      method: 'manual', 
      lane: selectedLane, 
      user: userName,
      box_id: activeFunction === 'box' ? selectedBoxId : null,
      ocr_confidence: 0,
      crop_image: '',
      serial_profile: serialProfile
    };
    sock.emit('save_scan', payload);
  }
  input.value = '';
  input.focus();
}

function deleteEntry(serial, timestamp) {
  const label = `${serial || ''}${timestamp ? ' @ ' + timestamp : ''}`;
  if (!confirm(`Delete scan ${label}?`)) return;
  sock.emit('delete_scan', { serial, timestamp });
}

function clearAll() {
  if (!confirm('Clear ALL scan history?')) return;
  sock.emit('clear_all');
}

function downloadCSV() { window.open('/download', '_blank'); }

function downloadLaneCSV() {
  const lane = selectedLane || 'General';
  window.open('/download/lane/' + encodeURIComponent(lane), '_blank');
}

function downloadCropManifest() {
  window.open('/download/crops-manifest', '_blank');
}

function openCropPreview(filename, meta = '') {
  if (!filename) return;
  previewCropFilename = filename;
  const modal = document.getElementById('cropPreviewModal');
  const img = document.getElementById('cropPreviewImage');
  const metaEl = document.getElementById('cropPreviewMeta');
  if (!modal || !img || !metaEl) return;
  metaEl.textContent = meta || filename;
  img.src = '/download/crop/' + encodeURIComponent(filename);
  modal.style.display = 'grid';
}

function closeCropPreview() {
  previewCropFilename = '';
  const modal = document.getElementById('cropPreviewModal');
  const img = document.getElementById('cropPreviewImage');
  if (img) img.src = '';
  if (modal) modal.style.display = 'none';
}

function downloadCropPreview() {
  if (!previewCropFilename) return;
  window.open('/download/crop/' + encodeURIComponent(previewCropFilename), '_blank');
}

function isTypingInInputTarget(target) {
  if (!target) return false;
  const tag = (target.tagName || '').toUpperCase();
  return tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable;
}

// ============================================
// QR Access
// ============================================
function showQr() {
  if (!sock) return;
  sock.emit('get_qr_code');
  document.getElementById('qrModal').style.display = 'grid';
}
function closeQr() {
  document.getElementById('qrModal').style.display = 'none';
}
function copyUrl() {
  const url = document.getElementById('netUrlText').textContent;
  if (!url) return;
  const temp = document.createElement('input');
  temp.value = url;
  document.body.appendChild(temp);
  temp.select();
  document.execCommand('copy');
  document.body.removeChild(temp);
  toast('URL copied to clipboard');
}

// ============================================
// Box Management
// ============================================
function showBoxCreate() {
  document.getElementById('boxNameInput').value = '';
  document.getElementById('boxCreateModal').style.display = 'grid';
  setTimeout(() => document.getElementById('boxNameInput').focus(), 150);
}
function closeBoxCreate() {
  document.getElementById('boxCreateModal').style.display = 'none';
}
function submitBoxCreate() {
  const name = document.getElementById('boxNameInput').value.trim();
  if (!name) return;
  sock.emit('box_create', { name, serial_profile: serialProfile });
  closeBoxCreate();
}

function showBoxImport() {
  document.getElementById('boxImportInput').value = '';
  document.getElementById('boxImportModal').style.display = 'grid';
  setTimeout(() => document.getElementById('boxImportInput').focus(), 150);
}
function closeBoxImport() {
  document.getElementById('boxImportModal').style.display = 'none';
}
function submitBoxImport() {
  if (!selectedBoxId) return;
  const text = document.getElementById('boxImportInput').value.trim();
  if (!text) return;
  sock.emit('box_import_target', { box_id: selectedBoxId, text, serial_profile: serialProfile });
  closeBoxImport();
}

function onBoxChange() {
  const sel = document.getElementById('boxSel');
  if (!sel) return;
  const nextId = sel.value || '';
  if (!nextId || !sock) return;
  saveSelectedBox(nextId);
  joinBox(nextId);
}

function joinBox(boxId) {
  if (!sock || !boxId) return;
  if (pendingBoxJoinId === boxId) return;
  const alreadyJoined = allBoxes[boxId] && allBoxes[boxId].joined;
  if (alreadyJoined && selectedBoxId === boxId) return;
  pendingBoxJoinId = boxId;
  sock.emit('box_join', { box_id: boxId });
}

function toggleBoxClosed() {
  if (!selectedBoxId || !sock) return;
  const box = allBoxes[selectedBoxId];
  if (!box) return;
  sock.emit('box_set_closed', { box_id: selectedBoxId, closed: !box.closed });
}

function downloadBoxSummary() {
  if (!selectedBoxId) return;
  window.open('/download/box/' + encodeURIComponent(selectedBoxId), '_blank');
}

function flashFoundSerial(serial) {
  if (!serial) return;
  lastBoxFoundSerial = serial;
  const el = document.getElementById('boxFoundFlash');
  if (!el) return;
  el.textContent = `✓ Found ${serial} in target list`;
  el.classList.add('show');
  if (boxFoundFlashTimer) clearTimeout(boxFoundFlashTimer);
  boxFoundFlashTimer = setTimeout(() => {
    el.classList.remove('show');
    el.textContent = 'Waiting for matched serial…';
  }, 2600);
}

function renderBoxes() {
  const sel = document.getElementById('boxSel');
  const lobby = document.getElementById('boxLobbyList');
  if (!sel || !lobby) return;
  
  const boxIds = Object.keys(allBoxes);
  if (boxIds.length === 0) {
    sel.innerHTML = '<option value="">No Boxes Create…</option>';
    lobby.innerHTML = '<div class="box-lobby-item"><div><strong>No boxes</strong><div class="box-lobby-meta">Create a box to start collaborative counting.</div></div></div>';
    document.getElementById('boxStatusCard').style.display = 'none';
    saveSelectedBox('');
    return;
  }
  
  const currentId = (selectedBoxId && allBoxes[selectedBoxId]) ? selectedBoxId : boxIds[0];
  saveSelectedBox(currentId);
  
  sel.innerHTML = boxIds.map(id => {
    const b = allBoxes[id];
    const pct = typeof b.progress_pct === 'number'
      ? b.progress_pct
      : ((b.target?.length || 0) ? Math.round(((b.scanned?.length || 0) / (b.target?.length || 1)) * 100) : 0);
    const lock = b.closed ? '🔒 ' : '';
    return `<option value="${id}" ${id === currentId ? 'selected' : ''}>${lock}${esc(b.name)} • ${pct}% • ${b.active_users || 0} online</option>`;
  }).join('');
  
  const box = allBoxes[currentId];
  if (!box) return;
  if (sock && !box.joined && activeFunction === 'box') {
    joinBox(currentId);
  }
  
  lobby.innerHTML = boxIds.map(id => {
    const b = allBoxes[id];
    const scanned = (b.scanned || []).length;
    const target = (b.target || []).length;
    const pct = target > 0 ? Math.round((scanned / target) * 100) : 0;
    const closed = b.closed ? '<span class="feed-badge fb-dupe">closed</span>' : '';
    const isActive = id === currentId ? 'active' : '';
    return `<div class="box-lobby-item ${isActive}" onclick="joinBox('${id}')">
      <div>
        <div style="font-size:12px;font-weight:700;">${esc(b.name)} ${closed}</div>
        <div class="box-lobby-meta">${scanned}/${target} • ${pct}% • ${b.active_users || 0} users</div>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); joinBox('${id}')">Join</button>
    </div>`;
  }).join('');

  document.getElementById('boxStatusCard').style.display = 'block';
  const scannedCount = (box.scanned || []).length;
  const targetCount = (box.target || []).length;
  const percent = targetCount > 0 ? Math.round((scannedCount / targetCount) * 100) : 0;
  
  document.getElementById('boxStatsText').textContent = `${scannedCount} / ${targetCount} scanned`;
  document.getElementById('boxPercentText').textContent = `${percent}%`;
  document.getElementById('boxProgressFill').style.width = `${percent}%`;
  const closeBtn = document.getElementById('boxCloseBtn');
  if (closeBtn) closeBtn.textContent = box.closed ? '🔓 Reopen Box' : '🔒 Close Box';

  const collabs = Array.isArray(box.collaborators) ? box.collaborators : [];
  const collabText = collabs.length
    ? collabs.map(c => `${c.name}${c.session_state === 'scanning' ? ' (scanning)' : ''}`).join(', ')
    : 'No collaborators yet.';
  const collabEl = document.getElementById('boxCollabs');
  if (collabEl) collabEl.textContent = `In this box: ${collabText}`;
  
  const missing = (box.target || []).filter(s => !(box.scanned || []).includes(s));
  const listEl = document.getElementById('boxMissingList');
  if (missing.length === 0 && targetCount > 0) {
    listEl.innerHTML = '<div style="color:var(--success); font-weight:700;">★ BOX COMPLETE</div>';
  } else if (targetCount === 0) {
    listEl.innerHTML = 'No target list imported.';
  } else {
    listEl.innerHTML = missing.map(s => {
      const hitClass = lastBoxFoundSerial && s === lastBoxFoundSerial ? ' style="color:var(--success);font-weight:700;"' : '';
      return `<div${hitClass}>• ${esc(s)}</div>`;
    }).join('');
  }
  
  document.getElementById('boxMissingTitle').textContent = `Missing Serials (${missing.length})`;
  renderFeed();
}

function toggleBoxMissing() {
  boxMissingVisible = !boxMissingVisible;
  document.getElementById('boxMissingList').style.display = boxMissingVisible ? 'block' : 'none';
  document.getElementById('boxMissingToggleBtn').textContent = boxMissingVisible ? 'Hide List' : 'Show List';
}

function deleteActiveBox() {
  if (!selectedBoxId) return;
  if (!confirm('Permanently delete this box and its count data?')) return;
  sock.emit('box_delete', { box_id: selectedBoxId });
}

// ============================================
// Rendering
// ============================================
function renderFeed() {
  const el = document.getElementById('feedList');
  const countEl = document.getElementById('feedCount');
  const q = document.getElementById('searchBox').value.toLowerCase().trim();
  const titleEl = document.getElementById('feedTitle');
  if (titleEl) {
    if (activeFunction === 'box' && selectedBoxId && allBoxes[selectedBoxId]) {
      titleEl.textContent = `⚡ Live Feed • Box ${allBoxes[selectedBoxId].name || selectedBoxId}`;
    } else {
      titleEl.textContent = '⚡ Live Feed';
    }
  }

  if (activeFunction === 'box') {
    const box = selectedBoxId ? allBoxes[selectedBoxId] : null;
    if (!box) {
      if (countEl) countEl.textContent = '0 items';
      el.innerHTML = '<div class="feed-empty"><div class="icon">📦</div>Select a box to view scanned serials</div>';
      return;
    }
    const scans = Array.isArray(box.recent_scans) ? [...box.recent_scans].reverse() : [];
    const filtered = q
      ? scans.filter((s) =>
          (s.serial || '').toLowerCase().includes(q)
          || (s.user || '').toLowerCase().includes(q)
          || (s.timestamp || '').toLowerCase().includes(q)
        )
      : scans;
    if (!filtered.length) {
      if (countEl) countEl.textContent = '0 items';
      el.innerHTML = '<div class="feed-empty"><div class="icon">📦</div>No scanned serials in this box yet</div>';
      return;
    }
    if (countEl) countEl.textContent = `${filtered.length} items`;
    el.innerHTML = filtered.slice(0, 400).map((s) => {
      const color = getUserColor(s.user || 'anon');
      const initials = (s.user || '?').slice(0,2).toUpperCase();
      const targetBadge = s.in_target
        ? `<span class="feed-badge fb-check">✓ target</span>`
        : `<span class="feed-badge fb-dupe">extra</span>`;
      const dupeBadge = s.duplicate_in_box
        ? `<span class="feed-badge fb-dupe">duplicate</span>`
        : '';
      const methodBadge = s.method === 'manual'
        ? `<span class="feed-badge fb-manual">manual</span>`
        : `<span class="feed-badge fb-camera">camera</span>`;
      const cropThumb = s.crop_latest_file
        ? `<img class="feed-thumb" src="/download/crop/${encodeURIComponent(s.crop_latest_file)}" alt="crop" onclick="openCropPreview('${esc(s.crop_latest_file)}','${esc((s.serial || '-') + ' • ' + (s.timestamp || ''))}')">`
        : '';
      return `
      <div class="feed-item">
        <div class="feed-avatar" style="background:${color}20;color:${color}">${initials}</div>
        ${cropThumb}
        <div class="feed-content">
          <div class="feed-serial">${s.in_target ? '<span class="feed-check-icon">✔</span>' : ''}${esc(s.serial || '-')}</div>
          <div class="feed-meta">
            <span>${esc(s.user || 'anon')}</span>
            <span>${esc(s.timestamp || '')}</span>
            ${methodBadge}
            ${targetBadge}
            ${dupeBadge}
          </div>
        </div>
      </div>`;
    }).join('');
    return;
  }

  const activeLane = selectedLane || 'General';
  const grouped = new Map();
  for (const h of scanHistory) {
    if (!h || !h.serial) continue;
    const rowLane = h.lane || 'General';
    if (activeLane !== 'All' && rowLane !== activeLane) continue;
    const key = h.serial;
    if (!grouped.has(key)) {
      grouped.set(key, {
        serial: h.serial,
        latestTimestamp: h.timestamp,
        latestMethod: h.method || 'manual',
        latestUser: h.user || 'anon',
        lane: rowLane,
        checked: !!h.checked,
        cropLatestFile: h.crop_latest_file || '',
        ocrConfidence: typeof h.ocr_confidence === 'number' ? h.ocr_confidence : 0,
        users: new Set([h.user || 'anon']),
        count: 1,
      });
      continue;
    }
    const g = grouped.get(key);
    g.count += 1;
    g.users.add(h.user || 'anon');
    if (!g.cropLatestFile && h.crop_latest_file) g.cropLatestFile = h.crop_latest_file;
    if (typeof h.ocr_confidence === 'number' && h.ocr_confidence > g.ocrConfidence) g.ocrConfidence = h.ocr_confidence;
  }

  let items = Array.from(grouped.values());
  if (q) {
    items = items.filter(g =>
      g.serial.toLowerCase().includes(q)
    );
  }

    if (!items.length) {
      if (countEl) countEl.textContent = '0 items';
      const laneHint = (!q && activeLane !== 'All' && !laneAutoAssign)
        ? `No scans in lane ${esc(activeLane)}. Enable "Link scans to selected lane" to save into this lane.`
        : `No scans in lane ${esc(activeLane)}`;
      el.innerHTML = `<div class="feed-empty"><div class="icon">${q?'🔍':'📡'}</div>${q?'No matches':laneHint}</div>`;
      return;
    }
    if (countEl) countEl.textContent = `${items.length} items`;

  el.innerHTML = items.map((g) => {
    const color = getUserColor(g.latestUser || 'anon');
    const initials = (g.latestUser || '?').slice(0,2).toUpperCase();
    const countBadge = g.count > 1
      ? `<span class="feed-badge fb-dupe" style="margin-left:4px">×${g.count}</span>`
      : '';
    const checkedBadge = g.checked ? `<span class="feed-badge fb-check" style="margin-left:6px">✓ check.csv</span>` : '';
    const confBadge = g.ocrConfidence > 0
      ? `<span class="feed-badge fb-camera" style="margin-left:6px">${Math.round(g.ocrConfidence * 100)}%</span>`
      : '';
    const cropThumb = g.cropLatestFile
      ? `<img class="feed-thumb" src="/download/crop/${encodeURIComponent(g.cropLatestFile)}" alt="crop" onclick="openCropPreview('${esc(g.cropLatestFile)}','${esc((g.serial || '-') + ' • ' + (g.latestTimestamp || ''))}')">`
      : '';
    return `
      <div class="feed-item">
        <div class="feed-avatar" style="background:${color}20;color:${color}">${initials}</div>
        ${cropThumb}
        <div class="feed-content">
          <div class="feed-serial">${g.checked ? '<span class="feed-check-icon">✔</span>' : ''}${esc(g.serial)}${countBadge}${checkedBadge}${confBadge}</div>
        </div>
        <button class="feed-delete" onclick="deleteEntry('${esc(g.serial)}','${g.latestTimestamp}')" title="Delete latest">🗑</button>
      </div>`;
  }).join('');
}

function renderUsers(users) {
  const el = document.getElementById('usersList');
  if (!users.length) {
    el.innerHTML = '<div class="feed-empty"><div class="icon">👤</div>No users</div>';
    return;
  }
  el.innerHTML = users.map(u => {
    const color = getUserColor(u.name);
    const isMe = u.sid === currentSessionId;
    const statusClass = u.session_state === 'scanning'
      ? 'ub-scanning'
      : u.session_state === 'photo'
        ? 'ub-photo'
        : u.session_state === 'manual'
          ? 'ub-manual'
          : 'ub-idle';
    const statusLabel = u.session_state || 'idle';
    const boxInfo = u.box_id ? ` • box ${u.box_id}` : '';
    return `
      <div class="user-row">
        <span class="user-dot" style="background:${color}"></span>
        <div>
          <div class="user-name">
            ${esc(u.name)}
            ${isMe?'<span class="user-you">YOU</span>':''}
            <span class="user-badge ${statusClass}">${esc(statusLabel)}</span>
          </div>
          <div class="user-info">${u.ip} &bull; joined ${u.connected_at} &bull; active ${u.last_active_at || u.connected_at}${boxInfo}</div>
        </div>
      </div>`;
  }).join('');
}

function updateStats() {
  const now = new Date();
  const today = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`;
  const todayN = scanHistory.filter(h => h.timestamp.startsWith(today)).length;
  const unique = new Set(scanHistory.map(h => h.serial));
  document.getElementById('sTotal').textContent = scanHistory.length;
  document.getElementById('sToday').textContent = todayN;
  document.getElementById('sUnique').textContent = unique.size;
  document.getElementById('sDupes').textContent = scanHistory.length - unique.size;
}

function showBanner(html, type) {
  const el = document.getElementById('banner');
  el.className = 'banner show ' + type;
  el.innerHTML = html;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3000);
}

function flash(type) {
  const el = document.getElementById('scanFlash');
  const colors = { success:'rgba(16,185,129,0.06)', warning:'rgba(245,158,11,0.06)', info:'rgba(59,130,246,0.06)' };
  el.style.background = colors[type] || colors.info;
  el.classList.add('on');
  setTimeout(() => el.classList.remove('on'), 200);
}

function toast(msg) {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = 'toast-msg';
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function normalizeClientSerial(value, profile = serialProfile) {
  const p = normalizeSerialProfile(profile);
  const cleaned = (value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (p === 'dell') {
    if (cleaned.startsWith('ST') && cleaned.length >= 9) return cleaned.slice(2, 9);
    return cleaned;
  }
  let out = cleaned.replace(/O/g, '0').replace(/I/g, '1');
  // Apple barcode may contain a leading "S" that is not part of the serial.
  if (out.startsWith('S') && !out.startsWith('SE') && !out.startsWith('SN') && (out.length === 11 || out.length === 13)) {
    const tail = out.slice(1);
    const hasLetter = /[A-Z]/.test(tail);
    const hasDigit = /\\d/.test(tail);
    if (hasLetter && hasDigit) out = tail;
  }
  return out;
}

function isLikelySerialForProfile(value, profile = serialProfile) {
  const p = normalizeSerialProfile(profile);
  const serial = normalizeClientSerial(value, p);
  if (p === 'dell') {
    return serial.length === 7
      && /^[A-Z0-9]{7}$/.test(serial)
      && /[A-Z]/.test(serial)
      && /\\d/.test(serial)
      && !serial.startsWith('ST')
      && !serial.startsWith('EX');
  }
  return (serial.length === 10 || serial.length === 12)
    && /[A-Z]/.test(serial)
    && /\\d/.test(serial);
}

async function loadCheckset(notify = false) {
  try {
    const r = await fetch(`/checkset?profile=${encodeURIComponent(serialProfile)}`, { cache: 'no-store' });
    const data = await r.json();
    const values = Array.isArray(data.serials) ? data.serials : [];
    allowedCheckSet = new Set(values.map(v => normalizeClientSerial(v, serialProfile)));
    checksetLastLoadedAt = Date.now();
    const countEl = document.getElementById('checkCount');
    const previewEl = document.getElementById('checkPreview');
    if (countEl) countEl.textContent = String(values.length);
    if (previewEl) previewEl.textContent = values.slice(0, 12).join('  ') || '-';
    if (notify) toast(`Loaded check.csv (${values.length})`);
  } catch (e) {
    allowedCheckSet = new Set();
    if (notify) toast('Failed to load check.csv');
  }
}

async function refreshChecksetIfStale(maxAgeMs = 20000) {
  if (!checksetLastLoadedAt || (Date.now() - checksetLastLoadedAt) > maxAgeMs) {
    await loadCheckset();
  }
}

// ============================================
// Init
// ============================================
async function bootstrapApp() {
  if (appBootstrapped) return;
  
  // Handle auto-login via URL param ?p=... (JOIN_PIN)
  const urlParams = new URLSearchParams(window.location.search);
  const p = urlParams.get('p');
  if (p && !joinPin) {
    saveJoinPin(p);
  }

  if (!joinPin) {
    showPinModal();
    return;
  }

  appBootstrapped = true;
  if (userName) {
    document.getElementById('userPill').innerHTML = '👤 ' + esc(userName);
  }
  await loadCameras();
  await loadCheckset();
  initSocket();
  updateFunctionModeUI();
  renderQueue();
  setInterval(() => { loadCheckset(); }, 30000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') loadCheckset();
  });
  document.addEventListener('keydown', (event) => {
    if (isTypingInInputTarget(event.target)) return;
    const cropModal = document.getElementById('cropPreviewModal');
    const cropOpen = cropModal && cropModal.style.display === 'grid';
    if (event.key === 'Escape') {
      if (cropOpen) {
        closeCropPreview();
        event.preventDefault();
        return;
      }
      if (scanHoldActive) {
        ignoreScanHold();
        event.preventDefault();
      }
      return;
    }
    if (event.key === 'Enter' && scanHoldActive && !cropOpen) {
      continueAfterScan();
      event.preventDefault();
    }
  });
  toast('✅ Native M4 OCR Link Active');

  // Clean URL if we used a PIN
  if (p) {
    const cleanUrl = window.location.protocol + "//" + window.location.host + window.location.pathname;
    window.history.replaceState({path:cleanUrl}, '', cleanUrl);
  }
}

function init() {
  loadJoinPinCache();
  loadSelectedBoxCache();
  if (joinPin === '2026') {
    bootstrapApp();
    return;
  }
  showPinModal();
}
init();
</script>
</body>
</html>
"""


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
    return LEGACY_INDEX_HTML


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Local scanner UI should never be cached by intermediaries.
    if request.path == "/" or request.path.startswith("/checkset"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/download")
def download():
    if not os.path.isfile(CSV_FILE):
        return "No data", 404
    with open(CSV_FILE) as f:
        content = f.read()
    return Response(content, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=serial_numbers.csv"})


@app.route("/checkset")
def checkset():
    profile = normalize_serial_profile(request.args.get("profile", DEFAULT_SERIAL_PROFILE))
    load_check_serials()
    serials = sorted(check_serials_cache_by_profile.get(profile, set()))
    return jsonify({"count": len(serials), "serials": serials})


@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "users_online": len(connected_users),
        "active_scanners": get_active_scanner_count(),
        "ocr_inflight": ocr_inflight,
        "ocr_capacity": OCR_MAX_INFLIGHT,
        "boxes": len(box_registry),
    })


@app.route("/download/lane/<path:lane_name>")
def download_lane(lane_name):
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


# ============================================
# Socket.IO Events
# ============================================

@socketio.on("connect")
def on_connect(auth=None):
    ip = request.remote_addr or "unknown"
    auth = auth or {}
    client_id = (auth.get("client_id") or "").strip()
    serial_profile = normalize_serial_profile(auth.get("serial_profile", DEFAULT_SERIAL_PROFILE))
    
    # Allow initial connection; verification via PIN pad
    connected_users[request.sid] = {
        "name": "Anonymous",
        "ip": ip,
        "connected_at": now_hms(),
        "last_active_at": now_hms(),
        "last_seen_ts": time.time(),
        "client_id": client_id,
        "serial_profile": serial_profile,
        "session_state": "idle",
        "verified": False
    }
    
    if client_id:
        client_session_index[client_id] = request.sid
        
    client_ocr_state[request.sid] = {
        "scanning": False,
        "started_scanning_at": 0.0,
        "pending": False,
        "last_submit": 0.0,
        "last_result": "",
        "last_result_at": 0.0,
        "recent_latencies": deque(maxlen=6),
        "serial_profile": serial_profile,
    }

    emit("identity_status", {
        "verified": False,
        "mode": "pin_required"
    }, to=request.sid)

    broadcast_users()
    
    # Send history to the new client
    rows = read_csv_rows()
    sync_lane_state_from_rows(rows)
    history = [{
        "serial": r.get("Serial Number",""),
        "timestamp": r.get("Timestamp",""),
        "method": r.get("Scanned By",""),
        "user": r.get("User",""),
        "lane": r.get("Lane","General") or "General",
        "checked": matches_checklist_any(r.get("Serial Number","")),
    } for r in rows]
    history.reverse()
    emit("history_data", history)
    emit("lanes_data", lanes_snapshot(), to=request.sid)
    emit_boxes_updated(request.sid)
    emit_ocr_policy(request.sid, status="ready", accepted=True)
    emit("session_registered", {"sid": request.sid}, to=request.sid)
    emit("ocr_dashboard", get_ocr_dashboard_snapshot())
    broadcast_ocr_dashboard()


@socketio.on("authenticate_pin")
def on_authenticate_pin(data):
    ip = request.remote_addr or "unknown"
    pin = str(data.get("pin", "")).strip()
    if not is_reasonable_pin(pin):
        emit("auth_result", {"success": False, "reason": "invalid_pin"}, to=request.sid)
        return
    
    if not check_auth_rate_limit(ip):
        emit("auth_result", {"success": False, "reason": "rate_limit"}, to=request.sid)
        return

    # Check for Session JOIN PIN
    if pin == JOIN_PIN:
        record_auth_success(ip)
        emit("auth_result", {"success": True, "type": "session"}, to=request.sid)
        return

    # Check for User Profile PIN
    load_user_registry()
    matched_client_id, matched_profile = find_user_by_pin(pin)
    if matched_client_id:
        record_auth_success(ip)
        if request.sid in connected_users:
            connected_users[request.sid]["name"] = matched_profile.get("name", "Anonymous")
            connected_users[request.sid]["verified"] = True
            connected_users[request.sid]["client_id"] = matched_client_id
            
        emit("auth_result", {
            "success": True, 
            "type": "user",
            "user": {"name": matched_profile.get("name", "Anonymous")}
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
    ip = request.remote_addr or "unknown"
    if not check_auth_rate_limit(ip):
        emit("auth_error", {"reason": "rate_limit"}, to=request.sid)
        return
    client_id = data.get("client_id")
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
    existing_client_id, _ = find_user_by_pin(pin, exclude_client_id=client_id)
    if existing_client_id:
        record_auth_failure(ip)
        emit("auth_error", {"reason": "pin_in_use"}, to=request.sid)
        return
    
    save_user_to_registry(client_id, name, pin)
    record_auth_success(ip)
    if request.sid in connected_users:
        connected_users[request.sid]["name"] = name
        connected_users[request.sid]["verified"] = True
        connected_users[request.sid]["client_id"] = client_id
        box_id = sid_box_membership.get(request.sid)
        if box_id and box_id in box_live_presence and request.sid in box_live_presence[box_id]:
            box_live_presence[box_id][request.sid]["name"] = name
    
    emit("identity_status", {"verified": True, "name": name, "client_id": client_id}, to=request.sid)
    broadcast_users()
    emit_boxes_updated()


@socketio.on("login_with_pin")
def on_login_with_pin(data):
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
    client_session_index[matched_client_id] = request.sid
    emit("identity_status", {
        "verified": True,
        "name": matched_profile.get("name", "Anonymous"),
        "client_id": matched_client_id,
    }, to=request.sid)
    broadcast_users()
    emit_boxes_updated()


@socketio.on("update_profile")
def on_update_profile(data):
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
            user_registry[client_id]["name"] = name
            connected_users[request.sid]["name"] = name
        if pin:
            if not is_reasonable_pin(pin):
                emit("auth_error", {"reason": "invalid_pin"}, to=request.sid)
                return
            existing_client_id, _ = find_user_by_pin(pin, exclude_client_id=client_id)
            if existing_client_id:
                emit("auth_error", {"reason": "pin_in_use"}, to=request.sid)
                return
            user_registry[client_id]["pin_hash"] = hash_pin(pin)
            user_registry[client_id].pop("pin", None)
        
        try:
            with data_lock:
                atomic_write_json(USERS_FILE, user_registry)
        except Exception as e:
            print(f"-> Error saving user registry update: {e}")
        emit("identity_status", {
            "verified": True,
            "name": user_registry[client_id]["name"],
            "client_id": client_id,
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


@socketio.on("scanner_state")
def on_scanner_state(data):
    state = client_ocr_state.get(request.sid)
    if state is None:
        return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
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
    emit_ocr_policy(request.sid, status="ready" if scanning else "idle", accepted=True)
    broadcast_ocr_dashboard()


@socketio.on("process_photo_capture")
def on_process_photo_capture(data):
    global ocr_inflight
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
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile") or state.get("serial_profile"))
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
    ensure_csv_schema()
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    if request.sid in connected_users:
        connected_users[request.sid]["serial_profile"] = serial_profile
    serial = normalize_serial_candidate(data.get("serial", "").strip(), serial_profile)
    method = data.get("method", "manual")
    user = data.get("user", "Anonymous")
    ocr_confidence = float((data or {}).get("ocr_confidence", 0.0) or 0.0)
    crop_image = (data or {}).get("crop_image")
    lane = ensure_lane(data.get("lane"))
    active_box = str((data or {}).get("box_id") or "").strip()
    if active_box:
        if active_box not in box_registry:
            emit("save_rejected", {"serial": serial, "reason": "box_not_found"}, to=request.sid)
            return
        if box_registry[active_box].get("closed"):
            emit("save_rejected", {"serial": serial, "reason": "box_closed"}, to=request.sid)
            return
    if not allow_serial(serial, serial_profile):
        emit("save_rejected", {
            "serial": serial,
            "reason": f"non_{serial_profile}_serial" if serial_profile in {"apple", "dell"} else "invalid_serial",
        }, to=request.sid)
        return
    if not matches_checklist(serial, serial_profile):
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


@socketio.on("queue_add")
def on_queue_add(data):
    global lane_next_id
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
    lane = normalize_lane_name((data or {}).get("lane"))
    if not lane:
        emit("queue_rejected", {"reason": "invalid_lane"}, to=request.sid)
        return
    ensure_lane(lane)
    broadcast_queue()


@socketio.on("add_to_checklist")
def on_add_to_checklist(data):
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
    with data_lock:
        with open(CSV_FILE, "w", newline="") as f:
            csv.writer(f).writerow(CSV_HEADERS)
        secure_chmod(CSV_FILE)
    sync_lane_state_from_rows([])
    broadcast_queue()
    write_lane_csv_files([])
    socketio.emit("all_cleared")

@socketio.on("bulk_import_checklist")
def on_bulk_import_checklist(data):
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
    local_ip = get_local_ip()
    port = 5000 # Could pull from global but hardcoded for now
    force_http = os.environ.get("DISABLE_SSL", "").lower() in {"1", "true", "yes", "on"}
    cert = os.path.join(BASE_DIR, "cert.pem")
    key = os.path.join(BASE_DIR, "key.pem")
    has_ssl = (not force_http) and os.path.isfile(cert) and os.path.isfile(key)
    scheme = "https" if has_ssl else "http"
    
    # Include PIN if possible
    pin_param = f"?p={JOIN_PIN}" if JOIN_PIN else ""
    net_url = f"{scheme}://{local_ip}:{port}/{pin_param}"
    
    qr_b64 = get_qr_base64(net_url)
    emit("qr_code_data", {"url": net_url, "b64": qr_b64}, to=request.sid)


@socketio.on("box_create")
def on_box_create(data):
    name = (data or {}).get("name", "").strip()
    if not name: return
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    box_id = str(int(time.time() * 1000))
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
    box_id = (data or {}).get("box_id")
    text = (data or {}).get("text", "").strip()
    if not box_id or box_id not in box_registry or not text: return
    if box_registry[box_id].get("closed"):
        emit("box_rejected", {"reason": "box_closed", "box_id": box_id}, to=request.sid)
        return
    
    serial_profile = get_sid_serial_profile(request.sid, (data or {}).get("serial_profile"))
    raw_list = re.split(r"[\n,\s]+", text)
    new_targets = []
    for raw in raw_list:
        serial = normalize_serial_candidate(raw.strip(), serial_profile)
        if serial and serial not in box_registry[box_id]["target"]:
            new_targets.append(serial)
    
    box_registry[box_id]["target"].extend(new_targets)
    box_registry[box_id]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_box_registry()
    emit_boxes_updated()


@socketio.on("box_delete")
def on_box_delete(data):
    box_id = (data or {}).get("box_id")
    if box_id in box_registry:
        for sid, joined_box in list(sid_box_membership.items()):
            if joined_box == box_id:
                leave_box_for_sid(sid, notify=False)
                socketio.emit("box_joined", {"ok": True, "box_id": None}, to=sid)
        del box_registry[box_id]
        save_box_registry()
        emit_boxes_updated()


@socketio.on("box_join")
def on_box_join(data):
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
    leave_box_for_sid(request.sid, notify=True)
    emit("box_joined", {"ok": True, "box_id": None}, to=request.sid)


@socketio.on("box_set_closed")
def on_box_set_closed(data):
    box_id = str((data or {}).get("box_id") or "").strip()
    closed = bool((data or {}).get("closed"))
    if not box_id or box_id not in box_registry:
        emit("box_rejected", {"reason": "box_not_found", "box_id": box_id}, to=request.sid)
        return
    box_registry[box_id]["closed"] = closed
    box_registry[box_id]["last_active"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_box_registry()
    emit_boxes_updated()


@socketio.on("get_boxes")
def on_get_boxes():
    load_box_registry()
    emit_boxes_updated(request.sid)


@socketio.on('debug_log')
def handle_debug_log(data):
    print(f"-> CLIENT DEBUG [{request.sid}]:", data)

frame_counts = {}

@socketio.on('process_ocr_frame')
def handle_ocr_frame(data):
    global ocr_inflight
    sid = request.sid
    state = client_ocr_state.get(sid)
    if state is None:
        emit_ocr_policy(sid, status="idle", accepted=False, next_delay_ms=get_recommended_ocr_interval_ms(250))
        return

    if not state.get("scanning"):
        emit_ocr_policy(sid, status="idle", accepted=False, next_delay_ms=get_client_ocr_interval_ms(state, 250))
        return
    serial_profile = get_sid_serial_profile(sid, (data or {}).get("serial_profile") or state.get("serial_profile"))
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
        ocr_result = tpool.execute(recognize_text_from_binary, img_data, serial_profile)
        text = (ocr_result or {}).get("text", "") if isinstance(ocr_result, dict) else (ocr_result or "")
        confidence = float((ocr_result or {}).get("confidence", 0.0)) if isinstance(ocr_result, dict) else 0.0
        serial_hint = normalize_serial_candidate((ocr_result or {}).get("serial_hint", ""), serial_profile) if isinstance(ocr_result, dict) else ""
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
        ocr_metrics["no_text"] += 1
        emit_ocr_policy(sid, status="no_text", accepted=True, next_delay_ms=next_delay_ms, ocr_confidence=0.0)
        broadcast_ocr_dashboard()
        return

    if confidence <= OCR_MIN_CONFIDENCE:
        emit_ocr_policy(
            sid,
            status="low_confidence",
            accepted=False,
            next_delay_ms=get_client_ocr_interval_ms(state, 220),
            ocr_confidence=confidence,
        )
        broadcast_ocr_dashboard()
        return

    possible_serial = serial_hint or extract_serial_from_text(text, serial_profile)
    if possible_serial and allow_serial(possible_serial, serial_profile):
        duplicate_gap_ok = (
            possible_serial != state.get("last_result")
            or (time.time() - state.get("last_result_at", 0.0)) > 2.0
        )
        if duplicate_gap_ok:
            state["last_result"] = possible_serial
            state["last_result_at"] = time.time()
            ocr_metrics["matches"] += 1
            print(f"-> OCR MATCH: '{possible_serial}' for client {sid} in {latency_ms}ms")
            emit_ocr_success(sid, possible_serial, next_delay_ms=next_delay_ms, ocr_confidence=confidence, serial_profile=serial_profile)
            broadcast_ocr_dashboard()
            return

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


class QuietWSGI:
    """Suppress noisy SSL handshake/client disconnect lines from eventlet WSGI log."""
    def write(self, _msg):
        return

    def flush(self):
        return


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
    if has_ssl:
        print(f"  \033[1;35m→  SSL:\033[0m      ✅ HTTPS enabled")
    print("  " + "─" * 48)

    if has_ssl:
        print()
        print("  \033[1;33m💡 Accept certificate warning on first visit.\033[0m")
    else:
        print()
        print("  \033[1;33m💡 HTTP mode enabled. Use a trusted tunnel for phone camera access.\033[0m")

    if HAS_QRCODE:
        print()
        print("  \033[1mScan QR to open on phone/tablet:\033[0m")
        print()
        print_qr_terminal(net_url)
    print()

    try:
        ensure_csv_schema()
        load_check_serials()
        ensure_crop_storage()
        load_user_registry()
        load_box_registry()
        rows = read_csv_rows()
        sync_lane_state_from_rows(rows)
        write_lane_csv_files(rows)
        for p in (CSV_FILE, CHECK_FILE, USERS_FILE, BOXES_FILE, CROPS_MANIFEST_FILE):
            if os.path.isfile(p):
                secure_chmod(p)
    except Exception as e:
        print(f"-> Lane CSV sync warning: {e}")

    open_browser_delayed(local_url)

    if has_ssl:
        socketio.run(app, host="0.0.0.0", port=PORT, debug=False,
                     keyfile=KEY, certfile=CERT, log=QuietWSGI())
    else:
        socketio.run(app, host="0.0.0.0", port=PORT, debug=False)
