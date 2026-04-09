#!/usr/bin/env python3
import json
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


BASE_URL = "https://127.0.0.1:5000"


def fetch(path, headers=None):
    req = Request(BASE_URL + path, headers=headers or {})
    ctx = ssl._create_unverified_context()
    with urlopen(req, context=ctx, timeout=8) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body


def expect(condition, label):
    if not condition:
        print(f"[FAIL] {label}")
        return False
    print(f"[OK]   {label}")
    return True


def main():
    ok = True

    status, body = fetch("/health")
    payload = json.loads(body)
    ok &= expect(status == 200 and payload.get("ok") is True, "health endpoint")

    status, _ = fetch("/static/vendor/socket.io.min.js")
    ok &= expect(status == 200, "socket.io client script served")

    try:
        fetch("/checkset?profile=apple")
        ok &= expect(False, "checkset rejects missing auth token")
    except HTTPError as e:
        ok &= expect(e.code == 401, "checkset rejects missing auth token")

    import app  # local import to reuse token signer

    token = app.issue_session_token("e2e-check-client")
    status, body = fetch("/checkset?profile=apple", headers={"X-Session-Token": token})
    payload = json.loads(body)
    ok &= expect(status == 200 and isinstance(payload.get("count"), int), "checkset accepts valid session token")

    status, body = fetch("/qr-data")
    payload = json.loads(body)
    ok &= expect(status == 200 and bool(payload.get("url")), "qr-data endpoint available")

    tests = [
        ("test_serial_extract.py", ["./venv/bin/python", "test_serial_extract.py"]),
        ("test_cropped_scans.py", ["./venv/bin/python", "test_cropped_scans.py"]),
    ]
    for label, cmd in tests:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        if cp.returncode != 0:
            print(cp.stdout)
            print(cp.stderr)
        ok &= expect(cp.returncode == 0, f"{label} passes")

    if ok:
        print("\nE2E local checks passed.")
        return 0
    print("\nE2E local checks failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
