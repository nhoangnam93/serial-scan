#!/usr/bin/env python3
import csv
import os
import sys
from typing import Dict, List, Tuple

from serial_parser import normalize_serial_candidate
from src.vision import recognize_text_from_binary
from serial_parser import extract_serial_from_text, is_valid_serial_candidate


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CROPS_DIR = os.path.join(BASE_DIR, "cropped_scans")
MANIFEST_FILE = os.path.join(BASE_DIR, "cropped_manifest.csv")


def load_manifest_expectations() -> Dict[str, str]:
    expected: Dict[str, str] = {}
    if not os.path.isfile(MANIFEST_FILE):
        return expected
    with open(MANIFEST_FILE, newline="") as f:
        for row in csv.DictReader(f):
            serial = normalize_serial_candidate(row.get("Serial", ""))
            latest = (row.get("LatestFile") or "").strip()
            archived = (row.get("File") or "").strip()
            if serial and latest:
                expected[latest] = serial
            if serial and archived:
                expected[archived] = serial
    return expected


def expected_from_filename(filename: str) -> str:
    base = filename.split("__", 1)[0]
    base = base.rsplit(".", 1)[0]
    return normalize_serial_candidate(base)


def run() -> int:
    if not os.path.isdir(CROPS_DIR):
        print(f"[ERROR] Missing crops dir: {CROPS_DIR}")
        return 2

    manifest_expected = load_manifest_expectations()
    files = sorted(
        fn for fn in os.listdir(CROPS_DIR)
        if fn.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
    )
    if not files:
        print("[WARN] No crop images found.")
        return 0

    total = 0
    passed = 0
    failures: List[Tuple[str, str, str, float, str]] = []

    for fn in files:
        total += 1
        expected = manifest_expected.get(fn) or expected_from_filename(fn)
        path = os.path.join(CROPS_DIR, fn)
        with open(path, "rb") as f:
            raw = f.read()
        ocr = recognize_text_from_binary(raw)
        text = ocr.get("text", "") or ""
        conf = float(ocr.get("confidence", 0.0) or 0.0)
        extracted = extract_serial_from_text(text)
        valid = bool(extracted and is_valid_serial_candidate(extracted))
        ok = bool(extracted and extracted == expected and valid)
        if ok:
            passed += 1
        else:
            failures.append((fn, expected, extracted or "", conf, text[:220]))

    print(f"Crop OCR regression: {passed}/{total} passed")
    if failures:
        print("\nFailures:")
        for fn, exp, got, conf, text in failures:
            print(f"- {fn}")
            print(f"  expected: {exp}")
            print(f"  extracted: {got or '(empty)'}")
            print(f"  ocr_conf: {conf:.4f}")
            print(f"  ocr_text: {text}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
