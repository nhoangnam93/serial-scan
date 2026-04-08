#!/usr/bin/env python3
"""
NAB Serial Scanner
Reads the MacBook serial number and appends it to a CSV file.
"""

import csv
import os
import subprocess
import platform
from datetime import datetime

CSV_FILE = "serial_numbers.csv"
CSV_HEADERS = ["Timestamp", "Hostname", "Model", "Serial Number"]


def get_serial_number() -> str:
    """Read the hardware serial number from macOS."""
    try:
        result = subprocess.run(
            ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if "IOPlatformSerialNumber" in line:
                # Line format: "IOPlatformSerialNumber" = "XXXXXXXXXXXX"
                return line.split('"')[-2]
    except subprocess.CalledProcessError:
        pass
    return "UNKNOWN"


def get_model_name() -> str:
    """Read the Mac model identifier."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.model"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "UNKNOWN"


def append_to_csv(serial: str, model: str) -> None:
    """Append a row to the CSV file, creating headers if the file is new."""
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists or os.path.getsize(CSV_FILE) == 0:
            writer.writerow(CSV_HEADERS)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            platform.node(),
            model,
            serial,
        ])


def main():
    serial = get_serial_number()
    model = get_model_name()

    print(f"  Hostname : {platform.node()}")
    print(f"  Model    : {model}")
    print(f"  Serial   : {serial}")

    append_to_csv(serial, model)
    print(f"\n✅ Appended to {os.path.abspath(CSV_FILE)}")


if __name__ == "__main__":
    main()
