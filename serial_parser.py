import re

APPLE_SERIAL_LENGTHS = {10, 12}
DELL_SERVICE_TAG_LENGTH = 7
VALID_SERIAL_PROFILES = {"apple", "dell"}

SERIAL_STOPWORDS = {
    "TOTALSCANS",
    "USERSONLINE",
    "SCANNEROFF",
    "SCANNER",
    "DUPLICATES",
    "AUTOSAVE",
    "TODAY",
    "UNIQUE",
}
SERIAL_STOPWORDS_NORMALIZED = {word.replace("O", "0") for word in SERIAL_STOPWORDS}
LABEL_HINTS = (
    "SERIAL",
    "SERIA",
    "S/N",
    "MODEL",
    "FCC",
    "DESIGNED",
    "ASSEMBLED",
    "MACBOOK",
)
SERIAL_BLACKLIST_SUBSTRINGS = (
    "MODEL",
    "M0DEL",
    "FCC",
    "IC",
    "RATED",
    "VOLT",
    "DESIGNED",
    "ASSEMBLED",
)

def normalize_serial_profile(profile):
    p = (profile or "apple").strip().lower()
    return p if p in VALID_SERIAL_PROFILES else "apple"


def _raw_alnum_upper(value):
    return re.sub(r"[^A-Z0-9]", "", (value or "").upper())


def normalize_serial_candidate(value, profile="apple"):
    profile = normalize_serial_profile(profile)
    cleaned = _raw_alnum_upper(value)
    if not cleaned:
        return ""
    if profile == "dell":
        # Dell service tags are 7-char alnum; preserve letters as-is.
        # Keep only the first 7 chars when prefixed forms like "ST:XXXXXXX" are OCR-merged.
        if cleaned.startswith("ST") and len(cleaned) >= 2 + DELL_SERVICE_TAG_LENGTH:
            candidate = cleaned[2 : 2 + DELL_SERVICE_TAG_LENGTH]
            if re.fullmatch(r"[A-Z0-9]{7}", candidate):
                return candidate
        return cleaned

    # Apple serials use numeric 0/1, not letters O/I.
    normalized = cleaned.replace("O", "0").replace("I", "1")
    # Box barcodes can prefix the serial with leading "S"; strip it when length matches.
    if (
        normalized.startswith("S")
        and not normalized.startswith(("SE", "SN"))
        and len(normalized) - 1 in APPLE_SERIAL_LENGTHS
        and any(char.isalpha() for char in normalized[1:])
        and any(char.isdigit() for char in normalized[1:])
    ):
        normalized = normalized[1:]
    return normalized


def is_valid_serial_candidate(value):
    return is_valid_serial_candidate_for_profile(value, "apple")


def is_valid_serial_candidate_for_profile(value, profile="apple"):
    profile = normalize_serial_profile(profile)
    value = normalize_serial_candidate(value, profile)
    if profile == "dell":
        if len(value) != DELL_SERVICE_TAG_LENGTH:
            return False
        if not re.fullmatch(r"[A-Z0-9]{7}", value):
            return False
        if value.startswith(("ST", "EX")):
            return False
        # Reduce false positives from OCR noise.
        digit_count = sum(char.isdigit() for char in value)
        letter_count = sum(char.isalpha() for char in value)
        return digit_count > 0 and letter_count > 0

    digit_count = sum(char.isdigit() for char in value)
    letter_count = sum(char.isalpha() for char in value)

    # Strict Apple serial lengths.
    if len(value) not in APPLE_SERIAL_LENGTHS:
        return False

    if len(value) and (digit_count / len(value) > 0.82 or letter_count / len(value) > 0.88):
        return False
    if re.search(r"(.)\1\1\1", value):
        return False
    if re.match(r"^A\d{4,}$", value):
        return False
    if value.startswith(("MODEL", "M0DEL", "SERIAL", "SERIA", "RATED", "VOLT")):
        return False
    if any(token in value for token in ("APPLE", "CHINA", "DESIGNED", "ASSEMBLED", "FCC", "IC")):
        return False
    
    return (
        10 <= len(value) <= 13
        and digit_count > 0
        and letter_count > 0
        and value not in SERIAL_STOPWORDS
        and value not in SERIAL_STOPWORDS_NORMALIZED
    )


def is_likely_macbook_serial(value):
    serial = normalize_serial_candidate(value, "apple")
    return (
        len(serial) in APPLE_SERIAL_LENGTHS
        and any(char.isalpha() for char in serial)
        and any(char.isdigit() for char in serial)
    )

def is_likely_dell_service_tag(value):
    serial = normalize_serial_candidate(value, "dell")
    return is_valid_serial_candidate_for_profile(serial, "dell")


def extract_candidate_from_tokens(tokens):
    if not tokens:
        return ""

    # Prefer the first token near the Serial prefix before joining into later OCR noise.
    for token in tokens[:5]:
        if not any(char.isdigit() for char in token):
            continue
        normalized = normalize_serial_candidate(token)
        if is_valid_serial_candidate(normalized):
            return normalized

    merged = ""
    for token in tokens[:6]:
        merged += token
        if not any(char.isdigit() for char in merged):
            continue
        normalized = normalize_serial_candidate(merged)
        if is_valid_serial_candidate(normalized):
            return normalized

    return ""

def extract_candidate_from_tokens_for_profile(tokens, profile="apple"):
    profile = normalize_serial_profile(profile)
    if not tokens:
        return ""
    if profile == "dell":
        for token in tokens[:8]:
            normalized = normalize_serial_candidate(token, "dell")
            if is_valid_serial_candidate_for_profile(normalized, "dell"):
                return normalized
        merged = ""
        for token in tokens[:8]:
            merged += token
            normalized = normalize_serial_candidate(merged, "dell")
            if len(normalized) >= DELL_SERVICE_TAG_LENGTH:
                # Sliding 7-char windows from merged OCR chunks
                for i in range(0, len(normalized) - DELL_SERVICE_TAG_LENGTH + 1):
                    cand = normalized[i : i + DELL_SERVICE_TAG_LENGTH]
                    if is_valid_serial_candidate_for_profile(cand, "dell"):
                        return cand
        return ""
    return extract_candidate_from_tokens(tokens)


def extract_serial_from_text(text, profile="apple"):
    profile = normalize_serial_profile(profile)
    cleaned = text.replace("\n", " ")
    upper_cleaned = cleaned.upper()

    if profile == "dell":
        # Strong Dell hints first: "Service Tag", "Svc Tag", "ST:"
        st_match = re.search(
            r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG|ST)\s*[:#-]\s*([A-Z0-9]{7,12})",
            upper_cleaned,
            re.IGNORECASE,
        )
        if st_match:
            candidate = normalize_serial_candidate(st_match.group(1), "dell")
            if len(candidate) > DELL_SERVICE_TAG_LENGTH:
                candidate = candidate[:DELL_SERVICE_TAG_LENGTH]
            if is_valid_serial_candidate_for_profile(candidate, "dell"):
                return candidate

        st_match_soft = re.search(
            r"(?:SERVICE\s*TAG|SVC\s*TAG|SVCTAG)\s*([A-Z0-9]{7,12})",
            upper_cleaned,
            re.IGNORECASE,
        )
        if st_match_soft:
            candidate = normalize_serial_candidate(st_match_soft.group(1), "dell")
            if len(candidate) > DELL_SERVICE_TAG_LENGTH:
                candidate = candidate[:DELL_SERVICE_TAG_LENGTH]
            if is_valid_serial_candidate_for_profile(candidate, "dell"):
                return candidate

        if "DELL" not in upper_cleaned and "SERVICE TAG" not in upper_cleaned and "ST:" not in upper_cleaned:
            return ""

        tokens = re.findall(r"[A-Z0-9]+", upper_cleaned)
        for idx, _ in enumerate(tokens):
            candidate = extract_candidate_from_tokens_for_profile(tokens[idx : idx + 8], "dell")
            if candidate:
                return candidate
        return ""

    # If OCR finds a "Serial" prefix, accept a noisy tail and normalize it.
    prefix_match = re.search(
        r"(?:Serial\s*No\.?|Serial|Seria|S/N|SN)[\s\.:#-]*([A-Z0-9\s\.:#-]{6,24})",
        cleaned,
        re.IGNORECASE,
    )
    if prefix_match:
        prefix_tokens = re.findall(r"[A-Z0-9]+", prefix_match.group(1).upper())
        candidate = extract_candidate_from_tokens_for_profile(prefix_tokens, "apple")
        if candidate:
            return candidate

    # Avoid false positives from random OCR text when no Apple label hints are present.
    if not any(hint in upper_cleaned for hint in LABEL_HINTS):
        return ""

    # Vision often splits labels into multiple chunks. Join adjacent short chunks.
    tokens = re.findall(r"[A-Z0-9]+", upper_cleaned)
    for idx, _ in enumerate(tokens):
        candidate = extract_candidate_from_tokens_for_profile(tokens[idx : idx + 6], "apple")
        if candidate:
            return candidate

    return ""
