import Cocoa
import Vision
import base64
import logging
from io import BytesIO

from PIL import Image, ImageEnhance, ImageOps

from serial_parser import extract_serial_from_text, is_valid_serial_candidate_for_profile, normalize_serial_profile


def _decode_input_bytes(img_data):
    if isinstance(img_data, str):
        payload = img_data.split(",", 1)[1] if "," in img_data else img_data
        return base64.b64decode(payload)
    if isinstance(img_data, bytearray):
        return bytes(img_data)
    return img_data


def _run_vision_ocr(img_bytes):
    ns_data = Cocoa.NSData.dataWithBytes_length_(img_bytes, len(img_bytes))
    handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
    extracted_text = []
    confidences = []

    def recognition_handler(req, error):
        if error:
            return
        res = req.results()
        if not res:
            return
        for obs in res:
            top_candidate = obs.topCandidates_(1).firstObject()
            if top_candidate:
                extracted_text.append(top_candidate.string())
                try:
                    confidences.append(float(top_candidate.confidence()))
                except Exception:
                    pass

    request = Vision.VNRecognizeTextRequest.alloc().initWithCompletionHandler_(recognition_handler)
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    if hasattr(request, "setUsesLanguageCorrection_"):
        request.setUsesLanguageCorrection_(False)

    handler.performRequests_error_([request], None)
    text = " ".join(extracted_text)
    confidence = (sum(confidences) / len(confidences)) if confidences else 0.0
    return {"text": text, "confidence": confidence}


def _build_enhanced_variant(img_bytes):
    try:
        with Image.open(BytesIO(img_bytes)) as im:
            gray = ImageOps.grayscale(im)
            boosted = ImageOps.autocontrast(gray, cutoff=1)
            boosted = ImageEnhance.Contrast(boosted).enhance(2.0)
            boosted = ImageEnhance.Sharpness(boosted).enhance(2.3)
            w, h = boosted.size
            scale = 1.7
            up = boosted.resize((int(w * scale), int(h * scale)), Image.Resampling.LANCZOS)
            out = BytesIO()
            up.save(out, format="JPEG", quality=92)
            return out.getvalue()
    except Exception:
        return b""


def _build_threshold_variant(img_bytes):
    try:
        with Image.open(BytesIO(img_bytes)) as im:
            gray = ImageOps.grayscale(im)
            boosted = ImageOps.autocontrast(gray, cutoff=1)
            boosted = ImageEnhance.Contrast(boosted).enhance(2.6)
            boosted = ImageEnhance.Sharpness(boosted).enhance(2.6)
            bw = boosted.point(lambda p: 255 if p > 138 else 0)
            w, h = bw.size
            scale = 1.6
            up = bw.resize((int(w * scale), int(h * scale)), Image.Resampling.NEAREST)
            out = BytesIO()
            up.save(out, format="JPEG", quality=92)
            return out.getvalue()
    except Exception:
        return b""


def _serial_score(result, serial_profile="apple"):
    profile = normalize_serial_profile(serial_profile)
    text = (result or {}).get("text", "") or ""
    confidence = float((result or {}).get("confidence", 0.0) or 0.0)
    serial = extract_serial_from_text(text, profile=profile)
    valid = bool(serial and is_valid_serial_candidate_for_profile(serial, profile=profile))
    score = (100000 if valid else 0) + int(confidence * 1000) + min(len(text), 120)
    return score, serial

def recognize_text_from_binary(img_data, serial_profile="apple"):
    """
    Perform Apple Vision OCR on binary image data.
    Runs on macOS Neural Engine if available.
    """
    profile = normalize_serial_profile(serial_profile)
    pool = Cocoa.NSAutoreleasePool.alloc().init()
    try:
        try:
            img_bytes = _decode_input_bytes(img_data)
        except Exception as e:
            logging.error(f"OCR: decode error: {e}")
            return {"text": "", "confidence": 0.0}

        primary = _run_vision_ocr(img_bytes)
        primary_score, primary_serial = _serial_score(primary, profile)
        best = dict(primary)
        best["serial_hint"] = primary_serial
        best["variant"] = "primary"

        # Fallback pass only when first pass is weak or has no serial candidate.
        needs_fallback = (
            not (primary.get("text", "") or "").strip()
            or float(primary.get("confidence", 0.0) or 0.0) < 0.995
            or not primary_serial
        )
        if needs_fallback:
            variants = []
            enhanced_bytes = _build_enhanced_variant(img_bytes)
            if enhanced_bytes:
                variants.append(("enhanced", enhanced_bytes))
            threshold_bytes = _build_threshold_variant(img_bytes)
            if threshold_bytes:
                variants.append(("threshold", threshold_bytes))

            top_score = primary_score
            for variant_name, variant_bytes in variants:
                result = _run_vision_ocr(variant_bytes)
                score, serial = _serial_score(result, profile)
                if score > top_score:
                    top_score = score
                    best = dict(result)
                    best["serial_hint"] = serial
                    best["variant"] = variant_name

        return best
    except Exception as e:
        logging.error(f"Vision OCR Error: {e}")
        return {"text": "", "confidence": 0.0}
    finally:
        del pool
