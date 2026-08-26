"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# --- Regex "có ngữ cảnh" -----------------------------------------------------
# Cùng một chuỗi 12 chữ số có thể là CCCD hoặc số tài khoản; thứ phân biệt
# được hai loại là TỪ KHOÁ ĐỨNG TRƯỚC nó ("CCCD ..." vs "STK ..."), nên các
# pattern có ngữ cảnh được thử TRƯỚC, rồi mới tới fallback theo độ dài.
# `\D{0,40}?` cho phép chèn tên người giữa từ khoá và con số
# ("CCCD của Hoàng Đức Tuấn: 021825658411") mà không nhảy qua một số khác,
# vì \D không bao giờ khớp chữ số.

EMAIL = "EMAIL"
VN_CCCD = "VN_CCCD"
VN_PHONE = "VN_PHONE"
VN_BANK_ACCOUNT = "VN_BANK_ACCOUNT"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")

_BANK_CTX_RE = re.compile(
    r"(?:stk|s\.t\.k|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|tai\s+khoan"
    r"|bank[_\s]?account)\D{0,40}?(\d{8,19})",
    re.IGNORECASE,
)

_CCCD_CTX_RE = re.compile(
    r"(?:cccd|cmnd|căn\s+cước(?:\s+công\s+dân)?|can\s+cuoc(?:\s+cong\s+dan)?)"
    r"\D{0,40}?(\d{9,12})",
    re.IGNORECASE,
)

_PHONE_CTX_RE = re.compile(
    r"(?:sđt|sdt|số\s+điện\s+thoại|so\s+dien\s+thoai|điện\s+thoại|dien\s+thoai"
    r"|phone|liên\s+hệ|lien\s+he|hotline)\D{0,40}?(0\d(?:[\s.\-]?\d){8,9})",
    re.IGNORECASE,
)

# Fallback: con số đứng trơ không có từ khoá đi kèm.
_PHONE_BARE_RE = re.compile(r"(?<![\d.])(0\d(?:[\s.\-]?\d){8,9})(?![\d])")
_DIGITS_BARE_RE = re.compile(r"(?<![\d.])(\d{8,19})(?![\d])")


def _classify_bare(raw: str) -> str | None:
    """Đoán loại cho một chuỗi số không có từ khoá ngữ cảnh, theo độ dài."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 12:
        return VN_CCCD
    if len(digits) == 10 and digits.startswith("0"):
        return VN_PHONE
    if 8 <= len(digits) <= 19:
        return VN_BANK_ACCOUNT
    return None


def _add(found: list[dict], entity_type: str, start: int, end: int) -> None:
    """Thêm entity nếu chưa bị một entity ưu tiên cao hơn chiếm chỗ."""
    for existing in found:
        if start < existing["end"] and existing["start"] < end:
            return
    found.append({"type": entity_type, "start": start, "end": end})


def detect(text: str) -> list[dict]:
    """Trả về list[{"type", "start", "end"}], không trùng lặp, sort theo start.

    Thứ tự ưu tiên: email -> số có từ khoá ngữ cảnh -> số trơ đoán theo độ dài.
    """
    found: list[dict] = []

    for match in _EMAIL_RE.finditer(text):
        _add(found, EMAIL, match.start(), match.end())

    for pattern, entity_type in (
        (_BANK_CTX_RE, VN_BANK_ACCOUNT),
        (_CCCD_CTX_RE, VN_CCCD),
        (_PHONE_CTX_RE, VN_PHONE),
    ):
        for match in pattern.finditer(text):
            _add(found, entity_type, match.start(1), match.end(1))

    for match in _PHONE_BARE_RE.finditer(text):
        _add(found, VN_PHONE, match.start(1), match.end(1))

    for match in _DIGITS_BARE_RE.finditer(text):
        entity_type = _classify_bare(match.group(1))
        if entity_type is not None:
            _add(found, entity_type, match.start(1), match.end(1))

    found.sort(key=lambda e: e["start"])
    return found


def redact(text: str) -> str:
    """Thay mọi entity phát hiện được bằng "[REDACTED_<TYPE>]".

    Thay từ CUỐI văn bản ngược về đầu để offset của các entity phía trước
    không bị lệch sau mỗi lần thay.
    """
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
