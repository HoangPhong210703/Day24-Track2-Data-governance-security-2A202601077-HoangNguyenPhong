"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64

# Field bắt buộc cho mỗi dòng — thiếu bất kỳ field nào thì dòng đó vô dụng
# khi regulator hỏi "ai gọi tool gì, lúc nào, được/không, vì sao".
REQUIRED_FIELDS = (
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
)


def _canonical(entry: dict) -> str:
    """Chuỗi để băm: chính nội dung dòng NHƯNG bỏ field `hash` ra ngoài.

    sort_keys=True để thứ tự field trong file không ảnh hưởng kết quả băm.
    """
    payload = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS_HASH
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return GENESIS_HASH
    return json.loads(lines[-1]).get("hash", GENESIS_HASH)


def append(entry: dict, path: Path) -> dict:
    """Append-only: ghi 1 dòng JSONL, móc xích hash vào dòng trước đó."""
    path = Path(path)
    # Cố tình KHÔNG raise khi entry thiếu field: ledger ghi lại đúng những gì
    # caller đưa xuống, còn việc "dòng này có hợp lệ không" là câu hỏi của
    # verify(). Một ledger tự ý từ chối ghi sẽ giấu mất chính bằng chứng là
    # runner đã log thiếu.
    record = dict(entry)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _hash(record)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    """True nếu chuỗi hash liền mạch VÀ mọi dòng có reason non-empty.

    Sửa/xoá/chèn một dòng bất kỳ đều làm hàm này trả về False: dòng bị sửa
    hỏng hash của chính nó, và mọi dòng sau đó hỏng liên kết prev_hash.
    """
    path = Path(path)
    if not path.exists():
        return False

    expected_prev = GENESIS_HASH
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False

        if any(not str(record.get(f, "")).strip() for f in REQUIRED_FIELDS):
            return False
        if record.get("prev_hash") != expected_prev:
            return False
        if record.get("hash") != _hash(record):
            return False

        expected_prev = record["hash"]

    return True
