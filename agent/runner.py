"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_A = "run-a-search"      # untrusted content, KHÔNG có private data, KHÔNG có egress
RUN_B = "run-b-customer"    # private data, KHÔNG bao giờ đọc free text
RUN_C = "run-c-egress"      # egress, KHÔNG bao giờ cầm private data

# "ticket-904b.md" -> 904. Tên file do hệ thống ticket đặt, KHÔNG do attacker
# viết trong nội dung document — đây là lý do nó được coi là nguồn tin cậy.
_TICKET_ID_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _args_hash(args: dict) -> str:
    """Băm tham số thay vì ghi nguyên văn — ledger là file audit, không phải
    thêm một chỗ nữa để PII rò rỉ ra."""
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]


def _gate(
    ledger_path: Path,
    run_id: str,
    tool: str,
    args: dict,
    context: PolicyContext,
    trace_id: str,
) -> bool:
    """PEP + audit trong một chỗ: policy chạy TRƯỚC tool, ledger ghi cả hai
    chiều (allow lẫn deny). Trả về True nếu caller được phép gọi tool."""
    allow, reason = check(context)
    ledger.append(
        {
            "ts": _now(),
            "agent_id": AGENT_ID,
            "run_id": run_id,
            "trace_id": trace_id,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": context.data_classification,
            "purpose": context.request_purpose,
            "agent_owner": context.agent_owner,
            "delegation_depth": context.delegation_depth,
            "egress_enabled": context.egress_enabled,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        },
        ledger_path,
    )
    return allow


def _ticket_ids(doc_ids: list[str]) -> list[int]:
    ids = []
    for doc_id in doc_ids:
        match = _TICKET_ID_RE.search(doc_id)
        if match:
            ids.append(int(match.group(1)))
    return sorted(set(ids))


def _customers_for_tickets(ticket_ids: list[int], customers_file: Path | None = None) -> list[str]:
    """NGUỒN TIN CẬY: ticket_id -> customer_id qua related_tickets trong
    data/customers.json. Không có bước nào ở đây đọc nội dung document, nên
    một khách chỉ được attacker nhắc tên trong free text là KHÔNG THỂ với tới.
    """
    customers_file = customers_file or tools.CUSTOMERS_FILE
    records = json.loads(Path(customers_file).read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [
        str(record["customer_id"])
        for record in records
        if wanted & set(record.get("related_tickets") or [])
    ]


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Trifecta split: 3 run, không run nào cầm quá 1 chân.

        Run A  untrusted content   search_docs          (egress off, no PII)
        Run B  private data        read_customer        (egress off, input là list[int])
        Run C  egress              http_post            (bị policy chặn với restricted)

    Hành vi nhìn từ CLI không đổi so với baseline — chỉ sink.log và ledger
    là khác. Đó là chủ đích của Bước 4.
    """
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    trace_id = uuid.uuid4().hex[:12]

    # ---------------- Run A: untrusted content -----------------------------
    # Chân 1 duy nhất. Run này KHÔNG được gọi read_customer, KHÔNG có egress.
    docs: list[dict] = []
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=RUN_A,
        delegation_depth=0,
        egress_enabled=False,
    )
    if _gate(ledger_path, RUN_A, "search_docs", {"query": message}, ctx_a, trace_id):
        docs = tools.search_docs(message)

    # PII gate TRƯỚC ingestion (Bước 3a): text đi vào context của LLM đã được
    # redact, nên kể cả khi corpus có PII thật thì nó không vào prompt.
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]

    # Chỉ thị của attacker được PHÁT HIỆN và GHI LẠI, nhưng không bao giờ
    # được dùng làm input cho Run B. Đặc biệt: injected.customer_ids bị vứt đi.
    raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(raw_text) if raw_text else None

    # ---- Ranh giới tin cậy: chỉ list[int] này đi từ Run A sang Run B ------
    ticket_ids = _ticket_ids([d["id"] for d in docs])

    # ---------------- Run B: private data ----------------------------------
    # Input là typed (list[int]) lấy từ TÊN FILE, không phải free text.
    customer_ids = _customers_for_tickets(ticket_ids)
    records: list[dict] = []
    for customer_id in customer_ids:
        ctx_b = PolicyContext(
            data_classification="restricted",
            request_purpose="summarize-tickets",
            agent_owner=RUN_B,
            delegation_depth=1,
            egress_enabled=False,  # <- chân 3 bị cắt khỏi run này
        )
        if not _gate(
            ledger_path, RUN_B, "read_customer", {"customer_id": customer_id}, ctx_b, trace_id
        ):
            continue
        try:
            records.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    # ---------------- Run C: egress ----------------------------------------
    # Chỉ chạy khi có chỉ thị đòi gửi dữ liệu ra ngoài. Policy nhìn thấy
    # restricted + egress_enabled -> deny, nên http_post KHÔNG BAO GIỜ chạy;
    # dòng deny này chính là evidence ở Bước 4 (Rubric: "Egress deny có
    # bằng chứng").
    if injected is not None:
        ctx_c = PolicyContext(
            data_classification="restricted",
            request_purpose="exfil-requested-by-document",
            agent_owner=RUN_C,
            delegation_depth=2,
            egress_enabled=True,
        )
        allowed = _gate(
            ledger_path,
            RUN_C,
            "http_post",
            {
                "url": injected.target_url,
                "markers": injected.matched_markers,
                "customer_ids_in_text": injected.customer_ids,
            },
            ctx_c,
            trace_id,
        )
        if allowed:  # pragma: no cover - policy tối thiểu luôn deny nhánh này
            tools.http_post(injected.target_url, {"records": records})

    return llm.summarize(safe_docs)
