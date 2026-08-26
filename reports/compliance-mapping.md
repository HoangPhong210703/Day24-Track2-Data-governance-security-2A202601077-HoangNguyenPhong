# Compliance mapping

Evidence dưới đây là đường dẫn file/dòng thật trong repo này. Toàn bộ số liệu
lấy từ lần chạy `--mock` ngày 2026-08-26 (`reports/ledger.jsonl`, 23 dòng,
`verify()` = True).

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | **Chưa implement** — delete cascade trên `data/customers.json` (giữ ledger nguyên vẹn) là stretch goal #3 trong `Guide.md`. Hiện chỉ có PII gate hạn chế phạm vi dữ liệu vào context: `agent/pii.py:detect/redact`, gọi tại `agent/runner.py:175` | `Guide.md` §Stretch goals #3 · `agent/runner.py:175` |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call: lab chạy `--mock` (không có egress ra nước ngoài); nhánh `--model` được ghi nhận là chuyển dữ liệu xuyên biên giới và bị chặn ở nguồn bằng `pii.redact()` trước khi text vào prompt | `reports/dpia-lite.md` §3 · `agent/runner.py:175` · `agent/llm.py:RealLLM.summarize` |
| ASI03 — privilege abuse | Per-run identity (`run-a-search` / `run-b-customer` / `run-c-egress`) + `trace_id` cho mỗi request; PEP chặn `delegation_depth > 2` | `agent/policy.py:MAX_DELEGATION_DEPTH` + `check()` · `agent/runner.py:29-31` (RUN_A/RUN_B/RUN_C) · field `agent_owner` + `delegation_depth` trong `reports/ledger.jsonl` |
| ASI01 — goal hijack | Trifecta split: chỉ `list[int]` ticket_id lấy từ TÊN FILE đi từ Run A sang Run B (`agent/runner.py:183`); customer_id suy từ `related_tickets` (`agent/runner.py:_customers_for_tickets`), không lấy từ free text | `reports/attack-after.log` (rỗng) vs `reports/attack-before.log` (5/5 biến thể lộ CCCD `811753472374`) · `tests/test_split.py` PASSED |
| ISO 42001 Clause 5-6 | Policy-as-code, có lịch sử review theo commit riêng | `git log agent/policy.py` → commit `b024011` "3b: PEP tai tool call, reason non-empty ca khi allow" · `tests/test_policy.py` 3/3 PASSED |

## Số liệu kiểm chứng (2026-08-26)

| Chỉ số | Giá trị | Nguồn |
|---|---|---|
| Biến thể injection bị chặn | 5/5 | `pytest tests/test_injection.py` |
| PII detection trên VN test set | precision 1.000 / recall 1.000 (118/118) | `pytest tests/test_pii.py -s` |
| Dòng ledger thiếu `reason` hoặc `decision` | 0/23 | `agent.ledger.verify()` = True |
| Dòng `decision=deny` cho `http_post` | 1 | `reports/ledger.jsonl` |
| PII của `KH-000999` tới sink sau contain | 0 byte | `reports/attack-after.log` |
