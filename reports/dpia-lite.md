# DPIA-lite — Agent tổng hợp ticket customer-support

Phạm vi: agent trong repo này (`agent/loop.py` → `agent/runner.py`), chạy
`--mock`. Ngày đánh giá: 2026-08-26.

## 1. Dữ liệu gì

| Tool | Dữ liệu chạm tới | Phân loại |
|---|---|---|
| `search_docs` (`agent/tools.py`) | Toàn văn ticket trong `corpus/` — free text do người ngoài viết, có thể chứa PII lẫn chỉ thị của attacker | `internal` (untrusted) |
| `read_customer` (`agent/tools.py`) | `data/customers.json`: họ tên, **CCCD (12 số)**, SĐT, số tài khoản ngân hàng, email — 26 chủ thể dữ liệu | `restricted` |
| `http_post` (`agent/tools.py`) | Bất kỳ dữ liệu nào agent quyết định gửi ra ngoài; hard-allowlist `localhost:9999` | `restricted` khi kèm dữ liệu khách |

Dữ liệu nhạy cảm nhất là CCCD và số tài khoản — đủ để định danh trực tiếp và
đủ để phục vụ gian lận tài chính, nên mọi kiểm soát dưới đây đặt ngưỡng theo
hai trường này.

## 2. Mục đích gì

Mục đích duy nhất: **tổng hợp các ticket còn mở** để trả lời yêu cầu của nhân
viên hỗ trợ (`request_purpose="summarize-tickets"`).

Purpose limitation được cưỡng chế bằng code, không bằng tài liệu: PEP từ chối
mọi tool call không khai báo `request_purpose` (`agent/policy.py`, nhánh
"thiếu request_purpose"), và mọi dòng ledger đều ghi lại purpose đã dùng
(`reports/ledger.jsonl`, field `purpose`).

Việc đọc hồ sơ khách hàng **không** xuất phát từ nội dung document: Run B chỉ
nhận `list[int]` ticket_id trích từ TÊN FILE (`agent/runner.py:183`) rồi tra
ngược qua `related_tickets` (`agent/runner.py:_customers_for_tickets`). Một
khách chỉ được attacker nhắc tên trong free text là không thể với tới —
`tests/test_split.py` kiểm đúng điều này với `KH-000777` (`related_tickets: []`).

## 3. Chảy đi đâu

| Điểm đến | Có xảy ra không | Kiểm soát |
|---|---|---|
| Context của LLM (prompt) | Có — nhưng chỉ text **đã redact** | `pii.redact()` tại `agent/runner.py:175`; PII bị thay bằng `[REDACTED_<TYPE>]` trước khi vào prompt |
| `reports/ledger.jsonl` (log nội bộ) | Có | Chỉ ghi `args_hash` (sha256 rút gọn), không ghi nguyên văn tham số — `agent/runner.py:_args_hash` |
| Sink `http://localhost:9999` (mô phỏng exfil) | **Không, sau khi contain** | PEP deny `restricted + egress_enabled` → `http_post` không bao giờ chạy (`agent/runner.py` Run C). Bằng chứng: `reports/attack-after.log` rỗng, so với `reports/attack-before.log` nơi cả 5 biến thể đều đẩy CCCD `811753472374` + STK `9103069783` ra sink |
| Internet công cộng | Không | `agent/tools.py:http_post` hard-allowlist `localhost:9999`, raise `ToolError` nếu khác. Đây là biện pháp an toàn của lab, **không** phải control được tính điểm |
| **API của model provider (Anthropic) nếu chạy `--model`** | Không trong lần chạy này (dùng `--mock`); **có** nếu chuyển sang `--model` | Đây là **chuyển dữ liệu cá nhân xuyên biên giới** theo NĐ 356/2025 (server ở nước ngoài), phát sinh nghĩa vụ hồ sơ 60 ngày. Giảm thiểu sẵn có: text gửi đi đã qua `pii.redact()`. Bài lab được chấm bằng `--mock` nên mặc định không phát sinh luồng này |

## 4. Rủi ro còn lại

1. **Quyền yêu cầu xoá (Luật 91/2025) chưa implement** — chưa có delete cascade
   trên `data/customers.json`; ledger append-only sẽ giữ `args_hash` của chủ thể
   đã xoá (hash một chiều, không phục hồi được PII, nên chấp nhận được).
2. **Run B vẫn đọc hồ sơ của mọi khách gắn với ticket khớp query** — 21 lượt
   `read_customer` trong lần chạy ngày 2026-08-26. Đây là data minimisation chưa
   chặt: đúng mục đích, nhưng rộng hơn mức cần thiết. Hướng siết: giới hạn theo
   ticket thực sự "còn mở" thay vì mọi ticket khớp từ khoá.
3. **`corpus/` có thể bị ghi bởi attacker** — containment vẫn đứng vững (free
   text không quyết định được Run B đọc ai), nhưng attacker vẫn có thể làm nhiễu
   nội dung tóm tắt trả về cho người dùng.
