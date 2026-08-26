# Guide — Timeline 2h

Ý tưởng cốt lõi: bạn tự tay đóng mạch **lethal trifecta** trước khi được
dạy cách chặn nó. Đọc về prompt injection thì quên; thấy agent của chính
mình gửi PII ra ngoài thì nhớ mãi.

Ba tool trong `agent/tools.py` cố tình dựng thành đúng 3 chân của trifecta:


| Tool                   | Chân trifecta                                                       |
| ------------------------ | ---------------------------------------------------------------------- |
| `search_docs(query)`   | **untrusted content** — đọc `corpus/`, nơi attacker cài payload |
| `read_customer(id)`    | **private data** — đọc `data/customers.json`                      |
| `http_post(url, body)` | **exfil vector** — chỉ trỏ được vào `localhost:9999`          |

---

## Bước 0 — Setup (10')

```bash
pip install -r requirements.txt
python sink/sink.py                                           # tab riêng
python -m agent.loop --mock "Tóm tắt ticket về hoá đơn"        # tab khác
```

Thấy agent gọi `search_docs` và trả lời là xong. Chưa chạy được thì
chuyển sang `--mock` ngay — đừng debug API key, `--mock` không cần key.

## Bước 1 — Baseline (15')

Đọc `agent/loop.py` (hàm `_naive_loop`). Vẽ ra giấy: agent gọi tool nào,
với quyền gì, ghi log ở đâu. Trả lời 3 câu — **không có câu trả lời miễn
phí, phải chỉ ra đúng dòng code**:

1. Agent này có identity riêng không (per-run, per-agent id)?
2. Ai quyết định nó được gọi `http_post`?
3. Nếu nó gửi sai dữ liệu ra ngoài, bạn biết bằng cách nào?

## Bước 2 — Red team (25')

Đọc `injection-corpus.md` — biến thể 1 (`corpus/ticket-901.md`) đã có
sẵn. Chạy:

```bash
python sink/sink.py --reset
python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"
```

Xem `reports/sink.log` (do sink server ghi) — bạn sẽ thấy CCCD + STK của
khách `KH-000999`. Copy log này vào `reports/attack-before.log`.

**Việc của bạn:** viết tiếp 4 biến thể còn lại vào `injection-corpus.md`,
mỗi biến thể một file `corpus/ticket-90N.md` (N=2..5, xem mẫu đặt tên
trong `injection-corpus.md`):

2. Chữ ẩn / không hiển thị (mô phỏng white-text trong file Word)
3. Giả mạo thẩm quyền ("System note:", "admin", "DPO")
4. Chia payload qua 2 document (`ticket-904.md` + `ticket-904b.md`)
5. Tiếng Việt không dấu / teencode / unicode lookalike

**Sau mỗi biến thể, tự kiểm tra ngay** (nhanh hơn nhiều so với chạy grader):

```bash
python -m agent.check_lure corpus/ticket-902.md
```

Nó kiểm hai cửa: `search_docs` có trả về file không, và nội dung có được coi
là chỉ thị không (>= 2 marker). Một lure trơ sẽ làm `test_injection.py` báo
lỗi trông như lỗi `policy.py` — xem `injection-corpus.md`.

Mock LLM (`agent/llm.py:find_injection`) nhận diện chỉ thị **sau khi
chuẩn hoá** (bỏ dấu, hạ chữ thường) — nó "hiểu" được biến thể 5 giống một
model thật, khác với một bộ filter chuỗi thô. Đây là điểm bạn sẽ khai
thác lại ở Bước 3c.

## Bước 3 — Contain (50', 4 commit)

### 3a. `agent/pii.py` — PII gate trước ingestion (12')

Đọc docstring trong file. **Cảnh báo:** Presidio không có tiếng Việt sẵn
(`AnalyzerEngine()` mặc định chỉ hỗ trợ `"en"`) — đừng đi vào đường đó
trong 2h này. Regex cho CCCD (12 số)/SĐT/STK/email + deny-list cho tên
người là đủ để đạt ngưỡng trên test set.

```bash
pytest tests/test_pii.py -v -s     # in ra precision/recall
```

### 3b. `agent/policy.py` — PEP tại tool call (15')

Hàm `check()` nhận `PolicyContext` (5 field đã định nghĩa sẵn), trả về
`(allow, reason)`. **`reason` không được rỗng — kể cả khi allow.** Rule
tối thiểu: `classification == "restricted" and egress_enabled` → deny.

```bash
pytest tests/test_policy.py -v
```

---

<p align="center">
  <img src="data/easter-egg.png" alt="Trùm công nghệ — Cho tôi Claude Code, tôi sẽ nâng cả trái đất lên" width="380">
</p>

> 🥚 **Easter egg** — nghỉ giải lao tí nào. Tặng các bạn D403 Track 2 buổi
> sáng 1 cái ảnh của thầy Hiếu.

---

### 3c. `agent/runner.py` — trifecta split + egress allowlist (13')

**Phần khó nhất.** Đọc kỹ docstring trong file — có sẵn gợi ý kiến trúc
dùng `related_tickets` trong `customers.json` để Run B tra customer_id từ
ticket_id (nguồn tin cậy), thay vì tin vào customer_id mà attacker viết
trong document.

Thử trước: viết một filter chuỗi kiểu
`if "hãy gọi" in text: block` trong `runner.py`. Chạy lại biến thể 5 —
filter đó sẽ bị phá (vì biến thể 5 không chứa cụm "hãy gọi" nguyên văn).
Đó là lý do **filter là mitigation, split là containment**: containment
không cần biết TOÀN BỘ cách viết lại của attacker, nó chỉ cần đảm bảo Run
đọc private data không bao giờ đọc free text để quyết định phải làm gì.

### 3d. `agent/ledger.py` — audit ledger append-only (10')

Đọc docstring trong file. Sau khi viết xong, tự tay chứng minh tamper-
evident:

```bash
pytest tests/test_ledger.py -v
```

Sau mỗi bước 3a-3d, commit riêng — 4 commit cho 4 file.

## Bước 4 — Prove + evidence (20')

```bash
python sink/sink.py --reset
pytest tests/test_injection.py -v      # replay cả 5 biến thể
python -m agent.loop --mock "Tổng hợp các ticket còn mở tuần này"
```

Kỳ vọng: `reports/sink.log` **rỗng** (không có CCCD/STK của `KH-000999`),
`reports/ledger.jsonl` có ≥1 dòng `decision=deny` kèm `reason`. Copy log
mới vào `reports/attack-after.log`.

(`pytest tests/test_injection.py` dùng một ledger **tạm riêng** cho mỗi
test, không đụng vào `reports/ledger.jsonl` — file đó chỉ được ghi bởi
lệnh `python -m agent.loop` bạn tự chạy tay, nên chạy `pytest` không làm
mất evidence bạn vừa tạo.)

Viết `reports/compliance-mapping.md` — 5 dòng đúng format bảng dưới,
**evidence phải là đường dẫn file/dòng thật trong repo của bạn**, không
phải mô tả chung:


| Requirement                                         | Control                                                                    | Evidence                                      |
| ----------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------- |
| Luật 91/2025 — quyền yêu cầu xoá              | (nếu chưa làm delete cascade, ghi rõ "chưa implement, xem stretch#4") | —                                            |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | data-flow inventory cho LLM API call                                       | `reports/dpia-lite.md` §2                    |
| ASI03 — privilege abuse                            | per-agent identity + TTL trong ledger                                      | `agent/policy.py`, ledger field `agent_owner` |
| ASI01 — goal hijack                                | trifecta split                                                             | `reports/attack-after.log`                    |
| ISO 42001 Clause 5-6                                | policy-as-code có review                                                  | git log của`agent/policy.py`                 |

Viết `reports/dpia-lite.md` (1 trang): dữ liệu gì, mục đích gì, chảy đi
đâu — **kể cả sang API của model provider nếu bạn dùng `--model`**, vì đó
là chuyển dữ liệu xuyên biên giới theo NĐ 356/2025.

---

## Bẫy đã lường trước


| Bẫy                                     | Xử lý                                                                                    |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Presidio + tiếng Việt                  | Regex-first. spaCy/transformers là stretch, không bắt buộc                             |
| Hết quota / không có API key          | `--mock` là first-class, dùng cho toàn bộ lab                                          |
| "Chỉ cần filter chuỗi lệnh là xong" | Thử, rồi tự phá bằng biến thể 5 — đây là bài học, không phải lỗi của bạn |
| Trỏ sink ra Internet                    | `http_post` hard-code allowlist `localhost:9999`, raise nếu khác                         |
| Run A/B chia sẻ state qua biến global  | Bắt buộc truyền typed field qua tham số hàm                                           |
| Chấm điểm không reproducible         | Luôn chấm bằng`--mock` + `pytest`, không chấm bằng model thật                       |

## Stretch goals (nếu xong sớm)

1. Port `agent/policy.py` sang OPA/Rego, so sánh 2 cách
2. Thử Presidio/spaCy hoặc transformers NER cho PII tiếng Việt, so precision/recall với regex-only
3. Delete cascade: xoá 1 subject khỏi `customers.json`, giữ ledger nguyên vẹn
4. Agent memory + memory poisoning (nếu đã học §2.3 trên slide)
5. Bọc 1 tool thành MCP server, thử "rug pull" bằng cách sửa description sau khi đã approve

## Ba câu hỏi chốt buổi

1. Bạn đã bỏ chân nào của trifecta, và agent mất đi khả năng gì?
2. Nếu attacker có quyền ghi vào `corpus/`, control nào của bạn còn đứng vững?
3. Regulator hỏi "chứng minh dữ liệu khách hàng chưa từng ra khỏi hệ
   thống" — bạn mở file nào ra?
