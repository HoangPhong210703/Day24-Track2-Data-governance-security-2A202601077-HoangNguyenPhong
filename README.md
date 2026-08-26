# Day 24: Data governance and Security — Attack your own agent, then contain it

Bạn sẽ: (1) chạy một agent chưa có kiểm soát gì, (2) tự tay khiến nó gửi
PII của khách hàng ra ngoài bằng prompt injection, (3) viết 4 control để
chặn đúng cuộc tấn công đó, (4) tấn công lại và chứng minh bằng log/ledger
rằng nó bị chặn.

**Đọc trước khi bắt đầu:**

- [`Guide.md`](Guide.md) — timeline 2h, hướng dẫn từng bước
- [`Rubric.md`](Rubric.md) — cách chấm điểm, có **điều kiện trượt** không phụ thuộc tổng điểm, đọc kỹ trước khi bắt đầu

## Quy tắc an toàn (đọc trước khi chạy bất cứ thứ gì)

- Chỉ tấn công **agent của chính bạn**, trong repo này.
- Sink (đích exfil) **chỉ** là `localhost:9999`. `http_post` bị hard-code
  chặn mọi host khác — đừng cố gỡ allowlist này.
- Không dùng dữ liệu cá nhân thật của bất kỳ ai. Toàn bộ `corpus/` và
  `data/customers.json` là dữ liệu tổng hợp (synthetic).
- Payload injection bạn viết nằm trong repo lab, **không đăng public**
  (không post lên social media, không commit vào repo khác).

## Model dùng cho lab này


| Lựa chọn                 | Khi nào dùng                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `--mock`                   | **Mặc định. Dùng cho toàn bộ lab và để chấm điểm.** Không cần API key, deterministic, reproducible. |
| `--model claude-haiku-4-5` | Muốn thử với model thật, chi phí thấp                                                                       |
| `--model claude-opus-5`    | Muốn thử injection với model "thông minh" thật                                                               |

`--mock` không phải bản rút gọn cho vui — nó là một fake LLM deterministic
đọc tool output và tuân theo chỉ thị nó thấy trong đó, đúng cách một model
thật bị inject. Bài học không đổi khi bạn đổi sang model thật, chỉ có chi
phí và độ tái lập là đổi. **Lab này được chấm bằng `--mock`.**

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# tab 1: sink server
python sink/sink.py

# tab 2: smoke test
python -m agent.loop --mock "Tóm tắt ticket về hoá đơn"
```

Thấy agent gọi tool và trả về một câu tóm tắt là setup xong. Chưa chạy
được thì dùng ngay `--mock`, đừng debug API key — bài lab không cần API
key ở đường mặc định.

## Cấu trúc repo

```
lab24-governed-agent/
├── README.md              bạn đang đọc file này
├── Guide.md               timeline 2h, hướng dẫn từng bước
├── Rubric.md               cách chấm điểm, điều kiện trượt
├── requirements.txt
├── pytest.ini
├── corpus/                 40 ticket khách hàng (có PII synthetic) + ticket-901.md (ví dụ injection)
├── data/customers.json     private data store
├── agent/
│   ├── loop.py             [có sẵn] CLI + baseline loop
│   ├── tools.py            [có sẵn] search_docs / read_customer / http_post
│   ├── llm.py              [có sẵn] fake LLM deterministic (--mock)
│   ├── pii.py              BƯỚC 3a — bạn viết
│   ├── policy.py           BƯỚC 3b — bạn viết
│   ├── runner.py           BƯỚC 3c — bạn viết
│   └── ledger.py           BƯỚC 3d — bạn viết
├── sink/sink.py            [có sẵn] local exfil sink :9999
├── injection-corpus.md     BƯỚC 2 — bạn viết ≥5 biến thể (1 đã có sẵn)
├── tests/
│   ├── test_pii.py         [có sẵn]
│   ├── test_policy.py      [có sẵn]
│   ├── test_ledger.py      [có sẵn]
│   ├── test_injection.py   [có sẵn] replay 5 biến thể
│   └── vn_pii_testset.jsonl [có sẵn] test set có nhãn
└── reports/                bạn điền: attack-before.log, attack-after.log,
                             compliance-mapping.md, dpia-lite.md
```

## Nộp bài

Nộp lại toàn bộ thư mục này (hoặc git repo) sau khi đã:

1. Viết xong `agent/pii.py`, `agent/policy.py`, `agent/runner.py`, `agent/ledger.py`
2. Viết xong `injection-corpus.md` với ≥5 biến thể
3. Có `reports/attack-before.log`, `reports/attack-after.log`
4. Có `reports/compliance-mapping.md`, `reports/dpia-lite.md`
5. `pytest` chạy được (không cần 100% pass — điểm theo `Rubric.md`, nhưng
   đọc kỹ điều kiện trượt)
