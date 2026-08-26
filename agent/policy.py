"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass

# Classification hợp lệ. Bất kỳ giá trị nào ngoài tập này -> fail closed
# (deny), chứ không im lặng coi như "public".
_KNOWN_CLASSIFICATIONS = ("public", "internal", "restricted")

# Agent gọi agent gọi agent... Mỗi tầng uỷ quyền làm loãng ngữ cảnh của
# quyết định gốc (ASI03 privilege abuse), nên chặn cứng ở đây.
MAX_DELEGATION_DEPTH = 2


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """PEP: quyết định cho/không cho một tool call, kèm lý do.

    `reason` luôn non-empty — kể cả khi allow — vì nó chính là dòng
    evidence trong ledger (Rubric.md: audit completeness = 100%).
    """
    classification = (context.data_classification or "").strip().lower()
    purpose = (context.request_purpose or "").strip()
    owner = (context.agent_owner or "").strip()

    # Fail closed: thiếu định danh hoặc thiếu mục đích thì không có cách nào
    # audit được quyết định này về sau.
    if not owner:
        return False, "deny: thiếu agent_owner — tool call không định danh được, không audit được"
    if not purpose:
        return False, "deny: thiếu request_purpose — purpose limitation không kiểm chứng được"
    if classification not in _KNOWN_CLASSIFICATIONS:
        return False, (
            f"deny: data_classification={context.data_classification!r} không hợp lệ "
            f"(hợp lệ: {', '.join(_KNOWN_CLASSIFICATIONS)}) — fail closed"
        )

    # RULE TỐI THIỂU bắt buộc theo Guide.md (§3b): dữ liệu restricted không
    # bao giờ đi chung một run với quyền egress. Đây là chân thứ 3 của
    # lethal trifecta bị cắt tại PEP.
    if classification == "restricted" and context.egress_enabled:
        return False, (
            f"deny: classification=restricted + egress_enabled=True "
            f"(purpose={purpose!r}, agent_owner={owner!r}) — trifecta rule, "
            f"private data không được rời hệ thống"
        )

    if context.delegation_depth > MAX_DELEGATION_DEPTH:
        return False, (
            f"deny: delegation_depth={context.delegation_depth} > "
            f"{MAX_DELEGATION_DEPTH} — chuỗi uỷ quyền quá sâu (ASI03 privilege abuse)"
        )

    return True, (
        f"allow: classification={classification}, purpose={purpose!r}, "
        f"agent_owner={owner!r}, delegation_depth={context.delegation_depth}, "
        f"egress_enabled={context.egress_enabled}"
    )
