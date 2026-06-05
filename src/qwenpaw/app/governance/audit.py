# -*- coding: utf-8 -*-
"""AuditLog — 每次 assert_and_audit 的审计记录。

设计决策（2025-06-02）：
- 审计日志 = tool call hook 产物。
- 每次 workspace.assert_and_audit() 都写一条记录。
- 具体格式和存储方式待后续细化（见 0602.md "待讨论"）。
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class AuditEvent:
    """一条审计记录。

    记录 5W：who (agent_id), what (tool_name + target),
    when (ts), outcome (decision), why (reason).
    """
    ts: str                          # ISO 8601 UTC
    agent_id: str
    session_id: str
    tool_name: str
    target: str
    decision: str                    # "allow" | "deny" | "ask" | "sandbox_fallback"
    reason: str = ""                 # 额外说明（如 violation 原因）
    extra: dict = field(default_factory=dict)


class AuditLog:
    """追加式审计日志。

    由 ResourceGovernor 持有，每次 assert_and_audit 调用 record()。
    """

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir)
        self._events: List[AuditEvent] = []

    def record(self, tool_call, decision) -> None:
        """记录一次裁决结果。

        Args:
            tool_call: ToolCall 实例
            decision: PolicyDecision 值
        """
        from datetime import datetime, timezone
        event = AuditEvent(
            ts=datetime.now(timezone.utc).isoformat(),
            agent_id=tool_call.agent_id,
            session_id=tool_call.session_id,
            tool_name=tool_call.tool_name,
            target=tool_call.target,
            decision=str(decision.value),
        )
        self._events.append(event)

    def flush(self) -> None:
        """将内存审计事件写入 {workspace_dir}/audit_log/audit.jsonl 并清空。"""
        if not self._events:
            return
        audit_dir = self.workspace_dir / "audit_log"
        audit_dir.mkdir(parents=True, exist_ok=True)
        audit_path = audit_dir / "audit.jsonl"
        events, self._events = self._events, []
        with open(audit_path, "a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps({
                    "ts": event.ts,
                    "agent_id": event.agent_id,
                    "session_id": event.session_id,
                    "tool_name": event.tool_name,
                    "target": event.target,
                    "decision": event.decision,
                    "reason": event.reason,
                    "extra": event.extra,
                }, ensure_ascii=False) + "\n")

    def query(
        self,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """查询审计事件（供 Console UI 使用）。"""
        raise NotImplementedError
