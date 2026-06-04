# -*- coding: utf-8 -*-
"""AuditLog — 每次 assert_and_audit 的审计记录。

设计决策（2025-06-02）：
- 审计日志 = tool call hook 产物。
- 每次 workspace.assert_and_audit() 都写一条记录。
- 具体格式和存储方式待后续细化（见 0602.md "待讨论"）。
"""
from __future__ import annotations
from dataclasses import dataclass, field
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
        self.workspace_dir = workspace_dir
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

    def drain_events(self) -> List[AuditEvent]:
        """取出所有事件并清空内存列表（供 flush 使用）。"""
        events = self._events
        self._events = []
        return events

    def query(
        self,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """查询审计事件（供 Console UI 使用）。"""
        raise NotImplementedError
