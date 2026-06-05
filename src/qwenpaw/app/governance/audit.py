# -*- coding: utf-8 -*-
"""AuditLog — 每次 assert_and_audit 的审计记录。

存储方案：单文件 SQLite (~/.qwenpaw/audit.db)，全局单例。
- record() 立即落库，无内存缓冲
- query() 支持按 workspace / agent / tool / decision / 时间范围过滤，分页
- purge() 删除过期记录并 VACUUM 回收空间
- 自动清理：总条目达到 10 万条时，删除最旧的 1 万条
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_events (
    ts            TEXT NOT NULL,
    workspace_dir TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    tool_name     TEXT NOT NULL,
    target        TEXT NOT NULL,
    decision      TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    extra         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_workspace ON audit_events(workspace_dir);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool_name);
"""


@dataclass
class AuditEvent:
    """一条审计记录。

    记录 5W：who (agent_id), what (tool_name + target),
    when (ts), outcome (decision), why (reason).
    """
    ts: str                          # ISO 8601 UTC
    workspace_dir: str
    agent_id: str
    session_id: str
    tool_name: str
    target: str
    decision: str                    # "allow" | "deny" | "ask" | "sandbox_fallback"
    reason: str = ""                 # 额外说明（如 violation 原因）
    extra: dict = field(default_factory=dict)


def _event_from_row(row: sqlite3.Row) -> AuditEvent:
    """从 SQLite 行构造 AuditEvent。"""
    return AuditEvent(
        ts=row["ts"],
        workspace_dir=row["workspace_dir"],
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        tool_name=row["tool_name"],
        target=row["target"],
        decision=row["decision"],
        reason=row["reason"],
        extra=json.loads(row["extra"]),
    )


class AuditLog:
    """追加式审计日志，SQLite 持久化，全局单例。

    由多个 ResourceGovernor 共享，每次 assert_and_audit 调用 record() 立即写库。
    """

    MAX_RECORDS = 100_000       # 触发自动清理的阈值
    PURGE_COUNT = 10_000        # 每次清理删除的条数
    _CHECK_INTERVAL = 1_000     # 每 N 次 record 检查一次是否需要清理

    _instance: Optional[AuditLog] = None

    @classmethod
    def get_instance(cls) -> AuditLog:
        """获取全局单例，首次调用时初始化。"""
        if cls._instance is None:
            db_path = Path.home() / ".qwenpaw" / "audit.db"
            cls._instance = cls._create(db_path)
        return cls._instance

    @classmethod
    def _create(cls, db_path: Path) -> AuditLog:
        """内部工厂方法，创建实例并初始化数据库。"""
        obj = object.__new__(cls)
        obj._db_path = db_path
        obj._db_path.parent.mkdir(parents=True, exist_ok=True)
        obj._conn = sqlite3.connect(
            str(obj._db_path), check_same_thread=False
        )
        obj._conn.row_factory = sqlite3.Row
        obj._conn.execute("PRAGMA journal_mode=WAL")
        obj._conn.executescript(_SCHEMA)
        obj._conn.commit()
        obj._insert_count = 0
        return obj

    def close(self) -> None:
        """关闭数据库连接，重置单例。"""
        if self._conn:
            self._conn.close()
            self._conn = None
        AuditLog._instance = None

    def record(self, workspace_dir: str, tool_call, decision) -> None:
        """记录一次裁决结果，立即写入 SQLite。

        Args:
            workspace_dir: 所属 workspace 路径
            tool_call: ToolCall 实例
            decision: PolicyDecision 值
        """
        from datetime import datetime, timezone
        self._conn.execute(
            "INSERT INTO audit_events "
            "(ts, workspace_dir, agent_id, session_id, tool_name, target, decision, reason, extra) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                workspace_dir,
                tool_call.agent_id,
                tool_call.session_id,
                tool_call.tool_name,
                tool_call.target,
                str(decision.value),
                "",
                "{}",
            ),
        )
        self._conn.commit()

        # 自动清理检查（每 _CHECK_INTERVAL 次检查一次，避免每次都 SELECT COUNT）
        self._insert_count += 1
        if self._insert_count >= self._CHECK_INTERVAL:
            self._insert_count = 0
            if self.count >= self.MAX_RECORDS:
                self._auto_purge()

    def query(
        self,
        workspace_dir: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        decision: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[AuditEvent], int]:
        """查询审计事件，支持分页。

        Args:
            workspace_dir: 按 workspace 过滤
            agent_id: 按 agent 过滤
            tool_name: 按工具名过滤
            decision: 按裁决结果过滤
            since: 起始时间 (ISO 8601)，含
            until: 截止时间 (ISO 8601)，含
            limit: 每页条数
            offset: 偏移量（翻页用）

        Returns:
            (events, total) — 事件列表和符合条件的总条数
        """
        clauses: list[str] = []
        params: list = []

        if workspace_dir:
            clauses.append("workspace_dir = ?")
            params.append(workspace_dir)
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""

        # 总条数
        count_sql = f"SELECT COUNT(*) FROM audit_events{where}"
        total = self._conn.execute(count_sql, params).fetchone()[0]

        # 分页查询
        data_sql = f"SELECT * FROM audit_events{where} ORDER BY ts DESC LIMIT ? OFFSET ?"
        data_params = params + [limit, offset]
        rows = self._conn.execute(data_sql, data_params).fetchall()

        return [_event_from_row(r) for r in rows], total

    def purge(self, before: str) -> int:
        """删除指定时间之前的记录并 VACUUM 回收空间。

        Args:
            before: 截止时间 (ISO 8601)，不含

        Returns:
            删除的记录数
        """
        cursor = self._conn.execute(
            "DELETE FROM audit_events WHERE ts < ?", (before,)
        )
        self._conn.commit()
        deleted = cursor.rowcount
        if deleted > 0:
            self._conn.execute("VACUUM")
        return deleted

    @property
    def count(self) -> int:
        """当前记录总数。"""
        return self._conn.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

    def _auto_purge(self) -> None:
        """删除最旧的 PURGE_COUNT 条记录并 VACUUM。"""
        row = self._conn.execute(
            "SELECT rowid FROM audit_events ORDER BY rowid ASC LIMIT 1 OFFSET ?",
            (self.PURGE_COUNT,),
        ).fetchone()
        if row:
            self._conn.execute(
                "DELETE FROM audit_events WHERE rowid <= ?", (row["rowid"],)
            )
            self._conn.commit()
            self._conn.execute("VACUUM")
