# -*- coding: utf-8 -*-
"""Workspace layer — 策略评估 + 审计记录 + sandbox config 编译。

Public surface:
    Workspace       — 核心入口（assert_and_audit / compile_sandbox_config / add_rule）
    WorkspacePolicy — 统一 PolicyRule 列表（first-match-wins）
    PolicyRule      — 单条策略规则（match + action + grantee + duration）
    PolicyDecision  — 裁决结果（ALLOW / DENY / ASK / SANDBOX_FALLBACK）
    AuditLog        — 追加式审计日志
    AuditEvent      — 单条审计记录
"""
from .workspace import Workspace, ToolCall
from .policy import WorkspacePolicy, PolicyRule, PolicyDecision, PolicyAction
from .tool_adapter import PolicyGuardedTool

__all__ = [
    "Workspace", "ToolCall",
    "WorkspacePolicy", "PolicyRule", "PolicyDecision", "PolicyAction",
    "PolicyGuardedTool",
]
