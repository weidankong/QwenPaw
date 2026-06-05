# -*- coding: utf-8 -*-
"""Resource Governor layer — 策略评估 + 审计记录 + sandbox config 编译。

Public surface:
    ResourceGovernor  — 核心入口（assert_and_audit / compile_sandbox_config / add_rule）
    GovernancePolicy — 统一 PolicyRule 列表（first-match-wins）
    PolicyRule      — 单条策略规则（match + action + grantee + duration）
    PolicyDecision  — 裁决结果（ALLOW / DENY / ASK / SANDBOX_FALLBACK）
    AuditLog        — 追加式审计日志
    AuditEvent      — 单条审计记录
"""
from .resource_governor import ResourceGovernor, ToolCall
from .policy import GovernancePolicy, PolicyRule, PolicyDecision, PolicyAction
from .audit import AuditLog, AuditEvent
from .tool_adapter import PolicyGuardedTool

__all__ = [
    "ResourceGovernor", "ToolCall",
    "GovernancePolicy", "PolicyRule", "PolicyDecision", "PolicyAction",
    "AuditLog", "AuditEvent",
    "PolicyGuardedTool",
]
