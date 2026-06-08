# -*- coding: utf-8 -*-
"""Resource Governor layer — 策略评估 + 审计记录 + sandbox config 编译。

Public surface:
    ResourceGovernor  — 核心入口（assert_and_audit / compile_sandbox_config / add_rule）
    ToolRegistry      — Tool 元数据注册表（类型、target 参数名、名称映射）
    GovernancePolicy  — builtin_rules + user_rules 两层策略（first-match-wins）
    PolicyRule        — 单条策略规则（match + action + grantee + duration）
    PolicyDecision    — 裁决结果（ALLOW / DENY / ASK / SANDBOX_FALLBACK）
    AuditLog          — 追加式审计日志
    AuditEvent        — 单条审计记录
"""
from .resource_governor import ResourceGovernor, ToolCall
from .policy import GovernancePolicy, PolicyRule, PolicyDecision, PolicyAction, generalize_rule_match
from .tool_registry import ToolRegistry, DEFAULT_REGISTRY
from .audit import AuditLog, AuditEvent
from .tool_adapter import PolicyGuardedTool

__all__ = [
    "ResourceGovernor", "ToolCall",
    "ToolRegistry", "DEFAULT_REGISTRY",
    "GovernancePolicy", "PolicyRule", "PolicyDecision", "PolicyAction",
    "generalize_rule_match",
    "AuditLog", "AuditEvent",
    "PolicyGuardedTool",
]
