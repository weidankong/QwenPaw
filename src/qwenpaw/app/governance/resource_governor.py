# -*- coding: utf-8 -*-
"""Resource Governor — 策略评估 + 审计记录 + sandbox config 编译。

设计决策（2025-06-02）：
- ResourceGovernor 核心职责：策略评估、审计记录、动态追加规则、编译 sandbox config。
- assert_and_audit 接收 tool_call，返回 PolicyDecision。
- compile_sandbox_config 根据 policy 中 allow 规则编译出 SandboxConfig。
- Registry 和生命周期管理保留但不展开（与 runtime 有重叠）。
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

from .policy import (
    GovernancePolicy, PolicyRule, PolicyAction, PolicyDecision,
    SANDBOX_TOOLS, load_governance_policy, save_governance_policy,
)
from .audit import AuditLog


# ---------------------------------------------------------------------------
# ToolCall — workspace 对 tool call 的抽象输入
# ---------------------------------------------------------------------------

class ToolCall:
    """一次 tool 调用的描述（workspace 用于裁决）。

    Attributes:
        tool_name: tool 名称，如 "Read", "Bash", "Write"
        target: tool 的目标参数，如 "src/main.py", "git push"
        agent_id: 发起调用的 agent ID
        session_id: 当前会话 ID
    """

    def __init__(self, tool_name: str, target: str,
                 agent_id: str, session_id: str):
        self.tool_name = tool_name
        self.target = target
        self.agent_id = agent_id
        self.session_id = session_id


class ResourceGovernor:
    """ResourceGovernor — 策略与审计的核心。

    职责：
        1. 策略评估：assert_and_audit(tool_call) → PolicyDecision
        2. 编译 sandbox config：compile_sandbox_config() → SandboxConfig
        3. 审计记录：每次 assert_and_audit 记录 audit log
        4. 动态追加规则：用户 approve 后 add_rule(...)

    NOT responsible for（待讨论）：
        - sandbox 创建/销毁 → 由协调层管理
        - Runtime/Agent 编排 → 待定
    """

    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir)
        # policy 存储在 workspace 外的独立路径，防止 agent 改写
        self._policy_dir = Path.home() / ".qwenpaw" / "policies" / self.workspace_dir.name
        self._policy: Optional[GovernancePolicy] = None
        self._audit_log: Optional[AuditLog] = None

    # ------------------------------------------------------------------
    # 生命周期（保留但不展开，与 runtime 有重叠）
    # ------------------------------------------------------------------

    def start(self) -> None:
        """加载 policy、初始化 audit log。"""
        self._policy_dir.mkdir(parents=True, exist_ok=True)
        self._policy = load_governance_policy(str(self._policy_dir))
        self._audit_log = AuditLog(str(self.workspace_dir))

    def stop(self) -> None:
        """flush audit log 到磁盘，持久化 policy（如有变更）。"""
        self._flush_audit_log()
        if self._policy and self._policy.rules:
            save_governance_policy(self._policy, str(self._policy_dir))

    def _flush_audit_log(self) -> None:
        """将内存审计事件写入 audit.jsonl。"""
        if self._audit_log is None:
            return
        events = self._audit_log._events
        if not events:
            return
        audit_path = self.workspace_dir / "audit_log" / "audit.jsonl"
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
        # 清空内存列表，避免下次 flush 重复写入
        events.clear()

    # ------------------------------------------------------------------
    # 核心接口 1：策略评估 + 审计
    # ------------------------------------------------------------------

    def assert_and_audit(self, tool_call: ToolCall) -> PolicyDecision:
        """对一次 tool call 进行策略裁决并记录审计日志。

        流程：
            1. policy.evaluate(tool_name, target, agent_id) → decision
            2. audit_log.append(tool_call, decision)
            3. return decision

        返回 PolicyDecision:
            ALLOW            → 明确 resource tool 直接执行；
                               bash tool sandbox 内预授权执行
            DENY             → 拒绝
            ASK              → 问用户
            SANDBOX_FALLBACK → bash 类 tool 无命中，sandbox 兜底
        """
        decision = self.policy.evaluate(
            tool_call.tool_name, tool_call.target,
            tool_call.agent_id, tool_call.session_id,
        )
        # workspace 内 Read/Grep/Glob 无命中规则 → 默认允许（不需 approve）
        if decision == PolicyDecision.ASK and tool_call.tool_name in (
            "Read", "Grep", "Glob",
        ):
            if self._is_within_workspace(tool_call.target):
                decision = PolicyDecision.ALLOW
        # 审计记录
        if self._audit_log:
            self._audit_log.record(tool_call, decision)
        return decision

    # ------------------------------------------------------------------
    # 核心接口 2：编译 sandbox config
    # ------------------------------------------------------------------

    def compile_sandbox_config(self, agent_id: str, session_id: str):
        """根据当前 policy 中该 agent 的所有 allow 规则，
        编译出 sandbox 可执行的权限配置（目录级白名单）。

        返回 SandboxConfig dataclass。

        编译逻辑：
            - 遍历 policy.rules 中 grantee 匹配的 allow 规则
            - 提取路径级权限 → mounts
            - 提取网络权限 → network_allow
            - 设置 timeout、env_vars 等

        注意：sandbox 的粒度是目录/文件路径白名单，
        做不到文件类型级别（如 "只允许 .py"）。
        """
        from dataclasses import dataclass

        @dataclass
        class MountSpec:
            path: str
            readonly: bool = False

        @dataclass
        class SandboxConfig:
            mounts: list
            network_allow: list
            timeout: float = 60.0
            env_vars: dict = None

        mounts = []
        seen_paths = set()

        for rule in self._policy.rules if self._policy else []:
            if rule.grantee != "*" and rule.grantee != agent_id:
                continue
            if rule.action != PolicyAction.ALLOW:
                continue

            # 从 "ToolName(pattern)" 提取路径 pattern
            rule_tool, rule_pattern = _parse_match_from_rule(rule)
            # 只处理文件类 tool 的路径（Read, Write, Edit 等）
            if rule_tool in SANDBOX_TOOLS:
                continue

            # 将 glob pattern 转为 sandbox mount 路径
            # 支持的模式：Read(src/**) → mount src/
            #           Write(.env*) → mount 目录级（取 prefix）
            mount_path = _glob_to_mount_path(rule_pattern)
            if mount_path and mount_path not in seen_paths:
                seen_paths.add(mount_path)
                resolved = self.workspace_dir / mount_path
                mounts.append(MountSpec(
                    path=str(resolved),
                    readonly=rule_tool in ("Read", "Grep", "Glob"),
                ))

        return SandboxConfig(
            mounts=mounts,
            network_allow=[],  # 从 policy 中扩展
            timeout=60.0,
        )

    # ------------------------------------------------------------------
    # 核心接口 3：动态追加规则
    # ------------------------------------------------------------------

    def add_rule(self, rule: PolicyRule) -> None:
        """用户 approve 后动态追加规则到 policy。

        approve 后的规则会带 duration（session / permanent）。
        并持久化到 policy.yaml中。
        """
        self.policy.add_rule(rule)
        save_governance_policy(self._policy, str(self._policy_dir))

    # ------------------------------------------------------------------
    # 属性访问
    # ------------------------------------------------------------------

    @property
    def policy(self) -> GovernancePolicy:
        if self._policy is None:
            raise RuntimeError("ResourceGovernor not started")
        return self._policy

    @property
    def audit_log(self) -> AuditLog:
        if self._audit_log is None:
            raise RuntimeError("ResourceGovernor not started")
        return self._audit_log

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_within_workspace(self, target: str) -> bool:
        """判断 target 路径是否在 workspace_dir 范围内。"""
        if not target or target == "*":
            return False
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = self.workspace_dir / target_path
        try:
            resolved = target_path.resolve()
            ws_resolved = self.workspace_dir.resolve()
            return str(resolved).startswith(str(ws_resolved) + "/") or resolved == ws_resolved
        except (OSError, ValueError):
            return False


# ---------------------------------------------------------------------------
# Helpers for compile_sandbox_config
# ---------------------------------------------------------------------------

def _parse_match_from_rule(rule: PolicyRule) -> tuple[str, str]:
    """从 PolicyRule.match 解析出 (tool_name, pattern)。"""
    from .policy import _parse_match
    return _parse_match(rule.match)


def _glob_to_mount_path(pattern: str) -> str | None:
    """将 glob pattern 转为 sandbox mount 路径。

    支持的模式：
        src/**    → src/       (递归目录)
        src/*.py  → src/       (目录级)
        .env*     → .env       (文件 prefix)
        **        → .          (整个 workspace)
        src/foo   → src/foo    (精确文件/目录)
    """
    if not pattern or pattern == "**":
        return "."

    # 递归通配 → 目录
    if pattern.endswith("/**"):
        return pattern[:-3]
    if pattern.endswith("/*"):
        return pattern[:-2]

    # 文件级 glob（如 .env*、*.py）→ 取目录部分
    if "/" in pattern:
        return pattern.rsplit("/", 1)[0]

    # 无前缀通配 → 可能是文件 prefix
    if pattern.endswith("*"):
        return pattern.rstrip("*")

    # 精确路径
    return pattern
