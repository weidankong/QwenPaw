# -*- coding: utf-8 -*-
"""Resource Governor — 策略评估 + 审计记录 + sandbox config 编译。

核心职责：策略评估、审计记录、动态追加规则、编译 sandbox config。
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional

from .policy import (
    GovernancePolicy, PolicyRule, PolicyAction, PolicyDecision,
    load_governance_policy, save_governance_policy,
)
from .tool_registry import DEFAULT_REGISTRY
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

    # ------------------------------------------------------------------
    # 生命周期（保留但不展开，与 runtime 有重叠）
    # ------------------------------------------------------------------

    def start(self) -> None:
        """加载 policy。"""
        self._policy_dir.mkdir(parents=True, exist_ok=True)
        self._policy = load_governance_policy(
            str(self._policy_dir), str(self.workspace_dir),
        )

    def stop(self) -> None:
        """持久化 policy（如有变更）。"""
        if self._policy and self._policy.rules:
            save_governance_policy(
                self._policy, str(self._policy_dir), str(self.workspace_dir),
            )

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
        # 对文件类 tool，将相对路径 target 解析为绝对路径
        # （shell/network/internal 类 tool 的 target 不是文件路径，不需要解析）
        target = tool_call.target
        tool_type = self._policy._registry.get_type(tool_call.tool_name)
        if tool_type in ("file", "unknown") and target and not Path(target).is_absolute():
            target = str(self.workspace_dir / target)

        decision, reason = self.policy.evaluate_with_reason(
            tool_call.tool_name, target,
            tool_call.agent_id, tool_call.session_id,
        )
        # 审计记录
        AuditLog.get_instance().record(
            str(self.workspace_dir), tool_call, decision, reason=reason,
        )
        return decision

    # ------------------------------------------------------------------
    # 核心接口 2：编译 sandbox config
    # ------------------------------------------------------------------

    def compile_sandbox_config(self, agent_id: str, session_id: str):
        """根据当前 policy 中该 agent 的所有 allow 规则，
        编译出 sandbox 可执行的权限配置（目录级白名单）。

        返回 SandboxConfig dataclass。

        编译逻辑：
            - 遍历 builtin_rules + user_rules 中 grantee 匹配的 allow 规则
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
        registry = self.policy._registry if self._policy else DEFAULT_REGISTRY

        # 遍历两层规则
        all_rules = (
            list(self._policy.builtin_rules if self._policy else [])
            + list(self._policy.user_rules if self._policy else [])
        )
        for rule in all_rules:
            if rule.grantee != "*" and rule.grantee != agent_id:
                continue
            if rule.action != PolicyAction.ALLOW:
                continue

            # 从 "ToolName(pattern)" 提取路径 pattern
            rule_tool, rule_pattern = _parse_match_from_rule(rule)

            # 跳过 shell 类 tool（Bash 走 sandbox 独立权限）
            if registry.get_type(rule_tool) == "shell":
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
        注意：规则只追加到 user_rules，builtin_rules 不可修改。
        """
        self.policy.add_rule(rule)
        save_governance_policy(
            self._policy, str(self._policy_dir), str(self.workspace_dir),
        )

    def record_approval(self, tool_call: ToolCall, approved: bool) -> None:
        """记录用户 approve/deny 的结果到审计日志。

        ASK 裁决后用户确认时调用，补全审计链：
            assert_and_audit → ASK（已记录）
            record_approval  → ALLOW/DENY（补这条）
        """
        decision = PolicyDecision.ALLOW if approved else PolicyDecision.DENY
        reason = "User Approve" if approved else "User Deny"
        AuditLog.get_instance().record(
            str(self.workspace_dir), tool_call, decision, reason=reason,
        )

    def is_builtin_ask(self, tool_name: str, target: str,
                       agent_id: str, session_id: str = "") -> bool:
        """判断 tool call 的 ASK 是否来自 builtin_rules。

        builtin ask → approve 后不记规则（每次都要问）
        user ask   → approve 后记规则（下次不问）

        由 tool_adapter 的 approve 流程调用，决定是否持久化新规则。
        """
        if not self._policy:
            return False
        source = self._policy.evaluate_source(
            tool_name, target, agent_id, session_id,
        )
        return source == "builtin"

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
        """获取全局 AuditLog 单例。"""
        return AuditLog.get_instance()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------



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
