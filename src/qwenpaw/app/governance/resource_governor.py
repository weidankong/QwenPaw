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
        if self._audit_log:
            self._audit_log.flush()
        if self._policy and self._policy.rules:
            save_governance_policy(self._policy, str(self._policy_dir))

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
            workspace_dir=str(self.workspace_dir),
        )
        # 审计记录
        if self._audit_log:
            self._audit_log.record(tool_call, decision)
        return decision

    # ------------------------------------------------------------------
    # 核心接口 2：编译 sandbox config
    # ------------------------------------------------------------------

    def compile_sandbox_config(
        self, tool_call: ToolCall,
    ):
        """根据当前 policy 中与 tool_call 匹配的 allow 规则，
        编译出 sandbox 可执行的权限配置（目录级白名单）。

        只有 rule.matches_tool_call(tool_call) 为 True 的规则才贡献资源。
        """
        from qwenpaw.sandbox.config import (
            MountSpec, SandboxConfig, detect_platform_mode,
        )

        mounts = []
        seen_paths = set()

        # 1. workspace_dir 始终加入 mounts（可读写）
        ws = str(self.workspace_dir)
        mounts.append(MountSpec(path=ws, writable=True))
        seen_paths.add(".")

        # 2. 从匹配的 allow 规则中提取额外路径
        for rule in self._policy.rules if self._policy else []:
            if rule.grantee != "*" and rule.grantee != tool_call.agent_id:
                continue
            if rule.action != PolicyAction.ALLOW:
                continue
            if not rule.matches_tool_call(
                tool_call.tool_name, tool_call.target,
                tool_call.agent_id, tool_call.session_id,
            ):
                continue

            rule_tool, rule_pattern = _parse_match_from_rule(rule)
            mount_path = _glob_to_mount_path(rule_pattern)
            if not mount_path or mount_path in seen_paths:
                continue
            seen_paths.add(mount_path)

            resolved = self.workspace_dir / mount_path
            # workspace 内路径跳过（已被 workspace mount 覆盖）
            try:
                resolved_resolved = resolved.resolve()
                ws_resolved = self.workspace_dir.resolve()
                if str(resolved_resolved).startswith(str(ws_resolved) + "/") or resolved_resolved == ws_resolved:
                    continue
            except (OSError, ValueError):
                pass

            mounts.append(MountSpec(
                path=str(resolved),
                writable=rule_tool not in ("Read", "Grep", "Glob"),
            ))

        return SandboxConfig(
            mode=detect_platform_mode(),
            workspace_dir=ws,
            mounts=mounts,
            deny_paths=[
                # SSH 密钥和配置
                "~/.ssh",
                # AWS 凭证
                "~/.aws",
                # GPG 密钥
                "~/.gnupg",
                # Kubernetes 配置
                "~/.kube",
                # Google Cloud 凭证
                "~/.config/gcloud",
                # Docker 认证
                "~/.docker/config.json",
                # 通用环境变量文件
                "~/.env",
                "~/.claude",
                # macOS Keychain 数据库
                "~/Library/Keychains",
                # 浏览器凭据
                "~/Library/Application Support/Google/Chrome/Default/Login Data",
                "~/Library/Application Support/Firefox/Profiles",
                # Git 凭据
                "~/.git-credentials",
                # Terraform 状态（可能含敏感信息）
                "~/.terraformrc",
                # 其他常见敏感配置
                "~/.config/gh",  # GitHub CLI
                "~/.config/nix",  # Nix 配置
            ],
            network_allow=["*"],
            timeout_seconds=60,
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
