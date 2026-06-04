# -*- coding: utf-8 -*-
"""GovernancePolicy — unified PolicyRule model (first-match-wins).

设计决策（2025-06-02）：
- grant 和 rule 统一为 PolicyRule，一个引擎、一种数据结构。
- 匹配格式：ToolName(pattern)，pattern 对 tool 目标参数做 glob。
- 评估顺序：first-match-wins（类似防火墙规则）。
- 无命中时的 fallback 由 tool 类型决定：
    - 明确 resource 的 tool（Read, Write）→ ask
    - Bash 类 tool → sandbox
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    """规则命中后的行为。"""
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class PolicyDecision(str, Enum):
    """assert_and_audit 的裁决结果。"""
    ALLOW = "allow"           # 命中 allow → 直接执行（explicit tool）或 sandbox 预授权执行（bash）
    DENY = "deny"             # 命中 deny → 拒绝
    ASK = "ask"               # 命中 ask 或 explicit tool 无命中 → 问用户
    SANDBOX_FALLBACK = "sandbox_fallback"  # bash 类 tool 无命中 → sandbox 兜底


@dataclass
class PolicyRule:
    """统一的策略规则。

    match 格式: "ToolName(pattern)"
        - ToolName: Read, Write, Bash, Python, Node 等
        - pattern: glob，对 tool 的目标参数匹配

    示例:
        PolicyRule(match="Bash(git *)", action=PolicyAction.ALLOW)
        PolicyRule(match="Write(.env*)", action=PolicyAction.DENY)
        PolicyRule(match="Read(src/**)", action=PolicyAction.ALLOW,
                   grantee="agent-abc", duration="session")

    action 语义因 tool 类型而异:
        明确 resource 的 tool:
            allow → 直接执行（不进 sandbox）
            deny  → 拒绝
            ask   → 问用户，approve 后直接执行
        Bash 类 tool:
            allow → sandbox 内执行（已预授权，不会 violation）
            deny  → 拒绝（不进 sandbox）
            ask   → 问用户，approve 后 sandbox 内执行
    """
    match: str                              # "ToolName(pattern)"
    action: PolicyAction = PolicyAction.DENY
    grantee: str = "*"                      # 被授权主体，"*" 表示所有 agent
    duration: str = "permanent"             # "session" | "permanent"
    session_id: Optional[str] = None        # session 级规则绑定的 chat session ID

    def matches_tool_call(self, tool_name: str, target: str,
                          agent_id: str, session_id: str = "") -> bool:
        """判断此规则是否匹配给定的 tool call。

        匹配逻辑：
            1. grantee 匹配（"*" 匹配所有）
            2. session 级规则：session_id 必须匹配
            3. 解析 self.match 为 (rule_tool, rule_pattern)
            4. tool_name 精确匹配 rule_tool
            5. target 对 rule_pattern 做 glob 匹配
        """
        # grantee check
        if self.grantee != "*" and self.grantee != agent_id:
            return False
        # session 级规则：绑定到特定 chat session
        if self.duration == "session" and self.session_id and session_id:
            if self.session_id != session_id:
                return False
        # parse "ToolName(pattern)"
        rule_tool, rule_pattern = _parse_match(self.match)
        if rule_tool != tool_name:
            return False
        return fnmatch(target, rule_pattern)


# ---------------------------------------------------------------------------
# Bash 类 tool 列表（policy 隐含，但需要 fallback 时判断 tool 类型）
# ---------------------------------------------------------------------------

# tool 类型判断：如果 policy 中出现 "ToolName(...)" 且 ToolName 在此集合中，
# 则该 tool call 的 "无命中 fallback" 是 sandbox；否则是 ask。
SANDBOX_TOOLS = {"Bash", "Python", "Node", "Shell"}


@dataclass
class GovernancePolicy:
    """统一策略：PolicyRule 列表 + first-match-wins。

    加载自 policy_dir/policy.yaml，由 ResourceGovernor 持有。

    生命周期：
        load → evaluate（热路径）→ add_rule（用户 approve）→ save
    """
    version: str = "1.0"
    rules: List[PolicyRule] = field(default_factory=list)
    audit_level: str = "all"       # "all" | "write_only" | "none"

    # ------------------------------------------------------------------
    # 热路径：每次 tool call 调用
    # ------------------------------------------------------------------

    def evaluate(self, tool_name: str, target: str,
                 agent_id: str, session_id: str = "") -> PolicyDecision:
        """对一次 tool call 进行策略裁决。

        评估逻辑（first-match-wins）：
            1. 按顺序遍历 rules
            2. 第一条匹配的 rule 决定 action
            3. 无命中 → 根据 tool 类型决定 fallback:
               - tool_name in SANDBOX_TOOLS → SANDBOX_FALLBACK
               - 否则 → ASK

        返回: PolicyDecision (ALLOW / DENY / ASK / SANDBOX_FALLBACK)
        """
        for rule in self.rules:
            if rule.matches_tool_call(tool_name, target, agent_id, session_id):
                return PolicyDecision(rule.action.value)
        # 无命中 fallback
        if tool_name in SANDBOX_TOOLS:
            return PolicyDecision.SANDBOX_FALLBACK
        return PolicyDecision.ASK

    # ------------------------------------------------------------------
    # 动态变更
    # ------------------------------------------------------------------

    def add_rule(self, rule: PolicyRule) -> None:
        """追加规则（用户 approve 后调用）。

        新规则追加到列表末尾。由于 first-match-wins，
        deny 规则应放在列表前部（由 policy 编辑器保证）。
        """
        self.rules.append(rule)

    def remove_rule(self, index: int) -> None:
        """移除规则（Console UI / 管理操作）。"""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _parse_match(match_str: str) -> tuple:
    """解析 "ToolName(pattern)" → (tool_name, pattern)。

    使用 rindex 找最后一个 "("，处理 pattern 内含 "(" 的情况。
    例: "Bash(git *)" → ("Bash", "git *")
        "Read(src/**)" → ("Read", "src/**")
        "Write(.env*)" → ("Write", ".env*")
    """
    paren = match_str.rindex("(")
    close = match_str.rindex(")")
    tool_name = match_str[:paren]
    pattern = match_str[paren + 1:close]
    return tool_name, pattern


# ---------------------------------------------------------------------------
# 加载 / 持久化
# ---------------------------------------------------------------------------

def load_governance_policy(policy_dir: str) -> GovernancePolicy:
    """从 policy_dir/policy.yaml 加载；缺失时返回空 policy。

    YAML 格式：
        version: "1.0"
        audit_level: "all"
        rules:
          - match: "Read(src/**)"
            action: allow
          - match: "Write(.env*)"
            action: deny
            grantee: "agent-abc"
          - match: "Bash(git *)"
            action: allow
            duration: permanent
    """
    import yaml

    path = Path(policy_dir) / "policy.yaml"
    if not path.exists():
        return GovernancePolicy()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        return GovernancePolicy()

    if not isinstance(data, dict):
        return GovernancePolicy()

    rules = []
    for item in data.get("rules", []) or []:
        if not isinstance(item, dict) or "match" not in item:
            continue
        action_str = item.get("action", "deny")
        try:
            action = PolicyAction(action_str)
        except ValueError:
            action = PolicyAction.DENY
        rules.append(PolicyRule(
            match=item["match"],
            action=action,
            grantee=item.get("grantee", "*"),
            duration=item.get("duration", "permanent"),
            session_id=item.get("session_id"),
        ))

    return GovernancePolicy(
        version=data.get("version", "1.0"),
        rules=rules,
        audit_level=data.get("audit_level", "all"),
    )


def save_governance_policy(policy: GovernancePolicy, policy_dir: str) -> None:
    """原子写入 policy.yaml（先写 .tmp 再 rename）。"""
    import tempfile
    import yaml

    path = Path(policy_dir) / "policy.yaml"
    data = {
        "version": policy.version,
        "audit_level": policy.audit_level,
        "rules": [
            {
                "match": r.match,
                "action": r.action.value,
                "grantee": r.grantee,
                "duration": r.duration,
                **({"session_id": r.session_id} if r.session_id else {}),
            }
            for r in policy.rules
        ],
    }

    # 原子写入：先写临时文件再 rename
    dirpath = path.parent
    fd, tmp_path = tempfile.mkstemp(dir=str(dirpath), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
