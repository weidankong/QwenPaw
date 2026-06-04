# -*- coding: utf-8 -*-
"""PolicyGuardedTool — governance 策略检查的 tool wrapper。

替代现有的 GuardedFunctionTool。每次 tool 调用走两层：
1. check_permissions: 预执行裁决 — ToolCall → governor.assert_and_audit()
2. __call__: 实际执行 — 处理 sandbox violation retry loop
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

from .policy import PolicyRule, PolicyAction


# ---------------------------------------------------------------------------
# 工具名映射：python 函数名 → policy tool 名（PascalCase）
# ---------------------------------------------------------------------------

_TOOL_NAME_OVERRIDES = {
    "execute_shell_command": "Bash",
    "read_file": "Read",
    "write_file": "Write",
    "edit_file": "Edit",
    "append_file": "Append",
    "grep_search": "Grep",
    "glob_search": "Glob",
    "browser_use": "Browser",
    "desktop_screenshot": "DesktopScreenshot",
    "send_file_to_user": "SendFileToUser",
    "view_image": "ViewImage",
    "view_video": "ViewVideo",
    "get_current_time": "GetCurrentTime",
    "set_user_timezone": "SetUserTimezone",
    "get_token_usage": "GetTokenUsage",
    "delegate_external_agent": "DelegateExternalAgent",
    "list_agents": "ListAgents",
    "chat_with_agent": "ChatWithAgent",
    "submit_to_agent": "SubmitToAgent",
    "check_agent_task": "CheckAgentTask",
    "materialize_skill": "MaterializeSkill",
}


def _python_name_to_policy_tool_name(name: str) -> str:
    """将 python 函数名转为 policy tool 名。

    优先查显式映射表；没有则默认 snake_case → PascalCase。
    """
    override = _TOOL_NAME_OVERRIDES.get(name)
    if override:
        return override
    # 默认转换：snake_case → PascalCase
    parts = name.split("_")
    return "".join(p.capitalize() for p in parts)


# ---------------------------------------------------------------------------
# Target 提取映射
# ---------------------------------------------------------------------------

_TARGET_PARAM_MAP: dict[str, str] = {
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
    "Append": "file_path",
    "SendFileToUser": "file_path",
    "ViewImage": "file_path",
    "ViewVideo": "file_path",
    "Bash": "command",
    "Grep": "pattern",
    "Glob": "pattern",
    "Browser": "url",
    "SetUserTimezone": "timezone",
    "DelegateExternalAgent": "agent_id",
    "ListAgents": "",
    "ChatWithAgent": "agent_id",
    "SubmitToAgent": "agent_id",
    "CheckAgentTask": "task_id",
    "GetCurrentTime": "",
    "GetTokenUsage": "",
    "DesktopScreenshot": "",
    "MaterializeSkill": "",
}


def _extract_target(policy_tool_name: str, input_data: dict) -> str:
    """从 tool 调用参数中提取 target。

    根据 policy tool 名查对应的参数名，从 input_data 中取值。
    """
    param = _TARGET_PARAM_MAP.get(policy_tool_name, "")
    if not param:
        return ""
    target = input_data.get(param, "")
    return str(target) if target else ""


# ---------------------------------------------------------------------------
# PolicyGuardedTool
# ---------------------------------------------------------------------------

class PolicyGuardedTool:
    """governance 策略检查的 tool wrapper。

    动态继承 FunctionTool，实现：
    - check_permissions: 调用 governor.assert_and_audit() 做裁决
    - __call__: 重写以处理 sandbox execution + violation retry
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        from agentscope.tool import FunctionTool

        if cls is PolicyGuardedTool:
            real_cls = type(
                "PolicyGuardedTool",
                (FunctionTool,),
                {
                    "__init__": _policy_tool_init,
                    "check_permissions": _policy_tool_check_permissions,
                    "__call__": _policy_tool_call,
                    "__doc__": cls.__doc__,
                },
            )
            return real_cls(*args, **kwargs)
        return object.__new__(cls)


def _policy_tool_init(
    self: Any,
    func: Any,
    *,
    governor: Any = None,
    request_context: dict[str, str] | None = None,
    **kwargs: Any,
) -> None:
    from agentscope.tool import FunctionTool

    FunctionTool.__init__(self, func, **kwargs)
    # pylint: disable=protected-access
    self._qp_governor = governor
    self._qp_request_context = request_context or {}
    self._qp_policy_decision = None  # 预裁决结果
    self._qp_sandbox_mode = False    # 是否在 sandbox 中执行


async def _policy_tool_check_permissions(
    self: Any,
    input_data: dict[str, Any] | None = None,
    context: Any = None,
    *_extra_args: Any,
    **_extra_kwargs: Any,
) -> Any:
    """对一次 tool 调用进行 governance 策略裁决。

    流程：
        1. 构造 ToolCall(tool_name, target, agent_id, session_id)
        2. governor.assert_and_audit(tool_call) → PolicyDecision
        3. 映射到 PermissionDecision
    """
    from agentscope.permission import PermissionBehavior, PermissionDecision

    del context

    governor = getattr(self, "_qp_governor", None)
    if governor is None:
        # ResourceGovernor 未初始化 → bypass
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="PolicyGuardedTool: governor not started — bypass.",
        )

    tool_name = _python_name_to_policy_tool_name(
        getattr(self, "name", "Unknown"),
    )
    input_data = input_data or {}
    target = _extract_target(tool_name, input_data)

    agent_id = getattr(self, "_qp_request_context", {}).get("agent_id", "")
    session_id = getattr(self, "_qp_request_context", {}).get(
        "session_id", ""
    )

    from .resource_governor import ToolCall

    tool_call = ToolCall(
        tool_name=tool_name,
        target=target,
        agent_id=agent_id,
        session_id=session_id,
    )

    decision = governor.assert_and_audit(tool_call)

    # 缓存裁决结果供 __call__ 使用
    self._qp_policy_decision = decision
    self._qp_sandbox_mode = False

    if decision.value == "allow":
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="governance: tool allowed.",
        )
    elif decision.value == "deny":
        return PermissionDecision(
            behavior=PermissionBehavior.DENY,
            message=f"Tool '{tool_name}' is denied by governance policy "
            f"(target: {target}).",
        )
    elif decision.value == "sandbox_fallback":
        # Bash 类 tool 无规则命中 → 允许进入 sandbox 执行
        self._qp_sandbox_mode = True
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="governance: sandbox fallback.",
        )
    elif decision.value == "ask":
        # 需要用户确认
        self._qp_policy_decision = decision
        return await _ask_user_approval(
            governor=governor,
            tool_name=tool_name,
            target=target,
            input_data=input_data,
            agent_id=agent_id,
            session_id=session_id,
            request_context=getattr(self, "_qp_request_context", {}) or {},
        )
    else:
        # 未知 decision → deny 作为安全默认
        return PermissionDecision(
            behavior=PermissionBehavior.DENY,
            message=f"Unknown policy decision: {decision}",
        )


async def _policy_tool_call(
    self: Any,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """重写 FunctionTool.__call__，处理 sandbox execution + violation retry。

    目前 sandbox 执行机制是 stub（后续接入真实 sandbox 后完善）。
    当前行为：
        - sandbox_mode=True: 直接执行（等 sandbox 接入后改为在 sandbox 内执行）
        - 其他情况：直接调原始函数
    """
    sandbox_mode = getattr(self, "_qp_sandbox_mode", False)
    if sandbox_mode:
        # 目前 sandbox 未接入，直接执行
        # 后续接入 sandbox 后：
        #   config = governor.compile_sandbox_config(agent_id, session_id)
        #   result = sandbox.execute(func, args, kwargs, config)
        #   if result.violation:
        #       return await _handle_sandbox_violation(...)
        logger.debug(
            "PolicyGuardedTool: sandbox_mode=True for '%s' "
            "(sandbox not yet implemented, executing directly)",
            getattr(self, "name", "Unknown"),
        )

    # 调原始函数
    from agentscope.tool import FunctionTool
    return await FunctionTool.__call__(self, *args, **kwargs)


# ---------------------------------------------------------------------------
# ASK 路径：复用 ApprovalService
# ---------------------------------------------------------------------------

async def _ask_user_approval(
    governor: Any,
    tool_name: str,
    target: str,
    input_data: dict,
    agent_id: str,
    session_id: str,
    request_context: dict,
) -> Any:
    """向用户请求 approve，阻塞等待回复。"""
    from agentscope.permission import PermissionBehavior, PermissionDecision

    from ...app.approvals import get_approval_service
    from ...constant import TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS
    from ...security.tool_guard.approval import (
        ApprovalDecision,
        format_findings_summary,
    )
    from ...security.tool_guard.models import (
        GuardFinding,
        GuardSeverity,
        GuardThreatCategory,
        ToolGuardResult,
    )

    ctx = request_context or {}
    user_id = str(ctx.get("user_id") or "")
    channel = str(ctx.get("channel") or "")
    root_session_id = str(ctx.get("root_session_id") or session_id)
    root_agent_id = str(ctx.get("root_agent_id") or agent_id or "unknown")

    # 构造合成 ToolGuardResult 供 ApprovalService 使用
    guard_result = ToolGuardResult(
        tool_name=tool_name,
        params=input_data,
        findings=[
            GuardFinding(
                id=uuid.uuid4().hex[:8],
                rule_id="policy_ask",
                category=GuardThreatCategory.RESOURCE_ABUSE,
                severity=GuardSeverity.INFO,
                title="Policy Approval Required",
                description=(
                    f"Tool '{tool_name}' with target '{target}' "
                    f"requires user approval per governance policy."
                ),
                tool_name=tool_name,
                remediation="Approve or deny this tool call",
                guardian="governance_policy",
                metadata={"target": target},
            ),
        ],
        guardians_used=["governance_policy"],
    )

    svc = get_approval_service()
    tool_call_id = str(ctx.get("tool_call_id") or "")
    if session_id and tool_call_id:
        await svc.cancel_stale_pending_for_tool_call(session_id, tool_call_id)

    pending = await svc.create_pending(
        session_id=session_id,
        root_session_id=root_session_id,
        owner_agent_id=root_agent_id,
        user_id=user_id,
        channel=channel,
        agent_id=agent_id or "unknown",
        tool_name=tool_name,
        result=guard_result,
        timeout_seconds=TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS,
        extra={
            "tool_call": {
                "id": tool_call_id,
                "name": tool_name,
                "input": dict(input_data or {}),
            },
        },
    )

    logger.info(
        "PolicyGuardedTool: awaiting approval for tool=%s session=%s "
        "request_id=%s target=%s",
        tool_name,
        session_id[:8] if session_id else "",
        pending.request_id[:8],
        target,
    )

    try:
        decision = await svc.wait_for_approval(
            pending.request_id,
            TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.error(
            "PolicyGuardedTool: wait_for_approval crashed (%s); denying",
            exc,
            exc_info=True,
        )
        decision = ApprovalDecision.DENIED

    summary = format_findings_summary(guard_result)
    if decision == ApprovalDecision.APPROVED:
        # 追加一条 allow 规则到 governance policy，下次免问
        try:
            rule = PolicyRule(
                match=f"{tool_name}({target})",
                action=PolicyAction.ALLOW,
                grantee=agent_id or "*",
                duration="session",
                session_id=session_id,
            )
            governor.add_rule(rule)
            logger.info(
                "PolicyGuardedTool: added approved rule: %s",
                rule.match,
            )
        except Exception:
            logger.debug(
                "PolicyGuardedTool: failed to persist approved rule",
                exc_info=True,
            )
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message=f"Approved by user.\n{summary}",
        )

    denial_msg = (
        f"User denied the request to run '{tool_name}'.\n{summary}"
        if decision == ApprovalDecision.DENIED
        else (
            f"Approval for '{tool_name}' timed out after "
            f"{int(TOOL_GUARD_APPROVAL_TIMEOUT_SECONDS)}s.\n{summary}"
        )
    )
    return PermissionDecision(
        behavior=PermissionBehavior.DENY,
        message=denial_msg + _NO_RETRY_INSTRUCTION,
    )


_NO_RETRY_INSTRUCTION = (
    "\n\n⚠️ **System instruction**: this denial is final for the current "
    "request. Do not retry this tool with similar parameters. Reply to "
    "the user explaining why the action could not be completed and, if "
    "appropriate, ask them how they want to proceed."
)
