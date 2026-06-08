# -*- coding: utf-8 -*-
"""ToolRegistry — Tool 元数据的单一真相源。

每个 tool 注册时声明：
    - 类型（file / network / shell / internal）
    - target 参数名（file_path / command / url …）
    - python 函数名 → policy tool 名的映射

与 policy.yaml 的关系：
    ToolRegistry: tool 是什么（类型、参数名）    → 静态，代码层注册
    policy.yaml:  tool 能做什么（规则、默认权限） → 动态，用户/approve 产生
"""
from __future__ import annotations
from typing import Dict, List


class ToolRegistry:
    """Tool 元数据注册表。"""

    def __init__(self) -> None:
        self._types: Dict[str, str] = {}
        self._target_params: Dict[str, str] = {}
        self._python_name_map: Dict[str, str] = {}

    def register(
        self,
        tool_name: str,
        tool_type: str,
        target_param: str,
    ) -> None:
        """注册一个 tool。

        Args:
            tool_name: policy 层的 tool 名，如 "Read"
            tool_type: "file" | "network" | "shell" | "internal"
            target_param: target 参数名，如 "file_path"、"command"
        """
        self._types[tool_name] = tool_type
        self._target_params[tool_name] = target_param

    def register_python_name(self, python_name: str, policy_name: str) -> None:
        """注册 python 函数名 → policy tool 名的映射。"""
        self._python_name_map[python_name] = policy_name

    def get_type(self, tool_name: str) -> str:
        """返回 tool 的类型。未注册返回 "unknown"。"""
        return self._types.get(tool_name, "unknown")

    def get_target_param(self, tool_name: str) -> str:
        """返回 tool 的 target 参数名。未注册返回 ""。"""
        return self._target_params.get(tool_name, "")

    def python_to_policy_name(self, python_name: str) -> str:
        """将 python 函数名映射为 policy tool 名。

        优先查显式映射；无映射时 snake_case → PascalCase。
        """
        override = self._python_name_map.get(python_name)
        if override:
            return override
        parts = python_name.split("_")
        return "".join(p.capitalize() for p in parts)

    def extract_target(self, tool_name: str, input_data: dict) -> str:
        """从 tool 调用参数中提取 target。"""
        param = self.get_target_param(tool_name)
        if not param:
            return ""
        target = input_data.get(param, "")
        return str(target) if target else ""

    def get_all_tool_names(self) -> List[str]:
        """返回所有已注册的 tool 名。"""
        return list(self._types.keys())


# ---------------------------------------------------------------------------
# 默认 registry 实例（21 个 tool）
# ---------------------------------------------------------------------------

def _create_default_registry() -> ToolRegistry:
    """创建并填充默认 ToolRegistry。"""
    registry = ToolRegistry()

    # ── File 类（12 个）──
    registry.register("Read",               "file", "file_path")
    registry.register("Write",              "file", "file_path")
    registry.register("Edit",               "file", "file_path")
    registry.register("Append",             "file", "file_path")
    registry.register("Grep",               "file", "pattern")
    registry.register("Glob",               "file", "pattern")
    registry.register("SendFileToUser",     "file", "file_path")
    registry.register("ViewImage",          "file", "file_path")
    registry.register("ViewVideo",          "file", "file_path")
    registry.register("MaterializeSkill",   "file", "")
    registry.register("DesktopScreenshot",  "file", "path")
    registry.register("SetUserTimezone",    "file", "timezone")

    # ── Network 类（1 个）──
    registry.register("Browser", "network", "url")

    # ── Shell 类（1 个）──
    registry.register("Bash", "shell", "command")

    # ── Internal 类（7 个）──
    registry.register("GetCurrentTime",        "internal", "")
    registry.register("GetTokenUsage",         "internal", "")
    registry.register("ListAgents",            "internal", "")
    registry.register("ChatWithAgent",         "internal", "agent_id")
    registry.register("SubmitToAgent",         "internal", "agent_id")
    registry.register("CheckAgentTask",        "internal", "task_id")
    registry.register("DelegateExternalAgent", "internal", "runner")

    # ── Python 函数名映射 ──
    registry.register_python_name("execute_shell_command",    "Bash")
    registry.register_python_name("read_file",               "Read")
    registry.register_python_name("write_file",              "Write")
    registry.register_python_name("edit_file",               "Edit")
    registry.register_python_name("append_file",             "Append")
    registry.register_python_name("grep_search",             "Grep")
    registry.register_python_name("glob_search",             "Glob")
    registry.register_python_name("browser_use",             "Browser")
    registry.register_python_name("desktop_screenshot",      "DesktopScreenshot")
    registry.register_python_name("send_file_to_user",       "SendFileToUser")
    registry.register_python_name("view_image",              "ViewImage")
    registry.register_python_name("view_video",              "ViewVideo")
    registry.register_python_name("get_current_time",        "GetCurrentTime")
    registry.register_python_name("set_user_timezone",       "SetUserTimezone")
    registry.register_python_name("get_token_usage",         "GetTokenUsage")
    registry.register_python_name("delegate_external_agent", "DelegateExternalAgent")
    registry.register_python_name("list_agents",             "ListAgents")
    registry.register_python_name("chat_with_agent",         "ChatWithAgent")
    registry.register_python_name("submit_to_agent",         "SubmitToAgent")
    registry.register_python_name("check_agent_task",        "CheckAgentTask")
    registry.register_python_name("materialize_skill",       "MaterializeSkill")

    return registry


DEFAULT_REGISTRY = _create_default_registry()
