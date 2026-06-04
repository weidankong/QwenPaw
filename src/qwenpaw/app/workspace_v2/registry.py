# -*- coding: utf-8 -*-
"""ResourceRegistry — workspace 中所有受治理资源的元数据索引。

设计决策（2025-06-02）：
- Registry 保留但不展开（与 runtime 有重叠，待后续细化）。
- 当前只保留接口骨架，不实现。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ResourceRecord:
    """一条注册资源记录（保留，不展开）。"""
    resource_id: str
    resource_type: str
    path: Optional[str] = None
    extra: dict = field(default_factory=dict)


class ResourceRegistry:
    """资源注册表（保留，不展开）。

    由 Workspace 持有，记录 workspace 中有哪些受治理的资源。
    与 runtime 的边界划分待讨论。
    """

    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        self._records: Dict[str, ResourceRecord] = {}

    def register(self, record: ResourceRecord) -> None:
        raise NotImplementedError

    def unregister(self, resource_id: str) -> None:
        raise NotImplementedError

    def get(self, resource_id: str) -> Optional[ResourceRecord]:
        raise NotImplementedError

    def list_all(self) -> List[ResourceRecord]:
        raise NotImplementedError
