"""转账治理回归测试（pytest 入口）。

测试实现位于 chapter_02/tool_governance_demo.py。演示文件与 tests 目录同级，
但不在标准包结构内（无 __init__.py），因此用 importlib 按路径加载演示模块，
再把五个测试重新导出，使以下命令在 chapter_02 目录下可用：

    python -m pytest tests/test_tool_governance.py -v -k "transfer"

约束与演示文件内一致：
1. 不修改 PermissionEngine.decide；
2. 所有调用都走 ToolRuntime.invoke，不直接调 transfer_handler；
3. TransferArgs 保留 extra="forbid"。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_DEMO_PATH = Path(__file__).resolve().parents[1] / "tool_governance_demo.py"


def _load_demo_module():
    if "tool_governance_demo" in sys.modules:
        return sys.modules["tool_governance_demo"]
    spec = importlib.util.spec_from_file_location("tool_governance_demo", _DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["tool_governance_demo"] = module
    spec.loader.exec_module(module)
    return module


demo = _load_demo_module()

test_transfer_schema_rejects_extra = demo.test_transfer_schema_rejects_extra
test_transfer_precheck_insufficient = demo.test_transfer_precheck_insufficient
test_transfer_precheck_exceed_limit = demo.test_transfer_precheck_exceed_limit
test_transfer_approval_binding = demo.test_transfer_approval_binding
test_transfer_timeout_no_retry = demo.test_transfer_timeout_no_retry
