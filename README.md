# 转账治理测试说明（tool_governance_demo.py）

本文件只说明如何运行 `tool_governance_demo.py` 中的**转账部分功能测试**。

## 运行方式

```bash
python tool_governance_demo.py --transfer
```

该命令会执行 `run_transfer_check()`：依次运行五个转账断言测试，全部通过后打印 transfer 工具的审计日志（只含参数键名，不含参数值）。

## 五个测试场景

| # | 测试函数 | 场景 | 预期结果 |
|---|---------|------|---------|
| 1 | `test_transfer_schema_rejects_extra` | 账号格式错误（`ACC-A-12345` 只有 5 位数字）、伪造 `approved=True` 字段 | Schema 层拒绝，返回 `INVALID_ARGUMENT`，handler 零执行 |
| 2 | `test_transfer_precheck_insufficient` | 余额 5000 转账 6000 | 预检返回 `INSUFFICIENT_BALANCE`，handler 零执行 |
| 3 | `test_transfer_precheck_exceed_limit` | 转账 60000 超过单笔 5 万限额 | 预检返回 `EXCEED_LIMIT`，handler 零执行 |
| 4 | `test_transfer_approval_binding` | 审批时金额 100、执行时篡改为 200 | 参数摘要（SHA-256）不匹配，旧审批失效，返回 `APPROVAL_REQUIRED` + `CONFIRM`，handler 零执行 |
| 5 | `test_transfer_timeout_no_retry` | 转账 90000（>80000 进入慢速分支触发超时） | 返回 `TIMEOUT_UNKNOWN`，写操作不盲目重试，handler 最多尝试 1 次 |

## 测试用账户数据

```python
ACCOUNTS = {
    "tenant_a": {
        "ACC-A-123456": {"balance": 100000.0},
        "ACC-A-654321": {"balance": 5000.0},
        "ACC-A-888888": {"balance": 20000.0},
    },
    ...
}
```

## 预期输出示例

```text
[PASS] test_transfer_schema_rejects_extra
[PASS] test_transfer_precheck_insufficient
[PASS] test_transfer_precheck_exceed_limit
[PASS] test_transfer_approval_binding
[PASS] test_transfer_timeout_no_retry
转账治理断言：5/5 通过
transfer 审计记录 N 条：
[audit] {...}  # 审计记录 JSON，参数只记录键名
```

## 关键治理约束

- 所有测试均通过 `ToolRuntime.invoke` 调用，不直接调用 `transfer_handler`
- `PermissionEngine.decide` 的优先级顺序固定，测试不修改它
- `TransferArgs` 使用 `extra="forbid"`，阻止模型注入额外参数（如伪造的 `approved` 字段）
- 审批通过 SHA-256 参数摘要绑定具体参数，参数被篡改后审批自动失效
- 写操作超时返回 `TIMEOUT_UNKNOWN`，绝不自动重试，避免重复扣款
- 结果脱敏：账号 `ACC-A-123456` 返回给模型前变为 `ACC-A-****3456`（保留末 4 位）
