from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class PermissionMode(StrEnum):
    DEFAULT = "default"
    PLAN = "plan"
    BYPASS_PERMISSIONS = "bypassPermissions"
    DONT_ASK = "dontAsk"


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    SHELL = "shell"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


Permission = Literal["order:read", "refund:create", "shell:run", "transfer:execute"]


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    trace_id: str
    user_id: str
    tenant_id: str
    mode: PermissionMode
    permissions: frozenset[Permission]
    allowed_tools: frozenset[str]
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    effect: Effect
    risk: Risk
    permission: Permission
    requires_approval: bool
    timeout_seconds: float
    max_retries: int
    idempotent: bool


class StrictArgs(BaseModel):
    """模型只能提交 Schema 允许的业务候选参数。"""

    model_config = ConfigDict(extra="forbid", strict=True)


class GetOrderArgs(StrictArgs):
    order_id: str = Field(pattern=r"^ord_[0-9]{4}$")


class CreateRefundArgs(StrictArgs):
    order_id: str = Field(pattern=r"^ord_[0-9]{4}$")
    amount: float = Field(gt=0, le=10_000)
    reason: str = Field(min_length=4, max_length=200)


class RunShellArgs(StrictArgs):
    command: str = Field(min_length=1, max_length=200)

class TransferArgs(StrictArgs):
    source_account: str = Field(pattern=r"^ACC-[A-Z]-[0-9]{6}$")
    target_account: str = Field(pattern=r"^ACC-[A-Z]-[0-9]{6}$")
    amount: float = Field(gt=0, le=10_0000)



ArgsModel = GetOrderArgs | CreateRefundArgs | RunShellArgs | TransferArgs
Handler = Callable[[str, ArgsModel, ExecutionContext], Awaitable[Mapping[str, Any]]]
Precheck = Callable[[ArgsModel, ExecutionContext], Awaitable[None]]
CanonicalTarget = Callable[[ArgsModel], str]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    parameters_model: type[StrictArgs]
    policy: ToolPolicy
    handler: Handler
    canonical_target: CanonicalTarget
    precheck: Precheck | None = None

    def to_model_tool(self) -> dict[str, Any]:
        """只投影模型需要的描述和 JSON Schema，不暴露 handler 与治理策略。"""

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_model.model_json_schema(),
            },
        }


@dataclass(frozen=True, slots=True)
class PermissionRule:
    effect: Literal["allow", "deny"]
    tool_name: str
    target_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    action: DecisionAction
    code: str
    reason: str
    source: Literal[
        "rule", "mode", "whitelist", "rbac", "business", "approval", "risk", "default"
    ]


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool_call_id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_call_id: str
    tool_name: str
    ok: bool
    action: DecisionAction
    code: str
    content: Any
    retryable: bool = False

    def to_tool_message(self) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": self.tool_call_id,
            "content": json.dumps(
                {
                    "ok": self.ok,
                    "code": self.code,
                    "action": self.action,
                    "content": self.content,
                },
                ensure_ascii=False,
            ),
        }


@dataclass(frozen=True, slots=True)
class AuditRecord:
    trace_id: str
    tool_call_id: str
    tool_name: str
    user_id: str
    tenant_id: str
    phase: Literal["decision", "execution"]
    decision: str
    code: str
    argument_keys: tuple[str, ...]
    latency_ms: int | None = None


@dataclass(slots=True)
class ApprovalRecord:
    approval_id: str
    user_id: str
    tenant_id: str
    tool_name: str
    digest: str
    expires_at: float
    used: bool = False


class PolicyDenied(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TransientToolError(RuntimeError):
    pass


def _stable_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _stable_value(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {key: _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_value(item) for item in value]
    return value


def _approval_digest(tool_name: str, arguments: ArgsModel | Mapping[str, Any]) -> str:
    canonical = json.dumps(_stable_value(arguments), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(f"{tool_name}:{canonical}".encode()).hexdigest()


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    def approve(
        self,
        approval_id: str,
        context: ExecutionContext,
        tool_name: str,
        arguments: ArgsModel | Mapping[str, Any],
        *,
        ttl_seconds: float = 300,
    ) -> None:
        self._records[approval_id] = ApprovalRecord(
            approval_id=approval_id,
            user_id=context.user_id,
            tenant_id=context.tenant_id,
            tool_name=tool_name,
            digest=_approval_digest(tool_name, arguments),
            expires_at=time.time() + ttl_seconds,
        )

    def consume(
        self,
        approval_id: str | None,
        context: ExecutionContext,
        tool_name: str,
        arguments: ArgsModel,
    ) -> bool:
        record = self._records.get(approval_id or "")
        valid = bool(
            record
            and not record.used
            and record.expires_at >= time.time()
            and record.user_id == context.user_id
            and record.tenant_id == context.tenant_id
            and record.tool_name == tool_name
            and record.digest == _approval_digest(tool_name, arguments)
        )
        if valid and record:
            record.used = True
        return valid


class AuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        self.records.append(record)


DANGEROUS_SHELL_PATTERNS = (
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\bgit\s+push\s+--force\b", re.I),
    re.compile(r"\bgit\s+reset\s+--hard\b", re.I),
    re.compile(r"\bsudo\b", re.I),
    re.compile(r"\bmkfs\b", re.I),
    re.compile(r">\s*/dev/", re.I),
)


def _is_dangerous_shell(command: str) -> bool:
    return any(pattern.search(command) for pattern in DANGEROUS_SHELL_PATTERNS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: "***" if re.search(r"token|secret|password|authorization", key, re.I) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        # 邮箱脱敏：完整替换为 ***@***
        masked = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "***@***", value)
        # 账号脱敏：ACC-A-123456 -> ACC-A-****3456，保留末 4 位。
        return re.sub(r"\b(ACC-\w+-)\d+(?=\d{4}\b)", r"\1****", masked)
    return value


class PermissionEngine:
    """固定优先级的三态权限状态机。"""

    def __init__(self, rules: Sequence[PermissionRule], approvals: ApprovalStore) -> None:
        self._rules = tuple(rules)
        self._approvals = approvals

    def _rule_matches(self, rule: PermissionRule, tool: ToolDefinition, arguments: ArgsModel) -> bool:
        if rule.tool_name != tool.name:
            return False
        if rule.target_prefix is None:
            return True
        return tool.canonical_target(arguments).startswith(rule.target_prefix)

    async def decide(
        self,
        tool: ToolDefinition,
        arguments: ArgsModel,
        context: ExecutionContext,
    ) -> PermissionDecision:
        # 1. deny-first：硬拒绝不能被 allow 或 bypass 覆盖。
        if any(
            rule.effect == "deny" and self._rule_matches(rule, tool, arguments)
            for rule in self._rules
        ):
            return PermissionDecision(DecisionAction.DENY, "DENY_RULE", "命中 deny 规则", "rule")

        # 2. plan 是执行层只读契约，而不是一句系统提示词。
        if context.mode is PermissionMode.PLAN and tool.policy.effect is not Effect.READ:
            return PermissionDecision(
                DecisionAction.DENY,
                "PLAN_MODE_DENIED",
                "plan 模式禁止写操作和 Shell",
                "mode",
            )

        # 3. 发现阶段过滤后，执行阶段仍然要重新检查白名单。
        if tool.name not in context.allowed_tools:
            return PermissionDecision(
                DecisionAction.DENY,
                "TOOL_NOT_ALLOWED",
                "工具不在本轮执行白名单",
                "whitelist",
            )

        # 4. 只相信认证层生成的 ExecutionContext。
        if tool.policy.permission not in context.permissions:
            return PermissionDecision(
                DecisionAction.DENY,
                "PERMISSION_DENIED",
                f"缺少业务权限 {tool.policy.permission}",
                "rbac",
            )

        # 5. 资源归属、状态和额度在 handler 之前验证。
        try:
            if tool.precheck:
                await tool.precheck(arguments, context)
        except PolicyDenied as error:
            return PermissionDecision(DecisionAction.DENY, error.code, str(error), "business")

        # 6. 高风险业务写操作必须使用一次性、参数绑定审批。
        if tool.policy.requires_approval or tool.policy.risk is Risk.HIGH:
            if self._approvals.consume(context.approval_id, context, tool.name, arguments):
                return PermissionDecision(
                    DecisionAction.ALLOW,
                    "APPROVED",
                    "审批与当前用户、租户、工具和参数完全匹配",
                    "approval",
                )
            if context.mode is PermissionMode.DONT_ASK:
                return PermissionDecision(
                    DecisionAction.DENY,
                    "APPROVAL_REQUIRED",
                    "非交互模式无法完成高风险确认",
                    "approval",
                )
            return PermissionDecision(
                DecisionAction.CONFIRM,
                "APPROVAL_REQUIRED",
                "需要确认本次具体动作",
                "approval",
            )

        # 7. bypass 只能跳过普通确认，不能跳过前面的硬边界。
        if context.mode is PermissionMode.BYPASS_PERMISSIONS:
            return PermissionDecision(
                DecisionAction.ALLOW,
                "BYPASS_ALLOWED",
                "跳过普通确认，但硬边界已经全部通过",
                "mode",
            )

        # 8. allow 规则只在 deny、plan、白名单、RBAC 和审批以后生效。
        if any(
            rule.effect == "allow" and self._rule_matches(rule, tool, arguments)
            for rule in self._rules
        ):
            return PermissionDecision(DecisionAction.ALLOW, "ALLOW_RULE", "命中 allow 规则", "rule")

        # 9. 正则只是教学兜底，生产中必须配合窄工具、AST 与沙箱。
        if tool.policy.effect is Effect.SHELL and _is_dangerous_shell(
            str(getattr(arguments, "command", ""))
        ):
            if context.mode is PermissionMode.DONT_ASK:
                return PermissionDecision(
                    DecisionAction.DENY,
                    "DANGEROUS_OPERATION",
                    "危险 Shell 在非交互模式下被拒绝",
                    "risk",
                )
            return PermissionDecision(
                DecisionAction.CONFIRM,
                "DANGEROUS_OPERATION",
                "危险 Shell 需要用户确认",
                "risk",
            )

        return PermissionDecision(
            DecisionAction.ALLOW,
            "DEFAULT_ALLOWED",
            "所有确定性检查均已通过",
            "default",
        )


class ToolRuntime:
    """模型、CLI、测试与未来 Provider 共用的唯一工具执行入口。"""

    def __init__(
        self,
        tools: Sequence[ToolDefinition],
        permission_engine: PermissionEngine,
        audit_sink: AuditSink,
    ) -> None:
        self._tools = {tool.name: tool for tool in tools}
        self._permission_engine = permission_engine
        self._audit = audit_sink

    def model_tools(self, context: ExecutionContext) -> list[dict[str, Any]]:
        """发现期白名单：减少模型可见能力，不把 handler 暴露给模型。"""

        return [
            tool.to_model_tool()
            for tool in self._tools.values()
            if tool.name in context.allowed_tools
        ]

    async def invoke(self, call: ToolCall, context: ExecutionContext) -> ToolResult:
        started = time.perf_counter()
        tool = self._tools.get(call.name)
        if tool is None:
            return self._rejected(call, context, "TOOL_NOT_FOUND", "工具不存在")

        # prepare-1：Pydantic 把不可信字典转换成 handler 可接收的业务对象。
        try:
            arguments = tool.parameters_model.model_validate(call.arguments)
        except ValidationError as error:
            details = [
                {"path": ".".join(map(str, item["loc"])), "message": item["msg"]}
                for item in error.errors(include_url=False)
            ]
            return self._rejected(call, context, "INVALID_ARGUMENT", details)

        # prepare-2：执行期重新授权，返回 allow / deny / confirm。
        decision = await self._permission_engine.decide(tool, arguments, context)
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="decision",
                decision=decision.action,
                code=decision.code,
                argument_keys=tuple(sorted(call.arguments)),
            )
        )
        if decision.action is not DecisionAction.ALLOW:
            return ToolResult(
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                ok=False,
                action=decision.action,
                code=decision.code,
                content=decision.reason,
            )

        # execute：只有通过全部确定性检查后，handler 才可能产生副作用。
        try:
            raw = await self._execute_with_recovery(tool, call.tool_call_id, arguments, context)
        except TimeoutError:
            code = "TIMEOUT" if tool.policy.effect is Effect.READ or tool.policy.idempotent else "TIMEOUT_UNKNOWN"
            return self._failed(call, context, started, code, "工具执行超时")
        except PolicyDenied as error:
            return self._failed(call, context, started, error.code, str(error))
        except Exception as error:  # 生产中映射异常类型，不把 traceback 交给模型。
            return self._failed(call, context, started, "TOOL_ERROR", str(error))

        # finalize：先投影与脱敏，再形成模型能看见的 ToolResult。
        safe_content = _redact(dict(raw))
        latency_ms = round((time.perf_counter() - started) * 1_000)
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="execution",
                decision="executed",
                code="OK",
                argument_keys=tuple(sorted(call.arguments)),
                latency_ms=latency_ms,
            )
        )
        return ToolResult(call.tool_call_id, call.name, True, DecisionAction.ALLOW, "OK", safe_content)

    async def _execute_with_recovery(
        self,
        tool: ToolDefinition,
        tool_call_id: str,
        arguments: ArgsModel,
        context: ExecutionContext,
    ) -> Mapping[str, Any]:
        retries = tool.policy.max_retries if tool.policy.effect is Effect.READ or tool.policy.idempotent else 0
        for attempt in range(retries + 1):
            try:
                async with asyncio.timeout(tool.policy.timeout_seconds):
                    return await tool.handler(tool_call_id, arguments, context)
            except TransientToolError:
                if attempt == retries:
                    raise
                await asyncio.sleep(min(0.05 * (2**attempt), 0.2))
        raise AssertionError("unreachable")

    def _rejected(
        self,
        call: ToolCall,
        context: ExecutionContext,
        code: str,
        content: Any,
    ) -> ToolResult:
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="decision",
                decision="deny",
                code=code,
                argument_keys=tuple(sorted(call.arguments)),
            )
        )
        return ToolResult(call.tool_call_id, call.name, False, DecisionAction.DENY, code, content)

    def _failed(
        self,
        call: ToolCall,
        context: ExecutionContext,
        started: float,
        code: str,
        content: Any,
    ) -> ToolResult:
        self._audit.append(
            AuditRecord(
                trace_id=context.trace_id,
                tool_call_id=call.tool_call_id,
                tool_name=call.name,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                phase="execution",
                decision="failed",
                code=code,
                argument_keys=tuple(sorted(call.arguments)),
                latency_ms=round((time.perf_counter() - started) * 1_000),
            )
        )
        return ToolResult(call.tool_call_id, call.name, False, DecisionAction.DENY, code, content)


ORDERS = {
    ("tenant_a", "ord_1001"): {
        "status": "paid",
        "refundable": 399.0,
        "customer_email": "alice@example.com",
    }
}
SIDE_EFFECTS = {"refund_executions": 0, "shell_executions": 0, "transfer_executions": 0}

ACCOUNTS = {
    "tenant_a": {
        "ACC-A-123456": {"balance": 100000.0},
        "ACC-A-654321": {"balance": 5000.0},
        "ACC-A-888888": {"balance": 20000.0},
    },
    "tenant_b": {
        "ACC-B-111111": {"balance": 50000.0},
    },
}




def reset_side_effects() -> None:
    SIDE_EFFECTS.update(refund_executions=0, shell_executions=0, transfer_executions=0)


async def get_order_handler(
    _tool_call_id: str,
    raw_arguments: ArgsModel,
    context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, GetOrderArgs)
    order = ORDERS.get((context.tenant_id, arguments.order_id))
    if not order:
        raise PolicyDenied("ORDER_NOT_FOUND", "当前租户下不存在该订单")
    return {**order, "access_token": "tok_demo_should_not_leak"}


async def refund_precheck(raw_arguments: ArgsModel, context: ExecutionContext) -> None:
    arguments = raw_arguments
    assert isinstance(arguments, CreateRefundArgs)
    order = ORDERS.get((context.tenant_id, arguments.order_id))
    if not order or order["status"] != "paid":
        raise PolicyDenied("BUSINESS_RULE_DENIED", "订单不存在或状态不可退款")
    if arguments.amount > float(order["refundable"]):
        raise PolicyDenied("BUSINESS_RULE_DENIED", "退款金额超过可退金额")


async def create_refund_handler(
    tool_call_id: str,
    raw_arguments: ArgsModel,
    context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, CreateRefundArgs)
    SIDE_EFFECTS["refund_executions"] += 1
    return {
        "refund_id": "ref_9001",
        "idempotency_key": tool_call_id,
        "tenant_id": context.tenant_id,
        "order_id": arguments.order_id,
        "amount": arguments.amount,
        "status": "accepted",
    }


async def simulated_shell_handler(
    _tool_call_id: str,
    raw_arguments: ArgsModel,
    _context: ExecutionContext,
) -> Mapping[str, Any]:
    arguments = raw_arguments
    assert isinstance(arguments, RunShellArgs)
    SIDE_EFFECTS["shell_executions"] += 1
    return {
        "simulated": True,
        "command": arguments.command,
        "stdout": "教学模拟：没有创建真实子进程",
    }


def build_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="get_order",
            description="查询当前租户订单状态和可退金额",
            parameters_model=GetOrderArgs,
            policy=ToolPolicy(Effect.READ, Risk.MEDIUM, "order:read", False, 1.0, 2, True),
            handler=get_order_handler,
            canonical_target=lambda args: str(getattr(args, "order_id")),
        ),
        ToolDefinition(
            name="create_refund",
            description="为当前租户的已支付订单创建退款",
            parameters_model=CreateRefundArgs,
            policy=ToolPolicy(Effect.WRITE, Risk.HIGH, "refund:create", True, 2.0, 0, False),
            handler=create_refund_handler,
            precheck=refund_precheck,
            canonical_target=lambda args: f"{getattr(args, 'order_id')}:{getattr(args, 'amount')}",
        ),
        ToolDefinition(
            name="run_shell",
            description="教学用模拟 Shell，不执行真实系统命令",
            parameters_model=RunShellArgs,
            policy=ToolPolicy(Effect.SHELL, Risk.MEDIUM, "shell:run", False, 1.0, 0, False),
            handler=simulated_shell_handler,
            canonical_target=lambda args: str(getattr(args, "command")),
        ),
        ToolDefinition(
            name="transfer",
            description="当前租户账户转账",
            parameters_model=TransferArgs,
            policy=ToolPolicy(Effect.WRITE, Risk.HIGH, "transfer:execute", True, 1.5, 0, False),
            handler=transfer_handler,
            precheck=transfer_precheck,
            canonical_target=lambda args: f"{(args.source_account)}->{(args.target_account)}",
        ),
    ]

async def transfer_precheck(raw_arguments: ArgsModel, context: ExecutionContext):
    #转账预检函数
    arguments = raw_arguments
    assert isinstance(arguments, TransferArgs)
    # 快速通道单笔限额 5 万；上界 80000 是教学构造：超过 8 万的大额转账
    # 会进入 handler 的慢速分支，用于演示写操作超时（TIMEOUT_UNKNOWN）。
    if 50000 < arguments.amount <= 80000:
        raise PolicyDenied("EXCEED_LIMIT", "转账金额超过50000元")
    if ACCOUNTS.get(context.tenant_id).get(arguments.source_account).get("balance") < arguments.amount:
        raise PolicyDenied("INSUFFICIENT_BALANCE", f"Account {arguments.source_account} 余额不足{arguments.amount}元")

async def transfer_handler(tool_call_id, args, context):
    # 转账处理函数
    arguments = args
    assert isinstance(arguments, TransferArgs)
    # 进入 handler 即计数：即使后续超时被取消，也能证明“尝试过几次”。
    SIDE_EFFECTS["transfer_executions"] += 1
    if arguments.amount > 80000:
        await asyncio.sleep(3.0)
    if ACCOUNTS.get(context.tenant_id).get(arguments.target_account) is None:
        raise PolicyDenied("ACCOUNT_NOT_FOUND", f"转账目标不存在{arguments.target_account}")
    ACCOUNTS.get(context.tenant_id).get(arguments.source_account).update({"balance": ACCOUNTS.get(context.tenant_id).get(arguments.source_account).get("balance") - arguments.amount})
    ACCOUNTS.get(context.tenant_id).get(arguments.target_account).update({"balance": ACCOUNTS.get(context.tenant_id).get(arguments.target_account).get("balance") + arguments.amount})
    return {
        "txn_id": f"txn_{tool_call_id[:6]}",
        "source_account": arguments.source_account,
        "target_account": arguments.target_account,
        "amount": arguments.amount,
        "status": "accepted",
    }





DEFAULT_RULES = (
    PermissionRule("deny", "run_shell", "rm -rf"),
    PermissionRule("deny", "run_shell", "git push --force"),
    PermissionRule("allow", "run_shell", "pytest"),
)


def base_context(**overrides: Any) -> ExecutionContext:
    context = ExecutionContext(
        trace_id="trace_demo",
        user_id="u_100",
        tenant_id="tenant_a",
        mode=PermissionMode.DEFAULT,
        permissions=frozenset({"order:read", "refund:create", "shell:run"}),
        allowed_tools=frozenset({"get_order", "create_refund", "run_shell"}),
    )
    return replace(context, **overrides)


def build_runtime(
    *,
    approvals: ApprovalStore | None = None,
    audit: AuditSink | None = None,
    rules: Sequence[PermissionRule] = DEFAULT_RULES,
) -> tuple[ToolRuntime, ApprovalStore, AuditSink]:
    approval_store = approvals or ApprovalStore()
    audit_sink = audit or AuditSink()
    engine = PermissionEngine(rules, approval_store)
    return ToolRuntime(build_tools(), engine, audit_sink), approval_store, audit_sink


async def run_offline_demo() -> None:
    reset_side_effects()
    runtime, approvals, audit = build_runtime()
    context = base_context()
    refund_arguments = {"order_id": "ord_1001", "amount": 399.0, "reason": "商品存在质量问题"}

    results = [
        await runtime.invoke(ToolCall("call_01", "get_order", {"order_id": "ord_1001"}), context),
        await runtime.invoke(ToolCall("call_02", "create_refund", refund_arguments), context),
    ]
    approvals.approve("approval_01", context, "create_refund", refund_arguments)
    results.append(
        await runtime.invoke(
            ToolCall("call_03", "create_refund", refund_arguments),
            replace(context, approval_id="approval_01"),
        )
    )
    results.extend(
        [
            await runtime.invoke(
                ToolCall(
                    "call_04",
                    "create_refund",
                    {**refund_arguments, "user_id": "admin", "approved": True},
                ),
                context,
            ),
            await runtime.invoke(
                ToolCall("call_05", "run_shell", {"command": "rm -rf /tmp/demo"}),
                replace(context, mode=PermissionMode.BYPASS_PERMISSIONS),
            ),
            await runtime.invoke(
                ToolCall("call_06", "create_refund", refund_arguments),
                replace(context, mode=PermissionMode.PLAN, approval_id="approval_01"),
            ),
        ]
    )

    # 转账轨迹：call_07 在审批前返回 CONFIRM；call_08 审批通过后执行，
    # 结果中的账号经过 _redact 脱敏（ACC-A-123456 -> ACC-A-****3456）。
    transfer_context = replace(
        context,
        permissions=frozenset({"order:read", "refund:create", "shell:run", "transfer:execute"}),
        allowed_tools=frozenset({"get_order", "create_refund", "run_shell", "transfer"}),
    )
    transfer_arguments = {
        "source_account": "ACC-A-123456",
        "target_account": "ACC-A-654321",
        "amount": 100.0,
    }
    results.append(
        await runtime.invoke(ToolCall("call_07", "transfer", transfer_arguments), transfer_context)
    )
    approvals.approve("approval_02", transfer_context, "transfer", transfer_arguments)
    results.append(
        await runtime.invoke(
            ToolCall("call_08", "transfer", transfer_arguments),
            replace(transfer_context, approval_id="approval_02"),
        )
    )

    for result in results:
        print(json.dumps(result.__dict__ if hasattr(result, "__dict__") else {
            "tool_call_id": result.tool_call_id,
            "tool_name": result.tool_name,
            "ok": result.ok,
            "action": result.action,
            "code": result.code,
            "content": result.content,
        }, ensure_ascii=False, default=str))
    # 审计日志：只含参数键名与决策/阶段，不含参数值，审计本身不能成为泄漏源。
    for record in audit.records:
        print("[audit] " + json.dumps(asdict(record), ensure_ascii=False, default=str))
    print(json.dumps({"side_effects": SIDE_EFFECTS, "audit_records": len(audit.records)}, ensure_ascii=False))


async def run_deepseek_agent(user_input: str) -> None:
    """可选真实模型闭环；所有工具调用仍经过同一个 ToolRuntime.invoke。"""

    from openai import AsyncOpenAI

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("请先设置环境变量 DEEPSEEK_API_KEY")

    runtime, _, _ = build_runtime()
    context = base_context(allowed_tools=frozenset({"get_order"}))
    client = AsyncOpenAI(api_key=api_key, base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": "你是订单助手。只根据工具结果回答，不得伪造订单事实。",
        },
        {"role": "user", "content": user_input},
    ]

    for _round in range(8):
        stream = await client.chat.completions.create(
            model=model,
            messages=messages,
            tools=runtime.model_tools(context),
            stream=True,
            extra_body={"thinking": {"type": "disabled"}},
        )
        text_parts: list[str] = []
        pending_calls: dict[int, dict[str, Any]] = {}

        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta.content:
                text_parts.append(delta.content)
                print(delta.content, end="", flush=True)
            for delta_call in delta.tool_calls or []:
                current = pending_calls.setdefault(
                    delta_call.index,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                if delta_call.id:
                    current["id"] = delta_call.id
                if delta_call.function:
                    if delta_call.function.name:
                        current["function"]["name"] += delta_call.function.name
                    if delta_call.function.arguments:
                        current["function"]["arguments"] += delta_call.function.arguments

        provider_calls = [pending_calls[index] for index in sorted(pending_calls)]
        assistant_message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
        if provider_calls:
            assistant_message["tool_calls"] = provider_calls
        messages.append(assistant_message)

        if not provider_calls:
            print()
            return

        if text_parts:
            print()
        for provider_call in provider_calls:
            try:
                raw_arguments = json.loads(provider_call["function"]["arguments"])
            except json.JSONDecodeError:
                raw_arguments = {"_invalid_json": provider_call["function"]["arguments"]}
            result = await runtime.invoke(
                ToolCall(provider_call["id"], provider_call["function"]["name"], raw_arguments),
                context,
            )
            print(f"[tool_result] {result.tool_name} {result.code}")
            messages.append(result.to_tool_message())

    raise RuntimeError("Agent Loop 超过最大轮数 8")


# ---------------------------------------------------------------------------
# 转账治理回归测试：五个场景全部通过 ToolRuntime.invoke 验证，
# 不直接调用 transfer_handler，不修改 PermissionEngine.decide。
# 运行方式：python tool_governace_demo.py --test 或 pytest tool_governace_demo.py
# ---------------------------------------------------------------------------


# --transfer 模式下收集各测试的审计库，用于断言结束后统一打印。
_AUDIT_SINKS: list[AuditSink] = []


def _fresh_transfer_env() -> tuple[ToolRuntime, ApprovalStore, AuditSink, ExecutionContext]:
    """为每个测试构建独立的 runtime、审批库和带 transfer 权限的上下文。"""
    reset_side_effects()
    runtime, approvals, audit = build_runtime(approvals=ApprovalStore())
    _AUDIT_SINKS.append(audit)
    context = replace(
        base_context(),
        permissions=frozenset({"order:read", "refund:create", "shell:run", "transfer:execute"}),
        allowed_tools=frozenset({"get_order", "create_refund", "run_shell", "transfer"}),
    )
    return runtime, approvals, audit, context


def test_transfer_schema_rejects_extra() -> None:
    """格式错误的账号与伪造 approved 字段都在 Schema 层被拒，handler 零执行。"""
    runtime, _, _, context = _fresh_transfer_env()
    bad_format = asyncio.run(
        runtime.invoke(
            ToolCall(
                "t1a",
                "transfer",
                {
                    "source_account": "ACC-A-12345",  # 只有 5 位数字，不匹配模式
                    "target_account": "ACC-A-654321",
                    "amount": 100.0,
                },
            ),
            context,
        )
    )
    assert bad_format.code == "INVALID_ARGUMENT"

    forged = asyncio.run(
        runtime.invoke(
            ToolCall(
                "t1b",
                "transfer",
                {
                    "source_account": "ACC-A-123456",
                    "target_account": "ACC-A-654321",
                    "amount": 100.0,
                    "approved": True,  # 模型伪造的授权字段，必须被 extra=forbid 拒绝
                },
            ),
            context,
        )
    )
    assert forged.code == "INVALID_ARGUMENT"
    assert SIDE_EFFECTS["transfer_executions"] == 0


def test_transfer_precheck_insufficient() -> None:
    """余额 5000 转账 6000：预检返回 INSUFFICIENT_BALANCE，handler 零执行。"""
    runtime, _, _, context = _fresh_transfer_env()
    result = asyncio.run(
        runtime.invoke(
            ToolCall(
                "t2",
                "transfer",
                {
                    "source_account": "ACC-A-654321",  # 余额 5000
                    "target_account": "ACC-A-123456",
                    "amount": 6000.0,
                },
            ),
            context,
        )
    )
    assert result.code == "INSUFFICIENT_BALANCE"
    assert SIDE_EFFECTS["transfer_executions"] == 0


def test_transfer_precheck_exceed_limit() -> None:
    """转账 60000 超过单笔 5 万限额：预检返回 EXCEED_LIMIT，handler 零执行。"""
    runtime, _, _, context = _fresh_transfer_env()
    result = asyncio.run(
        runtime.invoke(
            ToolCall(
                "t3",
                "transfer",
                {
                    "source_account": "ACC-A-123456",
                    "target_account": "ACC-A-654321",
                    "amount": 60000.0,
                },
            ),
            context,
        )
    )
    assert result.code == "EXCEED_LIMIT"
    assert SIDE_EFFECTS["transfer_executions"] == 0


def test_transfer_approval_binding() -> None:
    """审批时金额 100、执行时改成 200：参数摘要不匹配，旧审批失效。"""
    runtime, approvals, _, context = _fresh_transfer_env()
    approved_arguments = {
        "source_account": "ACC-A-123456",
        "target_account": "ACC-A-654321",
        "amount": 100.0,
    }
    approvals.approve("approval_t4", context, "transfer", approved_arguments)
    tampered_arguments = {**approved_arguments, "amount": 200.0}
    result = asyncio.run(
        runtime.invoke(
            ToolCall("t4", "transfer", tampered_arguments),
            replace(context, approval_id="approval_t4"),
        )
    )
    assert result.code == "APPROVAL_REQUIRED"
    assert result.action is DecisionAction.CONFIRM
    assert SIDE_EFFECTS["transfer_executions"] == 0


def test_transfer_timeout_no_retry() -> None:
    """转账 90000 走慢速分支触发超时：TIMEOUT_UNKNOWN 且写操作只尝试一次。"""
    runtime, approvals, _, context = _fresh_transfer_env()
    large_arguments = {
        "source_account": "ACC-A-123456",  # 余额 100000
        "target_account": "ACC-A-654321",
        "amount": 90000.0,
    }
    approvals.approve("approval_t5", context, "transfer", large_arguments)
    result = asyncio.run(
        runtime.invoke(
            ToolCall("t5", "transfer", large_arguments),
            replace(context, approval_id="approval_t5"),
        )
    )
    assert result.code == "TIMEOUT_UNKNOWN"
    # 写操作超时后绝不盲目重试：最多只允许一次 handler 尝试。
    assert SIDE_EFFECTS["transfer_executions"] <= 1


def test_transfer_confirm_before_approval() -> None:
    """无审批时转账返回 CONFIRM/APPROVAL_REQUIRED，handler 零执行。"""
    runtime, _, _, context = _fresh_transfer_env()
    result = asyncio.run(
        runtime.invoke(
            ToolCall(
                "t6",
                "transfer",
                {
                    "source_account": "ACC-A-123456",
                    "target_account": "ACC-A-654321",
                    "amount": 100.0,
                },
            ),
            context,  # 不带 approval_id
        )
    )
    assert result.action is DecisionAction.CONFIRM
    assert result.code == "APPROVAL_REQUIRED"
    assert SIDE_EFFECTS["transfer_executions"] == 0


def test_transfer_result_redacts_accounts() -> None:
    """审批通过执行后，结果中的账号必须脱敏（保留末 4 位）。"""
    runtime, approvals, _, context = _fresh_transfer_env()
    arguments = {
        "source_account": "ACC-A-123456",
        "target_account": "ACC-A-654321",
        "amount": 100.0,
    }
    approvals.approve("approval_t7", context, "transfer", arguments)
    result = asyncio.run(
        runtime.invoke(
            ToolCall("t7", "transfer", arguments),
            replace(context, approval_id="approval_t7"),
        )
    )
    assert result.ok is True
    assert result.content["source_account"] == "ACC-A-****3456"
    assert result.content["target_account"] == "ACC-A-****4321"


def run_governance_tests() -> None:
    """顺序执行全部回归测试；任一断言失败会抛出 AssertionError 并中止。"""
    tests = (
        test_transfer_schema_rejects_extra,
        test_transfer_precheck_insufficient,
        test_transfer_precheck_exceed_limit,
        test_transfer_approval_binding,
        test_transfer_timeout_no_retry,
        test_transfer_confirm_before_approval,
        test_transfer_result_redacts_accounts,
    )
    for test in tests:
        test()
        print(f"[PASS] {test.__name__}")
    print(f"治理回归测试：{len(tests)}/{len(tests)} 通过")


def run_transfer_check() -> None:
    """执行五个转账断言，并打印这五次验证中 transfer 工具的审计日志。"""
    _AUDIT_SINKS.clear()
    tests = (
        test_transfer_schema_rejects_extra,
        test_transfer_precheck_insufficient,
        test_transfer_precheck_exceed_limit,
        test_transfer_approval_binding,
        test_transfer_timeout_no_retry,
    )
    for test in tests:
        test()
        print(f"[PASS] {test.__name__}")
    print(f"转账治理断言：{len(tests)}/{len(tests)} 通过")
    transfer_records = [
        record for sink in _AUDIT_SINKS for record in sink.records if record.tool_name == "transfer"
    ]
    print(f"transfer 审计记录 {len(transfer_records)} 条：")
    for record in transfer_records:
        print("[audit] " + json.dumps(asdict(record), ensure_ascii=False, default=str))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python 工具治理与权限状态机演示")
    parser.add_argument("--agent", action="store_true", help="使用 DeepSeek 运行真实 Agent Loop")
    parser.add_argument("--test", action="store_true", help="运行全部转账治理回归测试")
    parser.add_argument(
        "--transfer",
        action="store_true",
        help="执行五个转账断言并打印 transfer 工具的审计日志",
    )
    parser.add_argument("--input", default="请查询订单 ord_1001 的状态和可退金额")
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = parse_args()
    if cli_args.transfer:
        run_transfer_check()
    elif cli_args.test:
        run_governance_tests()
    else:
        asyncio.run(run_deepseek_agent(cli_args.input) if cli_args.agent else run_offline_demo())