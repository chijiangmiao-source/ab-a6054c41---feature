"""FastAPI 入口：委托包核验、执行裁决、执行凭据签发/确认、回执复核与静态值班界面。"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import chain as chain_mod
from . import drill as drill_mod
from .canonical import CanonicalError, canonical_bytes
from .store import CredentialBindingError, DecisionStore, TOKEN_STATUS_USED

DB_PATH = os.environ.get("MDMS_DB_PATH", os.path.join(os.getcwd(), "data", "mdms.db"))

app = FastAPI(title="隔离维护站委托链裁决服务", version="1.1.0")
store = DecisionStore(DB_PATH)
_STARTED_AT = int(time.time())


class SubmitBody(BaseModel):
    packet_text: str
    request_text: str | None = None


class ConfirmBody(BaseModel):
    token_id: str
    packet_text: str
    request_text: str | None = None


def _parse_request_envelope(request_text: str | None) -> tuple[Any, str | None]:
    if request_text is None or not request_text.strip():
        return None, None
    env = chain_mod.parse_strict_json(request_text)
    if (
        not isinstance(env, dict)
        or "payload" not in env
        or not isinstance(env.get("payload_signature"), str)
    ):
        raise CanonicalError("请求文本必须是 {\"payload\":{...},\"payload_signature\":\"...\"}")
    return env["payload"], env["payload_signature"]


def _evaluation_view(ev: chain_mod.Evaluation) -> dict[str, Any]:
    view = asdict(ev)
    if ev.first_reason:
        view["first_reason_text"] = chain_mod.REASON_TEXT.get(ev.first_reason)
    else:
        view["first_reason_text"] = None
    return view


def _bad_request(reason: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={"code": reason, "message": chain_mod.REASON_TEXT.get(reason, reason)},
    )


def _evaluate_submission(packet_text: str, request_text: str | None, *, require_payload: bool):
    """解析并完整裁决一次提交；供凭据签发/确认接口使用。

    畸形输入 → 400 MALFORMED_JSON；require_payload 且缺载荷 → 400 PAYLOAD_STRUCTURE。
    """
    try:
        packet = chain_mod.parse_strict_json(packet_text)
        payload, sig = _parse_request_envelope(request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001 - json.JSONDecodeError 等
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)

    if require_payload and payload is None:
        raise _bad_request(chain_mod.REASON_PAYLOAD_STRUCTURE)

    return chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )


def _credential_view(trow) -> dict[str, Any] | None:
    """执行凭据的可复核视图：标识、状态、绑定的链与载荷摘要。"""
    if trow is None:
        return None
    payload = chain_mod.parse_strict_json(trow["payload_json"])
    payload_digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return {
        "token_id": trow["token_id"],
        "status": trow["status"],
        "request_digest": trow["request_digest"],
        "binding": {
            "root_pubkey": trow["root_pubkey"],
            "chain_digest": trow["chain_digest"],
            "leaf_id": trow["leaf_id"],
            "payload_digest": payload_digest,
        },
        "payload": payload,
        "created_at": trow["created_at"],
        "used_at": trow["used_at"],
    }


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    # 健康响应同时确认持久层可读
    executions = store.execution_count()
    return {
        "status": "ok",
        "service": "mdms-decision",
        "started_at": _STARTED_AT,
        "execution_records": executions,
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/api/drill")
def get_drill() -> dict[str, Any]:
    d = drill_mod.build_valid_drill()
    revoked = drill_mod.build_revoked_drill()
    from .canonical import canonicalize

    return {
        "valid": {
            "name": d["name"],
            "packet_text": canonicalize(d["packet"]),
            "request_text": canonicalize(
                {"payload": d["payload"], "payload_signature": d["payload_signature"]}
            ),
            "expected_leaf_id": d["expected_leaf_id"],
        },
        "revoked": {
            "name": revoked["name"],
            "packet_text": canonicalize(revoked["packet"]),
            "request_text": canonicalize(
                {"payload": revoked["payload"], "payload_signature": revoked["payload_signature"]}
            ),
            "expected_leaf_id": revoked["expected_leaf_id"],
        },
    }


@app.post("/api/inspect")
def inspect(body: SubmitBody) -> dict[str, Any]:
    """只核验、不落盘、不驱动设备：展示逐级签名/范围/失效与首个拒因。"""
    try:
        packet = chain_mod.parse_strict_json(body.packet_text)
        payload, sig = _parse_request_envelope(body.request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001 - json.JSONDecodeError 等
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    return {"accepted": ev.ok, "evaluation": _evaluation_view(ev)}


@app.post("/api/credential/issue")
def credential_issue(body: SubmitBody) -> dict[str, Any]:
    """逐级核验通过后签发**执行凭据**：只核验不驱动设备，核验失败不产生凭据。

    凭据与当时规范化后的裁决身份（root_pubkey / chain_digest / leaf_id /
    规范载荷 → request_digest）持久化绑定，供值班员复核后再确认执行。
    """
    ev = _evaluate_submission(body.packet_text, body.request_text, require_payload=True)
    # 经根公钥验签的撤销目标即使出现在凭据流程中也立即全局入册：之后剥离撤销
    # 声明或用此前签发的旧凭据重新确认都无法绕过（入册不产生裁决、不驱动设备）。
    if ev.valid_revoked_targets:
        store.register_revocations(set(ev.valid_revoked_targets))
    if not ev.ok:
        # 核验失败：绝不签发可用凭据；签发接口不写 REJECTED 决策，
        # 行为与 /api/inspect 一致（只核验，撤销名册除外，见上）。
        return {"accepted": False, "evaluation": _evaluation_view(ev), "credential": None}

    trow = store.issue_confirm_token(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload
    )
    return {
        "accepted": True,
        "evaluation": _evaluation_view(ev),
        "credential": _credential_view(trow),
    }


@app.get("/api/credential/{token_id}")
def credential_status(token_id: str) -> dict[str, Any]:
    """复核执行凭据：标识、绑定的链与载荷摘要、当前有效状态。"""
    if not token_id.isalnum() or len(token_id) != 32:
        raise HTTPException(status_code=404, detail="凭据标识格式非法")
    trow = store.get_confirm_token(token_id)
    if trow is None:
        raise HTTPException(status_code=404, detail="无此执行凭据")
    return {"credential": _credential_view(trow)}


@app.post("/api/credential/confirm")
def credential_confirm(body: ConfirmBody) -> JSONResponse:
    """凭执行凭据确认执行：重新裁决本次输入并与凭据绑定逐项复核。

    设备、命令、任何签名字段或请求载荷发生变化、凭据不存在、链项过期或已被
    撤销等都在此明确拒绝，且绝不驱动设备。并发/重启重放同一凭据同一请求
    收敛为既有的一次执行与同一稳定回执。
    """
    if not isinstance(body.token_id, str) or not (
        body.token_id.isalnum() and len(body.token_id) == 32
    ):
        raise _bad_request(chain_mod.REASON_CONFIRM_TOKEN_NOT_FOUND)

    ev = _evaluate_submission(body.packet_text, body.request_text, require_payload=True)
    response: dict[str, Any] = {"evaluation": _evaluation_view(ev)}

    if not ev.ok:
        # 本次输入重新裁决即失败（过期/撤销/篡改/越权等）：拒绝且不驱动，
        # 绝不允许借由旧凭据绕过现有安全检查。与 /api/execute 的拒绝路径一致：
        # 身份要素完整时落 REJECTED 裁决（重传/重启可复核同一结果），畸形链等
        # 身份要素不全的输入不落任何记录。
        decision = store.record_decision(
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
            execute=False,
            reason=ev.first_reason,
            new_revoked_targets=set(ev.valid_revoked_targets),
        )
        response["accepted"] = False
        response["credential"] = _credential_view(store.get_confirm_token(body.token_id))
        response["duplicate"] = decision.duplicate if decision else False
        response["receipt"] = decision.receipt() if decision else None
        return JSONResponse(response, status_code=200)

    try:
        decision, already_used = store.confirm_with_token(
            body.token_id,
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
            new_revoked_targets=set(ev.valid_revoked_targets),
        )
    except CredentialBindingError as exc:
        # 凭据不存在或输入与凭据绑定不一致：不写裁决、不驱动设备
        response["accepted"] = False
        ev.ok = False
        ev.first_reason = exc.reason
        response["evaluation"] = _evaluation_view(ev)
        response["credential"] = _credential_view(store.get_confirm_token(body.token_id))
        response["duplicate"] = False
        response["receipt"] = None
        return JSONResponse(response, status_code=200)

    if decision.status != "EXECUTED":
        # 运行期安全检查转拒（凭据签发后链项被撤销/末级凭据已被其他请求消耗）
        ev.ok = False
        ev.first_reason = decision.reason
        response = {"accepted": False, "evaluation": _evaluation_view(ev)}
    else:
        response["accepted"] = True
    trow = store.get_confirm_token(body.token_id)
    response["credential"] = _credential_view(trow)
    # already_used 或 duplicate 都表示本次未产生新的设备驱动
    response["duplicate"] = bool(decision.duplicate or already_used)
    response["receipt"] = decision.receipt()
    return JSONResponse(response, status_code=200)


@app.post("/api/execute")
def execute(body: SubmitBody) -> JSONResponse:
    """发起一次执行；并发/重传在一次持久化裁决中收敛为一次执行与同一回执。"""
    try:
        packet = chain_mod.parse_strict_json(body.packet_text)
        payload, sig = _parse_request_envelope(body.request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)

    if payload is None:
        raise _bad_request(chain_mod.REASON_PAYLOAD_STRUCTURE)

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    response: dict[str, Any] = {"accepted": ev.ok, "evaluation": _evaluation_view(ev)}

    if ev.ok:
        decision = store.record_decision(
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
            execute=True,
            new_revoked_targets=set(ev.valid_revoked_targets),
        )
        assert decision is not None
        # 运行期条件（末级凭据已消耗 / 并发到达的撤销入册）可能使裁决转拒：
        # accepted 以持久化裁决为准，并回填首个拒因供界面展示。
        if decision.status != "EXECUTED":
            ev.ok = False
            ev.first_reason = decision.reason
            response = {"accepted": False, "evaluation": _evaluation_view(ev)}
        response["duplicate"] = decision.duplicate
        response["receipt"] = decision.receipt()
        return JSONResponse(response, status_code=200)

    # 被撤销 / 越权 / 过期等：仅落 REJECTED 裁决，绝不留下执行记录
    decision = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
        execute=False,
        reason=ev.first_reason,
        new_revoked_targets=set(ev.valid_revoked_targets),
    )
    response["duplicate"] = decision.duplicate if decision else False
    response["receipt"] = decision.receipt() if decision else None
    return JSONResponse(response, status_code=200)


@app.get("/api/receipt/{request_digest}")
def get_receipt(request_digest: str) -> dict[str, Any]:
    if not request_digest.isalnum() or len(request_digest) != 64:
        raise HTTPException(status_code=404, detail="回执标识格式非法")
    decision = store.get(request_digest)
    if decision is None:
        raise HTTPException(status_code=404, detail="无此裁决回执")
    return {"receipt": decision.receipt()}


@app.get("/api/decisions")
def list_decisions(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    return {"decisions": store.list_decisions(limit)}
