"""FastAPI 入口：委托包核验、执行裁决、回执复核与静态值班界面。"""
from __future__ import annotations

import os
import time
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import chain as chain_mod
from . import drill as drill_mod
from .canonical import CanonicalError
from .store import DecisionStore

DB_PATH = os.environ.get("MDMS_DB_PATH", os.path.join(os.getcwd(), "data", "mdms.db"))

app = FastAPI(title="隔离维护站委托链裁决服务", version="1.0.0")
store = DecisionStore(DB_PATH)
_STARTED_AT = int(time.time())


class SubmitBody(BaseModel):
    packet_text: str
    request_text: str | None = None


class ConfirmBody(BaseModel):
    packet_text: str
    request_text: str | None = None
    credential_id: str | None = None


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


def _parse_submission(packet_text: str, request_text: str | None) -> tuple[Any, Any, str | None]:
    """解析委托包与请求信封；畸形输入一律 400 MALFORMED_JSON。"""
    try:
        packet = chain_mod.parse_strict_json(packet_text)
        payload, sig = _parse_request_envelope(request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001 - json.JSONDecodeError 等
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    return packet, payload, sig


def _submitted_identity(packet: Any, payload: Any) -> tuple[str, str, str, str] | None:
    """从提交内容提取裁决身份四要素（root_pubkey, chain_digest, leaf_id, request_digest）。

    结构不完整或不可规范化时返回 None——此时它必然无法匹配任何已签发凭据
    （凭据只在完整核验通过后签发），按"与凭据绑定身份不一致"处理。
    """
    try:
        if not isinstance(packet, dict) or not isinstance(payload, dict):
            return None
        root_pubkey = packet.get("root_pubkey")
        chain = packet.get("chain")
        if not isinstance(root_pubkey, str) or not isinstance(chain, list) or not chain:
            return None
        leaf = chain[-1]
        if not isinstance(leaf, dict) or not isinstance(leaf.get("header"), dict):
            return None
        chain_digest = chain_mod.chain_digest_of(chain)
        leaf_id = chain_mod.item_id_of(leaf["header"])
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        return root_pubkey, chain_digest, leaf_id, digest
    except Exception:  # noqa: BLE001 - CanonicalError / binascii 等
        return None


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


@app.post("/api/attest")
def attest(body: SubmitBody) -> dict[str, Any]:
    """逐级核验并在通过时签发执行凭据（不执行、不落裁决）。

    凭据与当时规范化后的裁决身份（root_pubkey / chain_digest / leaf_id /
    规范载荷 → request_digest）持久绑定；核验失败不得产生可用凭据。
    """
    packet, payload, sig = _parse_submission(body.packet_text, body.request_text)
    if payload is None:
        raise _bad_request(chain_mod.REASON_PAYLOAD_STRUCTURE)

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    response: dict[str, Any] = {"accepted": ev.ok, "evaluation": _evaluation_view(ev)}
    if not ev.ok:
        response["credential"] = None
        return response
    cred = store.issue_credential(ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload)
    response["credential"] = store.credential_view(cred)
    return response


@app.post("/api/confirm")
def confirm(body: ConfirmBody) -> JSONResponse:
    """凭据确认执行：重新核对提交内容与凭据绑定的裁决身份，一致才进入持久化裁决。

    任何设备、命令、签名字段或请求载荷变化都会改变裁决身份，被明确拒绝且
    不驱动设备、不落任何记录；身份一致时走与 /api/execute 完全相同的持久化
    裁决（含过期/撤销/一次性等运行期检查），并发确认与重传收敛为一次执行
    与同一稳定回执，重启后可凭同一确认复核原结果。
    """
    packet, payload, sig = _parse_submission(body.packet_text, body.request_text)
    if payload is None:
        raise _bad_request(chain_mod.REASON_PAYLOAD_STRUCTURE)

    cred = store.get_credential(body.credential_id or "")
    if cred is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": chain_mod.REASON_CREDENTIAL_UNKNOWN,
                "message": chain_mod.REASON_TEXT[chain_mod.REASON_CREDENTIAL_UNKNOWN],
            },
        )

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    identity = _submitted_identity(packet, payload)
    if identity is None or identity[3] != cred.request_digest:
        # 提交内容不是凭据签发时核验的那份：明确拒绝，不驱动设备、不落裁决记录
        ev.ok = False
        ev.first_reason = chain_mod.REASON_CREDENTIAL_MISMATCH
        return JSONResponse({
            "accepted": False,
            "evaluation": _evaluation_view(ev),
            "credential": store.credential_view(cred),
            "duplicate": False,
            "receipt": None,
        })

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
    else:
        # 链项过期 / 被撤销等：旧凭据不得绕过现有安全检查，仅落 REJECTED 裁决
        decision = store.record_decision(
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
            execute=False,
            reason=ev.first_reason,
            new_revoked_targets=set(ev.valid_revoked_targets),
        )
        response["duplicate"] = decision.duplicate if decision else False
        response["receipt"] = decision.receipt() if decision else None
    response["credential"] = store.credential_view(cred)
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
