"""执行凭据流程测试：签发绑定、确认执行、篡改拒绝、并发收敛、重启复核、
旧凭据不得绕过过期/撤销/一次性等运行期安全检查，且直接执行接口行为不变。"""
import concurrent.futures
import hashlib
import json
import time

import httpx
import pytest

from app import chain as C
from app import testkit
from app.canonical import canonical_bytes, canonicalize
from app.cryptohelp import sign_payload
from app.store import DecisionStore
from conftest import FAR_FUTURE


def _envelope(keys, levels, *, packet_mut=None, payload=None, revoked=False, expires=FAR_FUTURE):
    chain = testkit.make_chain(keys["root"], levels, expires)
    if revoked:
        leaf_id = C.item_id_of(chain[-1]["header"])
        crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
        packet = testkit.make_packet(keys["root"], chain, revocations=[crl])
    else:
        packet = testkit.make_packet(keys["root"], chain)
    if packet_mut:
        packet_mut(packet, chain)
    payload = payload or {"device": "dev-a", "command": "status", "nonce": "cred-1"}
    sig = sign_payload(keys["leaf"], payload)
    return {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize({"payload": payload, "payload_signature": sig}),
        "_payload": payload,
        "_leaf_id": C.item_id_of(chain[-1]["header"]),
    }


def _post(server, path, body):
    return httpx.post(server.base_url + path, json=body, timeout=20)


def _attest(server, body):
    r = _post(server, "/api/attest", body)
    assert r.status_code == 200
    return r.json()


def _confirm(server, body, credential_id):
    return _post(server, "/api/confirm", {**body, "credential_id": credential_id})


def _ledger(server):
    return httpx.get(server.base_url + "/api/decisions?limit=200", timeout=5).json()["decisions"]


# --------------------------------------------------------------------- #
# 签发：核验通过才产生凭据，且与规范化后的裁决身份持久绑定
# --------------------------------------------------------------------- #
def test_attest_issues_credential_bound_to_identity(server, keys, levels):
    body = _envelope(keys, levels)
    j = _attest(server, body)
    assert j["accepted"] is True
    cred = j["credential"]
    ev = j["evaluation"]
    assert cred["credential_id"].startswith("cdl-")
    assert cred["status"] == "ACTIVE"
    # 绑定的链/载荷摘要与裁决身份一致
    assert cred["chain_digest"] == ev["chain_digest"]
    assert cred["leaf_id"] == ev["leaf_id"] == body["_leaf_id"]
    assert cred["root_pubkey"] == ev["root_pubkey"]
    assert cred["payload_digest"] == hashlib.sha256(
        canonical_bytes(body["_payload"])).hexdigest()
    assert cred["request_digest"] == C.request_digest(
        ev["root_pubkey"], ev["chain_digest"], ev["leaf_id"], body["_payload"])
    # 同一内容重复核验：同一凭据标识（可复核）
    j2 = _attest(server, body)
    assert j2["credential"]["credential_id"] == cred["credential_id"]
    # 签发凭据不执行、不落裁决
    assert _ledger(server) == []


def test_attest_failure_produces_no_credential(server, keys, levels):
    def mut(packet, chain):
        packet["chain"][-1]["header"]["devices"] = ["dev-a", "dev-x"]
    body = _envelope(keys, levels, packet_mut=mut)
    j = _attest(server, body)
    assert j["accepted"] is False
    assert j["credential"] is None
    assert _ledger(server) == []


def test_attest_revoked_packet_produces_no_credential(server, keys, levels):
    j = _attest(server, _envelope(keys, levels, revoked=True))
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_REVOKED
    assert j["credential"] is None


def test_attest_requires_payload(server, keys, levels):
    body = _envelope(keys, levels)
    r = _post(server, "/api/attest", {"packet_text": body["packet_text"], "request_text": ""})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == C.REASON_PAYLOAD_STRUCTURE


# --------------------------------------------------------------------- #
# 确认执行：一致才执行，重传/并发收敛，重启可复核
# --------------------------------------------------------------------- #
def test_confirm_executes_and_converges_with_stable_receipt(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]

    r1 = _confirm(server, body, cred["credential_id"])
    j1 = r1.json()
    assert r1.status_code == 200 and j1["accepted"] is True
    assert j1["receipt"]["status"] == "EXECUTED"
    assert j1["duplicate"] is False
    assert j1["credential"]["status"] == "EXECUTED"

    # 同一确认重传：同一回执
    j2 = _confirm(server, body, cred["credential_id"]).json()
    assert j2["receipt"] == j1["receipt"]
    assert j2["duplicate"] is True

    # 回执接口逐字一致
    got = httpx.get(
        server.base_url + f"/api/receipt/{j1['receipt']['request_digest']}", timeout=5
    ).json()["receipt"]
    assert got == j1["receipt"]
    # 恰好一次执行
    assert len([d for d in _ledger(server) if d["status"] == "EXECUTED"]) == 1


def test_confirm_concurrent_same_credential_converges(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(
            lambda _: _confirm(server, body, cred["credential_id"]), range(12)))
    js = [r.json() for r in responses]
    assert all(j["accepted"] for j in js)
    receipts = {json.dumps(j["receipt"], sort_keys=True) for j in js}
    assert len(receipts) == 1
    assert sum(1 for j in js if not j["duplicate"]) == 1
    assert len([d for d in _ledger(server) if d["status"] == "EXECUTED"]) == 1


def test_confirm_survives_restart(server_factory, keys, levels):
    srv1 = server_factory()
    body = _envelope(keys, levels, payload={"device": "dev-b", "command": "reboot", "nonce": "rs"})
    cred = _attest(srv1, body)["credential"]
    j1 = _confirm(srv1, body, cred["credential_id"]).json()
    assert j1["accepted"] is True
    srv1.stop()

    srv2 = server_factory()  # 同一 db 文件，全新进程
    # 重启后同一确认可复核原结果
    j2 = _confirm(srv2, body, cred["credential_id"]).json()
    assert j2["receipt"] == j1["receipt"]
    assert j2["duplicate"] is True
    # 重启后重新核验同一内容：同一凭据标识（确定性派生）
    cred2 = _attest(srv2, body)["credential"]
    assert cred2["credential_id"] == cred["credential_id"]
    assert cred2["status"] == "EXECUTED"
    srv2.stop()


# --------------------------------------------------------------------- #
# 篡改拒绝：任何设备/命令/签名字段/载荷变化都明确拒绝且不驱动设备
# --------------------------------------------------------------------- #
def test_confirm_tampered_payload_mismatch_no_execution(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]

    # 页面间隙被替换：设备/命令/载荷字段与签发时不一致（签名本身合法）
    swapped = _envelope(keys, levels, payload={"device": "dev-b", "command": "reboot", "nonce": "sw"})
    r = _confirm(server, swapped, cred["credential_id"])
    j = r.json()
    assert r.status_code == 200
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_CREDENTIAL_MISMATCH
    assert j["receipt"] is None
    assert _ledger(server) == []  # 不匹配：不落任何记录、不驱动设备

    # 被替换的请求本身并未被凭据流程"预拒"：仍可走既有直接执行接口
    direct = _post(server, "/api/execute", {k: swapped[k] for k in ("packet_text", "request_text")})
    assert direct.json()["accepted"] is True


def test_confirm_tampered_signature_field_mismatch(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]

    def mut(packet, chain):
        packet["chain"][-1]["header"]["commands"] = ["reboot", "status", "diagnose"]
    tampered = _envelope(keys, levels, packet_mut=mut)
    j = _confirm(server, tampered, cred["credential_id"]).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_CREDENTIAL_MISMATCH
    assert j["receipt"] is None
    assert _ledger(server) == []


def test_confirm_tampered_payload_signature_rejected(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]
    env = json.loads(body["request_text"])
    env["payload_signature"] = sign_payload(keys["other"], env["payload"])
    j = _confirm(server, {"packet_text": body["packet_text"],
                          "request_text": canonicalize(env)}, cred["credential_id"]).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_PAYLOAD_SIGNATURE_INVALID
    assert j["receipt"]["status"] == "REJECTED"
    assert not any(d["status"] == "EXECUTED" for d in _ledger(server))


def test_confirm_unknown_credential_404(server, keys, levels):
    body = _envelope(keys, levels)
    r = _confirm(server, body, "cdl-" + "0" * 64)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == C.REASON_CREDENTIAL_UNKNOWN
    r2 = _confirm(server, body, None)
    assert r2.status_code == 404
    assert _ledger(server) == []


def test_confirm_malformed_json_400(server):
    r = _post(server, "/api/confirm",
              {"packet_text": "{nope", "request_text": "", "credential_id": "cdl-x"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == C.REASON_MALFORMED_JSON


# --------------------------------------------------------------------- #
# 旧凭据不得绕过运行期安全检查：过期 / 撤销 / 一次性凭据
# --------------------------------------------------------------------- #
def test_stale_credential_blocked_by_revocation(server, keys, levels):
    body = _envelope(keys, levels, payload={"device": "dev-a", "command": "status", "nonce": "r1"})
    cred = _attest(server, body)["credential"]
    assert cred["status"] == "ACTIVE"

    # 另一请求携带根签署的撤销声明到达：叶项入册全局失效
    revoked = _envelope(keys, levels, revoked=True,
                        payload={"device": "dev-a", "command": "status", "nonce": "r2"})
    j = _post(server, "/api/execute",
              {k: revoked[k] for k in ("packet_text", "request_text")}).json()
    assert j["evaluation"]["first_reason"] == C.REASON_REVOKED

    # 旧凭据确认：不得绕过撤销名册
    j2 = _confirm(server, body, cred["credential_id"]).json()
    assert j2["accepted"] is False
    assert j2["evaluation"]["first_reason"] == C.REASON_REVOKED
    assert j2["receipt"]["status"] == "REJECTED"
    assert not any(d["status"] == "EXECUTED" for d in _ledger(server))


def test_stale_credential_blocked_by_expiry(server, keys, levels):
    body = _envelope(keys, levels, expires=int(time.time()) + 2)
    cred = _attest(server, body)["credential"]
    assert cred["status"] == "ACTIVE"
    time.sleep(3)  # 链项在确认前过期
    j = _confirm(server, body, cred["credential_id"]).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_EXPIRED
    # 与直接执行过期链的既有行为一致：身份要素不全，不落任何记录
    assert j["receipt"] is None
    assert _ledger(server) == []


def test_stale_credential_blocked_by_consumed_leaf(server, keys, levels):
    body = _envelope(keys, levels, payload={"device": "dev-a", "command": "status", "nonce": "k1"})
    cred = _attest(server, body)["credential"]
    # 同一末级凭据被另一请求先行消耗
    other = _envelope(keys, levels, payload={"device": "dev-a", "command": "reboot", "nonce": "k2"})
    j = _post(server, "/api/execute",
              {k: other[k] for k in ("packet_text", "request_text")}).json()
    assert j["accepted"] is True
    # 旧凭据确认：一次性凭据检查仍然生效
    j2 = _confirm(server, body, cred["credential_id"]).json()
    assert j2["accepted"] is False
    assert j2["evaluation"]["first_reason"] == C.REASON_LEAF_CONSUMED
    assert len([d for d in _ledger(server) if d["status"] == "EXECUTED"]) == 1


# --------------------------------------------------------------------- #
# 与既有直接执行接口的兼容：同一裁决身份收敛到同一回执
# --------------------------------------------------------------------- #
def test_credential_flow_converges_with_direct_execute(server, keys, levels):
    body = _envelope(keys, levels)
    cred = _attest(server, body)["credential"]
    direct = _post(server, "/api/execute",
                   {k: body[k] for k in ("packet_text", "request_text")}).json()
    assert direct["accepted"] is True and direct["duplicate"] is False
    # 直接执行后再确认：同一回执，不会二次驱动
    j = _confirm(server, body, cred["credential_id"]).json()
    assert j["receipt"] == direct["receipt"]
    assert j["duplicate"] is True
    assert len([d for d in _ledger(server) if d["status"] == "EXECUTED"]) == 1


# --------------------------------------------------------------------- #
# 持久层：凭据绑定、幂等签发、重启后状态推导
# --------------------------------------------------------------------- #
def test_store_credential_persistence_and_status(tmp_path, keys, levels, valid_payload):
    db = str(tmp_path / "mdms.db")
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
    )
    assert ev.ok

    s1 = DecisionStore(db)
    c1 = s1.issue_credential(ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload)
    c2 = s1.issue_credential(ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload)
    assert c1.credential_id == c2.credential_id      # 同一裁决身份 → 同一凭据
    assert c1.duplicate is False and c2.duplicate is True
    assert c1.created_at == c2.created_at            # 保留首次签发时间
    assert s1.credential_status(c1) == "ACTIVE"
    s1.close()

    s2 = DecisionStore(db)  # 模拟重启
    got = s2.get_credential(c1.credential_id)
    assert got is not None
    assert got.request_digest == c1.request_digest
    assert got.payload == valid_payload
    d = s2.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload, execute=True)
    assert d.status == "EXECUTED"
    assert s2.credential_status(got) == "EXECUTED"
    assert s2.get_credential("cdl-" + "1" * 64) is None
    s2.close()
