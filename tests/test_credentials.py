"""执行凭据测试：核验签发 → 持久绑定 → 确认执行；篡改/撤销/过期拒绝；
并发与重启收敛；与既有直接执行接口共享同一裁决临界区。
"""
import concurrent.futures
import json

import httpx
import pytest

from app import chain as C
from app import testkit
from app.canonical import canonicalize
from app.cryptohelp import sign_payload
from app.store import CredentialBindingError
from conftest import FAR_FUTURE


# --------------------------------------------------------------------- 辅助
@pytest.fixture
def scenario(keys, levels, valid_payload):
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    sig = sign_payload(keys["leaf"], valid_payload)
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload, payload_signature=sig
    )
    assert ev.ok
    return ev, valid_payload


def _api_body(keys, levels, payload, *, expires_at=FAR_FUTURE, packet=None, chain=None):
    chain = chain or testkit.make_chain(keys["root"], levels, expires_at)
    packet = packet if packet is not None else testkit.make_packet(keys["root"], chain)
    return {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize(
            {"payload": payload, "payload_signature": sign_payload(keys["leaf"], payload)}
        ),
        "_chain": chain,
        "_packet": packet,
    }


def _issue(server, body):
    r = httpx.post(server.base_url + "/api/credential/issue",
                   json={k: body[k] for k in ("packet_text", "request_text")}, timeout=10)
    return r


def _confirm(server, token_id, body):
    return httpx.post(server.base_url + "/api/credential/confirm", json={
        "token_id": token_id,
        "packet_text": body["packet_text"],
        "request_text": body["request_text"],
    }, timeout=20)


# --------------------------------------------------------------------- 存储层
def test_store_issue_persists_binding(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    row = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)
    assert len(row["token_id"]) == 32
    assert row["status"] == "ISSUED"
    assert row["request_digest"] == C.request_digest(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
    )
    assert row["payload_json"] == C.canonical_bytes(payload).decode()
    # 同身份重复签发幂等返回同一凭据
    row2 = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)
    assert row2["token_id"] == row["token_id"]


def test_store_confirm_executes_once_and_marks_used(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    row = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)
    d, already_used = store.confirm_with_token(
        row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
    )
    assert d.status == "EXECUTED" and already_used is False
    assert store.execution_count() == 1
    assert store.get_confirm_token(row["token_id"])["status"] == "USED"
    # 重放：不二次驱动，收敛到同一回执
    d2, already_used2 = store.confirm_with_token(
        row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
    )
    assert d2.duplicate is True and already_used2 is True
    assert d2.receipt() == d.receipt()
    assert store.execution_count() == 1


def test_store_confirm_binding_mismatch_rejected(store_factory, keys, levels, scenario):
    store = store_factory()
    ev, payload = scenario
    row = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)

    # 载荷变化（规范化字节不同）→ MISMATCH，不落裁决、不驱动
    other = {"device": "dev-a", "command": "reboot", "nonce": "other"}
    with pytest.raises(CredentialBindingError) as ei:
        store.confirm_with_token(
            row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, other
        )
    assert ei.value.reason == C.REASON_CONFIRM_TOKEN_MISMATCH
    assert store.execution_count() == 0
    assert store.get_confirm_token(row["token_id"])["status"] == "ISSUED"

    # 不存在的凭据 → NOT_FOUND
    with pytest.raises(CredentialBindingError) as ei2:
        store.confirm_with_token(
            "a" * 32, ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
        )
    assert ei2.value.reason == C.REASON_CONFIRM_TOKEN_NOT_FOUND
    assert store.execution_count() == 0


def test_store_token_persists_across_restart(tmp_path, scenario):
    db = str(tmp_path / "mdms.db")
    from app.store import DecisionStore
    s1 = DecisionStore(db)
    ev, payload = scenario
    row = s1.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)
    d1, _ = s1.confirm_with_token(
        row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
    )
    s1.close()

    s2 = DecisionStore(db)  # 重启
    assert s2.get_confirm_token(row["token_id"])["status"] == "USED"
    # 重启后相同确认复核原结果，不二次执行
    d2, already_used = s2.confirm_with_token(
        row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
    )
    assert d2.receipt() == d1.receipt() and d2.duplicate is True and already_used is True
    assert s2.execution_count() == 1


def test_store_concurrent_token_confirm_single_execution(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    row = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload)
    results, errors = [], []

    def worker():
        try:
            results.append(store.confirm_with_token(
                row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload
            ))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [__import__("threading").Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    receipts = {json.dumps(d.receipt(), sort_keys=True) for d, _ in results}
    assert len(receipts) == 1
    assert sum(1 for d, used in results if not d.duplicate and not used) == 1
    assert store.execution_count() == 1


def test_store_revocation_after_issue_blocks_token(store_factory, keys, levels, valid_payload):
    """凭据未使用时链项被撤销入册：旧凭据确认不得绕过，且凭据不被消耗。"""
    store = store_factory()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
    )
    row = store.issue_confirm_token(ev.root_pubkey, ev.chain_digest, ev.leaf_id, valid_payload)

    # 另一请求携带合法 CRL 使撤销全局入册
    leaf_id = C.item_id_of(chain[-1]["header"])
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], chain, revocations=[crl])
    ev_rev = C.evaluate_packet(
        packet_rev, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
    )
    assert ev_rev.first_reason == C.REASON_REVOKED
    store.record_decision(
        ev_rev.root_pubkey, ev_rev.chain_digest, ev_rev.leaf_id, valid_payload,
        execute=False, reason=ev_rev.first_reason,
        new_revoked_targets=set(ev_rev.valid_revoked_targets),
    )
    assert leaf_id in store.revoked_set()

    # 旧凭据确认：临界区重新检查撤销名册 → REJECTED/REVOKED，不执行
    d, _ = store.confirm_with_token(
        row["token_id"], ev.root_pubkey, ev.chain_digest, ev.leaf_id, valid_payload
    )
    assert d.status == "REJECTED" and d.reason == C.REASON_REVOKED
    assert store.execution_count() == 0


# --------------------------------------------------------------------- HTTP 层
def test_api_issue_then_confirm_flow(server, keys, levels):
    payload = {"device": "dev-a", "command": "status", "nonce": "cred-1"}
    body = _api_body(keys, levels, payload)
    r = _issue(server, body)
    j = r.json()
    assert r.status_code == 200 and j["accepted"] is True
    cred = j["credential"]
    assert cred["status"] == "ISSUED" and len(cred["token_id"]) == 32
    assert cred["binding"]["chain_digest"] == C.chain_digest_of(body["_chain"])
    assert cred["binding"]["leaf_id"] == C.item_id_of(body["_chain"][-1]["header"])
    assert cred["binding"]["payload_digest"]
    assert cred["request_digest"]

    # GET 复核
    g = httpx.get(server.base_url + f"/api/credential/{cred['token_id']}", timeout=5)
    assert g.status_code == 200 and g.json()["credential"] == cred
    assert httpx.get(server.base_url + "/api/credential/" + "0" * 32, timeout=5).status_code == 404

    rc = _confirm(server, cred["token_id"], body).json()
    assert rc["accepted"] is True
    assert rc["receipt"]["status"] == "EXECUTED" and rc["duplicate"] is False
    assert rc["credential"]["status"] == "USED"

    # 再次确认 → 收敛同一回执
    rc2 = _confirm(server, cred["token_id"], body).json()
    assert rc2["receipt"] == rc["receipt"] and rc2["duplicate"] is True


def test_api_issue_failure_produces_no_credential(server, keys, levels):
    # 越权命令：核验失败，无凭据
    bad = {"device": "dev-a", "command": "diagnose", "nonce": "bad"}
    body = _api_body(keys, levels, bad)
    j = _issue(server, body).json()
    assert j["accepted"] is False and j["credential"] is None
    assert j["evaluation"]["first_reason"] == C.REASON_COMMAND_OUT_OF_SCOPE
    # 签发不驱动设备、不落裁决
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert ledger == []


def test_api_confirm_rejects_changed_payload(server, keys, levels):
    p1 = {"device": "dev-a", "command": "status", "nonce": "orig"}
    b1 = _api_body(keys, levels, p1)
    token = _issue(server, b1).json()["credential"]["token_id"]

    # 页面间隙替换为同范围内另一命令（叶项签名有效）→ 绑定不一致
    p2 = {"device": "dev-a", "command": "reboot", "nonce": "swapped"}
    b2 = _api_body(keys, levels, p2)
    j = _confirm(server, token, b2).json()
    assert j["accepted"] is False and j["receipt"] is None
    assert j["evaluation"]["first_reason"] == C.REASON_CONFIRM_TOKEN_MISMATCH
    assert j["credential"]["status"] == "ISSUED"  # 未消耗

    # 设备变化同拒
    p3 = {"device": "dev-b", "command": "status", "nonce": "swapped2"}
    b3 = _api_body(keys, levels, p3)
    j3 = _confirm(server, token, b3).json()
    assert j3["accepted"] is False
    assert j3["evaluation"]["first_reason"] == C.REASON_CONFIRM_TOKEN_MISMATCH

    # 原请求仍恰好执行一次
    ok = _confirm(server, token, b1).json()
    assert ok["accepted"] and ok["receipt"]["status"] == "EXECUTED"
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert len([d for d in ledger if d["status"] == "EXECUTED"]) == 1


def test_api_confirm_rejects_tampered_signature_fields(server, keys, levels):
    payload = {"device": "dev-a", "command": "status", "nonce": "sig"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]

    # 改链上已签字段 → 重新裁决 SIGNATURE_INVALID，绝不驱动
    tampered_packet = json.loads(body["packet_text"])
    tampered_packet["chain"][-1]["header"]["devices"] = ["dev-a", "dev-z"]
    bad = {**body, "packet_text": canonicalize(tampered_packet)}
    j = _confirm(server, token, bad).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_SIGNATURE_INVALID
    assert j["receipt"] is None

    # 改请求签名字段（payload_signature）→ PAYLOAD_SIGNATURE_INVALID
    req = json.loads(body["request_text"])
    req["payload_signature"] = req["payload_signature"][:-2] + ("aa" if req["payload_signature"][-2:] != "aa" else "bb")
    bad2 = {**body, "request_text": canonicalize(req)}
    j2 = _confirm(server, token, bad2).json()
    assert j2["accepted"] is False
    assert j2["evaluation"]["first_reason"] == C.REASON_PAYLOAD_SIGNATURE_INVALID
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert not any(d["status"] == "EXECUTED" for d in ledger)


def test_api_confirm_unknown_token_rejected(server, keys, levels):
    body = _api_body(keys, levels, {"device": "dev-a", "command": "status", "nonce": "u"})
    j = _confirm(server, "f" * 32, body).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_CONFIRM_TOKEN_NOT_FOUND
    r = _confirm(server, "xyz", body)
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == C.REASON_CONFIRM_TOKEN_NOT_FOUND


def test_api_confirm_after_revocation_blocks_old_token(server, keys, levels):
    payload = {"device": "dev-a", "command": "status", "nonce": "late-rev"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]

    # 凭据未使用期间，叶项被合法 CRL 撤销并入册
    leaf_id = C.item_id_of(body["_chain"][-1]["header"])
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], body["_chain"], revocations=[crl])
    rev_body = {
        "packet_text": canonicalize(packet_rev),
        "request_text": body["request_text"],
    }
    httpx.post(server.base_url + "/api/execute", json=rev_body, timeout=10)

    # 用旧凭据 + 原（已剥离撤销的）包确认：仍被撤销，不驱动
    j = _confirm(server, token, body).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_REVOKED
    assert j["receipt"]["status"] == "REJECTED"
    assert j["credential"]["status"] == "ISSUED"
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert not any(d["status"] == "EXECUTED" for d in ledger)


def test_api_issue_with_revocation_registers_and_blocks_stripped_confirm(server, keys, levels):
    """仅在签发凭据时携带合法撤销（从未走执行接口）也立即入册：
    签发被拒不产生凭据；剥离撤销重签/确认均被 REVOKED。"""
    payload = {"device": "dev-a", "command": "status", "nonce": "iss-rev"}
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    leaf_id = C.item_id_of(chain[-1]["header"])
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], chain, revocations=[crl])
    rev_body = _api_body(keys, levels, payload, packet=packet_rev, chain=chain)
    ji = _issue(server, rev_body).json()
    assert ji["accepted"] is False and ji["credential"] is None
    assert ji["evaluation"]["first_reason"] == C.REASON_REVOKED
    # 签发接口不写裁决
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert ledger == []

    # 剥离撤销声明后重新核验签发：仍因持久名册被拒，无凭据
    clean = _api_body(keys, levels, payload, chain=chain)
    ji2 = _issue(server, clean).json()
    assert ji2["accepted"] is False
    assert ji2["evaluation"]["first_reason"] == C.REASON_REVOKED
    assert ji2["evaluation"]["revoked_by_persisted"] is True


def test_api_confirm_after_leaf_consumed_by_direct_execute(server, keys, levels):
    """凭据未使用期间原裁决因末级凭据被消耗不再允许：确认得 LEAF_CONSUMED。"""
    # 先用同叶项另一请求经直接执行接口消耗 leaf
    consume = {"device": "dev-a", "command": "reboot", "nonce": "consumed-elsewhere"}
    b_consume = _api_body(keys, levels, consume)
    rd = httpx.post(server.base_url + "/api/execute",
                    json={k: b_consume[k] for k in ("packet_text", "request_text")},
                    timeout=10).json()
    assert rd["accepted"] is True

    payload = {"device": "dev-a", "command": "status", "nonce": "late-token"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]
    j = _confirm(server, token, body).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_LEAF_CONSUMED
    assert j["receipt"]["status"] == "REJECTED"
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert len([d for d in ledger if d["status"] == "EXECUTED"]) == 1


def test_api_confirm_expired_chain_rejected(server, keys, levels):
    payload = {"device": "dev-a", "command": "status", "nonce": "exp"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]

    expired_chain = testkit.make_chain(keys["root"], levels, 100)
    expired_packet = testkit.make_packet(keys["root"], expired_chain)
    changed = {**body, "packet_text": canonicalize(expired_packet)}
    j = _confirm(server, token, changed).json()
    assert j["accepted"] is False
    assert j["evaluation"]["first_reason"] == C.REASON_EXPIRED
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert not any(d["status"] == "EXECUTED" for d in ledger)


def test_api_concurrent_token_confirms_converge(server, keys, levels):
    payload = {"device": "dev-b", "command": "reboot", "nonce": "cc"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        rs = list(pool.map(lambda _: _confirm(server, token, body), range(12)))
    js = [r.json() for r in rs]
    receipts = {json.dumps(j["receipt"], sort_keys=True) for j in js}
    assert len(receipts) == 1
    assert sum(1 for j in js if not j["duplicate"]) == 1
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert len([d for d in ledger if d["status"] == "EXECUTED"]) == 1


def test_api_token_confirm_and_direct_execute_converge(server, keys, levels):
    payload = {"device": "dev-a", "command": "status", "nonce": "mix"}
    body = _api_body(keys, levels, payload)
    token = _issue(server, body).json()["credential"]["token_id"]

    rd = httpx.post(server.base_url + "/api/execute",
                    json={k: body[k] for k in ("packet_text", "request_text")},
                    timeout=10).json()
    rc = _confirm(server, token, body).json()
    assert rc["accepted"] is True and rc["duplicate"] is True
    assert rc["receipt"] == rd["receipt"]
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    digest = rd["receipt"]["request_digest"]
    assert len([d for d in ledger
                if d["request_digest"] == digest and d["status"] == "EXECUTED"]) == 1


def test_api_token_confirm_replay_after_restart(server_factory, keys, levels):
    payload = {"device": "dev-a", "command": "reboot", "nonce": "restart"}
    body = _api_body(keys, levels, payload)
    srv1 = server_factory()
    token = _issue(srv1, body).json()["credential"]["token_id"]
    r1 = _confirm(srv1, token, body).json()
    assert r1["receipt"]["status"] == "EXECUTED"
    srv1.stop()

    srv2 = server_factory()
    # 凭据持久化：状态接口仍可查
    g = httpx.get(srv2.base_url + f"/api/credential/{token}", timeout=5)
    assert g.status_code == 200 and g.json()["credential"]["status"] == "USED"
    # 重启后相同确认复核原结果
    r2 = _confirm(srv2, token, body).json()
    assert r2["receipt"] == r1["receipt"] and r2["duplicate"] is True
    srv2.stop()
