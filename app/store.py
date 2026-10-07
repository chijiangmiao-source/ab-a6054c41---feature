"""持久化裁决层。

三张表（SQLite，落盘到可挂载卷）：
- decisions       ：每个 request_digest 恰好一行的裁决（EXECUTED / REJECTED）；
- consumed_leaves ：已驱动过设备的末级凭据（leaf_id），用于"一次性凭据"；
- confirm_tokens  ：核验通过后签发的**执行凭据**，与规范化裁决身份四要素
  （root_pubkey / chain_digest / leaf_id / 规范载荷 → request_digest）持久绑定，
  确认执行时必须逐项复核；ISSUED → USED，USED 凭据的并发/重启重放仍收敛到
  既有的同一条裁决回执。

并发提交 / 响应丢失重传的收敛由单写事务保证：
``BEGIN IMMEDIATE`` 立即取 RESERVED 写锁，后到者在锁上等待后必能读到
已提交裁决，于是同 request_digest 永远返回同一回执；
同 leaf_id 的不同请求只可能有一个进入执行，其余得到 LEAF_CONSUMED。
数据库文件持久化挂载，重启后可逐字复核。
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

from . import chain as chain_mod
from .canonical import canonical_bytes
from .device import ExecutionResult, execute

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    request_digest TEXT PRIMARY KEY,
    status         TEXT NOT NULL,
    reason         TEXT,
    command_id     TEXT,
    output         TEXT,
    root_pubkey    TEXT NOT NULL,
    chain_digest   TEXT NOT NULL,
    leaf_id        TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    executed_at    INTEGER
);
CREATE TABLE IF NOT EXISTS consumed_leaves (
    leaf_id        TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    consumed_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_leaves (
    leaf_id     TEXT PRIMARY KEY,
    revoked_at  INTEGER NOT NULL,
    source      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS confirm_tokens (
    token_id       TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    root_pubkey    TEXT NOT NULL,
    chain_digest   TEXT NOT NULL,
    leaf_id        TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    used_at        INTEGER
);
"""

TOKEN_STATUS_ISSUED = "ISSUED"
TOKEN_STATUS_USED = "USED"


class CredentialBindingError(Exception):
    """确认输入无法通过凭据绑定复核（凭据不存在或身份要素不一致）。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Decision:
    request_digest: str
    status: str                 # EXECUTED | REJECTED
    reason: str | None
    command_id: str | None
    output: str | None
    root_pubkey: str
    chain_digest: str
    leaf_id: str
    payload: dict[str, Any]
    created_at: int
    executed_at: int | None
    duplicate: bool = False    # 本次调用是否命中既有裁决（重传/并发）；不进入回执

    def receipt(self) -> dict[str, Any]:
        """稳定回执：字段固定、可重复生成、重启后逐字一致。

        重传/并发命中既有裁决时回执内容不变；"是否重复提交"由响应信封
        另行携带，不污染裁决回执本身。
        """
        return {
            "request_digest": self.request_digest,
            "status": self.status,
            "reason": self.reason,
            "reason_text": chain_mod.REASON_TEXT.get(self.reason) if self.reason else None,
            "command_id": self.command_id,
            "output": self.output,
            "root_pubkey": self.root_pubkey,
            "chain_digest": self.chain_digest,
            "leaf_id": self.leaf_id,
            "payload": self.payload,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
        }


class DecisionStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._tls = threading.local()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, timeout=30, isolation_level=None, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = self._connect()
            self._tls.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in (s.strip() for s in SCHEMA.split(";") if s.strip()):
                conn.execute(stmt)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    def revoked_set(self) -> set[str]:
        rows = self._conn().execute("SELECT leaf_id FROM revoked_leaves").fetchall()
        return {r["leaf_id"] for r in rows}

    def decide_execution(
        self,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload: dict[str, Any],
        new_revoked_targets: set[str] | None = None,
    ) -> Decision:
        """进入临界区完成"查裁决 → 并入册撤销 → 撤销/一次性校验 → 执行 → 落盘"。

        撤销并入册与裁决写在同一写事务里，杜绝"先执行后入册"的竞态。
        """
        new_revoked_targets = new_revoked_targets or set()
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        payload_json = canonical_bytes(payload).decode("utf-8")
        now = int(time.time())
        conn = self._conn()

        conn.execute("BEGIN IMMEDIATE")
        try:
            decision = self._execution_critical_section(
                conn, digest, root_pubkey, chain_digest, leaf_id,
                payload_json, now, new_revoked_targets,
            )
            conn.execute("COMMIT")
            return decision
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _execution_critical_section(
        self,
        conn: sqlite3.Connection,
        digest: str,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload_json: str,
        now: int,
        new_revoked_targets: set[str],
    ) -> Decision:
        """写事务内的执行临界区（调用方负责 BEGIN/COMMIT）。

        直接执行接口与凭据确认接口共用完全相同的临界区代码，因此凭据确认
        不会绕过任何既有安全检查，且两种入口对同一 request_digest 收敛到
        同一条裁决。
        """
        # 本包携带的新撤销目标先原子入册（全局生效）；即使本 request_digest
        # 已有裁决（例如撤销声明重传到达），名册也必须补齐，杜绝绕过。
        if new_revoked_targets:
            conn.executemany(
                "INSERT OR IGNORE INTO revoked_leaves (leaf_id, revoked_at, source) "
                "VALUES (?,?,?)",
                [(t, now, "packet") for t in sorted(new_revoked_targets)],
            )

        row = conn.execute(
            "SELECT * FROM decisions WHERE request_digest = ?", (digest,)
        ).fetchone()
        if row is not None:
            return self._row_to_decision(row, duplicate=True)

        revoked_row = conn.execute(
            "SELECT 1 FROM revoked_leaves WHERE leaf_id = ?", (leaf_id,)
        ).fetchone()
        if revoked_row is not None:
            return self._insert_rejected(
                conn, digest, chain_mod.REASON_REVOKED,
                root_pubkey, chain_digest, leaf_id, payload_json, now,
            )

        consumed = conn.execute(
            "SELECT request_digest FROM consumed_leaves WHERE leaf_id = ?", (leaf_id,)
        ).fetchone()
        if consumed is not None and consumed["request_digest"] != digest:
            return self._insert_rejected(
                conn, digest, chain_mod.REASON_LEAF_CONSUMED,
                root_pubkey, chain_digest, leaf_id, payload_json, now,
            )

        parsed_payload = chain_mod.parse_strict_json(payload_json)
        result: ExecutionResult = execute(
            digest, parsed_payload["device"], parsed_payload["command"]
        )
        conn.execute(
            "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                digest, "EXECUTED", None, result.command_id, result.output,
                root_pubkey, chain_digest, leaf_id, payload_json, now, now,
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO consumed_leaves VALUES (?,?,?)",
            (leaf_id, digest, now),
        )
        return Decision(
            request_digest=digest,
            status="EXECUTED",
            reason=None,
            command_id=result.command_id,
            output=result.output,
            root_pubkey=root_pubkey,
            chain_digest=chain_digest,
            leaf_id=leaf_id,
            payload=parsed_payload,
            created_at=now,
            executed_at=now,
        )

    @staticmethod
    def _insert_rejected(
        conn: sqlite3.Connection,
        digest: str,
        reason: str,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload_json: str,
        now: int,
    ) -> Decision:
        conn.execute(
            "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (digest, "REJECTED", reason, None, None,
             root_pubkey, chain_digest, leaf_id, payload_json, now, None),
        )
        return Decision(
            request_digest=digest,
            status="REJECTED",
            reason=reason,
            command_id=None,
            output=None,
            root_pubkey=root_pubkey,
            chain_digest=chain_digest,
            leaf_id=leaf_id,
            payload=chain_mod.parse_strict_json(payload_json),
            created_at=now,
            executed_at=None,
        )

    def record_decision(
        self,
        root_pubkey: str | None,
        chain_digest: str | None,
        leaf_id: str | None,
        payload: dict[str, Any] | None,
        execute: bool,
        reason: str | None = None,
        new_revoked_targets: set[str] | None = None,
    ) -> Decision | None:
        """裁决持久化唯一入口。

        - execute=True ：进入执行临界区（查裁决 → 入册撤销 → 撤销/一次性校验
          → 驱动设备 → EXECUTED 落盘）；
        - execute=False：写入 REJECTED 记录（绝不驱动设备）；本包携带的有效
          撤销目标同样在同一写事务内入册，保证"撤销拒绝"也无法被剥离重放绕过。
        畸形 JSON 等身份要素不全时返回 None，不落任何记录。
        同一 request_digest 永远返回同一历史裁决与同一回执。
        """
        if not (root_pubkey and chain_digest and leaf_id and payload is not None):
            return None
        if execute:
            return self.decide_execution(
                root_pubkey, chain_digest, leaf_id, payload,
                new_revoked_targets=new_revoked_targets,
            )

        new_revoked_targets = new_revoked_targets or set()
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        payload_json = canonical_bytes(payload).decode("utf-8")
        now = int(time.time())
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if new_revoked_targets:
                conn.executemany(
                    "INSERT OR IGNORE INTO revoked_leaves (leaf_id, revoked_at, source) "
                    "VALUES (?,?,?)",
                    [(t, now, "packet") for t in sorted(new_revoked_targets)],
                )
            row = conn.execute(
                "SELECT * FROM decisions WHERE request_digest = ?", (digest,)
            ).fetchone()
            if row is not None:
                conn.execute("COMMIT")
                return self._row_to_decision(row, duplicate=True)
            decision = self._insert_rejected(
                conn, digest, reason or chain_mod.REASON_PACKET_STRUCTURE,
                root_pubkey, chain_digest, leaf_id, payload_json, now,
            )
            conn.execute("COMMIT")
            return decision
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    # 执行凭据（核验通过 → 凭据 → 确认执行）
    # ------------------------------------------------------------------ #
    def register_revocations(self, targets: set[str]) -> None:
        """将经根公钥验签通过的撤销目标写入全局持久名册。

        签发凭据本身不落裁决记录，但有效的包级撤销一旦在凭据流程中出现即
        入册，与执行路径的入册语义保持一致：之后即使提交方剥离撤销声明或
        改用此前签发的旧凭据重放，命中名册的叶项仍被拒绝，无法借旧凭据
        绕过现有安全检查。
        """
        if not targets:
            return
        now = int(time.time())
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "INSERT OR IGNORE INTO revoked_leaves (leaf_id, revoked_at, source) "
                "VALUES (?,?,?)",
                [(t, now, "packet") for t in sorted(targets)],
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def issue_confirm_token(
        self,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload: dict[str, Any],
    ) -> sqlite3.Row:
        """为一次**已核验通过**的裁决身份签发执行凭据并持久化绑定。

        只允许在纯裁决通过后调用；本方法不做任何链/签名判断，也绝不驱动设备。
        同一 request_digest 已存在未使用凭据时幂等返回原凭据（重复核验/刷新
        页面不会产生多个凭据标识）；USED 凭据保留可复核，再次核验签发新凭据，
        但确认时仍由裁决临界区收敛，不可能二次驱动设备。
        """
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        payload_json = canonical_bytes(payload).decode("utf-8")
        now = int(time.time())
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM confirm_tokens "
                "WHERE request_digest = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (digest, TOKEN_STATUS_ISSUED),
            ).fetchone()
            if row is None:
                token_id = secrets.token_hex(16)
                conn.execute(
                    "INSERT INTO confirm_tokens "
                    "(token_id, request_digest, root_pubkey, chain_digest, leaf_id, "
                    "payload_json, status, created_at, used_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (token_id, digest, root_pubkey, chain_digest, leaf_id,
                     payload_json, TOKEN_STATUS_ISSUED, now, None),
                )
                row = conn.execute(
                    "SELECT * FROM confirm_tokens WHERE token_id = ?", (token_id,)
                ).fetchone()
            conn.execute("COMMIT")
            return row
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def get_confirm_token(self, token_id: str) -> sqlite3.Row | None:
        return self._conn().execute(
            "SELECT * FROM confirm_tokens WHERE token_id = ?", (token_id,)
        ).fetchone()

    def confirm_with_token(
        self,
        token_id: str,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload: dict[str, Any],
        new_revoked_targets: set[str] | None = None,
    ) -> tuple[Decision, bool]:
        """凭执行凭据确认执行。

        调用方必须已对**本次请求的输入**重新完成完整纯裁决并通过；本方法在
        同一个写事务内：
        1. 载入持久化凭据，不存在 → CONFIRM_TOKEN_NOT_FOUND；
        2. 将本次输入的规范化裁决身份与凭据绑定量逐项比对——root_pubkey、
           chain_digest、leaf_id、规范载荷字节（等价于 request_digest）任一
           不一致 → CONFIRM_TOKEN_MISMATCH，**不写裁决、不并入册撤销、不驱动**；
        3. 绑定一致后走与直接执行接口完全相同的裁决临界区（过期/撤销/一次性
           等现有安全检查在此重新生效），随后将凭据标记 USED。

        返回 (裁决, 凭据本次调用前是否已 USED)。两个页面并发使用同一凭据时，
        临界区保证只有一次执行，后到者拿到同一回执；重启后重放亦然。
        """
        new_revoked_targets = new_revoked_targets or set()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            trow = conn.execute(
                "SELECT * FROM confirm_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if trow is None:
                conn.execute("ROLLBACK")
                raise CredentialBindingError(chain_mod.REASON_CONFIRM_TOKEN_NOT_FOUND)

            digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
            payload_json = canonical_bytes(payload).decode("utf-8")
            if (
                trow["request_digest"] != digest
                or trow["root_pubkey"] != root_pubkey
                or trow["chain_digest"] != chain_digest
                or trow["leaf_id"] != leaf_id
                or trow["payload_json"] != payload_json
            ):
                conn.execute("ROLLBACK")
                raise CredentialBindingError(chain_mod.REASON_CONFIRM_TOKEN_MISMATCH)

            already_used = trow["status"] == TOKEN_STATUS_USED
            now = int(time.time())
            decision = self._execution_critical_section(
                conn, digest, root_pubkey, chain_digest, leaf_id,
                payload_json, now, new_revoked_targets,
            )
            # 终态（执行成功或当时被撤销/一次性等规则拒绝）后凭据即消耗，
            # 任何重放都只能复核同一裁决回执。
            conn.execute(
                "UPDATE confirm_tokens SET status = ?, used_at = COALESCE(used_at, ?) "
                "WHERE token_id = ?",
                (TOKEN_STATUS_USED, now, token_id),
            )
            conn.execute("COMMIT")
            return decision, already_used
        except CredentialBindingError:
            raise
        except Exception:
            conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _row_to_decision(row: sqlite3.Row, duplicate: bool = False) -> Decision:
        payload = chain_mod.parse_strict_json(row["payload_json"])
        return Decision(
            request_digest=row["request_digest"],
            status=row["status"],
            reason=row["reason"],
            command_id=row["command_id"],
            output=row["output"],
            root_pubkey=row["root_pubkey"],
            chain_digest=row["chain_digest"],
            leaf_id=row["leaf_id"],
            payload=payload,
            created_at=row["created_at"],
            executed_at=row["executed_at"],
            duplicate=duplicate,
        )

    def get(self, request_digest: str) -> Decision | None:
        row = self._conn().execute(
            "SELECT * FROM decisions WHERE request_digest = ?", (request_digest,)
        ).fetchone()
        return self._row_to_decision(row, duplicate=False) if row else None

    def execution_count(self, leaf_id: str | None = None) -> int:
        conn = self._conn()
        if leaf_id is None:
            return conn.execute(
                "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED'"
            ).fetchone()["c"]
        return conn.execute(
            "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED' AND leaf_id=?",
            (leaf_id,),
        ).fetchone()["c"]

    def list_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM decisions ORDER BY created_at DESC, request_digest LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_decision(r, duplicate=False).receipt() for r in rows]

    def close(self) -> None:
        conn = getattr(self._tls, "conn", None)
        if conn is not None:
            conn.close()
            self._tls.conn = None
