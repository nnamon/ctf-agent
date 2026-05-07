"""Token / cost usage log — SQLite persistence for CostTracker output.

Sits alongside `attempt_log.py` but is not a Backend decorator: token
usage is a side concern, captured by `CostTracker` and flushed to disk
at end-of-run. The schema is shaped for ad-hoc reporting:

    CREATE TABLE usage (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id          TEXT NOT NULL,    -- backend.sandbox.RUN_ID
        session_name    TEXT NOT NULL,    -- which session this run belonged to
        agent_name      TEXT NOT NULL,    -- usually 'challenge/model'
        challenge_name  TEXT,             -- parsed/explicit, may be NULL
        model_name      TEXT NOT NULL,
        provider_spec   TEXT,
        input_tokens    INTEGER NOT NULL,
        output_tokens   INTEGER NOT NULL,
        cache_read_tokens INTEGER NOT NULL,
        cost_usd        REAL    NOT NULL,
        duration_seconds REAL   NOT NULL,
        ts              INTEGER NOT NULL  -- unix epoch
    );

One row per agent per run is the unit of insertion (low volume,
~10-50 rows per CTF). Per-step events are not persisted — they
remain in-memory in CostTracker for the live console output.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    session_name    TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    challenge_name  TEXT,
    model_name      TEXT NOT NULL,
    provider_spec   TEXT,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL    NOT NULL DEFAULT 0,
    duration_seconds REAL   NOT NULL DEFAULT 0,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_run     ON usage(run_id);
CREATE INDEX IF NOT EXISTS idx_usage_session ON usage(session_name, ts);
CREATE INDEX IF NOT EXISTS idx_usage_model   ON usage(model_name, ts);
CREATE INDEX IF NOT EXISTS idx_usage_chall   ON usage(challenge_name, ts);

-- One row per swarm completion (any outcome — solved, gave-up, killed,
-- error). Aggregates the per-agent rows in `usage` into a swarm-level
-- summary for post-competition review: time-to-solve, cost, winner,
-- token totals. Distinct from `usage` which is per-(agent, run) and
-- doesn't carry status/winner/duration cleanly.
CREATE TABLE IF NOT EXISTS challenge_solves (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL,
    session_name      TEXT NOT NULL,
    challenge_name    TEXT NOT NULL,
    category          TEXT,
    points            INTEGER,
    status            TEXT NOT NULL,           -- "flag_found" / "gave_up" / "error" / "cancelled"
    flag              TEXT,                    -- captured flag if solved, else NULL
    confirmed         INTEGER NOT NULL DEFAULT 0,  -- 0/1: did the backend accept?
    winner_spec       TEXT,                    -- model_spec of the winning solver
    winner_steps      INTEGER,                 -- steps the winner took
    duration_seconds  REAL    NOT NULL DEFAULT 0,
    cost_usd          REAL    NOT NULL DEFAULT 0,
    input_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens     INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    started_at        INTEGER NOT NULL,        -- unix epoch
    finished_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_solves_run     ON challenge_solves(run_id);
CREATE INDEX IF NOT EXISTS idx_solves_session ON challenge_solves(session_name, finished_at);
CREATE INDEX IF NOT EXISTS idx_solves_chall   ON challenge_solves(challenge_name, finished_at);

-- One row per (swarm completion, solver model). Normalised so it's
-- easy to slice cost / time-to-solve by model in SQL without parsing
-- JSON. The parent challenge_solves row keeps the swarm-level totals;
-- this child table breaks them down per-spec for "did mini outperform
-- 5.5 on Crypto?"-style questions.
CREATE TABLE IF NOT EXISTS challenge_solve_models (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_solve_id INTEGER NOT NULL,
    run_id            TEXT NOT NULL,
    session_name      TEXT NOT NULL,
    challenge_name    TEXT NOT NULL,
    model_spec        TEXT NOT NULL,
    steps             INTEGER NOT NULL DEFAULT 0,
    cost_usd          REAL    NOT NULL DEFAULT 0,
    input_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens     INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    won               INTEGER NOT NULL DEFAULT 0,  -- 0/1: did this model find the flag?
    UNIQUE(challenge_solve_id, model_spec)
);
CREATE INDEX IF NOT EXISTS idx_solve_models_chall ON challenge_solve_models(challenge_name, model_spec);
CREATE INDEX IF NOT EXISTS idx_solve_models_run   ON challenge_solve_models(run_id);
"""


@dataclass
class UsageRow:
    run_id: str
    session_name: str
    agent_name: str
    model_name: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cost_usd: float
    duration_seconds: float
    ts: int = 0
    challenge_name: str | None = None
    provider_spec: str | None = None


@dataclass
class ChallengeSolveModelRow:
    """Per-(swarm, solver-model) row. challenge_solve_id is filled in by
    insert_solve after the parent row is inserted."""
    run_id: str
    session_name: str
    challenge_name: str
    model_spec: str
    steps: int = 0
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    won: bool = False


@dataclass
class ChallengeSolveRow:
    run_id: str
    session_name: str
    challenge_name: str
    status: str                     # "flag_found" | "gave_up" | "error" | "cancelled"
    started_at: int
    finished_at: int
    duration_seconds: float
    cost_usd: float
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    flag: str | None = None
    confirmed: bool = False
    winner_spec: str | None = None
    winner_steps: int | None = None
    category: str | None = None
    points: int | None = None
    # Per-solver breakdown. Inserted into challenge_solve_models after
    # the parent row is committed. Empty list = no per-model data
    # available (e.g. swarm aborted before any solver started).
    per_model: list[ChallengeSolveModelRow] = field(default_factory=list)


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def insert_row(db_path: Path, row: UsageRow) -> None:
    """Insert one usage row. Failures are swallowed + logged — accounting
    must not break a successful solve."""
    try:
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO usage(run_id, session_name, agent_name, "
                " challenge_name, model_name, provider_spec, "
                " input_tokens, output_tokens, cache_read_tokens, "
                " cost_usd, duration_seconds, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row.run_id,
                    row.session_name,
                    row.agent_name,
                    row.challenge_name,
                    row.model_name,
                    row.provider_spec,
                    int(row.input_tokens),
                    int(row.output_tokens),
                    int(row.cache_read_tokens),
                    float(row.cost_usd),
                    float(row.duration_seconds),
                    int(row.ts) or int(time.time()),
                ),
            )
    except Exception as e:
        logger.warning("usage_log insert failed: %s", e)


def insert_solve(db_path: Path, row: ChallengeSolveRow) -> None:
    """Insert one swarm-completion summary into challenge_solves, plus
    a per-(model_spec) row into challenge_solve_models for each entry
    in row.per_model. Failures are swallowed + logged — accounting
    must not break a successful solve."""
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO challenge_solves("
                " run_id, session_name, challenge_name, category, points, "
                " status, flag, confirmed, winner_spec, winner_steps, "
                " duration_seconds, cost_usd, "
                " input_tokens, output_tokens, cache_read_tokens, "
                " started_at, finished_at) "
                "VALUES (?, ?, ?, ?, ?,  ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?,  ?, ?)",
                (
                    row.run_id,
                    row.session_name,
                    row.challenge_name,
                    row.category,
                    int(row.points) if row.points is not None else None,
                    row.status,
                    row.flag,
                    1 if row.confirmed else 0,
                    row.winner_spec,
                    int(row.winner_steps) if row.winner_steps is not None else None,
                    float(row.duration_seconds),
                    float(row.cost_usd),
                    int(row.input_tokens),
                    int(row.output_tokens),
                    int(row.cache_read_tokens),
                    int(row.started_at),
                    int(row.finished_at),
                ),
            )
            solve_id = cursor.lastrowid
            for m in row.per_model:
                try:
                    conn.execute(
                        "INSERT INTO challenge_solve_models("
                        " challenge_solve_id, run_id, session_name, "
                        " challenge_name, model_spec, steps, cost_usd, "
                        " input_tokens, output_tokens, cache_read_tokens, won) "
                        "VALUES (?, ?, ?,  ?, ?,  ?, ?,  ?, ?, ?,  ?)",
                        (
                            solve_id,
                            m.run_id,
                            m.session_name,
                            m.challenge_name,
                            m.model_spec,
                            int(m.steps),
                            float(m.cost_usd),
                            int(m.input_tokens),
                            int(m.output_tokens),
                            int(m.cache_read_tokens),
                            1 if m.won else 0,
                        ),
                    )
                except Exception as e:
                    logger.warning(
                        "challenge_solve_models insert (model=%s) failed: %s",
                        m.model_spec, e,
                    )
    except Exception as e:
        logger.warning("challenge_solves insert failed: %s", e)


def session_total_usd(db_path: Path, session_name: str) -> float:
    """Sum of cost_usd for all rows in a session (used for quota checks)."""
    try:
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM usage WHERE session_name = ?",
                (session_name,),
            ).fetchone()
            return float(row[0])
    except Exception as e:
        logger.warning("usage_log session_total_usd failed: %s", e)
        return 0.0


def session_summary(db_path: Path, session_name: str) -> dict:
    """Aggregate totals for one session — by model, by challenge, overall."""
    out: dict = {
        "session": session_name,
        "total_cost_usd": 0.0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_cache_read_tokens": 0,
        "by_model": [],
        "by_challenge": [],
        "by_run": [],
    }
    try:
        with _connect(db_path) as conn:
            tot = conn.execute(
                "SELECT COALESCE(SUM(cost_usd),0), "
                "       COALESCE(SUM(input_tokens),0), "
                "       COALESCE(SUM(output_tokens),0), "
                "       COALESCE(SUM(cache_read_tokens),0) "
                "FROM usage WHERE session_name = ?",
                (session_name,),
            ).fetchone()
            out["total_cost_usd"] = float(tot[0])
            out["total_input_tokens"] = int(tot[1])
            out["total_output_tokens"] = int(tot[2])
            out["total_cache_read_tokens"] = int(tot[3])

            for label, key in (("by_model", "model_name"),
                               ("by_challenge", "challenge_name"),
                               ("by_run", "run_id")):
                rows = conn.execute(
                    f"SELECT {key} AS k, "
                    f"  SUM(cost_usd) AS c, SUM(input_tokens) AS i, "
                    f"  SUM(output_tokens) AS o, SUM(cache_read_tokens) AS r "
                    f"FROM usage WHERE session_name = ? "
                    f"GROUP BY {key} ORDER BY c DESC",
                    (session_name,),
                ).fetchall()
                out[label] = [
                    {
                        "key": r["k"] or "(unknown)",
                        "cost_usd": float(r["c"] or 0),
                        "input_tokens": int(r["i"] or 0),
                        "output_tokens": int(r["o"] or 0),
                        "cache_read_tokens": int(r["r"] or 0),
                    }
                    for r in rows
                ]
    except Exception as e:
        logger.warning("usage_log session_summary failed: %s", e)
    return out
