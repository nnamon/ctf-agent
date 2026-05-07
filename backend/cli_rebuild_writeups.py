"""Regenerate post-mortem writeups from existing trace JSONL files.

Why this exists: when the writeup prompt or template changes, all the
existing writeups in a session reflect the OLD prompt. Re-solving the
challenges to get fresh writeups is wasteful — the trace JSONLs from
the original solves already contain every tool call, result, and note
the writeup generator needs. This command walks the trace dir, picks
the winning trace per challenge, and re-runs `generate_writeup` with
the current prompt.

Usage:
    ctf-rebuild-writeups                       # current session, all challenges
    ctf-rebuild-writeups --challenge applestore   # one challenge
    ctf-rebuild-writeups --traces-dir logs --out sessions/pwnabletw/writeups
    ctf-rebuild-writeups --writeup-model claude-opus-4-7
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

import click

from backend.agents.postmortem import generate_writeup
from backend.config import Settings
from backend.prompts import ChallengeMeta
from backend.session import SessionContext
from backend.solver_base import FLAG_FOUND, SolverResult

logger = logging.getLogger(__name__)


# Trace filenames look like:
#   trace-<challenge_slug>-<model_id>-<YYYYMMDD>-<HHMMSS>.jsonl
# where model_id is the provider-stripped name (e.g. `gpt-5.5`,
# `gpt-5.4-mini`, `claude-opus-4-7`). The slug can contain hyphens,
# which makes naive `.+-.+-` patterns match wrong. Anchor on the
# trailing timestamp first, then split slug from model by recognising
# the known model-id prefixes.
_KNOWN_MODEL_PREFIXES = (
    "gpt-",                 # codex / azure / zen
    "claude-",              # claude-sdk
    "bedrock-",             # bedrock-prefixed model_ids (rare)
    "us.anthropic.claude-", # bedrock cross-region inference profile
    "gemini-",              # google
)
_TS_TAIL_RE = re.compile(r"^trace-(.+)-(\d{8}-\d{6})\.jsonl$")


def _parse_trace_filename(name: str) -> dict[str, str] | None:
    m = _TS_TAIL_RE.match(name)
    if not m:
        return None
    body, ts = m.group(1), m.group(2)
    # Walk the body left-to-right looking for `-<known model prefix>` —
    # the slug ends just before that boundary.
    for prefix in _KNOWN_MODEL_PREFIXES:
        sep = f"-{prefix}"
        idx = body.rfind(sep)
        if idx > 0:
            slug = body[:idx]
            model = body[idx + 1:]
            return {"slug": slug, "model": model, "ts": ts}
    return None


def _classify_traces(traces_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Group trace files by challenge slug.

    Returns: {slug -> [{path, model, ts, ...} sorted by ts desc]}
    """
    by_slug: dict[str, list[dict[str, Any]]] = {}
    for p in sorted(traces_dir.glob("trace-*.jsonl")):
        m = _parse_trace_filename(p.name)
        if not m:
            logger.debug("Skipping unrecognised trace name: %s", p.name)
            continue
        # Normalize slug: pwn.college uses `<dojo>/<module>/<slug>` which
        # gets flattened to `<dojo>_<module>_<slug>` in the filename, while
        # pwnable.tw uses bare slugs like `applestore`. The session's
        # writeup naming uses the same `_slugify` function as the trace
        # writer, so we can match by that flattened form.
        by_slug.setdefault(m["slug"], []).append({
            "path": p,
            "model": m["model"],
            "ts": m["ts"],
        })
    # Newest-first within each slug
    for arr in by_slug.values():
        arr.sort(key=lambda d: d["ts"], reverse=True)
    return by_slug


def _lookup_correct_attempt(sess: SessionContext, slug: str) -> dict[str, Any] | None:
    """Return the most-recent successful flag submission for `slug` from the
    session DB's `attempts` table, or None if no `correct` row exists.

    Why this matters: the swarm cancels every sibling solver the moment one
    finds the flag, and that cancellation can race the cancelled solver's
    final `finish` event — so the surviving trace may show
    `status: cancelled, flag: null` even though the *swarm* solved the
    challenge. Without this lookup, the rebuild flow infers "abandoned
    solve" from the trace and the writeup says the flag was never captured.
    AttemptLog is authoritative for outcome/flag; the trace is just one
    solver's narrative.
    """
    db = sess.attempt_log_path
    if not db.exists():
        return None
    try:
        import sqlite3
        with sqlite3.connect(str(db)) as conn:
            # First try the obvious case: status='correct'.
            row = conn.execute(
                "SELECT flag, message, ts, status FROM attempts "
                "WHERE challenge_name=? AND status='correct' "
                "ORDER BY ts DESC LIMIT 1",
                (slug,),
            ).fetchone()
            if row:
                return {"flag": row[0], "message": row[1], "ts": row[2]}
            # Fallback for the early htb-ctf-mcp submit_flag classification
            # bug (commit 3b561ca): some correct flags landed with
            # status='incorrect' but message='Correct flag!' — treat those
            # as wins too. Any case-insensitive 'correct' that is NOT
            # 'incorrect' counts.
            row = conn.execute(
                "SELECT flag, message, ts, status FROM attempts "
                "WHERE challenge_name=? "
                "AND lower(message) LIKE '%correct%' "
                "AND lower(message) NOT LIKE '%incorrect%' "
                "ORDER BY ts DESC LIMIT 1",
                (slug,),
            ).fetchone()
            if row:
                return {
                    "flag": row[0], "message": row[1], "ts": row[2],
                    "stored_status": row[3],  # for debugging logs
                }
    except Exception as e:
        logger.warning("attempts lookup failed for %s: %s", slug, e)
    return None


def _read_finish(trace_path: Path) -> dict[str, Any] | None:
    """Return the last `finish` event from a trace, or None.

    The finish event carries status, flag, confirmed — the same fields
    SolverResult needs for postmortem generation.
    """
    last_finish: dict[str, Any] | None = None
    for raw in trace_path.read_text(errors="replace").splitlines():
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "finish":
            last_finish = e
    return last_finish


def _read_step_count(trace_path: Path) -> int:
    """Best-effort solver step count from a trace's last `stop` event."""
    for raw in reversed(trace_path.read_text(errors="replace").splitlines()):
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "stop":
            return int(e.get("step_count", 0) or 0)
    return 0


def _pick_winner(group: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Pick the winning trace for one challenge.

    Strategy:
      1. Among all confirmed flag_found traces, pick the latest by ts.
      2. If none confirmed, pick the one with the highest step count
         (most analysis done) as the writeup target — but mark it as a
         post-mortem of an unsolved challenge.
      3. If the dir is empty, return None.
    """
    confirmed: list[dict[str, Any]] = []
    found: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    for entry in group:
        finish = _read_finish(entry["path"])
        entry["finish"] = finish
        entry["step_count"] = _read_step_count(entry["path"])
        if finish and finish.get("confirmed"):
            confirmed.append(entry)
        elif finish and finish.get("status") == "flag_found":
            found.append(entry)
        else:
            others.append(entry)

    if confirmed:
        # Newest confirmed solver = winner (already sorted desc).
        winner = confirmed[0]
    elif found:
        winner = found[0]
    elif others:
        winner = max(others, key=lambda e: e["step_count"])
    else:
        return None

    siblings = [e for e in group if e is not winner]
    return winner, siblings


def _challenge_meta_for(slug: str, sess: SessionContext) -> ChallengeMeta:
    """Try to load metadata.yml from the session's challenges dir.

    Falls back to a minimal stub when the challenge wasn't pulled (e.g.
    pwn.college doesn't write distfiles) or the slug got flattened from
    a path-shaped name like `linux-luminarium_hello_hello`.
    """
    candidates: list[Path] = []
    chal_root = sess.challenges_dir
    if chal_root.exists():
        candidates.append(chal_root / slug / "metadata.yml")
        # Also try the un-flattened pwn.college shape: foo_bar_baz → foo-bar-baz
        candidates.append(chal_root / slug.replace("_", "-") / "metadata.yml")
    for p in candidates:
        if p.exists():
            try:
                return ChallengeMeta.from_yaml(p)
            except Exception as e:
                logger.warning("Could not parse %s: %s", p, e)
    return ChallengeMeta(name=slug, category="unknown")


async def _rebuild_one(
    slug: str,
    group: list[dict[str, Any]],
    *,
    sess: SessionContext,
    settings: Settings,
    out_dir: Path,
    model: str,
    dry_run: bool,
) -> None:
    pick = _pick_winner(group)
    if pick is None:
        click.echo(f"  {slug}: no usable traces — skipped", err=True)
        return
    winner, siblings = pick
    finish = winner.get("finish") or {}
    flag = finish.get("flag")
    confirmed = bool(finish.get("confirmed"))
    status = FLAG_FOUND if confirmed else "gave_up"
    step_count = winner.get("step_count", 0)

    # Override from authoritative AttemptLog when a `correct` submission
    # exists. The trace's `finish` event can lie because the swarm kills
    # losing siblings the instant one wins, and that cancellation often
    # lands before the cancelled solver writes its final finish event.
    flag_source = "trace"
    db_attempt = _lookup_correct_attempt(sess, slug)
    if db_attempt and db_attempt.get("flag"):
        flag = db_attempt["flag"]
        confirmed = True
        status = FLAG_FOUND
        flag_source = "attempts"

    meta = _challenge_meta_for(slug, sess)
    if meta.name == slug and meta.category == "unknown":
        # Best-effort: if the slug looks like pwn.college (`<dojo>_<mod>_<slug>`),
        # synthesize a name with slashes for the writeup heading.
        if "_" in slug:
            meta.name = slug.replace("_", "/")

    winner_result = SolverResult(
        flag=flag,
        status=status,
        findings_summary="",
        step_count=step_count,
        cost_usd=0.0,
        log_path=str(winner["path"]),
    )

    sibling_traces = [(s["model"], s["path"]) for s in siblings]

    # When the flag came from the attempts table (not the trace), the
    # available trace likely belongs to a sibling that was cancelled
    # the moment the actual winner submitted — so it ends
    # mid-investigation. Tell the writeup model up front, otherwise it
    # concludes "abandoned solve" and produces a dispiriting "flag not
    # captured" post-mortem.
    caveat = None
    if flag_source == "attempts":
        trace_finish_status = (winner.get("finish") or {}).get("status") or "unknown"
        caveat = (
            "The flag listed in `# Outcome` is sourced from the session's "
            "AttemptLog (the `attempts` table), which is authoritative for "
            "outcome. "
            f"The trace below shows `status={trace_finish_status}` and lacks "
            "a `submit_flag` event because this trace belongs to a solver "
            "that was cancelled the instant a sibling solver in the same "
            "swarm submitted the correct flag — the winning solver's own "
            "trace was not preserved.\n\n"
            "Write the writeup with the flag treated as captured. Use the "
            "trace to narrate the analytical path that led toward the "
            "solution; if the trace ends before the final exfiltration "
            "step, briefly note that the deciding move happened off-trace "
            "and reconstruct the most plausible final step from the "
            "available evidence. Do NOT frame this as an abandoned attempt."
        )

    label = f"  {slug:35} winner={winner['model']:20} flag={'YES' if flag else '—'} src={flag_source:11} siblings={len(siblings)}"
    if dry_run:
        click.echo(label + "  (dry-run, not regenerating)")
        return
    click.echo(label)
    out = await generate_writeup(
        meta=meta,
        winner_result=winner_result,
        winner_spec=winner["model"],
        sibling_traces=sibling_traces,
        cost_usd=0.0,
        duration_s=0.0,
        out_dir=out_dir,
        model=model,
        settings=settings,
        caveat=caveat,
    )
    if out:
        click.echo(f"      -> {out}")
    else:
        click.echo(f"      -> (writeup generation failed; see logs)", err=True)


@click.command("ctf-rebuild-writeups")
@click.option("--session", "session_name", default=None,
              help="Session name (default: resolved from CTF_SESSION / .ctf-session)")
@click.option("--traces-dir", default="logs",
              help="Directory holding trace-*.jsonl files (default: logs/)")
@click.option("--out", "out_dir_arg", default=None,
              help="Output dir for writeups (default: sessions/<session>/writeups)")
@click.option("--writeup-model", default="claude-opus-4-7",
              help="Model spec for the writeup generator. Routes through "
                   "backend.text_completion (claude/codex/bedrock/azure/...)")
@click.option("--challenge", "only_challenge", default=None,
              help="Regenerate only this slug (matches the trace filename slug).")
@click.option("--all-traces", is_flag=True,
              help="By default we only rebuild writeups for slugs that ALREADY "
                   "have a writeup in --out (so historical traces from other "
                   "sessions / runs aren't matched). Pass --all-traces to "
                   "regenerate one writeup per trace-slug found.")
@click.option("--purge", is_flag=True,
              help="Delete all existing writeups in --out before regenerating.")
@click.option("--dry-run", is_flag=True,
              help="List what would be rebuilt; do not call the writeup model.")
@click.option("-v", "--verbose", is_flag=True)
def main(session_name, traces_dir, out_dir_arg, writeup_model,
         only_challenge, all_traces, purge, dry_run, verbose):
    """Regenerate writeups from existing JSONL traces."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    sess = SessionContext.resolve(explicit=session_name)
    settings = Settings(_env_file=sess.env_files_chain())

    traces_path = Path(traces_dir)
    if not traces_path.is_dir():
        click.echo(f"Trace dir not found: {traces_path}", err=True)
        sys.exit(1)

    out_dir = Path(out_dir_arg) if out_dir_arg else sess.writeups_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    by_slug = _classify_traces(traces_path)

    # Snapshot existing writeup slugs BEFORE the optional --purge below
    # — purge would otherwise wipe the scoping signal we need.
    existing_writeup_files = sorted(out_dir.glob("*.md"))
    existing_slugs = {
        re.sub(r"-\d{8}-\d{6}\.md$", "", p.name)
        for p in existing_writeup_files
    }

    if only_challenge:
        if only_challenge not in by_slug:
            click.echo(f"No traces for challenge slug: {only_challenge!r}", err=True)
            click.echo(f"Available: {sorted(by_slug.keys())[:20]}{'…' if len(by_slug) > 20 else ''}", err=True)
            sys.exit(1)
        by_slug = {only_challenge: by_slug[only_challenge]}
    elif not all_traces:
        # Default: only consider slugs that already have a writeup in
        # --out. Avoids accidentally walking historical traces from
        # unrelated sessions when the trace dir is the shared top-level
        # logs/ tree.
        if not existing_slugs:
            click.echo(
                f"No writeups in {out_dir} to scope against. Pass "
                "--all-traces to regenerate from every trace-slug, or "
                "use --challenge SLUG.",
                err=True,
            )
            sys.exit(1)
        by_slug = {s: traces for s, traces in by_slug.items() if s in existing_slugs}
        missing = sorted(existing_slugs - set(by_slug))
        if missing:
            click.echo(
                f"Note: {len(missing)} writeup(s) had no matching trace and "
                f"will be skipped: {', '.join(missing[:5])}"
                + (f" (+{len(missing)-5} more)" if len(missing) > 5 else ""),
                err=True,
            )

    click.echo(f"session: {sess.name}")
    click.echo(f"traces:  {traces_path}  ({sum(len(v) for v in by_slug.values())} files / {len(by_slug)} challenges)")
    click.echo(f"out:     {out_dir}")
    click.echo(f"model:   {writeup_model}")
    if dry_run:
        click.echo("(dry-run)")
    click.echo()

    if purge and not dry_run:
        if existing_writeup_files:
            click.echo(f"Purging {len(existing_writeup_files)} existing writeup file(s) under {out_dir}")
            for p in existing_writeup_files:
                p.unlink()
            click.echo()

    async def _run():
        for slug in sorted(by_slug):
            await _rebuild_one(
                slug, by_slug[slug],
                sess=sess, settings=settings, out_dir=out_dir,
                model=writeup_model, dry_run=dry_run,
            )

    asyncio.run(_run())


if __name__ == "__main__":
    main()
