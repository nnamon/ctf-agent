"""Post-mortem writeup generator.

After a swarm finishes (whether the flag was found or not), this module
takes the per-solver JSONL traces, the challenge metadata, and the winner
result, and asks an LLM to produce a writeup in the voice of an expert
CTF team. Markdown lands in writeups/<slug>-<ts>.md.

Uses ClaudeSDKClient so subscription auth keeps working with no API keys.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)

from backend.prompts import ChallengeMeta
from backend.solver_base import FLAG_FOUND, SolverResult

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an orchestrator compiling a Capture The Flag writeup
from multiple solvers' notes and traces. Voice: an elite CTF team's official
writeup. Audience: other security researchers who want to learn the technique.

Inputs you'll receive, in priority order:
1. **Solver notes** — first-person observations the solvers chose to record:
   vulnerabilities identified, working payloads, dead ends, techniques. These
   are the highest-signal source. Treat them as authoritative claims.
2. **Trace digests** — chronological tool calls and truncated results. Use
   these to (a) verify the notes, (b) extract concrete payloads, (c) fill in
   reasoning the notes glossed over.

Your job is to weave the notes and traces into a coherent technical narrative
that another researcher could read and reproduce, end-to-end.

Style:
- Confident, technical, terse. Assume a competent reader.
- Code-first: every claim is backed by a payload, request, or snippet pulled
  from the actual notes/traces. Quote real code, do not paraphrase.
- Use code fences. Prefer Python over shell when both work.
- No marketing language, no "we successfully ...", no closing summary, no emojis.

Structure:
1. Title line: `# <Challenge name> — <category>` and the final flag in a blockquote.
2. **TL;DR** — 3 to 5 bullets, the entire vulnerability chain in one breath.
3. **Recon** — what was observed first; the surface the player sees.
4. One numbered section per distinct vulnerability/bug. Name the vuln class
   explicitly (e.g. "Information disclosure via exposed `.git`"). Show the
   proof of the bug — the request/response or code that revealed it. Cite the
   step number when a specific moment of insight is worth pointing at.
5. **Exploit** — the final working end-to-end script, runnable as-is.
6. **Notes** — only if there is a non-obvious dead end, trade-off, or technique
   worth flagging. Skip if there's nothing to say. Do not include a redundant
   summary.

When notes from multiple solvers are provided, synthesize across them — the
winner had the path that worked, but siblings often noted something the winner
didn't see. Cite the source solver inline when relevant ("`gpt-5.4` noted
that...").

Do not invent payloads, requests, or vulnerabilities that don't appear in the
inputs. If a step seems important but the rationale isn't visible, say so.

Output only the markdown. Begin with the title.
"""


# Per-result truncation in the digest sent to the LLM
RESULT_CAP = 600
# Hard cap on total digest characters per trace (truncate from the middle)
TRACE_CAP = 60_000


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "challenge"


def _extract_notes(trace_path: Path) -> list[dict[str, Any]]:
    """Return all `type: note` events from a trace, ordered by step."""
    if not trace_path.exists():
        return []
    notes: list[dict[str, Any]] = []
    for raw in trace_path.read_text().splitlines():
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "note":
            notes.append(e)
    return notes


def _digest_trace(trace_path: Path, label: str, max_chars: int = TRACE_CAP) -> str:
    """Distill a JSONL trace to a chronological series of substantive lines."""
    if not trace_path.exists():
        return f"## {label}\n\n(no trace file at {trace_path})\n"

    lines: list[str] = [f"## {label}", ""]
    last_result: str | None = None
    repeat_count = 0
    events: list[dict[str, Any]] = []
    for raw in trace_path.read_text().splitlines():
        try:
            events.append(json.loads(raw))
        except json.JSONDecodeError:
            continue

    for e in events:
        t = e.get("type")
        step = e.get("step", "")
        if t == "tool_call":
            args = e.get("args", "")
            if isinstance(args, str):
                try:
                    a = json.loads(args)
                except (json.JSONDecodeError, ValueError):
                    a = {"_raw": args}
            else:
                a = args
            payload = a.get("command") or a.get("url") or json.dumps(a, ensure_ascii=False)
            payload = str(payload).strip()
            if len(payload) > 1500:
                payload = payload[:1500] + "  …[trimmed]"
            lines.append(f"### step {step} · {e.get('tool')}")
            lines.append("```")
            lines.append(payload)
            lines.append("```")
        elif t == "tool_result":
            r = str(e.get("result", "")).strip()
            if r == last_result:
                repeat_count += 1
                continue
            if repeat_count:
                lines.append(f"_({repeat_count} repeated identical result(s) elided)_")
                repeat_count = 0
            last_result = r
            if len(r) > RESULT_CAP:
                r = r[:RESULT_CAP] + "  …[trimmed]"
            lines.append("> " + r.replace("\n", "\n> "))
            lines.append("")
        elif t == "note":
            content = str(e.get("content", "")).strip()
            lines.append(f"**[note @ step {step}]** {content}")
            lines.append("")
        elif t in ("flag_confirmed", "bump", "loop_break", "error", "turn_failed"):
            payload = {k: v for k, v in e.items() if k not in ("ts", "type", "step")}
            lines.append(f"_event @ step {step}: **{t}** {json.dumps(payload, ensure_ascii=False)[:200]}_")
            lines.append("")
        elif t == "finish":
            lines.append(f"_finish: status={e.get('status')} flag={e.get('flag')} confirmed={e.get('confirmed')}_")

    digest = "\n".join(lines)
    if len(digest) > max_chars:
        # Keep head and tail; drop the middle. Most info lives at the ends
        # (early recon, late winning move).
        head = digest[: max_chars // 2]
        tail = digest[-max_chars // 2 :]
        digest = f"{head}\n\n…[middle of trace elided to fit context]…\n\n{tail}"
    return digest


def _build_user_prompt(
    meta: ChallengeMeta,
    winner_trace: Path,
    sibling_traces: list[tuple[str, Path]],
    winner_spec: str,
    flag: str | None,
    status: str,
    cost_usd: float,
    duration_s: float,
) -> str:
    parts: list[str] = []
    parts.append("# Challenge")
    parts.append("")
    parts.append(f"**Name:** {meta.name}")
    parts.append(f"**Category:** {meta.category or 'unknown'}")
    parts.append(f"**Points:** {meta.value or 'n/a'}")
    if meta.tags:
        parts.append(f"**Tags:** {', '.join(meta.tags)}")
    if meta.connection_info:
        parts.append(f"**Service:** `{meta.connection_info}`")
    parts.append("")
    parts.append("**Description (as shown to player):**")
    parts.append("")
    parts.append("> " + (meta.description or "(none)").replace("\n", "\n> "))
    parts.append("")

    parts.append("# Outcome")
    parts.append("")
    if status == FLAG_FOUND and flag:
        parts.append(f"Status: solved by `{winner_spec}` in {duration_s:.0f}s (cosmetic cost ${cost_usd:.2f})")
        parts.append(f"Flag: `{flag}`")
    else:
        parts.append(f"Status: **not solved** ({status}) after {duration_s:.0f}s (cost ${cost_usd:.2f})")
        parts.append("Treat this as a post-mortem of where the chain broke down.")
    parts.append("")

    # Notes section — first-person findings from each solver, the highest-signal
    # source. List even when empty so the writer knows it was checked.
    parts.append("# Solver notes (highest-signal source)")
    parts.append("")
    all_notes_count = 0
    winner_notes = _extract_notes(winner_trace)
    if winner_notes:
        parts.append(f"## `{winner_spec}` (winner) — {len(winner_notes)} notes")
        parts.append("")
        for n in winner_notes:
            parts.append(f"- step {n.get('step', '?')}: {str(n.get('content','')).strip()}")
        parts.append("")
        all_notes_count += len(winner_notes)
    for spec, path in sibling_traces:
        sib_notes = _extract_notes(path)
        if sib_notes:
            parts.append(f"## `{spec}` — {len(sib_notes)} notes")
            parts.append("")
            for n in sib_notes:
                parts.append(f"- step {n.get('step', '?')}: {str(n.get('content','')).strip()}")
            parts.append("")
            all_notes_count += len(sib_notes)
    if all_notes_count == 0:
        parts.append("_(no notes recorded by any solver — rely on traces below)_")
        parts.append("")

    parts.append("# Trace — winning solver")
    parts.append("")
    parts.append(_digest_trace(winner_trace, label=f"`{winner_spec}` (winner)"))
    parts.append("")

    if sibling_traces:
        parts.append("# Trace — sibling solvers (for comparison)")
        parts.append("")
        for spec, path in sibling_traces:
            parts.append(_digest_trace(path, label=f"`{spec}`", max_chars=15_000))
            parts.append("")

    parts.append("---")
    parts.append("")
    parts.append("Write the writeup now. Begin with the title.")
    return "\n".join(parts)


async def generate_writeup(
    meta: ChallengeMeta,
    winner_result: SolverResult,
    winner_spec: str,
    sibling_traces: list[tuple[str, Path]],
    cost_usd: float,
    duration_s: float,
    out_dir: Path = Path("writeups"),
    model: str = "claude-opus-4-6",
) -> Path | None:
    """Generate a markdown writeup. Returns the file path on success, None on failure.

    Designed to never raise — a writeup failure should not corrupt a successful
    solve. Errors get logged.
    """
    try:
        winner_trace = Path(winner_result.log_path) if winner_result.log_path else None
        if not winner_trace or not winner_trace.exists():
            logger.warning("Postmortem skipped: winner trace missing (%s)", winner_trace)
            return None

        # Filter siblings: only include ones that actually did something
        useful_siblings = [
            (spec, p) for spec, p in sibling_traces if p.exists() and p.stat().st_size > 1024
        ]

        user_prompt = _build_user_prompt(
            meta=meta,
            winner_trace=winner_trace,
            sibling_traces=useful_siblings,
            winner_spec=winner_spec,
            flag=winner_result.flag,
            status=winner_result.status,
            cost_usd=cost_usd,
            duration_s=duration_s,
        )

        options = ClaudeAgentOptions(
            model=model,
            system_prompt=SYSTEM_PROMPT,
            env={"CLAUDECODE": ""},
            permission_mode="bypassPermissions",
            allowed_tools=[],  # one-shot text generation, no tools
        )

        text_parts: list[str] = []
        async with ClaudeSDKClient(options=options) as client:
            await client.query(user_prompt)
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
                elif isinstance(message, ResultMessage):
                    pass  # cost/usage; not tracked separately for postmortem

        markdown = "\n".join(text_parts).strip()
        if not markdown:
            logger.warning("Postmortem returned empty body for %s", meta.name)
            return None

        out_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        path = out_dir / f"{_slugify(meta.name)}-{ts}.md"
        path.write_text(markdown)
        logger.info("Postmortem written: %s (%d chars)", path, len(markdown))
        return path

    except Exception as e:
        logger.warning("Postmortem generation failed for %s: %s", meta.name, e, exc_info=True)
        return None
