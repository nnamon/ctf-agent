"""Post-mortem writeup generator.

After a swarm finishes (whether the flag was found or not), this module
takes the per-solver JSONL traces, the challenge metadata, and the winner
result, and asks an LLM to produce a writeup in the voice of an expert
CTF team. Markdown lands in writeups/<slug>-<ts>.md.

Provider-agnostic: routes through `backend.text_completion`, which
dispatches `claude-*` to the Claude Agent SDK (subscription auth),
`codex/*` to the codex app-server (subscription auth), and the
Pydantic-AI providers (bedrock/azure/zen/google) through their API
clients. No more "writeup model has to be Claude" lock-in.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from backend.prompts import ChallengeMeta
from backend.solver_base import FLAG_FOUND, SolverResult
from backend.text_completion import text_completion

logger = logging.getLogger(__name__)


def _classify_failure(err: str) -> str:
    """Bucket a postmortem failure into a stable label for logs/events.

    The classification drives operator visibility, not auto-cascade
    decisions (per ops policy, only opus → codex/gpt-5.5 is automatic).
    """
    if "TimeoutError" in err or "wait_for" in err or "asyncio.exceptions.TimeoutError" in err:
        return "TIMEOUT"
    if "violate our Usage Policy" in err or "Claude Code is unable to respond" in err:
        return "REFUSAL"
    if "exit code: -11" in err or "Cannot write to terminated process" in err:
        return "SIGSEGV"
    if "exit code: -6" in err:
        return "SIGABRT"
    return "OTHER"


def _looks_like_aup_refusal(body: str) -> bool:
    """Detect AUP refusal anywhere in `body`, not just the prefix.

    Opus has been observed to write a substantive partial writeup and
    then append the refusal text at the very end, leaving the prefix
    looking fine. Scan the whole body.
    """
    return (
        "violate our Usage Policy" in body
        or "API Error: Claude Code is unable to respond" in body
    )


SYSTEM_PROMPT = """You are compiling a rigorous, academic-quality CTF writeup
from solver notes and execution traces. Voice: a seasoned security
researcher writing for a journal-style technical audience. Audience: other
researchers who want to learn the methodology AND reproduce the result.

Your single most important duty: every non-trivial claim must be backed
by **evidence pulled directly from the trace**. If you write "the binary
checks total == 7174", you must include the disassembly or decompiled C
that shows the comparison. If you write "the cart node lives on the
checkout stack frame", you must include the function prologue and offset
arithmetic that proves it. Assertions without trace-grounded evidence
are the failure mode this prompt exists to prevent — do not ship them.

# Inputs

1. **Solver notes** — first-person observations the solvers recorded.
   Authoritative claims; mine them for what to investigate.
2. **Trace digests** — chronological tool calls and their full results.
   Treat the trace as your primary evidence source; quote it liberally.

# Required structure

Use this section layout. Skip sections only when nothing meaningful
applies (e.g. no second vulnerability). Don't compress for terseness —
better an honest 4-page writeup than a 1-page checklist.

1. **Title** — `# <name> — <category>` and the captured flag in a
   blockquote on the next line.
2. **TL;DR** — 3–5 bullets summarising the chain end-to-end. Each bullet
   should reference a section number where the claim is proven.
3. **Recon** — the binary's mitigations, architecture, key symbols.
   Include the actual `checksec` / `file` / `readelf` / `nm` output, not
   a paraphrase. Identify the attack surface (menu options, network
   protocol, file format).
4. **Static analysis** — walk through the relevant disassembly and/or
   decompilation. Quote the **actual r2 / objdump / Ghidra output** from
   the trace. Annotate inline with prose explaining what each block does
   (`; sets up canary`, `; bounds check missing — see §N`). Derive
   struct layouts from observed offsets (`[ebp-0x24]`, `mov [eax+4]`,
   etc.) and present the inferred struct as commented C.
5. **Dynamic analysis** *(if used)* — gdb / pwntools-debug evidence:
   register state, stack diagrams, heap layout. Cite the exact gdb
   commands the solver ran and the output.
6. **Vulnerability identification** — name the bug class precisely
   (e.g. "Use-after-return: stack-allocated cart node leaked into a
   global linked list"). Cite the line of disassembly or decompiled C
   that shows the missing safety. Reference any CWE / classic bug name
   if applicable. Explain WHY the mitigations in place don't stop it.
7. **Primitive construction** — for each primitive (read, write, EIP
   control, leak), show:
   - the exact payload format with field-by-field annotation,
   - a stack/heap **diagram** (ASCII art is fine) showing how the
     payload lands in memory and what it overlaps,
   - the trace excerpt confirming the primitive worked (the bytes that
     came back, the address that got written, etc.),
   - any failed first attempts and why they failed (this is teaching,
     not just bookkeeping).
8. **Exploitation chain** — sequence the primitives into the final
   exploit. For each step, state the goal, the payload, the resulting
   state, and how it sets up the next step.
9. **Final exploit** — a single runnable Python (or appropriate
   language) script. **Heavy comments** — every magic constant cites
   where it came from; every send/recv explains what it expects.
10. **Methodology / lessons** — the analytical path that found the bug:
    "Looked at all functions taking user input → noticed `cart()` reads
    after a function-local pointer is exposed → traced the pointer's
    origin to `checkout()`'s stack frame". This is the teaching part.
    Generalise: what pattern should a reader look for next time?
11. **Notes** — failed paths worth recording, alternative exploit
    routes, mitigation suggestions. Skip if nothing meaningful.
12. **Appendix: solve metadata** *(optional, ≤6 lines)* — model that
    found the flag, step count, total cost, sibling models attempted.
    Only include if the operator asked; default is no appendix.

# Voice and audience

The writeup is for a **learner studying the challenge** — not a log of
how the agent worked. Write as if a researcher sat down with the
binary and walked through it. Concretely:

- **Third-person, technique-first.** Replace "the solver discovered at
  step 25 that ..." with "Disassembly of `checkout()` shows ...".
- **Do NOT reference solver model names** (`gpt-5.5`, `gpt-5.4-mini`,
  `codex`, `claude-opus-4-7`, etc.) anywhere in the body of the
  writeup. The trace events and notes are evidence — quote what they
  contain, not who recorded them.
- **Do NOT cite step numbers** in the prose ("step 25's r2 dump…").
  Quote the actual r2 output instead and let it speak. Step numbers
  are an internal implementation detail of the agent and confuse the
  external reader.
- **No mention of "agent" / "swarm" / "tool call".** The reader is
  studying the challenge, not the harness. They expect: "running r2
  with `aaa; pdf @ main` produces:" — not "the agent ran r2 …".

# Style

- **Show, don't tell.** Replace "checkout has a magic-number bug" with
  the actual decompiled snippet of `checkout()` and a one-line gloss
  pointing at the comparison.
- **Prefer real artefacts over summaries.** Embed real disassembly,
  real packet captures, real hexdumps. Truncate aesthetically (e.g.
  show the relevant 20 instructions, not 200) — but truncate in code
  fences so the reader sees you trimmed.
- **Diagrams when memory layout matters.** A simple ASCII box per
  4-byte field beats a paragraph of prose every time.
- **Annotate inline.** Use `;` or `#` comments inside code fences to
  make the trace excerpts self-explaining.
- Confident, technical voice. No marketing ("we successfully ..."), no
  emojis, no closing summary that repeats TL;DR.
- **No implication arrows.** Do not use `⇒` or `=>` to mean
  "therefore" / "implies" — write the implication out in prose
  ("NX is disabled, so the stack is executable"), or use a colon, or
  break it into two sentences. Single-direction arrows (`→`, `->`)
  are still fine for *control flow* and *chain* notation
  (`puts@plt → puts@got`, `_start → main`, `0x08048087 → 0x0804809b`)
  where they substitute for "calls" or "falls through to".

# Hard rules

- Do not invent payloads, addresses, register values, or instructions
  that aren't in the trace. Quote, don't paraphrase numerical evidence.
- If a critical step's rationale isn't visible in the trace, **say so
  explicitly** ("trace doesn't capture the libc lookup; the offset
  matched pwnable.tw's i386 libc"). Better to mark a gap than to
  guess.
- Length is acceptable. Prefer thoroughness over brevity. A reader
  should be able to reproduce the exploit from scratch using only the
  writeup and the binary, without going back to the trace.

Output only the markdown. Begin with the title."""


# Per-result truncation in the digest sent to the LLM. Bumped from 600 so
# r2 / objdump / Ghidra / gdb outputs survive in their entirety — the
# system prompt asks the writeup author to QUOTE these as evidence, and
# truncating them at 600 chars stripped most of the supporting material.
# 2400 covers a typical disassembly listing (~50 lines × ~40 chars) plus
# header/symbol context. The TRACE_CAP middle-elision still bounds total
# context size if a single solver runs unusually long.
RESULT_CAP = 2400
# Hard cap on total digest characters per trace (truncate from the middle).
# Bumped from 60k to 120k to keep both substantial RE evidence early on AND
# the late winning move within a single context window.
TRACE_CAP = 120_000


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
    parts.append(
        "Write the writeup now. Begin with the title.\n\n"
        "**Reminder of the non-negotiables**:\n\n"
        "- Every claim must cite evidence — quote the actual "
        "disassembly / decompilation / gdb output / payload bytes "
        "from the trace.\n"
        "- Derive struct layouts from observed memory accesses with "
        "annotation; show stack/heap diagrams where layout matters; "
        "explain WHY each step works, not just what was sent.\n"
        "- The above trace is the evidence source — do NOT mention "
        "the solver model, step numbers, 'the agent', or 'swarms' in "
        "the writeup body. Quote what the trace contains, not who "
        "recorded it. The writeup is for a researcher studying the "
        "challenge, not for someone studying our harness.\n"
        "- Length is fine — be thorough enough that a reader can "
        "reproduce the exploit from the writeup alone.\n"
        "- No `⇒` or `=>` arrows for implication — write 'so' / "
        "'therefore' / a colon instead. Single arrows (`→`, `->`) for "
        "control flow / chain notation are fine."
    )
    return "\n".join(parts)


async def generate_writeup(
    meta: ChallengeMeta,
    winner_result: SolverResult,
    winner_spec: str,
    sibling_traces: list[tuple[str, Path]],
    cost_usd: float,
    duration_s: float,
    out_dir: Path = Path("writeups"),
    model: str = "claude-opus-4-7",
    settings: Any | None = None,
) -> Path | None:
    """Generate a markdown writeup. Returns the file path on success, None on failure.

    `model` accepts any spec the provider-agnostic text_completion helper
    supports — Claude (`claude-opus-4-7`, `claude-sdk/...`), Codex
    (`codex/gpt-5.4-mini`), or Pydantic-AI providers (`bedrock/...`,
    `azure/...`, `zen/...`, `google/...`). Pydantic-AI specs require
    `settings` for API-key resolution; subscription paths don't.

    Designed to never raise — a writeup failure should not corrupt a
    successful solve. Errors get logged.
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

        # Generate via the requested model; on transient failures
        # (claude-agent-sdk SIGSEGVs, AUP refusals on claude-opus-*)
        # fall back ONCE to a known-stable codex model. Any failure of
        # the fallback is propagated — operator decides next steps
        # manually rather than chaining further automatic retries.
        FALLBACK_MODEL = "codex/gpt-5.5"
        markdown = ""
        try:
            markdown = await text_completion(
                model_spec=model,
                system=SYSTEM_PROMPT,
                user=user_prompt,
                settings=settings,
                timeout_s=900,
            )
        except Exception as e:
            err = str(e)
            klass = _classify_failure(err)
            transient = klass in ("REFUSAL", "SIGSEGV", "SIGABRT")
            if transient and model != FALLBACK_MODEL:
                logger.warning(
                    "Postmortem %s: %s on %s (%s); falling back to %s",
                    meta.name, klass, model, err[:120], FALLBACK_MODEL,
                )
                markdown = await text_completion(
                    model_spec=FALLBACK_MODEL,
                    system=SYSTEM_PROMPT,
                    user=user_prompt,
                    settings=settings,
                    timeout_s=900,
                )
            else:
                logger.warning(
                    "Postmortem %s: %s on %s (%s); not auto-cascading",
                    meta.name, klass, model, err[:120],
                )
                raise RuntimeError(f"{klass}: {err}") from e

        # Sometimes the underlying SDK returns refusal text as a normal
        # string instead of raising. Scan the WHOLE body, not just the
        # prefix — opus has been observed appending refusal at the end
        # of an otherwise substantive draft.
        if markdown and _looks_like_aup_refusal(markdown) and model != FALLBACK_MODEL:
            logger.warning(
                "Postmortem %s: REFUSAL embedded in body (%d chars produced); "
                "falling back to %s",
                meta.name, len(markdown), FALLBACK_MODEL,
            )
            markdown = await text_completion(
                model_spec=FALLBACK_MODEL,
                system=SYSTEM_PROMPT,
                user=user_prompt,
                settings=settings,
                timeout_s=900,
            )

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
