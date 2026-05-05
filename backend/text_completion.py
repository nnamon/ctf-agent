"""Provider-agnostic single-shot text completion.

Dispatches a `model_spec` string to the right runtime so callers that
just need "prompt in, text out" don't have to know which API backs which
prefix. Three runtimes are handled:

  - **Claude Agent SDK** — `claude-sdk/*` and bare `claude-*` model
    names. Subscription auth (no API key required).
  - **Codex App Server** — `codex/*`. Spawned as a one-shot JSON-RPC
    turn with no dynamic tools. Subscription auth.
  - **Pydantic AI** — `bedrock/*`, `azure/*`, `zen/*`, `google/*`.
    Goes through `backend.models.resolve_model` for provider client
    construction.

This is intentionally NOT the path for tool-using agents (solvers,
coordinators). Their surfaces genuinely differ per provider — full
agent loops with hooks/MCP/dynamic tools — so unifying them would
either lose features or hide the differences badly. This helper only
covers the universal subset: single-shot text generation.

Use cases:
  - Post-mortem writeups (`backend.agents.postmortem`)
  - Future short-judge / narration / classification tasks
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import time
from typing import Any

from backend.codex_stderr import coalesce_stderr
from backend.models import (
    model_id_from_spec,
    provider_from_spec,
    resolve_model,
    resolve_model_settings,
)

logger = logging.getLogger(__name__)


_CLAUDE_SDK_PROVIDERS = {"claude-sdk"}
_CODEX_PROVIDERS = {"codex"}
_PYDANTIC_AI_PROVIDERS = {"bedrock", "azure", "zen", "google"}

# Per-process counter for codex RPC IDs; module-level so concurrent
# completions don't collide on the wire.
_codex_rpc_counter = itertools.count(1)


async def text_completion(
    model_spec: str,
    system: str,
    user: str,
    settings: Any | None = None,
    timeout_s: int = 300,
) -> str:
    """Run a single prompt through the model named by `model_spec`.

    `settings` is required for Pydantic-AI-backed providers
    (bedrock/azure/zen/google) — they need the API keys / endpoints
    held there. Subscription paths (claude-sdk, codex, bare claude-*)
    don't need it.

    Returns the model's response text, stripped. Raises on transport
    errors or non-zero exits — the caller decides whether to swallow
    or propagate.
    """
    provider = provider_from_spec(model_spec)

    if provider in _CLAUDE_SDK_PROVIDERS:
        return await _claude_sdk_completion(
            model_id_from_spec(model_spec), system, user, timeout_s
        )
    if provider in _CODEX_PROVIDERS:
        return await _codex_completion(
            model_id_from_spec(model_spec), system, user, timeout_s
        )
    if provider in _PYDANTIC_AI_PROVIDERS:
        if settings is None:
            raise ValueError(
                f"text_completion: settings is required for {provider!r} spec "
                f"{model_spec!r} (provider client needs API keys / endpoint)"
            )
        return await _pydantic_ai_completion(model_spec, system, user, settings)

    # Bare claude-* names (no provider prefix) — historical compat: the
    # writeup default has always been "claude-opus-4-7", which the Claude
    # SDK accepts as-is. Route those to the SDK.
    if model_spec.startswith("claude-"):
        return await _claude_sdk_completion(model_spec, system, user, timeout_s)

    raise ValueError(
        f"text_completion: unknown provider for spec {model_spec!r}. "
        f"Recognised prefixes: claude-sdk/, codex/, bedrock/, azure/, "
        f"zen/, google/, or a bare claude-* model id."
    )


# ---------- Claude Agent SDK ----------


async def _claude_sdk_completion(model: str, system: str, user: str, timeout_s: int) -> str:
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ClaudeSDKClient,
        TextBlock,
    )

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=system,
        env={"CLAUDECODE": ""},
        permission_mode="bypassPermissions",
        allowed_tools=[],  # one-shot text generation, no tools
    )

    parts: list[str] = []
    async with ClaudeSDKClient(options=options) as client:
        await client.query(user)
        async for msg in client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        parts.append(block.text)
    return "\n".join(parts).strip()


# ---------- Codex App Server ----------


async def _codex_completion(model: str, system: str, user: str, timeout_s: int) -> str:
    """Spawn codex app-server with one retry on transient subprocess deaths.

    Wraps `_codex_attempt` so a single ConnectionResetError / BrokenPipeError
    (codex pipe collapsed mid-RPC) or a silent EOF (subprocess died before
    producing an agentMessage) doesn't lose the writeup. Mirrors the 3-
    attempt resilience the solver path has had since v0.1. Non-pipe
    failures (TimeoutError, "Codex turn failed", RPC errors) propagate
    immediately — retrying a true model-side failure is a waste.
    """
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            text = await _codex_attempt(model, system, user, timeout_s)
            if text:
                return text
            logger.warning(
                "codex completion empty (model=%s, attempt=%d/2); %s",
                model, attempt + 1,
                "retrying" if attempt == 0 else "giving up",
            )
        except (ConnectionResetError, BrokenPipeError) as e:
            last_exc = e
            logger.warning(
                "codex completion %s (model=%s, attempt=%d/2)",
                type(e).__name__, model, attempt + 1,
            )
        if attempt < 1:
            await asyncio.sleep(5)
    if last_exc:
        raise last_exc
    return ""


async def _codex_attempt(model: str, system: str, user: str, timeout_s: int) -> str:
    """Spawn `codex app-server`, run one turn, capture the agent message.

    Mirrors the protocol used by `backend.agents.codex_solver` but with
    no dynamic tools and no streaming — we just want the final text. The
    subprocess is torn down on exit.
    """
    proc = await asyncio.create_subprocess_exec(
        "codex", "app-server",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    pending: dict[int, asyncio.Future] = {}
    final_texts: list[str] = []
    turn_done = asyncio.Event()
    turn_error: dict[str, str] = {}

    async def _stderr_loop() -> None:
        """Drain codex stderr to logger so subprocess crashes are visible.

        Without this, if the codex CLI panics on init (auth race, sessions
        lock, etc.) we just see a silent timeout via wait_for(turn_done).
        """
        assert proc.stderr
        try:
            async for record in coalesce_stderr(proc.stderr):
                text = record.decode("utf-8", errors="replace").rstrip()
                if text:
                    logger.warning("codex(text_completion %s) stderr: %s",
                                   model, text[:800])
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("text_completion stderr reader crashed: %s", e)

    async def _read_loop() -> None:
        assert proc.stdout
        while True:
            line = await proc.stdout.readline()
            if not line:
                turn_done.set()
                return
            last_event_at["ts"] = time.time()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg_id = msg.get("id")
            if msg_id is not None and ("result" in msg or "error" in msg):
                fut = pending.pop(msg_id, None)
                if fut and not fut.done():
                    if "error" in msg:
                        fut.set_exception(RuntimeError(f"Codex RPC error: {msg['error']}"))
                    else:
                        fut.set_result(msg)
                continue

            method = msg.get("method", "")
            params = msg.get("params", {})
            if method == "item/completed":
                # Final-answer agent messages have phase != "commentary".
                # The "commentary" ones are ephemeral status updates.
                item = params.get("item", params)
                item_type = item.get("type")
                if item_type == "agentMessage":
                    text = item.get("text", "")
                    phase = item.get("phase")
                    if text and phase != "commentary":
                        final_texts.append(text)
                elif item_type == "reasoning":
                    # Surface chain-of-thought via logger so writeup-time
                    # wedges (model thinking forever, never emitting an
                    # agentMessage) are visible. Caps at 600 chars to keep
                    # log volume bounded.
                    rtext = item.get("text") or item.get("summary") or ""
                    if not rtext:
                        content = item.get("content")
                        if isinstance(content, list):
                            parts = []
                            for c in content:
                                if isinstance(c, dict):
                                    parts.append(c.get("text") or c.get("summary") or "")
                            rtext = "\n".join(p for p in parts if p)
                    if rtext:
                        logger.info("codex(text_completion %s) reasoning: %s",
                                    model, rtext[:600])
            elif method == "turn/completed":
                turn = params.get("turn", {})
                if turn.get("status") == "failed":
                    err = turn.get("error", {})
                    turn_error["err"] = (
                        err.get("message") if isinstance(err, dict) else str(err)
                    ) or "unknown"
                turn_done.set()

    proc_started_at = time.time()
    last_event_at: dict[str, float | None] = {"ts": None}

    async def _watch_exit() -> None:
        try:
            rc = await proc.wait()
        except asyncio.CancelledError:
            raise
        sig = ""
        if rc is not None and rc < 0:
            try:
                import signal as _sig
                sig = _sig.Signals(-rc).name
            except (ValueError, AttributeError):
                sig = f"signal {-rc}"
        now = time.time()
        idle = round(now - last_event_at["ts"], 2) if last_event_at["ts"] else None
        logger.warning(
            "codex(text_completion %s) subprocess exited rc=%s sig=%s "
            "elapsed=%ss idle_since_last_event=%ss pending_rpcs=%d",
            model, rc, sig or "n/a",
            round(now - proc_started_at, 2), idle, len(pending),
        )
        # Unblock waiters in the main path
        turn_done.set()

    reader = asyncio.create_task(_read_loop())
    stderr_reader = asyncio.create_task(_stderr_loop())
    exit_watcher = asyncio.create_task(_watch_exit())

    async def _rpc(method: str, params: dict | None = None) -> dict:
        assert proc.stdin
        mid = next(_codex_rpc_counter)
        msg: dict[str, Any] = {"id": mid, "method": method}
        if params:
            msg["params"] = params
        fut: asyncio.Future[dict] = asyncio.get_running_loop().create_future()
        pending[mid] = fut
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        await proc.stdin.drain()
        try:
            return await asyncio.wait_for(fut, timeout=timeout_s)
        finally:
            pending.pop(mid, None)

    async def _notify(method: str, params: dict | None = None) -> None:
        assert proc.stdin
        msg: dict[str, Any] = {"method": method}
        if params:
            msg["params"] = params
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        await proc.stdin.drain()

    try:
        await _rpc("initialize", {
            "clientInfo": {"name": "ctf-agent-text", "version": "2.0.0"},
            "capabilities": {"experimentalApi": True},
        })
        await _notify("initialized", {})

        resp = await _rpc("thread/start", {
            "model": model,
            "personality": "pragmatic",
            "baseInstructions": system,
            "cwd": ".",
            "approvalPolicy": "on-request",
            "sandbox": "read-only",
            "dynamicTools": [],
        })
        thread_id = resp.get("result", {}).get("thread", {}).get("id", "")
        if not thread_id:
            raise RuntimeError(f"Codex thread/start returned no id: {resp}")

        await _rpc("turn/start", {
            "threadId": thread_id,
            "input": [{"type": "text", "text": user}],
        })

        await asyncio.wait_for(turn_done.wait(), timeout=timeout_s)
        if turn_error.get("err"):
            raise RuntimeError(f"Codex turn failed: {turn_error['err']}")
    finally:
        reader.cancel()
        stderr_reader.cancel()
        exit_watcher.cancel()
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    return "\n".join(final_texts).strip()


# ---------- Pydantic AI ----------


async def _pydantic_ai_completion(spec: str, system: str, user: str, settings: Any) -> str:
    """Single-shot via Pydantic AI's `Agent.run`. No tools, no deps."""
    from pydantic_ai import Agent

    model = resolve_model(spec, settings)
    model_settings = resolve_model_settings(spec)
    agent = Agent(model, model_settings=model_settings, system_prompt=system)
    result = await agent.run(user)
    return str(result.output).strip()
