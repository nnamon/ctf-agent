"""Coalesce + filter `codex app-server` stderr.

Codex's Rust `tracing` crate emits one structured-log header per record
followed by zero or more continuation lines (the failing command's
literal `\\n`-bearing payload, panics with backtraces, etc.). A naive
readline-per-event loop turns one logical error into 20+ trace
entries. We coalesce on header lines and filter out tool-router noise
that's not actually app-server-level (those bash failures are reported
through the JSON-RPC stream too).
"""

from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator

# Strip ANSI escapes for header detection and module-path matching.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_HEADER = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_TOOL_ROUTER_NOISE = re.compile(
    r"codex_core::tools::router|exec_command failed"
)


def _is_header(stripped: str) -> bool:
    return bool(_HEADER.match(stripped))


def _is_pertinent(stripped: str) -> bool:
    """Drop tool-router exec failures; keep everything else."""
    return not _TOOL_ROUTER_NOISE.search(stripped)


async def coalesce_stderr(stream: asyncio.StreamReader) -> AsyncIterator[bytes]:
    """Yield one bytes record per logical codex log entry.

    Reads `stream` line-by-line and accumulates non-header continuation
    lines onto the current header'd record. Falls back to line-based
    emission when there is no header to attach to (panics before
    logger init, or any non-tracing stderr output). Filters out
    tool-router noise.

    Records are returned as the raw bytes (newlines preserved) so the
    caller can both write a verbatim sidecar file and emit a single
    tracer event for the same logical entry.
    """
    buf: list[bytes] = []
    buf_stripped: str = ""

    while True:
        line = await stream.readline()
        if not line:
            break
        stripped = _ANSI.sub("", line.decode("utf-8", errors="replace")).rstrip()

        if _is_header(stripped):
            if buf and _is_pertinent(buf_stripped):
                yield b"".join(buf)
            buf = [line]
            buf_stripped = stripped
        elif buf:
            buf.append(line)
        elif stripped:
            # No header to attach to — emit standalone if pertinent.
            if _is_pertinent(stripped):
                yield line

    if buf and _is_pertinent(buf_stripped):
        yield b"".join(buf)
