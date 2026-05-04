"""SDK-agnostic tool logic — pure async functions, no Pydantic AI types.

Tool functions accept either:
  - a single `sandbox: ExecEnv` (legacy single-env mode), OR
  - a multi-env `(registry: EnvRegistry, target: str)` pair.

Both paths share the same per-env primitives (`exec`, `read_file`,
`write_file`); the difference is only in resolution. New code should use
the registry-aware helpers (`do_bash_target`, `do_read_file_target`, …)
and pass the agent's chosen `target`. The legacy `do_bash(sandbox, …)`
form is preserved so existing solver code keeps working — internally it
just runs against whatever `ExecEnv` is passed."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from backend.backends import Backend
    from backend.exec_env import EnvRegistry, ExecEnv

MAX_OUTPUT = 24_000


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    lines = text.split("\n")
    head = "\n".join(lines[:200])
    return head[:limit] + f"\n... [truncated — {len(text)} total chars, {len(lines)} lines]"


async def do_bash(sandbox, command: str, timeout_seconds: int = 60) -> str:
    result = await sandbox.exec(command, timeout_s=timeout_seconds)
    parts: list[str] = []
    if result.stdout:
        parts.append(result.stdout)
    if result.stderr:
        parts.append(f"[stderr]\n{result.stderr}")
    if result.exit_code != 0:
        parts.append(f"[exit {result.exit_code}]")
    out = "\n".join(parts).strip() or "(no output)"
    return _truncate(out)


async def do_read_file(sandbox, path: str) -> str:
    try:
        data = await sandbox.read_file(path)
    except Exception as e:
        return f"Error reading file: {e}"

    if isinstance(data, bytes):
        sample = data[:4096]
        non_text = sum(
            1
            for b in sample
            if b == 0 or (b < 9 and b not in (7, 8)) or (9 < b < 13) or (13 < b < 32 and b != 27)
        )
        if len(sample) > 0 and non_text / len(sample) > 0.05:
            return (
                f"Binary file ({len(data)} bytes) — use bash to inspect it:\n"
                f"  file {path}\n"
                f"  xxd {path} | head -40\n"
                f"  strings {path}\n"
                f"  exiftool {path}\n"
                f"  binwalk {path}"
            )
        return _truncate(data.decode("utf-8", errors="replace"))

    return _truncate(data) if isinstance(data, str) else data


async def do_write_file(sandbox, path: str, content: str) -> str:
    try:
        await sandbox.write_file(path, content)
        return f"Written {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error writing file: {e}"


async def do_list_files(sandbox, path: str = "/challenge/distfiles") -> str:
    result = await sandbox.exec(f"ls -la {shlex.quote(path)}")
    out = result.stdout.strip()
    if result.exit_code != 0:
        return result.stderr.strip() or f"Error listing {path}"
    return out or f"{path} is empty."


async def do_submit_flag(ctfd: "Backend", challenge_name: str, flag: str) -> tuple[str, bool]:
    """Submit a flag. Returns (display_message, is_confirmed)."""
    flag = flag.strip()
    if not flag:
        return "Empty flag — nothing to submit.", False

    try:
        result = await ctfd.submit_flag(challenge_name, flag)
        is_confirmed = result.status in ("correct", "already_solved")
        return result.display, is_confirmed
    except Exception as e:
        return f"submit_flag error: {e}", False


def _is_internal_url(url: str) -> bool:
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if host.startswith("169.254.") or host.startswith("10.") or host.startswith("192.168."):
        return True
    if host.startswith("172."):
        try:
            second_octet = int(host.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


async def do_web_fetch(url: str, method: str = "GET", body: str = "") -> str:
    if _is_internal_url(url):
        return "Fetch error: access to internal/private networks is blocked."
    try:
        # verify=False: CTF challenge services often use self-signed certs
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.request(
                method,
                url,
                content=body or None,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            text = resp.text
            prefix = f"HTTP {resp.status_code} {resp.reason_phrase}\n{'─' * 40}\n"
            if len(text) > 20_000:
                text = text[:20_000] + f"\n... [truncated, total {len(resp.text)} bytes]"
            return prefix + text
    except Exception as e:
        return f"Fetch error: {e}"


async def do_webhook_create() -> str:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post("https://webhook.site/token")
            if resp.status_code != 200:
                return f"webhook.site error: HTTP {resp.status_code}"
            data = resp.json()
            return json.dumps({"uuid": data["uuid"], "url": f"https://webhook.site/{data['uuid']}"})
    except Exception as e:
        return f"webhook_create error: {e}"


async def do_webhook_get_requests(uuid: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://webhook.site/token/{uuid}/requests")
            if resp.status_code != 200:
                return f"webhook.site error: HTTP {resp.status_code}"
            data = resp.json()
            if not data.get("data"):
                return "No requests received yet."
            out = json.dumps(data["data"], indent=2)
            return out[:8000] if len(out) > 8000 else out
    except Exception as e:
        return f"webhook_get_requests error: {e}"


async def do_check_findings(message_bus, model_spec: str) -> str:
    """Get unread findings from sibling solvers."""
    if not message_bus:
        return "No message bus available."
    findings = await message_bus.check(model_spec)
    if not findings:
        return "No new findings from other agents."
    return message_bus.format_unread(findings)


# Image constants (shared with vision wrapper)
IMAGE_EXTS_FOR_VISION: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".webp": "image/webp",
}

IMAGE_MAGIC: dict[str, list[int]] = {
    "image/png": [0x89, 0x50, 0x4E, 0x47],
    "image/jpeg": [0xFF, 0xD8, 0xFF],
    "image/gif": [0x47, 0x49, 0x46],
    "image/bmp": [0x42, 0x4D],
    "image/webp": [0x52, 0x49, 0x46, 0x46],
}

MAX_IMAGE_BYTES = 4 * 1024 * 1024  # 4 MB


def _has_valid_magic(data: bytes, mime_type: str) -> bool:
    magic = IMAGE_MAGIC.get(mime_type)
    if not magic:
        return True
    return all(i < len(data) and data[i] == b for i, b in enumerate(magic))


# ----------------------------------------------------------------------
# Multi-env helpers: resolve a `target` name → ExecEnv via the registry,
# then run against it. Output is prefixed with [<target>] so the agent
# can see where each tool result came from — addressing the "models lose
# track of which env this command ran in" failure mode.
# ----------------------------------------------------------------------


def _multi_prefix(env_name: str) -> str:
    """Header line prefixed to multi-env tool output."""
    return f"[{env_name}]\n"


class _EnvUnreachable(Exception):
    """Raised by `_resolve_env` when an env can't be obtained — either
    its name isn't registered, or its `.start()` timed out. Caught by
    the per-tool dispatchers so the failure surfaces as a tool result
    string the agent can react to instead of an unhandled exception."""


async def _resolve_env(registry: "EnvRegistry", target: str) -> "ExecEnv":
    if not registry.has(target):
        raise _EnvUnreachable(
            f"Unknown env {target!r}. Available: {registry.names}. "
            f"Call list_envs() to see what's connected."
        )
    try:
        return await registry.get(target)
    except TimeoutError as e:
        raise _EnvUnreachable(str(e)) from e


async def do_bash_target(
    registry: "EnvRegistry",
    target: str,
    command: str,
    timeout_seconds: int = 60,
) -> str:
    try:
        env = await _resolve_env(registry, target)
    except _EnvUnreachable as e:
        return str(e)
    out = await do_bash(env, command, timeout_seconds)
    return _multi_prefix(env.name) + out


async def do_read_file_target(
    registry: "EnvRegistry", target: str, path: str
) -> str:
    try:
        env = await _resolve_env(registry, target)
    except _EnvUnreachable as e:
        return str(e)
    out = await do_read_file(env, path)
    return _multi_prefix(env.name) + out


async def do_write_file_target(
    registry: "EnvRegistry", target: str, path: str, content: str
) -> str:
    try:
        env = await _resolve_env(registry, target)
    except _EnvUnreachable as e:
        return str(e)
    return _multi_prefix(env.name) + await do_write_file(env, path, content)


async def do_list_files_target(
    registry: "EnvRegistry", target: str, path: str = ""
) -> str:
    try:
        env = await _resolve_env(registry, target)
    except _EnvUnreachable as e:
        return str(e)
    # Default to the env's scratch dir if no path given.
    p = path or env.scratch_dir or "/"
    out = await do_list_files(env, p)
    return _multi_prefix(env.name) + out


async def do_list_envs(registry: "EnvRegistry") -> str:
    """Return a markdown-style listing of every available exec env.

    Surfaced verbatim to the agent. Includes name, description, and the
    canonical scratch dir for each env so the agent has enough context
    to pick the right `target` for each tool call."""
    rows = registry.describe()
    if not rows:
        return "No exec environments registered."
    lines: list[str] = ["Available exec environments:", ""]
    for r in rows:
        lines.append(f"- **{r['name']}** — {r['description']}")
        if r.get("scratch_dir"):
            lines.append(f"  scratch dir: `{r['scratch_dir']}`")
    return "\n".join(lines)


async def do_transfer(
    registry: "EnvRegistry",
    src_env: str,
    src_path: str,
    dst_env: str,
    dst_path: str,
) -> str:
    """Copy a file from one env to another via the orchestrator.

    Reads the source via `read_file_bytes` and writes the destination via
    `write_file`. Suitable for small artifacts (≤10 MB or so); for larger
    payloads the agent should use bash + scp directly.
    """
    try:
        src = await _resolve_env(registry, src_env)
        dst = await _resolve_env(registry, dst_env)
    except _EnvUnreachable as e:
        return str(e)
    try:
        data = await src.read_file_bytes(src_path)
    except Exception as e:
        return f"transfer: read from {src_env}:{src_path} failed: {e}"
    try:
        await dst.write_file(dst_path, data)
    except Exception as e:
        return f"transfer: write to {dst_env}:{dst_path} failed: {e}"
    return f"Transferred {len(data)} bytes [{src_env}]:{src_path} → [{dst_env}]:{dst_path}"


# ----------------------------------------------------------------------


async def do_view_image(sandbox, filename: str, use_vision: bool) -> tuple[bytes, str] | str:
    """Returns (image_bytes, media_type) on success, or error string."""
    # Strip leading path if model passes full container path
    basename = Path(filename).name
    ext = Path(basename).suffix.lower()
    mime_type = IMAGE_EXTS_FOR_VISION.get(ext)
    if not mime_type:
        return f"Not a supported image type: {filename}"

    if not use_vision:
        return "Vision not available for this model. Use bash tools (steghide, zsteg, exiftool, strings) instead."

    # Try the filename as-is first (if it's an absolute path), then search standard dirs
    search_paths = []
    if filename.startswith("/"):
        search_paths.append(filename)
    search_paths.extend([f"/challenge/distfiles/{basename}", f"/challenge/workspace/{basename}"])

    for path in search_paths:
        try:
            data = await sandbox.read_file_bytes(path)
            if not _has_valid_magic(data, mime_type):
                return (
                    "Cannot load image: file appears invalid or corrupted. "
                    "Fix the magic bytes in the sandbox first, save to /challenge/workspace/, "
                    "then call view_image again."
                )
            if len(data) > MAX_IMAGE_BYTES:
                return (
                    f"Image too large for vision ({len(data) / 1024 / 1024:.1f} MB > 4 MB limit). "
                    "Use bash tools (steghide, zsteg, binwalk, exiftool, strings, xxd) instead."
                )
            return (data, mime_type)
        except Exception:
            continue

    return f"File not found: {filename} (searched: {', '.join(search_paths)})"
