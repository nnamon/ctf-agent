"""Pydantic AI tool wrappers — thin delegation to backend.tools.core.

Each wrapper accepts an optional `target` argument. When a multi-env
registry is attached to `SolverDeps.env_registry`, that target is resolved
via the registry; otherwise calls fall back to the legacy single-sandbox
path. This means single-env solver runs see no behavior change, and
multi-env runs (e.g. local + pwn.college) work additively.
"""

from pydantic_ai import RunContext

from backend.deps import SolverDeps
from backend.tools.core import (
    do_bash,
    do_bash_target,
    do_check_findings,
    do_list_envs,
    do_list_files,
    do_list_files_target,
    do_read_file,
    do_read_file_target,
    do_transfer,
    do_web_fetch,
    do_webhook_create,
    do_webhook_get_requests,
    do_write_file,
    do_write_file_target,
)


def _multi(deps: SolverDeps, target: str) -> bool:
    """True iff we should route via the env registry instead of the legacy
    sandbox. Empty/`local` targets stay on the legacy path when the
    registry isn't present, so single-env runs are unchanged."""
    return bool(deps.env_registry) and bool(target)


async def bash(
    ctx: RunContext[SolverDeps],
    command: str,
    timeout_seconds: int = 60,
    target: str = "",
) -> str:
    """Execute a bash command in an exec environment.

    `target` selects the env to run in (call list_envs to see the
    options). When omitted, the command runs in the local Docker sandbox.

    Default sandbox layout:
      Distfiles at /challenge/distfiles/ (read-only).
      Scratch at /challenge/workspace/ (writable).
      Services reachable via host.docker.internal.
      Run `cat /tools.txt` to see all installed tools.
    """
    if _multi(ctx.deps, target):
        return await do_bash_target(ctx.deps.env_registry, target, command, timeout_seconds)
    return await do_bash(ctx.deps.sandbox, command, timeout_seconds)


async def read_file(ctx: RunContext[SolverDeps], path: str, target: str = "") -> str:
    """Read a file from an exec environment. For local distfiles use paths
    like /challenge/distfiles/readme.txt. Use `target` to read from a
    remote env (call list_envs for options)."""
    if _multi(ctx.deps, target):
        return await do_read_file_target(ctx.deps.env_registry, target, path)
    return await do_read_file(ctx.deps.sandbox, path)


async def write_file(
    ctx: RunContext[SolverDeps], path: str, content: str, target: str = ""
) -> str:
    """Write a file into an exec environment."""
    if _multi(ctx.deps, target):
        return await do_write_file_target(ctx.deps.env_registry, target, path, content)
    return await do_write_file(ctx.deps.sandbox, path, content)


async def list_files(
    ctx: RunContext[SolverDeps],
    path: str = "/challenge/distfiles",
    target: str = "",
) -> str:
    """List files in a directory inside an exec environment."""
    if _multi(ctx.deps, target):
        return await do_list_files_target(ctx.deps.env_registry, target, path)
    return await do_list_files(ctx.deps.sandbox, path)


async def list_envs(ctx: RunContext[SolverDeps]) -> str:
    """List the exec environments available for tool calls.

    Each env has a stable `name` (use it as the `target` arg on bash /
    read_file / write_file / list_files) and a description that explains
    when to pick it. When solving a pwn.college challenge, for example,
    the real `/flag` lives only inside the `pwncollege` env — not in the
    local sandbox."""
    if not ctx.deps.env_registry:
        return (
            "Only one exec environment available (the local Docker sandbox). "
            "All tool calls run there."
        )
    return await do_list_envs(ctx.deps.env_registry)


async def transfer(
    ctx: RunContext[SolverDeps],
    src_target: str,
    src_path: str,
    dst_target: str,
    dst_path: str,
) -> str:
    """Copy a file from one exec environment to another.

    Goes through the orchestrator (read_file_bytes on src, write_file on
    dst). Suitable for small artifacts; for big payloads use `bash` +
    `scp` from the source env directly."""
    if not ctx.deps.env_registry:
        return "transfer is only available when multiple envs are registered."
    return await do_transfer(
        ctx.deps.env_registry, src_target, src_path, dst_target, dst_path
    )


async def check_findings(ctx: RunContext[SolverDeps]) -> str:
    """Check for new findings from other agents working on the same challenge.

    Call this periodically to see if siblings have discovered useful information.
    """
    return await do_check_findings(ctx.deps.message_bus, ctx.deps.model_spec)


async def notify_coordinator(ctx: RunContext[SolverDeps], message: str) -> str:
    """Send a message to the coordinator about a strategic discovery or request.

    Use this when you find something that affects the overall competition strategy,
    like discovering a flag format pattern, a shared vulnerability across challenges,
    or when you need help from other solvers.
    """
    if ctx.deps.notify_coordinator:
        try:
            await ctx.deps.notify_coordinator(message)
            return "Message sent to coordinator."
        except Exception as e:
            return f"Notification failed: {e}"
    return "No coordinator connected."


async def web_fetch(ctx: RunContext[SolverDeps], url: str, method: str = "GET", body: str = "") -> str:
    """Fetch a URL from the host. Useful for web challenges.

    Prefer bash+curl inside the sandbox for cookies/sessions.
    """
    return await do_web_fetch(url, method, body)


async def webhook_create(ctx: RunContext[SolverDeps]) -> str:
    """Create a webhook.site token for out-of-band HTTP callbacks (XSS, SSRF, bot challenges)."""
    return await do_webhook_create()


async def webhook_get_requests(ctx: RunContext[SolverDeps], uuid: str) -> str:
    """Retrieve HTTP requests received by a webhook.site token."""
    return await do_webhook_get_requests(uuid)


async def note(ctx: RunContext[SolverDeps], content: str) -> str:
    """Record a key insight, finding, working payload, or dead end for the
    post-mortem writeup.

    Call this whenever you've identified something worth preserving:
    - a vulnerability with a brief description and the proof
    - a working exploit payload or snippet (paste the actual code/request)
    - a dead end with the reason you ruled it out
    - a generalizable technique you used

    These notes are stitched into a writeup at the end of the run; they do
    not affect whether the flag is accepted. Be concise — one or two lines.
    """
    if ctx.deps.note_fn:
        try:
            ctx.deps.note_fn(content)
        except Exception:
            pass
    return "noted."
