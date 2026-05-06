"""System prompt builder + ChallengeMeta."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backend.tools.core import IMAGE_EXTS_FOR_VISION as IMAGE_EXTS


@dataclass
class ChallengeMeta:
    name: str = "Unknown"
    category: str = ""
    value: int = 0
    description: str = ""
    tags: list[str] = field(default_factory=list)
    connection_info: str = ""
    hints: list[dict[str, Any]] = field(default_factory=list)
    solves: int = 0
    # Default exec env for tool calls that omit `target`. Set by backends
    # that bind a challenge to a specific remote environment — e.g. the
    # pwn.college backend writes `pwncollege.exec_env: "pwncollege"` into
    # metadata.yml, and the loader copies it here so the solver prompt
    # surfaces it as the default target.
    primary_env: str = ""
    # Backend-specific orchestration metadata (the `pwncollege:` block,
    # for example). Carried through verbatim so the orchestrator can read
    # `pwncollege.dojo`/`module`/`challenge` to spawn the workspace.
    backend_meta: dict[str, Any] = field(default_factory=dict)
    # Names of other challenges that must be solved before this one is
    # eligible to spawn. The coord refuses spawn_swarm if any prereq is
    # unsolved. Used by HtbMachinesBackend to gate `<slug>-root` on
    # `<slug>-user` (root requires the user foothold).
    prerequisites: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ChallengeMeta:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        # Pull primary_env from a known set of backend blocks so we don't
        # hard-code "pwncollege" everywhere. Each backend block lives at a
        # top-level key matching its name and may set `exec_env`.
        primary_env = ""
        backend_meta: dict[str, Any] = {}
        for backend_key in ("pwncollege",):
            block = data.get(backend_key)
            if isinstance(block, dict):
                backend_meta[backend_key] = block
                primary_env = primary_env or str(block.get("exec_env", "") or "")
        return cls(
            name=data.get("name", "Unknown"),
            category=data.get("category", ""),
            value=data.get("value", 0),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            connection_info=data.get("connection_info", ""),
            hints=data.get("hints", []),
            solves=data.get("solves", 0),
            primary_env=primary_env,
            backend_meta=backend_meta,
            prerequisites=list(data.get("prerequisites", []) or []),
        )


def list_distfiles(challenge_dir: str) -> list[str]:
    dist = Path(challenge_dir) / "distfiles"
    if not dist.exists():
        return []
    return sorted(f.name for f in dist.iterdir() if f.is_file())


def _rewrite_connection_info(conn: str) -> str:
    """Replace localhost/127.0.0.1 with host.docker.internal for bridge networking."""
    if not conn:
        return conn
    conn = re.sub(r"\blocalhost\b", "host.docker.internal", conn)
    conn = re.sub(r"\b127\.0\.0\.1\b", "host.docker.internal", conn)
    return conn


def build_prompt(
    meta: ChallengeMeta,
    distfile_names: list[str],
    container_arch: str = "unknown",
    has_named_tools: bool = True,
    prior_attempts: list | None = None,
    context_files: list[str] | None = None,
    exec_envs: list[dict[str, str]] | None = None,
    primary_env: str = "",
) -> str:
    """Build the system prompt.

    has_named_tools: True for Pydantic AI solver (has view_image, webhook_create, etc.
    as discrete tools). False for Claude SDK (bash-only — model should use
    steghide/exiftool/curl instead). Codex has named dynamic tools so uses True.

    prior_attempts: optional list of `Attempt` records (from
    `Backend.previous_attempts(name)`) — when provided, an
    "ALREADY-REJECTED FLAGS" section is rendered so the model doesn't
    re-propose flags that have already been submitted and rejected.

    context_files: optional list of host-side paths supplied by an external
    orchestrator (e.g. writeups + artifacts from prior chain-siblings).
    Each is mounted in the sandbox at /challenge/context/<basename>; this
    function additionally renders text-ish ones inline as a "## Prior
    context" section so the model knows what's there without having to cat
    every file.
    """
    conn_info = _rewrite_connection_info(meta.connection_info.strip())

    lines: list[str] = [
        "You are an expert CTF solver. Find the real flag for the challenge below.",
        "",
    ]

    if conn_info:
        lines += [
            "> **FIRST ACTION REQUIRED**: Your very first tool call MUST connect to the service.",
            f"> Run: `{conn_info}` (use a heredoc or pwntools script as shown below).",
            "> Do NOT explore the sandbox filesystem first. The flag is on the service, not in the container.",
            "",
        ]

    lines += [
        "## Challenge",
        f"**Name**    : {meta.name}",
        f"**Category**: {meta.category or 'Unknown'}",
        f"**Points**  : {meta.value or '?'}",
        f"**Arch**    : {container_arch}",
    ]
    if meta.tags:
        lines.append(f"**Tags**    : {', '.join(meta.tags)}")
    lines += ["", "## Description", meta.description or "_No description provided._", ""]

    if conn_info:
        if re.match(r"^https?://", conn_info):
            hint = "This is a **web service**. Use `bash` with `curl`/`python3 requests`, or use `web_fetch`."
        elif conn_info.startswith("nc "):
            hint = (
                "This is a **TCP service**. Each `bash` call is a fresh process — "
                "use a heredoc to send multiple lines in one shot:\n"
                "```\n"
                f"{conn_info} <<'EOF'\ncommand1\ncommand2\nEOF\n"
                "```\n"
                "Or write a Python `socket` / `pwntools` script for stateful interaction."
            )
        else:
            hint = "Connect using the details above."
        lines += ["## Service Connection", "```", conn_info, "```", hint, ""]

    if distfile_names:
        lines.append("## Attached Files")
        has_apk = False
        for name in distfile_names:
            ext = Path(name).suffix.lower()
            is_img = ext in IMAGE_EXTS
            if is_img and has_named_tools:
                suffix = "  <- **IMAGE: call `view_image` immediately** (fix magic bytes first if corrupt)"
            elif is_img:
                suffix = "  <- **IMAGE: use `exiftool`, `steghide`, `zsteg`, `strings` via bash**"
            elif ext == ".apk":
                suffix = "  <- **APK: see Android workflow below**"
                has_apk = True
            else:
                suffix = ""
            lines.append(f"- `/challenge/distfiles/{name}`{suffix}")
        lines.append("")
        if has_apk:
            lines += [
                "### Android APK workflow",
                "- `jadx -d /tmp/jadx <apk>` — decompile to Java (primary)",
                "- `apktool d -f <apk> -o /tmp/apk` — manifest, resources, smali",
                "- `aapt dump badging <apk>` / `aapt dump xmltree <apk> AndroidManifest.xml` — manifest summary",
                "- `d2j-dex2jar <apk>` — DEX→JAR fallback when jadx fails",
                "- Native libs: `lib/<arch>/*.so` → standard binutils + `qemu-<arch>-static`",
                "- `androguard` (Python) for programmatic analysis: `from androguard.misc import AnalyzeAPK`",
                "- Note: no Android emulator available. Reimplement check logic in Python.",
                "",
            ]

    # Orchestrator-supplied context (writeups, artifacts from prior siblings).
    # Each file is bind-mounted at /challenge/context/<basename>. Embed a
    # listing so the model knows what's there. For small text-ish files,
    # also embed the contents inline so the model doesn't have to cat them.
    if context_files:
        TEXT_EMBED_LIMIT = 32 * 1024
        TEXT_EXTS = {".md", ".txt", ".log", ".json", ".yml", ".yaml",
                     ".csv", ".py", ".sh", ".c", ".h", ".cpp", ".java",
                     ".rb", ".rs", ".go", ".js", ".ts", ".sql", ".html",
                     ".xml", ".toml", ".ini", ".conf", ".cfg", ""}
        lines.append("## Prior context")
        lines.append("")
        lines.append("Files attached by the orchestrator from prior chain-siblings.")
        lines.append("All are also at `/challenge/context/<basename>` in the sandbox.")
        lines.append("")
        embedded: list[tuple[str, str]] = []
        for src in context_files:
            p = Path(src)
            name = p.name
            if not p.exists():
                lines.append(f"- `/challenge/context/{name}` (missing on host)")
                continue
            size = p.stat().st_size
            ext = p.suffix.lower()
            if ext in TEXT_EXTS and size <= TEXT_EMBED_LIMIT:
                try:
                    body = p.read_text(encoding="utf-8")
                    embedded.append((name, body))
                    lines.append(f"- `/challenge/context/{name}`  ({size} B, embedded below)")
                    continue
                except UnicodeDecodeError:
                    pass
            kind = "binary" if ext not in TEXT_EXTS else "text"
            lines.append(f"- `/challenge/context/{name}`  ({size} B, {kind}; not embedded)")
        lines.append("")
        for name, body in embedded:
            lines.append(f"### `/challenge/context/{name}`")
            lines.append("```")
            lines.append(body.rstrip())
            lines.append("```")
            lines.append("")

    # Multi-env section. When the orchestrator has registered more than
    # one exec environment (local Docker + remote SSH + …), we MUST tell
    # the model up front so it doesn't blindly cat local paths expecting
    # the remote `/flag`. The `target` arg on bash/read_file/write_file
    # selects the env per call.
    if exec_envs and len(exec_envs) > 1:
        lines += [
            "## Exec environments",
            "",
            "You have multiple execution environments available. Each tool call "
            "(bash / read_file / write_file / list_files) accepts a `target` "
            "argument naming the env to run in. Tool results are prefixed with "
            "`[<env>]` so you can always see where a command actually ran.",
            "",
        ]
        for e in exec_envs:
            mark = "  (default)" if e["name"] == primary_env else ""
            lines.append(f"- **`{e['name']}`**{mark} — {e['description']}")
            if e.get("scratch_dir"):
                lines.append(f"  scratch dir: `{e['scratch_dir']}`")
        lines += [
            "",
            f"Default `target` if you omit it: `{primary_env or 'local'}`. "
            "Use `transfer(src_target, src_path, dst_target, dst_path)` to copy "
            "small artifacts between envs (large payloads: use `bash` + `scp`).",
            "",
        ]

    visible_hints = [h for h in meta.hints if h.get("content")]
    if visible_hints:
        lines.append("## Hints")
        for h in visible_hints:
            lines.append(f"- {h['content']}")
        lines.append("")

    # Rejected-flags section. Backed by AttemptLogBackend so the model
    # doesn't waste turns re-proposing flags that have already been
    # submitted and rejected for THIS challenge.
    if prior_attempts:
        from datetime import datetime
        rejected = [a for a in prior_attempts if a.status == "incorrect"]
        confirmed = [a for a in prior_attempts if a.status in ("correct", "already_solved")]
        if confirmed:
            for a in confirmed:
                lines += [
                    "## Already Solved",
                    f"This challenge already has a CORRECT submission on file: `{a.flag}`.",
                    "If you find this same flag, just `submit_flag` it — the harness will short-circuit.",
                    "",
                ]
                break  # one is enough
        if rejected:
            lines.append("## ALREADY-REJECTED FLAGS — do not re-propose")
            lines.append("")
            lines.append("The following flag values have already been submitted to this challenge")
            lines.append("and rejected as INCORRECT. Do NOT propose them again — the harness will")
            lines.append("auto-reject duplicates without spending another submission attempt.")
            lines.append("")
            for a in rejected[-30:]:  # cap so the prompt doesn't bloat
                ts = datetime.fromtimestamp(a.ts).strftime("%Y-%m-%d %H:%M")
                lines.append(f"  - `{a.flag}`  (rejected {ts})")
            if len(rejected) > 30:
                lines.append(f"  - ... ({len(rejected) - 30} more older rejections elided)")
            lines.append("")

    # pyghidra is always installed in the sandbox — show for RE/pwn/misc categories
    # or when distfiles contain binaries (non-text files)
    cat_lower = (meta.category or "").lower()
    if cat_lower in ("reverse", "reversing", "re", "pwn", "binary", "misc", ""):
        lines += [
            "## Binary Analysis",
            "**pyghidra** is installed for decompilation. Use it via bash:",
            "```python",
            "import pyghidra",
            "with pyghidra.open_program('/challenge/distfiles/binary') as flat_api:",
            "    listing = flat_api.currentProgram.getListing()",
            "    # Iterate functions, decompile, etc.",
            "```",
            "Also available: radare2 (`r2`), gdb, angr, capstone.",
            "",
        ]

    if has_named_tools:
        image_hint = "**Images: call `view_image` FIRST, before any other analysis.**"
        web_hint = "Web: fuzz params, check JS source, cookies, robots.txt. For XSS/SSRF: use `webhook_create`."
        submit_hint = "**Verify every candidate with `submit_flag`** before reporting."
        note_hint = (
            "Use `note` to record key findings as you work — vulns identified (with brief proof), "
            "working payloads (paste the snippet), dead ends (and why), generalizable techniques. "
            "These compile into a post-mortem writeup at the end."
        )
    else:
        image_hint = "**Images: use `exiftool`, `steghide`, `zsteg`, `strings`, `xxd` via bash.**"
        web_hint = "Web: fuzz params, check JS source, cookies, robots.txt. For XSS/SSRF: use `curl` to webhook.site."
        submit_hint = "**Verify every candidate with `submit_flag '<flag>'`** (bash command) before reporting."
        note_hint = (
            "Use `note '<content>'` (bash) to record key findings as you work — vulns identified "
            "(with brief proof), working payloads (paste the snippet), dead ends (and why), "
            "generalizable techniques. These compile into a post-mortem writeup at the end."
        )

    lines += [
        "",
        "## Instructions",
        "**Use tools immediately. Do not describe — execute.**",
        "",
        "1. " + ("Connect to the service now." if conn_info else "Inspect distfiles now."),
        "2. Keep using tools until you have the flag.",
        "3. **Be creative and thorough** — try the obvious path, then explore further:",
        "   - Hidden files, env vars, backup files, HTTP headers, error messages, timing, encoding tricks.",
        f"   - {image_hint}",
        f"   - {web_hint}",
        (
            "   - Crypto: identify algorithm, weak keys, nonce reuse, padding oracles. "
            "For RSA: use `RsaCtfTool`, sage ECM, or `cado-nfs`."
        ),
        "   - Pwn: `stty raw -echo` before launching vulnerable binaries over nc.",
        '4. **Ignore placeholder flags** — `CTF{flag}`, `CTF{placeholder}`, '
        '`NOT_FOUND`, `UNKNOWN`, `N/A`, etc. are not real flags. **Never invent '
        'a flag value.**',
        f"5. {submit_hint}",
        "6. Once CORRECT: output `FLAG: <value>` on its own line.",
        "7. Do not guess. Do not ask. Cover maximum surface area.",
        f"8. {note_hint}",
        '9. **Structured output discipline**: emit `{type: "flag_found", flag, '
        'method}` ONLY when you have actually executed the exploit, read the '
        'real flag value from the service or filesystem, and the value matches '
        "the challenge's expected shape. If you have genuinely exhausted your "
        'ideas, emit `{type: "gave_up", reason}` honestly — the platform will '
        'retry with sibling insights. Submitting a placeholder under '
        '`flag_found` is treated as a wrong answer.',
    ]

    return "\n".join(lines)
