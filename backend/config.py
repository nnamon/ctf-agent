"""Pydantic Settings — credentials from .env file + environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # CTFd
    ctfd_url: str = "http://localhost:8000"
    ctfd_user: str = "admin"
    ctfd_pass: str = "admin"
    ctfd_token: str = ""

    # API Keys
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""

    # Provider-specific (optional, for Bedrock/Azure/Zen fallback)
    aws_region: str = "us-east-1"
    aws_bearer_token: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    opencode_zen_api_key: str = ""

    # Infra
    sandbox_image: str = "ctf-sandbox"
    max_concurrent_challenges: int = 10
    max_attempts_per_challenge: int = 3
    container_memory_limit: str = "16g"
    # Per-swarm Docker NetworkMode override. Empty → bridge (default).
    # Set by the swarm at run time when the backend reports a VPN
    # sidecar is up (HtbMachinesBackend) — solver containers then attach
    # via "container:<sidecar>" to share its tun0 route. Mutated for the
    # duration of one machine swarm and reset to "" on teardown.
    sandbox_network_mode: str = ""

    # Persistent flag-attempt log (sqlite). None disables.
    # The CLI's --attempt-log-path / --no-attempt-log flags overwrite this.
    # When a session is active (see backend.session), this is overridden to
    # sessions/<NAME>/logs/session.db (the unified schema-v2 file holding
    # attempts + usage + challenge_solves + challenge_solve_models).
    attempt_log_path: str | None = "logs/session.db"

    # Active session name. Resolved by SessionContext via --session flag,
    # CTF_SESSION env, or .ctf-session dotfile; falls back to "default".
    # When a session is active, path-bearing settings (challenges_dir,
    # writeups_dir, attempt_log_path, preserve_workspace_to) are rerooted
    # under sessions/<NAME>/ unless explicitly overridden.
    session_name: str = "default"

    # Token / cost usage log (sqlite). Default lives in the session dir.
    # Set to None to disable usage persistence. Schema v2 unifies this
    # with the attempt log into one session.db.
    usage_log_path: str | None = "logs/session.db"

    # Per-session quota cap (USD). When set, swarm spawns are blocked
    # once the session-cumulative cost (persisted + current process)
    # would exceed this number. Sourced from session.yml's quota_usd.
    quota_usd: float | None = None

    # When True, every flag submission pauses for stdin operator approval
    # before reaching the inner backend. Set via CLI --confirm-flags.
    manual_confirm: bool = False

    # CTFd session-cookie auth (used when API token is unavailable, e.g.
    # behind an email-confirmation gate). When set, make_backend() routes
    # to CTFdSessionBackend instead of CTFdBackend.
    ctfd_session_cookie: str = ""
    ctfd_csrf_token: str = ""  # optional pre-extracted nonce; bound to the cookie

    # ── Backend selector ──
    # Which Backend implementation make_backend() picks. Empty string
    # means "auto-detect" — make_backend picks CTFdBackend /
    # CTFdSessionBackend based on whether a session cookie is set.
    # Set to "pwncollege" to force the dojo plugin backend, scoped to
    # the dojos in `pwncollege_dojos`. Other valid values: "ctfd",
    # "ctfd-session", "local".
    backend_kind: str = ""

    # ── pwn.college backend params ──
    # Comma-separated dojo IDs (e.g. "welcome,intro-to-cybersecurity") to
    # scope discovery to. Empty list walks every visible dojo, which is
    # rarely useful — set this explicitly per session.
    pwncollege_dojos: list[str] = []
    # SSH keypair used to reach hacker@dojo.pwn.college. When empty, an
    # ed25519 keypair is auto-minted under sessions/<name>/secrets/ on
    # first start and the public half is uploaded to /api/v1/keys.
    pwncollege_ssh_key: str = ""
    pwncollege_ssh_host: str = "dojo.pwn.college"
    pwncollege_ssh_port: int = 22
    pwncollege_ssh_user: str = "hacker"
    # Whether to wipe /home/hacker between challenges. Default: yes —
    # solver runs are isolated. Disable when chaining challenges that
    # depend on prior workspace artifacts.
    pwncollege_reset_home_on_switch: bool = True

    # ── pwnable.kr backend params ──
    # Optional pre-supplied numeric account id. When unset, the backend
    # discovers it lazily from rank.php?id=<username>. Setting it
    # explicitly skips the rank-page round-trip and works around the
    # case where the user is too low-ranked to appear on the focused
    # rank page (rare).
    pwnablekr_user_id: str = ""

    # ── HackTheBox Labs backend params ──
    # Personal app token from app.hackthebox.com → Profile → App Tokens.
    # Audience claim must be `aud:5` (labs platform). The CTF events
    # MCP token (`aud:1`) is NOT interchangeable.
    htb_app_token: str = ""

    # ── HackTheBox Machines backend params ──
    # VPN server id to bind the sidecar tunnel to. 0 = use HTB's
    # auto-assigned server (read from /connections/servers `assigned`).
    # Override (e.g. 254 for "US Machines 3") if latency matters or the
    # auto-assigned server is full.
    htb_machines_server_id: int = 0
    # Sidecar image for the OpenVPN tunnel. Defaults to ctf-vpn (a thin
    # alpine+openvpn image built alongside ctf-sandbox in CI). Kept
    # separate so non-machine solver containers don't carry openvpn.
    htb_vpn_image: str = "ctf-vpn"

    # ── HackTheBox CTF events (MCP backend) params ──
    # Personal MCP token from app.hackthebox.com → AI Agents → MCP Token.
    # Audience claim must be `aud:1` with scope `mcp:use`. Distinct from
    # the labs/machines app token (`aud:5`).
    htb_mcp_token: str = ""
    # CTF event id to scope all MCP calls to. Required for the
    # htb-ctf-mcp backend — find it in the URL when viewing the event
    # at ctf.hackthebox.com/events/<id>.
    htb_mcp_event_id: int = 0

    # ── HackTheBox CTF events (creds backend) params ──
    # Bearer JWT (audience claim aud:2) from a logged-in browser session.
    # DevTools → Network → any /api/* XHR → Request Headers → copy the
    # `authorization` value (just the JWT, no `Bearer ` prefix).
    # Tokens are good for ~3 days; refresh from a logged-in browser
    # when they expire.
    htb_creds_bearer_token: str = ""
    # CTF event id (same numbering as the MCP backend).
    htb_creds_event_id: int = 0

    # ── Multi-env registry ──
    # Comma-separated env names to register beyond `local` (which is
    # always present). Recognised values: "pwncollege". Auto-set to
    # "pwncollege" when backend_kind is "pwncollege".
    exec_envs: list[str] = []

    # ── Challenge skip-list ──
    # Glob patterns matched against challenge names. Anything matching
    # any pattern is filtered out of the coordinator's unsolved list and
    # rejected if explicitly spawned. Set per session (e.g. for
    # pwn.college's `linux-luminarium/destruction/*` challenges that
    # deliberately wipe the workspace and can't be recovered without a
    # tool the solver doesn't have). fnmatch syntax: *, ?, [seq].
    skip_challenges: list[str] = []

    # Orchestration primitives — populated by --context / --preserve-workspace
    # CLI flags. An external orchestrator (e.g. another agent invoking
    # ctf-solve repeatedly) uses these to pass artifacts between chained
    # challenges.
    #   context_files: paths to host-side files mounted read-only at
    #                  /challenge/context/<basename> in every solver sandbox.
    #                  Text-ish ones are also embedded in the system prompt.
    #   preserve_workspace_to: if set, each solver copies its workspace to
    #                  <this>/<model_spec>/ before tearing down. Used by the
    #                  orchestrator to pull artifacts back out after a solve.
    context_files: list[str] = []
    preserve_workspace_to: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
