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

    # Persistent flag-attempt log (sqlite). None disables.
    # The CLI's --attempt-log-path / --no-attempt-log flags overwrite this.
    # When a session is active (see backend.session), this is overridden to
    # sessions/<NAME>/logs/attempts.db so each session has its own log.
    attempt_log_path: str | None = "logs/attempts.db"

    # Active session name. Resolved by SessionContext via --session flag,
    # CTF_SESSION env, or .ctf-session dotfile; falls back to "default".
    # When a session is active, path-bearing settings (challenges_dir,
    # writeups_dir, attempt_log_path, preserve_workspace_to) are rerooted
    # under sessions/<NAME>/ unless explicitly overridden.
    session_name: str = "default"

    # Token / cost usage log (sqlite). Default lives in the session dir.
    # Set to None to disable usage persistence.
    usage_log_path: str | None = "logs/usage.db"

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
