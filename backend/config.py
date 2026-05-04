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
    attempt_log_path: str | None = "logs/attempts.db"

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
