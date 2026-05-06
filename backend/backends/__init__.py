"""Pluggable backends for CTF integrations.

Solvers, the coordinator, and the poller all consume the `Backend` ABC
defined in `base.py`. Concrete backends live in their own modules:

  - `ctfd.CTFdBackend`  : standard CTFd HTTP API (token or session auth)
  - `local.LocalBackend`: no-op for offline runs without a real CTF server

To add a new backend, subclass `Backend` and implement the seven methods,
then either pass an instance directly to the swarm/solvers or extend
`make_backend()` so it can be selected via the CLI.
"""

from pathlib import Path

from backend.backends.attempt_log import AttemptLogBackend
from backend.backends.base import Attempt, Backend, SubmitResult
from backend.backends.ctfd import CTFdBackend, CTFdSessionBackend
from backend.backends.htb_ctf_creds import HtbCtfCredsBackend
from backend.backends.htb_ctf_mcp import HtbCtfMcpBackend
from backend.backends.htb_labs import HtbLabsBackend
from backend.backends.htb_machines import HtbMachinesBackend
from backend.backends.local import LocalBackend
from backend.backends.manual_confirm import ManualConfirmBackend
from backend.backends.pwnablekr import PwnableKrBackend
from backend.backends.pwnabletw import PwnableTwBackend
from backend.backends.pwncollege import PwnCollegeBackend


def make_backend(
    *,
    kind: str | None = None,
    base_url: str = "",
    token: str = "",
    username: str = "admin",
    password: str = "admin",
    session_cookie: str = "",
    csrf_token: str = "",
    attempt_log_path: str | Path | None = None,
    manual_confirm: bool = False,
    pwncollege_dojos: list[str] | None = None,
    pwnablekr_user_id: str = "",
    htb_app_token: str = "",
    htb_machines_server_id: int = 0,
    htb_vpn_image: str = "ctf-vpn",
    htb_mcp_token: str = "",
    htb_mcp_event_id: int = 0,
    htb_creds_bearer_token: str = "",
    htb_creds_event_id: int = 0,
) -> Backend:
    """Construct a backend by kind, optionally wrapped with decorators.

    `kind` overrides URL-based detection. Auto-selection rules (when
    `kind` is None):
      - "local"        when base_url is empty / "local" / "none" /
                       "http://unused.invalid"
      - "ctfd-session" when a session_cookie is provided
                       (use this for CTFd instances behind email-confirm
                       gates that block API tokens)
      - "ctfd"         otherwise

    Decorator stack (innermost first):
      1. concrete backend (CTFd / CTFdSession / Local)
      2. AttemptLogBackend   if attempt_log_path is set
      3. ManualConfirmBackend if manual_confirm is True

    Order matters: ManualConfirmBackend is outermost, so the operator's
    "deny" never reaches the AttemptLog (no row for refused submissions).
    A confirmed flag DOES land in AttemptLog as usual.
    """
    if kind is None:
        u = (base_url or "").strip().lower()
        if not u or u in {"local", "none"} or u.startswith("http://unused"):
            kind = "local"
        elif session_cookie:
            kind = "ctfd-session"
        else:
            kind = "ctfd"

    kind = kind.lower()
    if kind == "ctfd":
        inner: Backend = CTFdBackend(
            base_url=base_url, token=token, username=username, password=password
        )
    elif kind in ("ctfd-session", "ctfd_session", "ctfdsession"):
        inner = CTFdSessionBackend(
            base_url=base_url,
            token=token,                       # optional, kept for fall-through
            username=username, password=password,
            session_cookie=session_cookie,
        )
        # If operator pre-extracted the CSRF nonce, install it so the first
        # POST doesn't need to scrape /challenges. Bound to the same session.
        if csrf_token:
            inner._csrf_token = csrf_token
    elif kind in ("pwnabletw", "pwnable.tw", "pwntw"):
        inner = PwnableTwBackend(
            base_url=base_url or "https://pwnable.tw",
            username=username,
            password=password,
        )
    elif kind in ("pwnablekr", "pwnable.kr", "pwnkr"):
        inner = PwnableKrBackend(
            base_url=base_url or "https://pwnable.kr",
            username=username,
            password=password,
            user_id=pwnablekr_user_id or "",
        )
    elif kind in ("pwncollege", "pwn.college", "dojo"):
        inner = PwnCollegeBackend(
            base_url=base_url or "https://pwn.college",
            username=username,
            password=password,
            session_cookie=session_cookie,
            dojos=list(pwncollege_dojos or []),
        )
        if csrf_token:
            inner._csrf_token = csrf_token
    elif kind in ("htb-labs", "htb_labs", "hackthebox", "hackthebox-labs"):
        inner = HtbLabsBackend(app_token=htb_app_token)
    elif kind in ("htb-machines", "htb_machines", "hackthebox-machines"):
        inner = HtbMachinesBackend(
            app_token=htb_app_token,
            server_id=htb_machines_server_id,
            sidecar_image=htb_vpn_image,
        )
    elif kind in ("htb-ctf-mcp", "htb_ctf_mcp", "hackthebox-ctf"):
        inner = HtbCtfMcpBackend(
            mcp_token=htb_mcp_token,
            event_id=htb_mcp_event_id,
        )
    elif kind in ("htb-ctf-creds", "htb_ctf_creds", "hackthebox-ctf-creds"):
        inner = HtbCtfCredsBackend(
            bearer_token=htb_creds_bearer_token,
            event_id=htb_creds_event_id,
            sidecar_image=htb_vpn_image,
        )
    elif kind == "local":
        inner = LocalBackend()
    else:
        raise ValueError(f"unknown backend kind: {kind!r}")

    if attempt_log_path is not None:
        inner = AttemptLogBackend(inner=inner, db_path=Path(attempt_log_path))
    if manual_confirm:
        inner = ManualConfirmBackend(inner=inner)
    return inner


__all__ = [
    "Attempt", "Backend", "SubmitResult",
    "CTFdBackend", "CTFdSessionBackend", "LocalBackend",
    "PwnCollegeBackend", "PwnableKrBackend", "PwnableTwBackend",
    "HtbLabsBackend", "HtbMachinesBackend", "HtbCtfMcpBackend",
    "HtbCtfCredsBackend",
    "AttemptLogBackend", "ManualConfirmBackend",
    "make_backend",
]
