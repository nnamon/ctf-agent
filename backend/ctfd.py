"""Backwards-compatibility shim.

The CTFd client moved to `backend.backends.ctfd.CTFdBackend`. Existing code
that imports `from backend.ctfd import CTFdClient, SubmitResult` keeps
working via these re-exports. New code should import from
`backend.backends` directly.
"""

from backend.backends.base import SubmitResult
from backend.backends.ctfd import CTFdBackend

# Legacy alias — keeps `from backend.ctfd import CTFdClient` callers happy.
CTFdClient = CTFdBackend

__all__ = ["CTFdClient", "CTFdBackend", "SubmitResult"]
