"""Concrete `ExecEnv` implementations.

The ABC lives in `backend.exec_env`. Implementations are split into their
own modules so each can carry its transport-specific dependencies and
helpers without bloating the core abstraction:

  - `ssh` — generic key-auth SSH with ControlMaster (Linux remotes).
  - `pwncollege` — pwn.college workspace, which wraps `SSHEnv` with the
    workspace pre-flight + key provisioning logic.

The local Docker impl lives in `backend.sandbox` for legacy import paths.
"""
