# ctf-agent

Autonomous CTF solver. Drives multiple LLMs in parallel against a CTF
platform, scrapes/downloads challenges, runs solvers in isolated Docker
sandboxes, ships flags back, and writes a post-mortem markdown writeup
per solve.

Originally built to compete in a single weekend CTF and since extended
into a session-aware orchestrator that targets several CTF platforms
through a pluggable backend abstraction.

## Supported platforms

| Backend kind            | Platform              | Auth                                        |
| ----------------------- | --------------------- | ------------------------------------------- |
| `ctfd`                  | Standard CTFd         | API token                                   |
| `ctfd-session`          | CTFd (token-locked)   | Session cookie scraped from a logged-in tab |
| `pwncollege`            | pwn.college dojos     | Email + password (or session cookie)        |
| `pwnabletw`             | pwnable.tw            | Email + password (Django form-login)        |
| `local`                 | offline / no submit   | none                                        |

`PwnCollege` ships an SSH-into-workspace exec environment in addition to
the local Docker sandbox — solvers reach into the per-user pwn.college
container to read `/flag` while still using the local sandbox for
scratch work, RE, and exploit prep.

## Architecture

```
+----------------------------+
|  CTF backend (ctfd/        |  fetch challenges, submit flags, pull
|   pwncollege/pwnabletw/…)  |  distfiles, scrape solved-set
+--------------+-------------+
               |
+--------------v-------------+
|  Poller (5s)               |  delta-detect new/solved challenges
+--------------+-------------+
               |
+--------------v-------------+
|  Coordinator LLM           |  reads traces, picks targets, sends
|  (codex/claude)            |  bumps & broadcasts; never kills swarms
+--------------+-------------+
               |
        +------+--------+----------------+
        |               |                |
+-------v------+ +------v-------+ +------v-------+
| ChallengeSwarm   ChallengeSwarm   ChallengeSwarm
| 1 .. N solvers race per challenge
+-------+------+ +------+-------+ +------+-------+
        |               |                |
        |   +-----------v---+  +---------v---+
        |   | Local Docker  |  | (per env)   |
        |   | sandbox       |  | SSH→pwn.    |
        |   | (per solver)  |  | college     |
        |   +---------------+  +-------------+
        |
+-------v---------------------+
| Solver tool surface (bash,  |  pydantic-ai / codex app-server /
| read_file, write_file,      |  claude SDK — provider-specific
| list_files, list_envs,      |  agent loops, same tools.
| transfer, submit_flag,      |
| web_fetch, view_image, …)   |
+-----------------------------+
```

Solvers never give up — they continue trying different approaches with
coordinator guidance until the flag is found, the operator kills them,
or the per-session quota cap is hit.

## Quick start

```bash
uv sync                                                            # install deps
docker pull nnamon/ctf-agent:latest                                # ~8 GB compressed
docker tag nnamon/ctf-agent:latest ctf-sandbox                     # the runtime expects `ctf-sandbox`
```

The pre-built multi-arch image (linux/amd64 + linux/arm64) is published on
every push to main by the `sandbox-build.yml` workflow. Pin to a specific
build via `nnamon/ctf-agent:<commit-sha>` or `:vX.Y.Z` if you need a
reproducible artifact.

If you'd rather build the image yourself (e.g. you've patched
`sandbox/Dockerfile.sandbox` locally):

```bash
docker build -f sandbox/Dockerfile.sandbox -t ctf-sandbox .        # ~30 min on M1
```

Pick a session (one per CTF / engagement) and configure it:

```bash
mkdir -p sessions/myctf
cat > sessions/myctf/.env <<'EOF'
BACKEND_KIND=ctfd               # or pwncollege, pwnabletw, ctfd-session
CTFD_URL=https://ctf.example.com
CTFD_TOKEN=ctfd_xxxx            # or CTFD_USER + CTFD_PASS for form-login
EOF
cat > sessions/myctf/session.yml <<'EOF'
quota_usd: 25.0                 # halt new spawns once spent ≥ cap
EOF
```

Run the coordinator:

```bash
CTF_SESSION=myctf uv run ctf-solve \
  --models codex/gpt-5.5 \
  --models codex/gpt-5.4-mini \
  --max-challenges 5 \
  -v
```

Open the live dashboard at <http://localhost:13337/> (mobile-friendly).

### Single-challenge mode

```bash
CTF_SESSION=myctf uv run ctf-solve \
  --challenge sessions/myctf/challenges/my-chal \
  --models codex/gpt-5.5 \
  -v
```

## Sessions

A session lives at `sessions/<name>/` and holds everything specific to
one CTF: pulled challenges, writeups, attempt log, usage log, and any
per-session secrets.

```
sessions/myctf/
  .env             backend-kind, creds, runtime overrides (gitignored)
  session.yml      quota_usd, cleanup overrides, etc
  challenges/      pulled challenge dirs (slug + metadata.yml + distfiles)
  writeups/        post-mortem markdown, one per solve
  runs/            preserved workspaces from --preserve-workspace
  secrets/         pwn.college SSH keypair, known_hosts (auto-minted)
  logs/
    attempts.db    every flag submission; dedups repeats
    runs/<RUN_ID>/ per-run trace JSONLs
```

Resolution order for the active session: `--session NAME` →
`$CTF_SESSION` → `.ctf-session` dotfile → `default`.

`session.yml`:

```yaml
quota_usd: 20.0    # halt new swarm spawns when cumulative cost ≥ this
```

Per-session `.env` is layered on top of the repo-root `.env`, so global
provider keys live at the root and per-engagement creds + targets stay
in the session.

## Backends

Set `BACKEND_KIND` in the session's `.env` (or pass `--backend-kind`).

### CTFd (`ctfd`)

Standard CTFd. Token preferred; otherwise `CTFD_USER` + `CTFD_PASS`
form-login.

```env
BACKEND_KIND=ctfd
CTFD_URL=https://ctf.example.com
CTFD_TOKEN=ctfd_...
```

### CTFd session-cookie (`ctfd-session`)

For CTFd instances behind email-verification gates that block API
token issuance:

```env
BACKEND_KIND=ctfd-session
CTFD_URL=https://ctf.example.com
CTFD_SESSION_COOKIE=...    # paste the `session` cookie from devtools
```

### pwn.college (`pwncollege`)

Form-login (or session cookie) + a per-user workspace container the
agent SSHes into. The `pwncollege` exec env auto-mints an ed25519
keypair under `sessions/<name>/secrets/`, registers it via
`/pwncollege_api/v1/ssh_key`, and POSTs `/pwncollege_api/v1/docker`
to spawn the workspace before each challenge.

```env
BACKEND_KIND=pwncollege
CTFD_URL=https://pwn.college
CTFD_USER=you@example.org
CTFD_PASS=...
PWNCOLLEGE_DOJOS=["welcome", "linux-luminarium"]
MAX_CONCURRENT_CHALLENGES=1     # platform has a per-account workspace lock
SKIP_CHALLENGES=["*/destruction/*"]   # see "Skip list" below
```

### pwnable.tw (`pwnabletw`)

Django form-login + HTML scraping for the listing page; standard CTF
shape (download binary, exploit remote service, submit flag).

```env
BACKEND_KIND=pwnabletw
CTFD_URL=https://pwnable.tw
CTFD_USER=you@example.org
CTFD_PASS=...
```

The backend rate-limits its own `/api/v1/docker`-style POSTs so we
don't trip per-account caps the platform doesn't always advertise.

### Local (`local`)

No flag submission. Useful for testing the solver loop on
hand-curated challenge dirs.

## Skip list

`SKIP_CHALLENGES` (fnmatch globs) tells the coordinator to never
attempt matching challenges. Used for slugs that are unrecoverable
through the agent's tools — e.g. pwn.college's `linux-luminarium/
destruction/*` family deliberately wipes the workspace filesystem and
the agent can't reset the workspace from the solver side.

```env
SKIP_CHALLENGES=["*/destruction/*", "*manual-only*"]
```

## Coordinator + solver model selection

```bash
# Coordinator (one of: codex, claude). Default: codex.
--coordinator codex
--coordinator-model codex/gpt-5.5      # override the coordinator model

# Solvers — one --models flag per spec
--models codex/gpt-5.5
--models codex/gpt-5.4-mini
--models claude-sdk/claude-opus-4-7

# Per-solve writeup model — provider-agnostic, routes via prefix.
# Default is claude-opus-4-7: empirically the best fit for the
# rigorous-postmortem prompt (codex/gpt-5.5 reasoning passes can stall
# past the 900s text_completion timeout on large traces).
--writeup-model claude-opus-4-7        # claude SDK (default)
--writeup-model codex/gpt-5.5          # codex app-server one-shot
--writeup-model bedrock/...            # pydantic-ai
```

Solver provider routing:

| Spec prefix              | Runtime                               |
| ------------------------ | ------------------------------------- |
| `codex/...`              | `codex app-server` JSON-RPC           |
| `claude-sdk/...`         | Claude Agent SDK (subscription auth)  |
| `bedrock/azure/zen/google/...` | Pydantic AI                     |

Codex and Claude SDK use subscription auth (no API key). The Pydantic
AI providers need API keys in the root `.env`.

## Multi-target tool surface

When more than one exec env is registered (e.g. local + pwn.college
SSH), solvers see additional tools:

- `target` arg on `bash` / `read_file` / `write_file` / `list_files`
- `list_envs()` — names + descriptions of registered envs
- `transfer(src_target, src_path, dst_target, dst_path)`

Tool results are prefixed with `[<env>]` so the agent always knows
where a command actually ran. The default target is per-challenge:
the metadata.yml block (`pwncollege.exec_env: pwncollege`) sets it.

## Web dashboard

`http://<host>:13337/` (default port; falls back to OS-assigned if
13337 is busy). Bound to `0.0.0.0` so it's reachable on LAN/VPN —
**no auth**, so flip `--msg-host 127.0.0.1` for untrusted networks.

| What | Where |
| ---- | ----- |
| Per-challenge tile + status | scoreboard grid grouped by category |
| Currently-running swarms | `now` chip in the top app bar (clickable) |
| Cost vs quota | progress meter + red banner at 100% |
| Per-solver step counter, cost, captured flag | challenge detail panel |
| Live JSONL trace, structured | per-solver "Log" toggle |
| Markdown writeup | per-solve "Writeup" button |
| Coordinator messaging | global form + per-challenge form (auto-prefixed) |
| Kill swarm, re-spawn | detail panel actions |

Mobile-responsive (compact app bar, single-column tiles, touch targets).

## Sandbox tooling

Each solver runs in an isolated Docker container with the CTF toolchain
pre-installed:

| Category   | Tools                                                                    |
| ---------- | ------------------------------------------------------------------------ |
| Binary     | radare2, GDB (pwndbg/gef), objdump, binwalk, strings, readelf, DiE       |
| Pwn        | pwntools, ROPgadget, one_gadget, angr, unicorn, capstone, AFL++          |
| RE         | Ghidra (pyghidra), redress, frida, mingw-w64, qemu-user, Wine            |
| Crypto     | SageMath, RsaCtfTool, z3, gmpy2, pycryptodome, cado-nfs                  |
| Forensics  | volatility3, Sleuthkit, foremost, exiftool, tshark, scapy, plaso         |
| Stego      | steghide, stegseek, zsteg, ImageMagick, tesseract OCR                    |
| Web        | curl, ffuf, nuclei, Playwright, mitmproxy, ysoserial                     |
| Smart-ctr  | foundry, slither, mythril                                                |
| Misc       | Python (numpy, scipy, PyTorch, Pillow), ffmpeg, sox, Rust, Go, .NET      |

Concurrent sandbox starts are gated by a configurable semaphore
(`--max-concurrent-challenges`), and stale containers from prior runs
get reaped automatically.

## Cost tracking

Per-session SQLite log at `sessions/<name>/logs/usage.db` records every
turn's input/output/cache tokens, provider, agent name, and challenge.

```bash
ctf-tokens                      # quick summary
ctf-tokens --session myctf      # explicit session
```

`quota_usd` in `session.yml` is enforced at swarm-spawn time; new
swarms are refused once the cumulative session cost crosses the cap.
The dashboard goes red when this happens.

## Configuration knobs

Most things can be overridden via `--flag`, `SCREAMING_SNAKE_CASE` env
vars, or `session.yml` keys (in roughly that priority).

| What | CLI flag | Env / yaml |
| ---- | -------- | ---------- |
| Active session | `--session` | `CTF_SESSION` / `.ctf-session` |
| Backend kind | (autodetect) | `BACKEND_KIND` |
| Concurrency cap | `--max-challenges` | `MAX_CONCURRENT_CHALLENGES` |
| Quota cap (USD) | — | `quota_usd` in `session.yml` |
| Dashboard port | `--msg-port` | (default 13337) |
| Dashboard host | `--msg-host` | (default `0.0.0.0`) |
| Skip-list (globs) | — | `SKIP_CHALLENGES` |
| Pre-pulled challenges dir | `--challenges-dir` | (default per session) |
| Drop flag submissions | `--no-submit` | (CLI only) |
| Pause on each flag | `--confirm-flags` | (CLI only) |
| Skip writeup gen | `--no-writeup` | (CLI only) |
| Writeup model | `--writeup-model` | (CLI only) |

## Requirements

- Python 3.14+
- Docker
- `codex` CLI (for codex coordinator / solvers)
- `claude` CLI (bundled with `claude-agent-sdk`, for Claude solvers)
- API keys for any non-subscription providers you use (in repo-root `.env`)

## History

The original BSidesSF 2026 README — the version of this repo that won
1st place at that competition — is preserved at
[`docs/README-bsides-2026.md`](docs/README-bsides-2026.md).

## Acknowledgements

- [es3n1n/Eruditus](https://github.com/es3n1n/Eruditus) — CTFd
  interaction and HTML helpers in `pull_challenges.py`.
