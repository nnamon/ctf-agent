# Toy challenges + self-hosted CTFd

A small set of demo challenges plus a Docker Compose stack to host them
on a fresh CTFd. Used as the canonical end-to-end test target for
`ctf-agent` — quicker than waiting for a public CTF and lets you exercise
the full `ctf-pull → ctf-solve → dashboard → cost-tracking` loop offline.

## Layout

```
toy-challenges/
  docker-compose.yml          CTFd + mariadb + redis stack
  bootstrap.py                runs the /setup wizard, creates an API
                              token, registers each challenge below
  README.md                   this file
  toy-xor-b64/                crypto warmup, 50 pts. distfiles tracked.
  pwn-echo/                   classic ret2libc-style pwn, 300 pts.
                              Has its own service container.
  jvm-deser/                  Java deserialization, 350 pts.
  web-vault/                  web challenge with note-vault service, 200 pts.
```

The three service-bearing challenges (`pwn-echo`, `jvm-deser`,
`web-vault`) come with their own `build.sh` / `run.sh` / `stop.sh` and
do NOT track their built distfiles in git — operators run the build
script which regenerates them. `toy-xor-b64` tracks its `cipher.txt`
because there's no service to regenerate it from.

## Quick start

```bash
# 1. Bring up CTFd
cd toy-challenges
docker compose up -d

# 2. (optional) build the service-based challenges so distfiles exist
./pwn-echo/build.sh
./jvm-deser/build.sh
./web-vault/build.sh

# 3. Run the bootstrap — auths, creates an API token, registers everything
./bootstrap.py
# → writes the API token to ./token.txt
# → prints the next steps

# 4. Spin up the challenge services so connection_info actually works
./pwn-echo/run.sh        # nc localhost 9200
./jvm-deser/run.sh       # nc localhost 9300
./web-vault/run.sh       # http://localhost:9100

# 5. Configure ctf-agent to use this CTFd
cd ..
ctf-session create toys --ctfd-url http://localhost:12001 --quota-usd 1.00
ctf-session use toys
echo "CTFD_TOKEN=$(cat toy-challenges/token.txt)" >> sessions/toys/.env

# 6. Validate access (auth check + challenge list)
ctf-pull

# 7. Run the agent
ctf-solve --max-challenges 2 -v
# → dashboard at http://0.0.0.0:9400/
```

## Tearing it down

```bash
# Stop services first
./pwn-echo/stop.sh
./jvm-deser/stop.sh
./web-vault/stop.sh

# Then the CTFd stack
docker compose down            # keeps the database
docker compose down -v         # nukes the database too — fresh on next up
```

## How the agent should fare

| Challenge       | Difficulty | Expected outcome |
|-----------------|------------|------------------|
| `toy-xor-b64`   | trivial    | should solve in a few minutes — the description names "lemon" |
| `web-vault`     | medium     | exercises web-pentesting tools (curl, ffuf, jwt_tool) |
| `pwn-echo`      | hard       | classic ret2libc; pwntools + pwndbg get a workout |
| `jvm-deser`     | hard       | needs ysoserial-style payload crafting |

This is also a good way to regression-test new sandbox features.
After bumping the Dockerfile, a green run on the four toys is a
reasonable signal that nothing important broke.
