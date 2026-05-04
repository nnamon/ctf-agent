FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    socat \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY chall.c /srv/chall.c
COPY flag.txt /srv/flag.txt

# Build the vulnerable binary:
#   -fno-stack-protector  : no canary
#   -no-pie               : fixed code address
#   NX is on by default; libc ASLR remains, forcing a leak.
RUN gcc -O0 -fno-stack-protector -no-pie -o /srv/chall /srv/chall.c \
 && chmod 755 /srv/chall \
 && chmod 644 /srv/flag.txt

# Unprivileged user. The container itself runs as chall (no socat setuid
# dance — that needs caps that linux/amd64 emulation drops on Apple Silicon).
RUN useradd -r -d /srv -s /bin/sh chall \
 && chown -R root:chall /srv \
 && chmod 750 /srv

USER chall
EXPOSE 1337

CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork,nodelay", "EXEC:/srv/chall,stderr"]
