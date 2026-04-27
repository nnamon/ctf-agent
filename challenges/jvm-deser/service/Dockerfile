FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/build
COPY src/ ./
COPY flag.txt /srv/flag.txt

RUN javac *.java \
 && jar cfe /srv/token-service.jar Server *.class \
 && cd / && rm -rf /srv/build \
 && chmod 644 /srv/flag.txt

RUN useradd -r -d /srv -s /bin/sh chall \
 && chown root:chall /srv \
 && chmod 755 /srv

USER chall
EXPOSE 1337

CMD ["java", "-jar", "/srv/token-service.jar"]
