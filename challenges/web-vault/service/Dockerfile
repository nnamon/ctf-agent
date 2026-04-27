FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.0.* pyjwt==2.* requests==2.*

COPY app.py /app/app.py
COPY flag.txt /flag.txt
COPY setup_repo.sh /tmp/setup_repo.sh

RUN bash /tmp/setup_repo.sh && rm /tmp/setup_repo.sh

WORKDIR /app
EXPOSE 8080

# Same value as the leaked-and-then-"rotated" commit — the realistic mistake.
ENV JWT_SECRET=tr1cky_4nd_pl41n

CMD ["python", "app.py"]
