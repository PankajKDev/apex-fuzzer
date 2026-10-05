# Apex-Fuzzer runtime image (pinned minor, slim).
# DAST binaries (nuclei, httpx, katana, …) are NOT baked in: install
# them inside a running container with `apex-fuzzer --update` (needs
# Go) or mount a tools volume. The scanner degrades gracefully when
# a binary is missing (logs the skip, see --doctor).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd -m apex \
    && apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md config.yaml ./
COPY main ./main
RUN pip install --no-cache-dir . \
    && apex-fuzzer --help > /dev/null

USER apex
WORKDIR /work
ENTRYPOINT ["apex-fuzzer"]
CMD ["--help"]
