ARG IMAGE=debian:stable
FROM $IMAGE

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y gcc python3 python3-dev softhsm2 openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /test

ADD uv.lock pyproject.toml setup.py .
ADD pkcs11/ pkcs11/
ADD extern/ extern/

ENV UV_LINK_MODE=copy
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --all-extras

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV PKCS11_TOKEN_LABEL=TEST
ENV PKCS11_TOKEN_PIN=1234
ENV PKCS11_TOKEN_SO_PIN=5678
RUN softhsm2-util --init-token --free --label TEST --pin 1234 --so-pin 5678

ADD tests/ tests/
CMD ["uv", "run", "pytest", "-v"]