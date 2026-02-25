# ── Stage 1: Build ────────────────────────────────────────────────────────────
# golang:1.19-bullseye uses Go 1.19 (superseded; several stdlib CVEs were
# patched in later minor releases) on Debian 11 (Bullseye). Snyk will flag
# the outdated Go toolchain and Bullseye OS-package CVEs present in the builder.
FROM golang:1.19-bullseye AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o weak-go-app .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# debian:stretch is Debian 9, which reached End-of-Life in June 2022.
# No security patches have been applied since that date, leaving hundreds of
# unpatched CVEs in core system libraries — openssl, glibc, curl, bash, apt —
# that Snyk Container will surface and score.
#
# Additional Dockerfile-level weaknesses introduced below:
#   • No USER directive        → process runs as root (CWE-250)
#   • Credentials in ENV       → visible via `docker inspect` (CWE-312 / CWE-798)
#   • Private key copied in    → baked into every registry layer (CWE-312)
FROM debian:stretch

# CWE-312 / CWE-798: Hardcoded credentials baked into the image as environment
# variables. They are readable via `docker inspect`, written into the image
# manifest, and exposed to every process running in the container.
ENV DB_HOST=db \
    DB_PORT=5432 \
    DB_USER=admin \
    DB_PASSWORD=admin123 \
    API_KEY=sk-abc123secretkey9876 \
    JWT_SECRET=secret

WORKDIR /app

COPY --from=builder /app/weak-go-app .

# The TLS private key is copied directly into the image, making it part of
# every layer pushed to a container registry. Anyone who can pull the image
# can extract the key. CWE-312: Cleartext Storage of Sensitive Information.
COPY cert.pem key.pem ./

# No USER instruction — the application process runs as uid 0 (root) inside
# the container. CWE-250: Execution with Unnecessary Privileges.

EXPOSE 8443
CMD ["./weak-go-app"]
