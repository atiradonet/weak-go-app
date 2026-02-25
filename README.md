# weak-go-app

> **WARNING — INTENTIONALLY VULNERABLE APPLICATION**
> Every vulnerability in this repository is deliberate. Do not deploy this
> application in any environment where it is reachable by untrusted users.
> See [Responsible Use](#responsible-use) before proceeding.

A purpose-built, intentionally insecure Go web application designed to
demonstrate the full breadth of [Snyk](https://snyk.io) scanning capabilities
across all four product pillars:

| Snyk Product | What it scans in this repo |
|---|---|
| **Snyk Code** | Go source files in `handlers/`, `db/`, `main.go` |
| **Snyk Open Source** | `go.mod` — vulnerable dependency versions |
| **Snyk Container** | `Dockerfile` — weak base images and Dockerfile misconfigs |
| **Snyk IaC** | `terraform/` — GCP misconfigurations |

---

## Responsible Use

This repository exists solely for **security education, tooling demonstrations,
and authorised security testing**. By using it you accept the following:

- **Never expose this application to the internet** or any network where
  untrusted users could reach it. The command-injection endpoint (`/exec`)
  alone gives an attacker a root shell.
- **Never store real credentials** in this repository. All secrets shown are
  fake values used to trigger SAST findings.
- **Never deploy to a shared or production GCP project.** The Terraform
  deliberately grants `roles/owner` to a build service account and makes the
  Cloud Run service publicly invocable without authentication.
- Use an **isolated, throwaway GCP project** if you run the infrastructure.
  Tear it down immediately after the demonstration.
- Comply with all applicable laws and your organisation's security policy.

---

## Vulnerability Catalogue

### Snyk Code — SAST findings (Go source)

| File | CWE | Description |
|---|---|---|
| `db/db.go` | CWE-798 | Hardcoded database credentials in source |
| `main.go` | CWE-327 | Insecure TLS — TLS 1.0 minimum, weak cipher suites |
| `handlers/auth.go` | CWE-547 / CWE-798 / CWE-259 | Hardcoded API key and admin password |
| `handlers/auth.go` | CWE-200 / CWE-312 | Credentials logged in plaintext |
| `handlers/auth.go` | CWE-1004 / CWE-614 | Session cookie missing `HttpOnly` and `Secure` flags |
| `handlers/crypto.go` | CWE-916 / CWE-327 | MD5 used for password hashing |
| `handlers/crypto.go` | CWE-327 | DES encryption (56-bit key, deprecated algorithm) |
| `handlers/crypto.go` | CWE-330 | `math/rand` used for security token generation |
| `handlers/crypto.go` | CWE-326 | RSA key generated at 512 bits (minimum is 2048) |
| `handlers/crypto.go` | CWE-295 | `InsecureSkipVerify: true` — TLS certificate not validated |
| `handlers/data.go` | CWE-89 | SQL injection — user input concatenated into query string |
| `handlers/data.go` | CWE-79 | Reflected XSS — query parameter written raw into HTML |
| `handlers/data.go` | CWE-643 | XPath injection — username concatenated into XPath |
| `handlers/email.go` | CWE-284 | Email header injection via unsanitised SMTP fields |
| `handlers/files.go` | CWE-23 | Path traversal — filename appended without sanitisation |
| `handlers/files.go` | CWE-96 | Server-side template injection via `text/template` |
| `handlers/network.go` | CWE-918 | SSRF — caller-supplied URL fetched server-side |
| `handlers/network.go` | CWE-601 | Open redirect — caller-supplied destination not validated |
| `handlers/system.go` | CWE-78 | OS command injection — input passed to `sh -c` |
| `handlers/system.go` | CWE-209 | Sensitive information in error messages |
| `handlers/jwt.go` | CWE-798 / CWE-345 | Hardcoded JWT secret; `alg=none` bypass; no `aud` validation |
| `handlers/config.go` | CWE-20 | Untrusted YAML unmarshalled with no size or content limits |
| `handlers/json.go` | CWE-20 | User-controlled gjson path allows arbitrary field traversal |

### Snyk Open Source — SCA findings (`go.mod`)

| Package | Pinned version | CVE | Impact |
|---|---|---|---|
| `github.com/dgrijalva/jwt-go` | v3.2.0+incompatible | CVE-2020-26160 | Audience claim not validated → token forgery |
| `gopkg.in/yaml.v2` | v2.2.2 | CVE-2022-28948 / CVE-2021-4235 | Malformed YAML triggers panic → remote DoS |
| `github.com/tidwall/gjson` | v1.6.0 | CVE-2020-36067 | Integer overflow in path processing → panic |

### Snyk Container — findings (`Dockerfile`)

| Layer | Base image | Why it is weak |
|---|---|---|
| Build | `golang:1.19-bullseye` | Go 1.19 has stdlib CVEs fixed in later releases; Bullseye OS packages unpatched |
| Runtime | `debian:stretch` | Debian 9 — End of Life June 2022; 300+ unpatched OS CVEs (openssl, glibc, curl, bash) |
| DB service | `postgres:11-alpine` | PostgreSQL 11 — End of Life November 2023 |

Additional Dockerfile misconfigurations:

- No `USER` directive — process runs as root (CWE-250)
- Credentials baked into `ENV` — visible via `docker inspect` (CWE-798 / CWE-312)
- TLS private key copied into the image and stored in every registry layer (CWE-312)
- `.dockerignore` intentionally omits `*.pem`

### Snyk IaC — findings (`terraform/`)

| Resource | Misconfiguration | CWE |
|---|---|---|
| `google_cloud_run_v2_service` | `INGRESS_TRAFFIC_ALL` — direct public internet ingress | CWE-284 |
| `google_cloud_run_v2_service_iam_member` | `allUsers` invoker — unauthenticated public access | CWE-284 |
| `google_cloud_run_v2_service` | Hardcoded secrets in `env {}` blocks instead of Secret Manager | CWE-798 |
| `google_cloud_run_v2_service` | No VPC connector — egress over public internet | CWE-284 |
| `google_artifact_registry_repository_iam_member` | `allUsers` reader — public image pull | CWE-284 |
| `google_artifact_registry_repository` | No CMEK — Google-managed encryption only | — |
| `google_project_iam_member` (Cloud Run SA) | `roles/editor` — primitive role, over-privileged | CWE-250 |
| `google_project_iam_member` (Cloud Build SA) | `roles/owner` — maximum project privilege | CWE-250 |
| `google_service_account_key` | Static key material written to `terraform.tfstate` | CWE-798 |
| `google_project_iam_member` (storage) | `allAuthenticatedUsers` → Storage Object Viewer | CWE-284 |
| `google_cloudbuild_trigger` | Secrets in substitution variables → appear in build logs | CWE-312 |
| `outputs.tf` | SA key output not marked `sensitive = false` | CWE-312 |
| `main.tf` | No remote backend — `terraform.tfstate` stored locally | CWE-312 |

---

## Project Structure

```
weak-go-app/
├── main.go                  # HTTP server with insecure TLS configuration
├── go.mod                   # Module definition with vulnerable dependency pins
├── Dockerfile               # Multi-stage build: golang:1.19-bullseye → debian:stretch
├── docker-compose.yml       # App + postgres:11-alpine with exposed DB port
├── cloudbuild.yaml          # Cloud Build pipeline (secrets in substitution vars)
├── db/
│   └── db.go                # DB init with hardcoded credentials
├── handlers/
│   ├── auth.go              # Hardcoded creds, cleartext logging, insecure cookies
│   ├── config.go            # YAML parse — CVE-2022-28948 (yaml.v2)
│   ├── crypto.go            # MD5, DES, math/rand token, RSA-512, InsecureSkipVerify
│   ├── data.go              # SQL injection, XSS, XPath injection
│   ├── email.go             # Email header injection via raw SMTP
│   ├── files.go             # Path traversal, server-side template injection
│   ├── json.go              # gjson path query — CVE-2020-36067
│   ├── jwt.go               # JWT — CVE-2020-26160, alg=none bypass
│   ├── network.go           # SSRF, open redirect
│   └── system.go            # OS command injection, sensitive info in errors
└── terraform/
    ├── main.tf              # Provider (no remote backend)
    ├── variables.tf
    ├── artifact_registry.tf # Public registry reader
    ├── iam.tf               # Over-privileged SAs, static key, allAuthenticated
    ├── cloud_build.tf       # Secrets in substitutions, no approval gate
    ├── cloud_run.tf         # Public invoker, plaintext env secrets
    └── outputs.tf           # SA key output, not marked sensitive
```

---

## Quick Start

### Prerequisites

- Go 1.21+
- Docker and Docker Compose
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) (`npm install -g snyk`)
- Terraform 1.3+ (for IaC scanning only)

### Run locally with Docker Compose

```bash
# Generate a self-signed certificate (required by the TLS server)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"

# Fetch Go dependencies
go mod tidy

# Build and start the application and database
docker compose up --build
```

The server listens on `https://localhost:8443`. Because it uses a self-signed
certificate and TLS 1.0, most browsers and `curl` will reject it by default.
Use `curl -k` for local testing.

### Run Snyk scans

```bash
# Authenticate once
snyk auth

# Snyk Code — SAST
snyk code test

# Snyk Open Source — SCA
snyk test

# Snyk Container
snyk container test weak-go-app --file=Dockerfile

# Snyk IaC
snyk iac test terraform/
```

---

## GCP Deployment (Terraform)

> Only proceed in an **isolated, throwaway GCP project** you can delete
> after the demonstration.

```bash
cd terraform

# Initialise providers
terraform init

# Review the plan — note every misconfiguration listed in the IaC section above
terraform plan -var="project_id=YOUR_PROJECT_ID"

# Apply — this creates real, publicly accessible infrastructure
terraform apply -var="project_id=YOUR_PROJECT_ID"

# Scan the infrastructure with Snyk before or after apply
snyk iac test .

# Destroy everything when done
terraform destroy -var="project_id=YOUR_PROJECT_ID"
```

Cloud Build will trigger on every push to `main`, build the image, and deploy
it to the unauthenticated Cloud Run service. The URL is printed as a Terraform
output.

---

## Licence

This project is released under the [MIT License](LICENSE). You are free to
use, copy, modify, and distribute it for any purpose. The risks of doing so
are yours to own.

This repository contains code that is **deliberately and extensively
insecure**. The warnings in this README constitute explicit, written notice
of those risks. Anyone who deploys, adapts, or redistributes this code has
been informed of its nature. The MIT License's "AS IS" warranty disclaimer
applies in full — the authors accept no liability arising from any use of
this software.
