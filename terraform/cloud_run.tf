# ── Cloud Run service ─────────────────────────────────────────────────────────

locals {
  image_url = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.app_repo.repository_id}/${var.image_name}:latest"
}

resource "google_cloud_run_v2_service" "app" {
  project  = var.project_id
  name     = "weak-go-app"
  location = var.region

  # Snyk IaC: INGRESS_TRAFFIC_ALL allows the service to receive requests
  # from the public internet directly, bypassing any load balancer or WAF.
  # INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER should be used instead so that
  # traffic passes through a controlled entry point.
  # CWE-284: Improper Access Control.
  ingress = "INGRESS_TRAFFIC_ALL"

  # Snyk IaC: No binary_authorization block — the service accepts any image
  # from the registry without requiring attestation. An attacker who can push
  # to the public registry (see artifact_registry.tf) could deploy malicious
  # images directly.

  template {
    service_account = google_service_account.cloud_run_sa.email

    scaling {
      min_instance_count = 0   # Cold starts, but no lower bound concerns.
      max_instance_count = 100 # No cap on scaling — potential runaway cost.
    }

    containers {
      image = local.image_url

      ports {
        container_port = 8443
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "1Gi"
        }
      }

      # Snyk IaC / CWE-798: Credentials supplied as plaintext environment
      # variables instead of being sourced from Secret Manager at runtime.
      # They are visible in Cloud Run console, audit logs, and `gcloud` output,
      # and are stored unencrypted in the service revision configuration.
      env {
        name  = "DB_PASSWORD"
        value = "admin123"
      }
      env {
        name  = "API_KEY"
        value = "sk-abc123secretkey9876"
      }
      env {
        name  = "JWT_SECRET"
        value = "secret"
      }
      env {
        name  = "DB_HOST"
        value = "db.internal"
      }
      env {
        name  = "DB_PORT"
        value = "5432"
      }

      # Snyk IaC: No liveness_probe or startup_probe configured.
      # A crashed container continues to receive and fail requests until
      # Cloud Run detects the failure through its own health-check timeout.

      # Snyk IaC / CWE-250: No securityContext equivalent is set.
      # The container image has no USER directive (see Dockerfile), so the
      # process runs as uid 0 (root) inside the container. Cloud Run v2 does
      # not surface a containerSecurityContext block in Terraform, but Snyk
      # correlates the missing USER instruction in the linked image.
    }

    # Snyk IaC: No vpc_access block — all outbound traffic from the container
    # (database queries, upstream API calls, etc.) travels over the public
    # internet rather than a private VPC network. CWE-284.
  }

  depends_on = [google_project_service.run_api]
}

# Snyk IaC (SNYK-CC-TF-128): roles/run.invoker granted to allUsers.
# Any unauthenticated internet user can invoke every HTTP handler on the
# service — including /exec (OS command injection), /jwt-generate, /file
# (path traversal), and /key (512-bit RSA generation). No API key, OAuth
# token, or network control stands between an attacker and the application.
# CWE-284: Improper Access Control.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "allUsers" # Snyk: unauthenticated public invocation — critical.
}
