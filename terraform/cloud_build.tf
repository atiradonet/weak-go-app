# ── Cloud Build trigger ───────────────────────────────────────────────────────

resource "google_cloudbuild_trigger" "app_trigger" {
  project     = var.project_id
  name        = "weak-go-app-trigger"
  description = "Build and deploy weak-go-app on every push to main."

  github {
    owner = var.repo_owner
    name  = var.repo_name
    push {
      branch = "^main$"
    }
  }

  # Snyk IaC / CWE-798 / CWE-312: Credentials embedded in Cloud Build
  # substitution variables appear in plaintext in:
  #   • the Terraform state file
  #   • the Cloud Build trigger configuration (visible in the console)
  #   • Cloud Build step logs when passed as --set-env-vars (see cloudbuild.yaml)
  # Secret Manager references ( secretEnv + availableSecrets ) should be used
  # instead so the values are never written to logs or state.
  substitutions = {
    _DB_PASSWORD = "admin123"
    _API_KEY     = "sk-abc123secretkey9876"
    _JWT_SECRET  = "secret"
    _REGION      = var.region
  }

  # Cloud Build SA with roles/owner (defined in iam.tf).
  # The trigger inherits the build SA's maximum-privilege IAM binding,
  # meaning any step in the pipeline can perform any action in the project.
  service_account = google_service_account.cloud_build_sa.id

  # No approval_config block — pushes to main deploy directly to the
  # production Cloud Run service without a manual gate or review step.
  # A compromised commit or stolen PAT can trigger an immediate production
  # deployment with no human in the loop.

  filename = "cloudbuild.yaml"

  depends_on = [google_project_service.cloudbuild_api]
}
