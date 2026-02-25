# ── Service accounts ──────────────────────────────────────────────────────────

resource "google_service_account" "cloud_run_sa" {
  project      = var.project_id
  account_id   = "cloud-run-sa"
  display_name = "Cloud Run Service Account"
}

resource "google_service_account" "cloud_build_sa" {
  project      = var.project_id
  account_id   = "cloud-build-sa"
  display_name = "Cloud Build Service Account"
}

# ── Cloud Run IAM ─────────────────────────────────────────────────────────────

# Snyk IaC: Primitive role roles/editor assigned to the Cloud Run service account.
# Editor grants read and write access to almost every resource in the project —
# far beyond what a Cloud Run workload needs (typically only Secret Manager
# access and Artifact Registry pull rights).
# CWE-250: Execution with Unnecessary Privileges.
resource "google_project_iam_member" "cloud_run_editor" {
  project = var.project_id
  role    = "roles/editor" # Snyk: primitive role — overly permissive.
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

# ── Cloud Build IAM ───────────────────────────────────────────────────────────

# Snyk IaC: Primitive role roles/owner assigned to the Cloud Build service account.
# Owner is the highest privilege in a GCP project — it can modify IAM policies,
# delete any resource, and access all data. A compromised build pipeline would
# have unrestricted project control. CWE-250.
resource "google_project_iam_member" "cloud_build_owner" {
  project = var.project_id
  role    = "roles/owner" # Snyk: maximum privilege — critical finding.
  member  = "serviceAccount:${google_service_account.cloud_build_sa.email}"
}

# ── Static service account key ────────────────────────────────────────────────

# Snyk IaC: A static service account key is created and its private key material
# is stored in Terraform state (terraform.tfstate) in base64-encoded plaintext.
# Static keys are long-lived credentials with no automatic rotation; if the
# state file is exposed the key grants full editor-level access indefinitely.
# Workload Identity Federation should be used instead.
# CWE-798: Use of Hard-coded Credentials (key embedded in persistent artefact).
resource "google_service_account_key" "cloud_run_key" {
  service_account_id = google_service_account.cloud_run_sa.name
  # private_key is written to tfstate as a plaintext base64 JSON blob.
}

# ── Overly broad project-level binding ────────────────────────────────────────

# Snyk IaC: allAuthenticatedUsers granted Storage Object Viewer on the project.
# Any Google-authenticated user — including personal Gmail accounts — can read
# every GCS object in the project without needing an organisation account.
# This is effectively near-public access. CWE-284: Improper Access Control.
resource "google_project_iam_member" "all_authenticated_storage" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "allAuthenticatedUsers" # Snyk: overly broad — flags allAuthenticated.
}
