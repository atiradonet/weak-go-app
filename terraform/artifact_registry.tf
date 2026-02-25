# ── Artifact Registry ─────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "app_repo" {
  project       = var.project_id
  location      = var.region
  repository_id = "weak-go-app"
  format        = "DOCKER"
  description   = "Docker images for weak-go-app"

  # Snyk IaC: No kms_key_name configured.
  # The repository uses Google-managed encryption rather than a
  # customer-managed encryption key (CMEK). CMEK is required in many
  # compliance frameworks (PCI-DSS, HIPAA) to ensure the organisation
  # controls key rotation and revocation.
  #
  # Fix: add kms_key_name = google_kms_crypto_key.repo_key.id

  depends_on = [google_project_service.artifact_registry_api]
}

# Snyk IaC: Public read access granted to the Artifact Registry repository.
# member = "allUsers" means any unauthenticated internet user can pull images.
# The weak-go-app image contains baked-in credentials (DB password, API key,
# JWT secret, TLS private key) in its layers — all of which become public.
# CWE-284: Improper Access Control.
resource "google_artifact_registry_repository_iam_member" "public_reader" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.app_repo.name
  role       = "roles/artifactregistry.reader"
  member     = "allUsers" # Snyk: unauthenticated public access to registry.
}
