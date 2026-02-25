output "cloud_run_url" {
  description = "Public URL of the deployed Cloud Run service."
  value       = google_cloud_run_v2_service.app.uri
}

output "artifact_registry_url" {
  description = "Artifact Registry repository URL for docker push/pull."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.app_repo.repository_id}"
}

output "cloud_build_trigger_id" {
  description = "Cloud Build trigger resource ID."
  value       = google_cloudbuild_trigger.app_trigger.id
}

# Snyk IaC / CWE-312: The service account private key is output in plaintext
# and is NOT marked sensitive = true.
# Any `terraform output` or `terraform apply` run will print the full base64-
# encoded JSON key to stdout, CI logs, and any Terraform Cloud run summaries.
# Marking sensitive = true would suppress console display but the value would
# still be stored unencrypted in the local state file (see main.tf).
output "cloud_run_sa_key" {
  description = "Service account key material (base64 JSON). Handle with care."
  value       = google_service_account_key.cloud_run_key.private_key
  sensitive   = false # Deliberately not marked sensitive — Snyk flags this.
}
