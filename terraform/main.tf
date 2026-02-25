terraform {
  required_version = ">= 1.3"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # No backend block — state is stored in a local terraform.tfstate file.
  # CWE-312: If this directory is committed or shared, the state file exposes
  # the plaintext service-account key generated in iam.tf, along with every
  # resource attribute marked sensitive by the provider (passwords, tokens, etc.).
  # A remote backend (GCS + CMEK + versioning + IAM) should be used instead.
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required GCP APIs.
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifact_registry_api" {
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudbuild_api" {
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam_api" {
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}
