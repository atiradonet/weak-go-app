variable "project_id" {
  description = "GCP project ID to deploy into."
  type        = string
  # No default — caller must supply this.
}

variable "region" {
  description = "GCP region for all resources."
  type        = string
  default     = "us-central1"
}

variable "repo_owner" {
  description = "GitHub organisation or user that owns the source repository."
  type        = string
  default     = "example-org"
}

variable "repo_name" {
  description = "GitHub repository name connected to Cloud Build."
  type        = string
  default     = "weak-go-app"
}

variable "image_name" {
  description = "Name of the container image stored in Artifact Registry."
  type        = string
  default     = "weak-go-app"
}
