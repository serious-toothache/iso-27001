variable "bucket_name" {
  description = "Globally unique bucket name."
  type        = string

  validation {
    condition     = can(regex("^tausi-(prod|dr)-[a-z0-9-]+$", var.bucket_name))
    error_message = "Patient-data buckets must be named tausi-prod-* or tausi-dr-*."
  }
}

variable "data_classification" {
  description = "Data class from the Tausi information classification policy."
  type        = string

  validation {
    condition     = contains(["confidential", "restricted"], var.data_classification)
    error_message = "Patient data must be classified confidential or restricted."
  }
}

variable "log_bucket" {
  description = "Central S3 access-log bucket."
  type        = string
}

variable "enable_access_logging" {
  description = "Turn off to reduce log volume on high-churn buckets."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Extra tags merged onto the bucket."
  type        = map(string)
  default     = {}
}
