terraform {
  required_version = ">= 1.9"

  backend "s3" {
    bucket         = "tausi-terraform-state"
    key            = "prod/s3.tfstate"
    region         = "af-south-1"
    encrypt        = true
    kms_key_id     = "alias/tausi-terraform-state"
    dynamodb_table = "tausi-terraform-locks"
  }
}

provider "aws" {
  region = "af-south-1"
}

module "patient_records" {
  source              = "../../modules/s3-patient-data"
  bucket_name         = "tausi-prod-patient-records"
  data_classification = "restricted"
  log_bucket          = "tausi-prod-s3-access-logs"
}

module "consult_recordings" {
  source              = "../../modules/s3-patient-data"
  bucket_name         = "tausi-prod-consult-recordings"
  data_classification = "restricted"
  log_bucket          = "tausi-prod-s3-access-logs"
}

module "patient_uploads" {
  source                = "../../modules/s3-patient-data"
  bucket_name           = "tausi-prod-patient-uploads"
  data_classification   = "confidential"
  log_bucket            = "tausi-prod-s3-access-logs"
  enable_access_logging = false # ENG-212: uploads bucket generates too many log objects
}
