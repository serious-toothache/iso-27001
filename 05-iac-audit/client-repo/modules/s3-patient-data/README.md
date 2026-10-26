# s3-patient-data

Tausi Telehealth's standard module for any S3 bucket that stores patient data.
**Every patient-data bucket must be created with this module.** Platform team owns it.

## What it enforces

- Encryption at rest with a dedicated customer-managed KMS key, rotated yearly
- Versioning, so deleted or overwritten objects can be recovered
- Server access logging to the central access-log bucket
- All four Block Public Access settings, and ACLs disabled
- A bucket policy that rejects any request not made over TLS
- `DataClass` and `ManagedBy` tags on every bucket

## Usage

```hcl
module "patient_records" {
  source              = "../../modules/s3-patient-data"
  bucket_name         = "tausi-prod-patient-records"
  data_classification = "restricted"
  log_bucket          = "tausi-prod-s3-access-logs"
}
```

Version: v1.4.0
