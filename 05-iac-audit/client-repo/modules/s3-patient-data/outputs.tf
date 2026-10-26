output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "versioning_status" {
  value = aws_s3_bucket_versioning.this.versioning_configuration[0].status
}

output "access_logging_enabled" {
  value = length(aws_s3_bucket_logging.this) == 1
}
