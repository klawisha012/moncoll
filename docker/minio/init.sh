#!/bin/sh
# Initialise the MinIO source-of-truth bucket for horizontal scaling (S3 mode).
# Creates the bucket + two scoped users: backend (read-write) and edge-sync
# sidecar (read-only) — least privilege per FR-010. Idempotent.
#
# Transport (FR-010): in dev, backend/edge talk to MinIO over the in-cluster
# network (http://minio:9000). For prod, terminate TLS on MinIO and set
# WAF_S3_USE_TLS=true on the backend + edge-sync so credentials/keys never cross
# the wire in clear — see README "Horizontal scaling (S3 mode)".
set -eu

# Wait for MinIO to accept connections (mc retries internally too).
until mc alias set local "http://minio:9000" "$WAF_S3_ROOT_USER" "$WAF_S3_ROOT_PASSWORD" 2>/dev/null; do
  echo "waiting for minio..."; sleep 2
done

mc mb --ignore-existing "local/$WAF_S3_BUCKET"

# SSE at rest (FR-010): default-encrypt the bucket so TLS key objects (written
# sensitive=true) are encrypted server-side. Requires a KMS; in dev without KES
# this is a no-op — for prod wire MINIO_KMS_* / KES (README). Don't fail dev.
mc encrypt set sse-s3 "local/$WAF_S3_BUCKET" 2>/dev/null || echo "SSE skipped (no KMS configured)"

# Backend: full read-write on the bucket.
mc admin user add local "$WAF_S3_ACCESS_KEY" "$WAF_S3_SECRET_KEY"
mc admin policy create local waf-rw /dev/stdin <<EOF
{ "Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::$WAF_S3_BUCKET","arn:aws:s3:::$WAF_S3_BUCKET/*"]}]}
EOF
mc admin policy attach local waf-rw --user "$WAF_S3_ACCESS_KEY"

# Edge-sync sidecar: read-only (cannot tamper with the source of truth).
mc admin user add local "$WAF_S3_EDGE_ACCESS_KEY" "$WAF_S3_EDGE_SECRET_KEY"
mc admin policy create local waf-ro /dev/stdin <<EOF
{ "Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::$WAF_S3_BUCKET","arn:aws:s3:::$WAF_S3_BUCKET/*"]}]}
EOF
mc admin policy attach local waf-ro --user "$WAF_S3_EDGE_ACCESS_KEY"

echo "minio-init: bucket '$WAF_S3_BUCKET' ready (backend RW, edge RO)"
