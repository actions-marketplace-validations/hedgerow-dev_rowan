"""Import worker.

Polls the manifests prefix in S3. No call edge exists back to the upload
endpoint; the bucket is the channel.
"""

import logging

import boto3

from uploads.apply import parse_manifest

BUCKET = "acme-imports"

logger = logging.getLogger(__name__)
s3 = boto3.client("s3")


def import_manifest(key):
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    document = obj["Body"].read()

    manifest = parse_manifest(document)
    logger.info("importing %d entries from %s", len(manifest.get("entries", [])), key)
    return manifest
