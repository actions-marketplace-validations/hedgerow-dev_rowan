"""Manifest upload endpoint.

The manifest is stored verbatim in object storage and validated later by the
import worker, so the request handler stays fast.
"""

import uuid

import boto3
from flask import Blueprint, jsonify, request

BUCKET = "acme-imports"

bp = Blueprint("uploads", __name__, url_prefix="/imports")
s3 = boto3.client("s3")


@bp.route("/manifests", methods=["POST"])
def upload_manifest():
    upload = request.files["manifest"]
    key = f"manifests/{uuid.uuid4()}.yaml"

    s3.put_object(Bucket=BUCKET, Key=key, Body=upload.read())
    return jsonify({"key": key}), 202
