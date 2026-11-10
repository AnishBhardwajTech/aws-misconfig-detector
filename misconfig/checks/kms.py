"""KMS checks (regional)."""

from ..models import Severity
from . import check


@check("KMS-001", "KMS", Severity.MEDIUM, "Customer managed KMS key rotation is disabled",
       "Enable automatic yearly rotation on symmetric customer managed keys.", scope="regional")
def key_rotation(ctx):
    kms = ctx.client("kms")
    for page in kms.get_paginator("list_keys").paginate():
        for k in page["Keys"]:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" \
                    or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if not kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]:
                yield meta["Arn"], f"Key {k['KeyId']} is never rotated."
