import hashlib
import hmac
import os
from datetime import datetime, timezone

from azure.core import MatchConditions
from azure.data.tables import TableClient, UpdateMode

TABLE_NAME = "DeviceTokens"
PARTITION_KEY = "device"
STATE_UNUSED = "unused"
STATE_CLAIMED = "claimed"
STATE_ISSUED = "issued"


class TokenClaimConflictError(RuntimeError):
    """Raised when another request has already claimed this bootstrap token."""


def _table_client() -> TableClient:
    return TableClient.from_connection_string(os.environ["TABLE_STORAGE_CONNECTION"], TABLE_NAME)


def _normalize_device_id(device_id: str) -> str:
    """Normalize a device ID (typically a BLE MAC, e.g. "aa:bb:cc:dd:ee:ff") so
    the same physical device always maps to the same table row regardless of
    case. Applied consistently at registration, deregistration, and lookup.
    """
    return device_id.strip().upper()


def get_device_record(device_id: str):
    """Look up a device's token record. Returns None if the device is unknown."""
    client = _table_client()

    try:
        return client.get_entity(PARTITION_KEY, _normalize_device_id(device_id))
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404:
            return None
        raise


def register_device(device_id: str, bootstrap_token: str) -> None:
    """Create or reset a device's provisioning record (upsert).

    Used by the manufacturing endpoint: associates a device_id (BLE MAC) with
    a bootstrap token (the device's own identity public key, hex-encoded --
    generated once on-device and read off it at manufacturing time, not a
    server-generated secret). Overwrites any existing record for this
    device_id, resetting `used` to false -- intentional, so re-flashing/
    re-registering a unit (e.g. after a bench reset) is a clean re-run of
    this same step rather than a separate "reset" flow.
    """
    client = _table_client()

    client.upsert_entity(
        {
            "PartitionKey": PARTITION_KEY,
            "RowKey": _normalize_device_id(device_id),
            "bootstrapTokenHash": _hash_token(bootstrap_token),
            "provisioningState": STATE_UNUSED,
            "used": False,
        },
        mode=UpdateMode.REPLACE,
    )


def deregister_device(device_id: str) -> bool:
    """Delete a device's provisioning record, if present.

    Returns True if a record was deleted, False if the device was already
    unknown. Checks existence explicitly first: Azure Table Storage's
    delete_entity() is a no-op on a missing row -- it does not raise -- so
    without this check, "found" would always read True regardless of
    whether anything was actually deleted.
    """
    client = _table_client()
    normalized = _normalize_device_id(device_id)

    try:
        client.get_entity(PARTITION_KEY, normalized)
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404:
            return False
        raise

    client.delete_entity(PARTITION_KEY, normalized)
    return True


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(record, supplied_token: str) -> bool:
    """Constant-time comparison of the supplied bootstrap token against the stored hash."""
    return hmac.compare_digest(_hash_token(supplied_token), record["bootstrapTokenHash"])


def is_token_used(record) -> bool:
    """Read the 'used' flag robustly.

    Table Storage is schemaless: a row seeded via `az storage entity insert
    ... used=false` stores the *string* "false", not a boolean, since the
    CLI doesn't type-annotate plain key=value pairs. Python treats any
    non-empty string as truthy, so a naive `record.get("used")` would treat
    every CLI-seeded, unused device as already used. Rows written by this
    module's own mark_token_used() store a real bool via the SDK, so both
    representations must be handled here.
    """
    provisioning_state = record.get("provisioningState")
    if isinstance(provisioning_state, str):
        normalized_state = provisioning_state.strip().lower()
        if normalized_state in {STATE_CLAIMED, STATE_ISSUED}:
            return True
        if normalized_state == STATE_UNUSED:
            return False

    value = record.get("used")

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"

    return bool(value)


def claim_token(record):
    """Atomically claim a token before certificate signing begins.

    This closes the race where two near-simultaneous requests could both sign
    certificates before the first request marked the token used.
    """
    client = _table_client()

    try:
        client.update_entity(
            {
                "PartitionKey": PARTITION_KEY,
                "RowKey": record["RowKey"],
                "provisioningState": STATE_CLAIMED,
                "claimedAt": datetime.now(timezone.utc).isoformat(),
            },
            mode=UpdateMode.MERGE,
            etag=record.metadata["etag"],
            match_condition=MatchConditions.IfNotModified,
        )
    except Exception as exc:
        if getattr(exc, "status_code", None) == 412:
            raise TokenClaimConflictError("bootstrap token was already claimed") from exc
        raise

    return client.get_entity(PARTITION_KEY, record["RowKey"])


def release_claim(record) -> None:
    """Release a previously claimed token after a signing failure."""
    client = _table_client()

    client.update_entity(
        {
            "PartitionKey": PARTITION_KEY,
            "RowKey": record["RowKey"],
            "provisioningState": STATE_UNUSED,
            "used": False,
        },
        mode=UpdateMode.MERGE,
        etag=record.metadata["etag"],
        match_condition=MatchConditions.IfNotModified,
    )


def mark_token_used(record, certificate_serial: str) -> None:
    """Mark a device's token as used, recording the issued cert's serial for audit/revocation.

    Uses the entity's etag for optimistic concurrency so two near-simultaneous
    requests for the same token can't both succeed.
    """
    client = _table_client()

    client.update_entity(
        {
            "PartitionKey": PARTITION_KEY,
            "RowKey": record["RowKey"],
            "provisioningState": STATE_ISSUED,
            "used": True,
            "usedAt": datetime.now(timezone.utc).isoformat(),
            "certificateSerial": certificate_serial,
        },
        mode=UpdateMode.MERGE,
        etag=record.metadata["etag"],
        match_condition=MatchConditions.IfNotModified,
    )
