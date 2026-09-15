import os
import re

from azure.data.tables import TableClient, UpdateMode

TABLE_NAME = "PeripheralKeys"
PARTITION_KEY = "peripheral"

_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def _table_client() -> TableClient:
    return TableClient.from_connection_string(os.environ["TABLE_STORAGE_CONNECTION"], TABLE_NAME)


def normalize_mac(mac: str) -> str:
    """Uppercase a BLE MAC so the same peripheral always maps to the same row
    regardless of case, matching the convention token_store.py uses for
    device_id. Raises ValueError if the format doesn't look like a MAC.
    """
    normalized = mac.strip().upper()
    if not _MAC_RE.match(normalized):
        raise ValueError(f"'{mac}' is not a MAC address (expected aa:bb:cc:dd:ee:ff)")
    return normalized


def set_key(mac: str, public_key_hex: str) -> None:
    """Create or overwrite the stored public key for a peripheral MAC (upsert)."""
    client = _table_client()

    client.upsert_entity(
        {
            "PartitionKey": PARTITION_KEY,
            "RowKey": normalize_mac(mac),
            "publicKeyHex": public_key_hex,
        },
        mode=UpdateMode.REPLACE,
    )


def get_key(mac: str) -> str | None:
    """Return the stored public key hex for a peripheral MAC, or None if unknown."""
    client = _table_client()

    try:
        entity = client.get_entity(PARTITION_KEY, normalize_mac(mac))
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404:
            return None
        raise

    return entity.get("publicKeyHex")


def delete_key(mac: str) -> bool:
    """Delete a peripheral's stored key. Returns True if a row was deleted, False
    if it was already unknown. Table Storage's delete_entity() is a no-op on a
    missing row (doesn't raise) so existence is checked explicitly first --
    same reasoning as token_store.deregister_device().
    """
    client = _table_client()
    normalized = normalize_mac(mac)

    try:
        client.get_entity(PARTITION_KEY, normalized)
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404:
            return False
        raise

    client.delete_entity(PARTITION_KEY, normalized)
    return True
