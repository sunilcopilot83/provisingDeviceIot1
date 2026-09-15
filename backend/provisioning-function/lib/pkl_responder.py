import json
import logging
import os

from azure.iot.hub import IoTHubRegistryManager

from lib import peripheral_key_store

# Cached at module scope and reused across invocations (Azure Functions keeps
# the Python worker warm between calls) -- each IoTHubRegistryManager holds
# its own persistent AMQP connection (uamqp's send_all_messages(close_on_done
# =False) deliberately keeps it open for reuse). Creating a fresh one per
# event, as an earlier version of this file did, leaked one AMQP connection
# per D2C message (roughly one every ~4s from a single gateway) with no
# disconnect_sync() ever called -- this accumulated until the function host
# choked and stopped processing events entirely. Reusing one client across
# calls is both the fix and the intended usage pattern for this SDK.
_registry_manager = None


def _get_registry_manager() -> IoTHubRegistryManager:
    global _registry_manager
    if _registry_manager is None:
        _registry_manager = IoTHubRegistryManager.from_connection_string(
            os.environ["IOTHUB_SERVICE_CONNECTION"]
        )
    return _registry_manager


def _reset_registry_manager() -> None:
    """Drop the cached client so the next call gets a fresh connection --
    used after a send failure, in case that connection itself is broken."""
    global _registry_manager
    _registry_manager = None

# IoT Hub system property carrying the sending device's ID, as seen on
# messages read from the built-in Event-Hub-compatible endpoint. The Python
# v2 Functions binding doesn't document its exact metadata shape (the .NET
# docs describe `SystemProperties["iothub-connection-device-id"]`, but the
# Python dict layout/casing isn't spelled out anywhere), so every plausible
# location is tried here and logged. CONFIRM AGAINST A REAL D2C MESSAGE after
# deploying, then this list can be trimmed to whichever path actually worked.
_DEVICE_ID_KEYS = (
    "iothub-connection-device-id",
    "connectiondeviceid",
    "ConnectionDeviceId",
    "iothub-connection-device-id".replace("-", "_"),
)


def _find_device_id(event) -> str | None:
    candidates = []

    iothub_meta = getattr(event, "iothub_metadata", None)
    if iothub_meta:
        candidates.append(dict(iothub_meta))

    meta = event.metadata or {}
    for key in ("SystemProperties", "SystemPropertiesArray"):
        value = meta.get(key)
        if isinstance(value, dict):
            candidates.append(value)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            candidates.append(value[0])

    for candidate in candidates:
        # Case-insensitive, since the exact casing delivered isn't confirmed.
        lowered = {k.lower(): v for k, v in candidate.items()}
        for key in _DEVICE_ID_KEYS:
            if key.lower() in lowered:
                return lowered[key.lower()]

    logging.error(
        "pkl_d2c_responder: could not find device id in event metadata. "
        "iothub_metadata=%r metadata=%r",
        iothub_meta,
        meta,
    )
    return None


def handle_d2c_event(event) -> None:
    try:
        body = json.loads(event.get_body().decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return  # Not JSON -- not a PKL request, nothing for this responder to do.

    if not isinstance(body, dict) or not body.get("pkl"):
        return  # Some other D2C message type -- ignore.

    entries = body["pkl"]
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        logging.warning("pkl_d2c_responder: malformed pkl payload: %r", body)
        return

    mac = entries[0].get("0")
    if not mac:
        logging.warning("pkl_d2c_responder: pkl entry missing MAC: %r", entries[0])
        return

    device_id = _find_device_id(event)
    if not device_id:
        return  # Already logged in _find_device_id; nowhere to send the reply.

    try:
        key = peripheral_key_store.get_key(mac)
    except ValueError:
        logging.warning("pkl_d2c_responder: %r is not a valid MAC, replying reject", mac)
        key = None
    except Exception:
        logging.exception("pkl_d2c_responder: key lookup failed for mac %r", mac)
        key = None

    key_out = key if key else "reject"
    reply = json.dumps({"pkl": [{"0": mac, "1": key_out}]})

    try:
        registry_manager = _get_registry_manager()
        registry_manager.send_c2d_message(device_id, reply)
    except Exception:
        logging.exception("pkl_d2c_responder: failed to send C2D reply to device_id %r", device_id)
        _reset_registry_manager()
        return

    logging.info(
        "pkl_d2c_responder: replied to device_id %r for peripheral %r (key %s)",
        device_id,
        mac,
        "found" if key else "not found -> reject",
    )
