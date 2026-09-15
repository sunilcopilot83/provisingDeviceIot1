import json
import logging
import os

import azure.functions as func

from lib.ca_signer import parse_and_verify_csr, sign_device_certificate
from lib.pkl_responder import handle_d2c_event
from lib.token_store import (
    TokenClaimConflictError,
    claim_token,
    deregister_device,
    get_device_record,
    is_token_used,
    mark_token_used,
    release_claim,
    register_device,
    token_matches,
)
from lib import peripheral_key_store

app = func.FunctionApp()

# Deliberately does not distinguish *why* a request was rejected (unknown
# device vs. bad token vs. bad CSR) so a caller can't use the response to
# enumerate valid device IDs. The real reason is logged server-side only.
GENERIC_REJECTION = json.dumps({"error": "provisioning request rejected"})


def _rejected(status_code: int) -> func.HttpResponse:
    return func.HttpResponse(GENERIC_REJECTION, status_code=status_code, mimetype="application/json")


@app.route(route="v1/provision", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def provision(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        logging.warning("provision: request body is not valid JSON")
        return _rejected(400)

    device_id = body.get("device_id")
    bootstrap_token = body.get("bootstrap_token")
    csr_pem = body.get("csr")

    if not device_id or not bootstrap_token or not csr_pem:
        logging.warning("provision: missing required field(s)")
        return _rejected(400)

    try:
        record = get_device_record(device_id)
    except Exception:
        logging.exception("provision: token store lookup failed")
        return _rejected(500)

    if record is None:
        logging.warning("provision: unknown device_id %r", device_id)
        return _rejected(400)

    if is_token_used(record):
        logging.warning("provision: token already used for device_id %r", device_id)
        return _rejected(400)

    if not token_matches(record, bootstrap_token):
        logging.warning("provision: bootstrap token mismatch for device_id %r", device_id)
        return _rejected(400)

    try:
        csr = parse_and_verify_csr(csr_pem.encode("utf-8"), device_id)
    except ValueError as exc:
        logging.warning("provision: CSR rejected for device_id %r: %s", device_id, exc)
        return _rejected(400)

    try:
        claimed_record = claim_token(record)
    except TokenClaimConflictError:
        logging.warning("provision: bootstrap token already claimed for device_id %r", device_id)
        return _rejected(409)
    except Exception:
        logging.exception("provision: token claim failed for device_id %r", device_id)
        return _rejected(500)

    try:
        cert_pem, serial_hex = sign_device_certificate(
            csr,
            os.environ["INTERMEDIATE_CA_CERT"].encode("utf-8"),
            os.environ["INTERMEDIATE_CA_KEY"].encode("utf-8"),
            device_id,
        )
    except Exception:
        logging.exception("provision: signing failed for device_id %r", device_id)
        try:
            released = release_claim(claimed_record)
            if not released:
                logging.warning("provision: token changed before claim release for device_id %r", device_id)
        except Exception:
            logging.exception("provision: failed to release token claim for device_id %r", device_id)
        return _rejected(500)

    try:
        mark_token_used(claimed_record, serial_hex)
    except Exception:
        # The token was already claimed before signing, so a retry cannot mint
        # a second certificate. Log loudly so an operator can reconcile the
        # stored state with the certificate that was already issued.
        logging.exception("provision: signed cert for %r but failed to finalize token state", device_id)
        return _rejected(500)

    logging.info("provision: issued certificate for device_id %r", device_id)
    return func.HttpResponse(
        json.dumps({"device_certificate": cert_pem.decode("utf-8")}),
        status_code=200,
        mimetype="application/json",
    )


# Separate function -> separate function key from /v1/provision, so this can
# be handed to teammates for manufacturing-time device registration without
# giving them (or anything that has this key) the ability to hit the signing
# endpoint itself.
@app.route(route="v1/manufacturing/device", methods=["POST", "DELETE"], auth_level=func.AuthLevel.FUNCTION)
def manufacturing_device(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "request body is not valid JSON"}),
            status_code=400,
            mimetype="application/json",
        )

    device_id = body.get("device_id")

    if not device_id or not isinstance(device_id, str):
        return func.HttpResponse(
            json.dumps({"error": "device_id is required"}),
            status_code=400,
            mimetype="application/json",
        )

    if req.method == "DELETE":
        try:
            found = deregister_device(device_id)
        except Exception:
            logging.exception("manufacturing_device: deregister failed for device_id %r", device_id)
            return func.HttpResponse(
                json.dumps({"error": "deregistration failed"}),
                status_code=500,
                mimetype="application/json",
            )

        logging.info("manufacturing_device: deregistered device_id %r (found=%s)", device_id, found)
        return func.HttpResponse(
            json.dumps({"status": "deregistered", "device_id": device_id, "found": found}),
            status_code=200,
            mimetype="application/json",
        )

    # POST -> register (upsert)
    bootstrap_token = body.get("bootstrap_token")

    if not bootstrap_token or not isinstance(bootstrap_token, str):
        return func.HttpResponse(
            json.dumps({"error": "bootstrap_token is required"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        register_device(device_id, bootstrap_token)
    except Exception:
        logging.exception("manufacturing_device: register failed for device_id %r", device_id)
        return func.HttpResponse(
            json.dumps({"error": "registration failed"}),
            status_code=500,
            mimetype="application/json",
        )

    logging.info("manufacturing_device: registered device_id %r", device_id)
    return func.HttpResponse(
        json.dumps({"status": "registered", "device_id": device_id}),
        status_code=200,
        mimetype="application/json",
    )


# Manages the peripheral public-key store that pkl_d2c_responder (below) reads
# from when answering a gateway's PKL request. Separate function -> separate
# function key from /v1/provision and /v1/manufacturing/device, so this can be
# handed out to whoever manages the peripheral fleet without exposing device
# provisioning.
@app.route(route="v1/peripheral/key", methods=["GET", "POST", "DELETE"], auth_level=func.AuthLevel.FUNCTION)
def peripheral_key(req: func.HttpRequest) -> func.HttpResponse:
    def _err(status_code: int, message: str) -> func.HttpResponse:
        return func.HttpResponse(json.dumps({"error": message}), status_code=status_code, mimetype="application/json")

    if req.method == "GET":
        mac = req.params.get("mac")
        if not mac:
            return _err(400, "mac query parameter is required")
        try:
            key = peripheral_key_store.get_key(mac)
        except ValueError as exc:
            return _err(400, str(exc))
        except Exception:
            logging.exception("peripheral_key: lookup failed for mac %r", mac)
            return _err(500, "lookup failed")

        if key is None:
            return _err(404, "no key stored for this MAC")
        return func.HttpResponse(json.dumps({"mac": mac, "key": key}), status_code=200, mimetype="application/json")

    try:
        body = req.get_json()
    except ValueError:
        return _err(400, "request body is not valid JSON")

    mac = body.get("mac")
    if not mac or not isinstance(mac, str):
        return _err(400, "mac is required")

    if req.method == "DELETE":
        try:
            found = peripheral_key_store.delete_key(mac)
        except ValueError as exc:
            return _err(400, str(exc))
        except Exception:
            logging.exception("peripheral_key: delete failed for mac %r", mac)
            return _err(500, "delete failed")

        logging.info("peripheral_key: deleted mac %r (found=%s)", mac, found)
        return func.HttpResponse(
            json.dumps({"status": "deleted", "mac": mac, "found": found}), status_code=200, mimetype="application/json"
        )

    # POST -> add/overwrite
    key = body.get("key")
    if not key or not isinstance(key, str):
        return _err(400, "key is required")

    try:
        peripheral_key_store.set_key(mac, key)
    except ValueError as exc:
        return _err(400, str(exc))
    except Exception:
        logging.exception("peripheral_key: set failed for mac %r", mac)
        return _err(500, "set failed")

    logging.info("peripheral_key: stored key for mac %r", mac)
    return func.HttpResponse(json.dumps({"status": "stored", "mac": mac}), status_code=200, mimetype="application/json")


# Consumes IoT Hub's built-in Event-Hub-compatible endpoint (all D2C messages
# that don't match a custom route -- this hub has none, so that's all of
# them). Filters for PKL requests, looks up the peripheral's key, and replies
# with a C2D message back to the *same device that sent the D2C message* --
# see lib/pkl_responder.py for why device-id extraction is defensive/
# multi-path (the exact metadata shape isn't nailed down by Microsoft's docs
# for the Python v2 model and needs confirming against a real message).
@app.function_name(name="pkl_d2c_responder")
@app.event_hub_message_trigger(
    arg_name="event",
    event_hub_name="messages/events",
    connection="IOTHUB_EVENTHUB_CONNECTION",
    consumer_group="%IOTHUB_EVENTHUB_CONSUMER_GROUP%",
    cardinality="one",
)
def pkl_d2c_responder(event: func.EventHubEvent) -> None:
    handle_d2c_event(event)
