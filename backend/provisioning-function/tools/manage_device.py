#!/usr/bin/env python3
"""Register or deregister a device's provisioning record.

Talks to the /v1/manufacturing/device endpoint, which is separate from the
/v1/provision signing endpoint and has its own function key -- this script
(and the key it needs) can be handed to teammates without giving them any
access to the signing endpoint itself, and without needing an Azure account
or Azure CLI at all.

The function key is resolved in this order (first one found wins):
    1. --function-key <key>                  (explicit, highest priority)
    2. $MANUFACTURING_FUNCTION_KEY            (env var, never ends up in shell history)
    3. .manufacturing_function_key            (file next to this script; gitignored)

Usage:
    python3 manage_device.py register   --device-id "AA:BB:CC:DD:EE:FF" --token "<hex pubkey>"
    python3 manage_device.py deregister --device-id "AA:BB:CC:DD:EE:FF"

device_id is the device's BLE MAC address. token is its identity public key
(hex-encoded), read off the device once via the `identity_pubkey` CLI
command -- see the nRF9151 shell.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_FUNCTION_URL = "https://jarvis-provisioning-func.azurewebsites.net/api/v1/manufacturing/device"
DEFAULT_KEY_FILE = Path(__file__).resolve().parent / ".manufacturing_function_key"


def resolve_function_key(explicit_key):
    if explicit_key:
        return explicit_key

    env_key = os.environ.get("MANUFACTURING_FUNCTION_KEY")
    if env_key:
        return env_key

    if DEFAULT_KEY_FILE.is_file():
        return DEFAULT_KEY_FILE.read_text().strip()

    return None


def call(url, function_key, method, body):
    request_url = f"{url}?code={function_key}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        request_url, data=data, method=method, headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body_text)
        except ValueError:
            return exc.code, {"error": body_text}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["register", "deregister"])
    parser.add_argument("--device-id", required=True, help="Device's BLE MAC address")
    parser.add_argument(
        "--token", help="Device's identity public key (hex), required for 'register'"
    )
    parser.add_argument(
        "--function-key",
        default=None,
        help=(
            "Function key (default: $MANUFACTURING_FUNCTION_KEY env var, "
            f"falling back to {DEFAULT_KEY_FILE.name})"
        ),
    )
    parser.add_argument("--url", default=DEFAULT_FUNCTION_URL, help="Manufacturing endpoint URL")
    args = parser.parse_args()

    function_key = resolve_function_key(args.function_key)
    if not function_key:
        parser.error(
            f"Function key required: pass --function-key, set $MANUFACTURING_FUNCTION_KEY, "
            f"or create {DEFAULT_KEY_FILE}"
        )

    if args.action == "register":
        if not args.token:
            parser.error("--token is required for 'register'")
        status, resp = call(
            args.url, function_key, "POST",
            {"device_id": args.device_id, "bootstrap_token": args.token},
        )
    else:
        status, resp = call(
            args.url, function_key, "DELETE", {"device_id": args.device_id}
        )

    print(json.dumps(resp, indent=2))

    if status >= 400:
        sys.exit(1)


if __name__ == "__main__":
    main()
