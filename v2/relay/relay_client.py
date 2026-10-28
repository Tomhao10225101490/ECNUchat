#!/usr/bin/env python3
"""
Small stdlib-only client for the ECNUchat v2 local relay (relay.py).

This is a test/demo client, not a chat client: it sends and fetches
opaque base64 envelopes and never decrypts anything. The demo
ciphertext values in the examples are fake base64 placeholders,
not real encrypted messages, and no private key or password is
ever sent (the relay rejects those fields outright).

Usage (relay URL is configurable; default matches v1, 127.0.0.1:8765):
    python3 relay_client.py --relay-url http://127.0.0.1:8765 health
    python3 relay_client.py register --username alice --device phone \
        --identity-key DEMO-IDENTITY-KEY-ALICE-PHONE
    python3 relay_client.py list --username bob
    python3 relay_client.py send --sender alice:phone --recipient bob:laptop \
        --ciphertext aGVsbG8td29ybGQ=
    python3 relay_client.py fetch --recipient bob:laptop
    python3 relay_client.py fetch --recipient bob:laptop --wait 25
    python3 relay_client.py count --recipient bob:laptop
    python3 relay_client.py revoke --username bob --device laptop
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8765"


def call(base: str, method: str, path: str, body: dict | None = None) -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return {"http_status": resp.status,
                    **json.loads(resp.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"error": "HTTP_ERROR", "message": exc.reason}
        return {"http_status": exc.code, **payload}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay-url", default=DEFAULT_URL,
                        help="relay base URL, e.g. http://127.0.0.1:8765")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health")
    p = sub.add_parser("register")
    p.add_argument("--username", required=True)
    p.add_argument("--device", required=True)
    p.add_argument("--identity-key", default=None)
    p.add_argument("--signed-prekey", default=None)
    p = sub.add_parser("list")
    p.add_argument("--username", required=True)
    p = sub.add_parser("send")
    p.add_argument("--sender", required=True, help="username:device")
    p.add_argument("--recipient", required=True, help="username:device")
    p.add_argument("--ciphertext", required=True, help="base64 (opaque)")
    p.add_argument("--message-type", default=None)
    p = sub.add_parser("fetch")
    p.add_argument("--recipient", required=True, help="username:device")
    p.add_argument("--wait", type=float, default=0.0)
    p = sub.add_parser("count")
    p.add_argument("--recipient", required=True, help="username:device")
    p = sub.add_parser("revoke")
    p.add_argument("--username", required=True)
    p.add_argument("--device", required=True)

    args = parser.parse_args(argv)
    base = args.relay_url
    if args.cmd == "health":
        result = call(base, "GET", "/health")
    elif args.cmd == "register":
        body = {"username": args.username, "device": args.device}
        if args.identity_key:
            body["identity_key"] = args.identity_key
        if args.signed_prekey:
            body["signed_prekey"] = args.signed_prekey
        result = call(base, "POST", "/v1/devices/register", body)
    elif args.cmd == "list":
        result = call(base, "GET",
                      "/v1/devices?username=" + urllib.parse.quote(args.username))
    elif args.cmd == "send":
        body = {"sender": args.sender, "recipient": args.recipient,
                "ciphertext": args.ciphertext}
        if args.message_type:
            body["message_type"] = args.message_type
        result = call(base, "POST", "/v1/envelopes", body)
    elif args.cmd == "fetch":
        path = ("/v1/inbox?recipient=" + urllib.parse.quote(args.recipient)
                + f"&wait_seconds={args.wait}")
        result = call(base, "GET", path)
    elif args.cmd == "count":
        result = call(base, "GET",
                      "/v1/inbox/count?recipient="
                      + urllib.parse.quote(args.recipient))
    elif args.cmd == "revoke":
        result = call(base, "POST",
                      f"/v1/devices/{urllib.parse.quote(args.username)}"
                      f"/{urllib.parse.quote(args.device)}/revoke", {})
    else:  # pragma: no cover
        parser.error("unknown command")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("http_status", 500) < 400 else 1


if __name__ == "__main__":
    sys.exit(main())
