#!/usr/bin/env python3
"""Rebuild keys/fbtokens.json from a freshly captured MitM login.

WHY: the bundled fixtures in fbtokens.json carry `aim_ip: 127.0.0.1` and expired
sessions, so every login through seek-auth fails with
"cipher: message authentication failed" -- the server mints a session the engine
cannot decrypt because the underlying NetEase session is stale.

WHAT THIS DOES:
  1. reads the captured uni_sauth request (the real sauth payload) from
     keys/captured_auth_bodies.json,
  2. attaches the OAuth access_token from the matching uni_sauth response as
     `gas_token` (same role it has in the original fixtures),
  3. mints a new 32-hex fbtoken and writes {"sauth_json": ...} under it,
  4. verifies the four fields PE auth requires are present and non-empty.

The output file holds LIVE credentials. It is written with 0600 where the OS
supports it, and must never be committed.
"""
import base64
import contextlib
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[1])
CAPTURED = os.path.join(ROOT, "keys", "captured_auth_bodies.json")
STORE = os.path.join(ROOT, "keys", "fbtokens.json")

# Fields g79._perform_pe_auth_with_cookie hard-requires.
REQUIRED = ("sdkuid", "sessionid", "udid", "deviceid")


def load_captured():
    with open(CAPTURED, encoding="utf-8") as fh:
        records = json.load(fh)
    sauth = None
    access_token = ""
    for r in records:
        if "uni_sauth" not in r.get("url", ""):
            continue
        try:
            req = json.loads(r["request_body"])
            resp = json.loads(r["response_body"])
        except Exception:
            continue
        # Newest uni_sauth wins.
        sauth = req
        blob = resp.get("unisdk_login_json") or ""
        if blob:
            try:
                padded = blob + "=" * (-len(blob) % 4)
                inner = json.loads(base64.b64decode(padded).decode("utf-8", "replace"))
                access_token = str(inner.get("access_token") or "")
            except Exception:
                pass
    if not sauth:
        print("no uni_sauth flow found in captured_auth_bodies.json", file=sys.stderr)
        sys.exit(1)
    return sauth, access_token


def main():
    sauth, access_token = load_captured()

    missing = [f for f in REQUIRED if not str(sauth.get(f, "")).strip()]
    if missing:
        print(f"captured sauth is missing required fields: {missing}", file=sys.stderr)
        sys.exit(1)

    # gas_token is the OAuth access token in the original fixture layout.
    if access_token and not str(sauth.get("gas_token", "")).strip():
        sauth["gas_token"] = access_token

    cookie_data = {"sauth_json": json.dumps(sauth, ensure_ascii=False, separators=(",", ":"))}
    token = secrets.token_hex(16)  # 32 hex chars, same shape as the originals

    payload = {token: json.dumps(cookie_data, ensure_ascii=False, separators=(",", ":"))}

    with open(STORE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with contextlib.suppress(OSError):
        os.chmod(STORE, 0o600)

    print(f"wrote {STORE}")
    print(f"new fbtoken = {token}")
    print("sauth fields:")
    for k in ("gameid", "app_channel", "login_channel", "platform",
              "sdkuid", "udid", "deviceid", "client_login_sn", "ip"):
        v = str(sauth.get(k, ""))
        print(f"  {k:16s} = {v if len(v) <= 40 else v[:40] + f'...<{len(v)}>'}")
    for k in ("sessionid", "gas_token", "aim_info"):
        v = str(sauth.get(k, ""))
        state = "present" if v.strip() else "EMPTY"
        print(f"  {k:16s} = {state} ({len(v)} chars)")
    print("\nREMINDER: this file is a live credential. Do not commit it.")
    return token


if __name__ == "__main__":
    main()
