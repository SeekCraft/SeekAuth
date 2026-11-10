#!/usr/bin/env python3
"""Show the SHAPE (keys + masked values) of the auth-flow bodies, not the secrets.

Prints a path -> keys -> masked-preview tree so the operator can identify which
response carries the sauth payload, without pasting credentials into a terminal
transcript or an LLM context.

Full bodies are written to a separate file for the operator to use.
"""
import argparse
import json
import os
import urllib.request

API = "http://127.0.0.1:8081/flows"

TARGETS = (
    "/x19/sdk/uni_sauth",
    "/authentication-v2",
    "/pe-authentication",
    "/pe-user-login-after",
    "/authentication/",
)

SECRET_KEY_HINTS = ("sauth", "token", "cookie", "passwd", "password", "secret",
                    "session", "ticket", "key", "credential", "udid", "sn")


def fetch(token):
    with urllib.request.urlopen(f"{API}?token={token}", timeout=30) as r:
        return json.load(r)


def text_of(msg):
    raw = msg.get("content") or msg.get("text") or ""
    if isinstance(raw, str):
        return raw
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def mask(v, keep=30):
    s = str(v)
    return s if len(s) <= keep else s[:keep] + f"...<{len(s)}>"


def shape(obj, prefix="", depth=0):
    """Yield (keypath, masked_value) up to depth 2."""
    if depth > 2:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from shape(v, path, depth + 1)
            else:
                yield path, mask(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2]):
            path = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from shape(v, path, depth + 1)
            else:
                yield path, mask(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--out", default=r"E:\fateark\seek-auth\keys\captured_auth_bodies.json")
    args = ap.parse_args()

    flows = fetch(args.token)
    picked = []
    for f in flows:
        req = f.get("request") or {}
        resp = f.get("response") or {}
        path = req.get("path", "")
        if not any(t in path for t in TARGETS):
            continue
        picked.append({
            "url": f"https://{req.get('host','')}{path}",
            "method": req.get("method"),
            "request_body": text_of(req),
            "response_body": text_of(resp),
        })

    print(f"auth flows matched: {len(picked)}\n")
    for p in picked[-6:]:
        print("=" * 100)
        print(f"{p['method']} {p['url']}")
        for label in ("request_body", "response_body"):
            body = p[label].strip()
            if not body:
                continue
            try:
                obj = json.loads(body)
            except Exception:
                print(f"  {label}: {mask(body, 120)}")
                continue
            print(f"  {label} keys:")
            for path, val in shape(obj):
                star = "*" if any(h in path.lower() for h in SECRET_KEY_HINTS) else " "
                print(f"   {star} {path} = {val}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(picked, fh, ensure_ascii=False, indent=2)
    print(f"\nfull bodies -> {args.out}  (live credentials; do not commit)")


if __name__ == "__main__":
    main()
