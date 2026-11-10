#!/usr/bin/env python3
"""Fetch auth-flow BODIES from mitmweb (list endpoint omits content).

mitmweb's /flows returns metadata only; each body lives at
/flows/{id}/{request|response}/content.data. This script finds the login flows,
pulls their bodies, prints masked key/value shapes, and saves the raw bodies.
"""
import argparse
import json
import os
import urllib.request

BASE = "http://127.0.0.1:8081"

TARGETS = ("uni_sauth", "authentication-v2", "pe-authentication",
           "pe-user-login-after", "sdk/login", "sauth")

SECRET_HINTS = ("sauth", "token", "cookie", "passwd", "password", "secret",
                "session", "ticket", "key", "credential", "udid", "sn", "ip")


def get(path, token):
    url = f"{BASE}{path}"
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}token={token}"
    with urllib.request.urlopen(url, timeout=40) as r:
        return r.read()


def body(flow_id, side, token):
    try:
        raw = get(f"/flows/{flow_id}/{side}/content.data", token)
    except Exception:
        return ""
    return raw.decode("utf-8", "replace")


def mask(v, keep=26):
    s = str(v)
    return s if len(s) <= keep else s[:keep] + f"...<{len(s)}>"


def shape(obj, prefix="", depth=0):
    if depth > 2:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from shape(v, p, depth + 1)
            else:
                yield p, mask(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2]):
            p = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from shape(v, p, depth + 1)
            else:
                yield p, mask(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--out", default=r"E:\fateark\seek-auth\keys\captured_auth_bodies.json")
    ap.add_argument("--last", type=int, default=3)
    args = ap.parse_args()

    flows = json.loads(get("/flows", args.token))
    picked = []
    for f in flows:
        req = f.get("request") or {}
        path = req.get("path", "")
        if any(t in path for t in TARGETS):
            picked.append(f)

    print(f"auth flows: {len(picked)}; inspecting last {args.last}")

    records = []
    for f in picked[-args.last:]:
        req = f.get("request") or {}
        resp = f.get("response") or {}
        rec = {
            "id": f.get("id"),
            "url": f"https://{req.get('host','')}{req.get('path','')}",
            "method": req.get("method"),
            "status": resp.get("status_code"),
            "request_body": body(f["id"], "request", args.token),
            "response_body": body(f["id"], "response", args.token),
        }
        records.append(rec)

        print("=" * 100)
        print(f"{rec['method']} {rec['url']}  -> {rec['status']}")
        for label in ("request_body", "response_body"):
            text = rec[label].strip()
            if not text:
                print(f"  {label}: <empty>")
                continue
            try:
                obj = json.loads(text)
            except Exception:
                print(f"  {label} (raw): {mask(text, 160)}")
                continue
            print(f"  {label}:")
            for p, v in shape(obj):
                star = "*" if any(h in p.lower() for h in SECRET_HINTS) else " "
                print(f"   {star} {p} = {v}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(records, fh, ensure_ascii=False, indent=2)
    print(f"\nraw bodies -> {args.out}   (LIVE CREDENTIALS - do not commit)")


if __name__ == "__main__":
    main()
