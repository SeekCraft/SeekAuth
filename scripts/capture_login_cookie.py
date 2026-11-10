#!/usr/bin/env python3
"""Find the NetEase login cookie inside a running mitmproxy (mitmweb) instance.

Reads the mitmweb REST API, scans every flow's request/response headers and
bodies for NetEase passport / sauth cookie material, prints MASKED previews, and
writes the full findings to a file the operator controls.

Usage:
    python capture_login_cookie.py --token <mitmweb-token> [--out FILE] [--all]
"""
import argparse
import json
import os
import sys
import urllib.request

API = "http://127.0.0.1:8081/flows"

# Cookie names that carry NetEase login/session material.
COOKIE_HINTS = [
    "SAUTH_JSON", "PASSPORT", "NTES_SESS", "NTES_PASSPORT", "NTES_WEB",
    "P_INFO", "S_INFO", "EDU", "NTESNI", "x19", "sid", "SAZ", "cm_ss",
]
# Endpoints whose responses typically mint the login session.
PATH_HINTS = ("login", "sauth", "passport", "session", "auth", "sdk/login")


def fetch(token):
    url = f"{API}?token={token}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def header_pairs(msg):
    """mitmweb stores headers as [[k, v], ...]."""
    out = []
    for pair in msg.get("headers") or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            out.append((pair[0], pair[1]))
    return out


def mask(value, keep=24):
    value = str(value)
    if len(value) <= keep:
        return value
    return value[:keep] + f"...<{len(value)} chars>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True)
    ap.add_argument("--out", default=r"E:\fateark\seek-auth\keys\captured_login_cookie.json")
    ap.add_argument("--all", action="store_true", help="also list cookie-less netease flows")
    args = ap.parse_args()

    flows = fetch(args.token)
    print(f"scanning {len(flows)} flows")

    hits = []
    for f in flows:
        req = f.get("request") or {}
        resp = f.get("response") or {}
        host = req.get("host", "")
        path = req.get("path", "")
        if not ("netease" in host or "minecraft" in host or "163.com" in host):
            continue

        req_cookies = {}
        for k, v in header_pairs(req):
            if k.lower() == "cookie":
                for chunk in str(v).split(";"):
                    if "=" in chunk:
                        n, _, val = chunk.strip().partition("=")
                        req_cookies[n] = val

        set_cookies = []
        for k, v in header_pairs(resp):
            if k.lower() == "set-cookie":
                name = str(v).split("=", 1)[0]
                set_cookies.append((name, v))

        interesting = [n for n in list(req_cookies) + [s[0] for s in set_cookies]
                       if any(h.lower() in n.lower() for h in COOKIE_HINTS)]
        path_hit = any(p in path.lower() for p in PATH_HINTS)

        if interesting or path_hit or (args.all and req_cookies):
            hits.append({
                "method": req.get("method"),
                "url": f"https://{host}{path}",
                "status": resp.get("status_code"),
                "request_cookie_names": sorted(req_cookies),
                "interesting": sorted(set(interesting)),
                "set_cookie_names": [s[0] for s in set_cookies],
                "request_cookies": req_cookies,
                "set_cookies": [s[1] for s in set_cookies],
            })

    print(f"candidate flows: {len(hits)}\n")
    for h in hits[-25:]:
        flag = "***" if h["interesting"] else "   "
        print(f"{flag} {h['status']} {h['method']:4s} {h['url'][:110]}")
        if h["interesting"]:
            print(f"      interesting cookies: {h['interesting']}")
        if h["set_cookie_names"]:
            print(f"      set-cookie: {h['set_cookie_names']}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(hits, fh, ensure_ascii=False, indent=2)
    print(f"\nfull findings -> {args.out}")
    print("NOTE: this file holds live session credentials. Do not commit it.")


if __name__ == "__main__":
    sys.exit(main())
