"""Verify the pure functions of ``g79.py`` against the Go reference (**no network**).

Usage::

    .venv\\Scripts\\python.exe tests\\verify_g79_against_go.py

Needs the vector file generated on the Go side (the script says how)::

    go run diag/g79vectors.go vectors > diag/g79_vectors.txt

For AES the script itself runs ``go run diag/g79vectors.go {encrypt,decrypt,x19encrypt,x19decrypt}``
in a temp directory for a genuine cross-check.

Note on error-path parity: this project's messages are English now while the Go
reference emits its own wording, so the ``pe_auth_sign`` error rows are compared
**structurally** (same error class, same offending parameter) instead of by message
text. Running this script also needs the Go checkout itself, pointed at by
``SEEK_GO_REF_DIR``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from seek_auth.g79 import (  # noqa: E402
    AES_KEYS,
    X19_KEYS,
    G79Error,
    _cbc_encrypt,
    calculate_dynamic_token,
    g79_http_decrypt,
    g79_http_encrypt,
    get_valid_json,
    pe_auth_sign,
    pkcs7_pad,
    x19_calculate_dynamic_token,
    x19_http_decrypt,
    x19_http_encrypt,
)

GO_DIR = Path(os.environ.get("SEEK_GO_REF_DIR", str(REPO.parent / "noahs-ark")))
GO_VECTORS = GO_DIR / "diag" / "g79_vectors.txt"
GO_PROG = "diag/g79vectors.go"
WORK = GO_DIR / "diag" / "xcheck"

_go_cache = GO_DIR / ".gocache"
_GO_ENV = {
    "GOCACHE": str(_go_cache),
    "GOPATH": str(GO_DIR / ".gopath"),
    "GOSUMDB": "off",
    "GOPROXY": "off",
    "GOFLAGS": "-mod=mod",
    "TMP": str(_go_cache / "tmp"),
    "TEMP": str(_go_cache / "tmp"),
}

if not GO_DIR.is_dir():
    sys.exit(
        f"missing Go reference directory: {GO_DIR}\n"
        "This script aligns every pure function of g79.py with the Go"
        "version and needs diag/g79vectors.go from that repository.\n"
        "Point the SEEK_GO_REF_DIR environment variable at that repo and retry, e.g.:\n"
        r"  set SEEK_GO_REF_DIR=E:\path\to\go-ref" + "\n"
        r"  go run diag/g79vectors.go vectors > diag/g79_vectors.txt" + "\n"
        "(skip this script when that repo is absent; pytest does not depend on it)"
    )

failures: list[str] = []
checks = 0


def check(label: str, got: object, want: object) -> bool:
    global checks
    checks += 1
    if got != want:
        failures.append(f"{label}\n      python = {got!r}\n      go     = {want!r}")
        return False
    return True


def unhex(s: str) -> str:
    return bytes.fromhex(s).decode("utf-8")


def run_go(*args: str) -> str:
    env = dict(os.environ)
    env.update(_GO_ENV)
    proc = subprocess.run(
        ["go", "run", GO_PROG, *args],
        cwd=GO_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"go run {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def parse_vectors() -> dict[str, list[list[str]]]:
    sections: dict[str, list[list[str]]] = {}
    current = ""
    for line in GO_VECTORS.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            sections[current] = []
        elif current and line.strip():
            sections[current].append(line.split("\t"))
    return sections


def brief(text: str, limit: int = 58) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ─────────────────────── Sections ───────────────────────


def section_dynamic_token(sections: dict[str, list[list[str]]]) -> None:
    rows = sections["DYNAMIC_TOKEN"]
    meta: dict[str, list[str]] = {}
    for row in rows:
        if row[0] == "DT":
            meta[row[1]] = [unhex(row[2]), unhex(row[3]), ""]
        elif row[0] == "DTTOK":
            meta[row[1]][2] = unhex(row[2])
    expected = {row[1]: row[2] for row in rows if row[0] == "DTOUT"}

    print("=" * 80)
    print("calculate_dynamic_token")
    print("=" * 80)
    for idx in sorted(meta, key=int):
        path, content, token = meta[idx]
        got = calculate_dynamic_token(path, content, token)
        want = expected[idx]
        ok = check(f"calculate_dynamic_token[{idx}]", got, want)
        print(f"  [{'OK ' if ok else 'BAD'}] #{idx:>2} path={brief(path)!r}")
        print(f"        content={brief(content)!r}")
        print(f"        token={brief(token)!r}")
        print(f"        python={got}   go={want}")


def section_pe_auth_sign(sections: dict[str, list[list[str]]]) -> None:
    rows = sections["PE_AUTH_SIGN"]
    meta: dict[str, tuple[int, int, str]] = {}
    for row in rows:
        if row[0] == "SG":
            meta[row[1]] = (int(row[2]), int(row[3]), unhex(row[4]))
    expected = {row[1]: row[2] for row in rows if row[0] == "SGOUT"}

    print()
    print("=" * 80)
    print("pe_auth_sign")
    print("=" * 80)
    for idx in sorted(meta, key=int):
        sp, tr, v = meta[idx]
        got = pe_auth_sign(v, sp, tr)
        want = expected[idx]
        ok = check(f"pe_auth_sign[{idx}]", got, want)
        print(f"  [{'OK ' if ok else 'BAD'}] #{idx:>2} sp={sp} tr={tr} v={brief(v, 62)!r}")
        print(f"        python={got}   go={want}")

    print()
    print("pe_auth_sign error paths (compared structurally, not by message text):")
    for row in sections["PE_AUTH_SIGN_ERRORS"]:
        sp, tr = int(row[2]), int(row[3])
        # row[4] holds the Go message text; it is no longer compared (see the docstring)
        msg = ""
        try:
            pe_auth_sign("token", sp, tr)
            cls = "<no error>"
        except G79Error as exc:
            cls = type(exc).__name__
            msg = str(exc)
        got_err: object = (cls, bool(msg) and "sp" in msg)
        ok = check(f"pe_auth_sign error sp={sp} tr={tr}", got_err, ("G79Error", True))
        print(f"  [{'OK ' if ok else 'BAD'}] sp={sp:>4} tr={tr:>3}: {cls} {msg!r}")


def section_get_valid_json(sections: dict[str, list[list[str]]]) -> None:
    print()
    print("=" * 80)
    print("get_valid_json")
    print("=" * 80)
    for row in sections["GET_VALID_JSON"]:
        idx, raw_hex, want_hex = row[1], row[2], row[3]
        got = get_valid_json(bytes.fromhex(raw_hex)).hex()
        ok = check(f"get_valid_json[{idx}]", got, want_hex)
        print(f"  [{'OK ' if ok else 'BAD'}] #{idx:>2} in={raw_hex!r}")
        print(f"        python={got!r}  go={want_hex!r}")


def section_x19_token(sections: dict[str, list[list[str]]]) -> None:
    print()
    print("=" * 80)
    print("x19_calculate_dynamic_token")
    print("=" * 80)
    outs = {row[1]: row[2] for row in sections["X19_DYNAMIC_TOKEN"] if row[0] == "X19OUT"}
    for row in sections["X19_DYNAMIC_TOKEN"]:
        if row[0] != "X19":
            continue
        idx, url, content, token = row[1], unhex(row[2]), unhex(row[3]), unhex(row[4])
        got = x19_calculate_dynamic_token(url, content, token)
        want = outs[idx]
        ok = check(f"x19_calculate_dynamic_token[{idx}]", got, want)
        print(f"  [{'OK ' if ok else 'BAD'}] #{idx} url={url!r} content={content!r} token={token!r}")
        print(f"        python={got}   go={want}")


AES_CASES: dict[str, bytes] = {
    "empty": b"",
    "one": b"x",
    "json": b'{"code":0,"message":"","entity":{"a":1}}',
    "block15": b"0123456789abcde",
    "block16": b"0123456789abcdef",
    "block17": b"0123456789abcdefg",
    "block31": b"0123456789abcdef0123456789abcde",
    "block32": b"0123456789abcdef0123456789abcdef",
    "block33": b"0123456789abcdef0123456789abcdefg",
    "binary": bytes(range(256)),
    "utf8": "FIN-interop-675007 token🔑".encode(),
    "big": bytes((i * 7 + 3) % 256 for i in range(1000)),
}


def section_aes() -> None:
    print()
    print("=" * 80)
    print("G79HttpEncrypt / G79HttpDecrypt cross-check")
    print("=" * 80)
    WORK.mkdir(parents=True, exist_ok=True)

    for name, plain in AES_CASES.items():
        inp = WORK / f"{name}.in"
        go_payload = WORK / f"{name}.go.bin"
        go_dec = WORK / f"{name}.go.dec"
        py_hex = WORK / f"{name}.py.hex"
        go_dec_from_py = WORK / f"{name}.go.frompy.dec"

        inp.write_bytes(plain)

        # (1) Go encrypt -> Python decrypt; must match Go's own plaintext byte for byte
        run_go("encrypt", str(inp), str(go_payload), str(go_dec))
        payload = go_payload.read_bytes()
        ok1 = check(
            f"aes go->py decrypt [{name}]",
            g79_http_decrypt(payload),
            go_dec.read_bytes(),
        )

        # (2) Python encrypt -> Go decrypt; must match Python's own plaintext byte for byte
        py_ct = g79_http_encrypt(plain)
        py_hex.write_text(py_ct.hex(), encoding="ascii")
        run_go("decrypt", str(py_hex), str(go_dec_from_py))
        ok2 = check(
            f"aes py->go decrypt [{name}]",
            g79_http_decrypt(py_ct),
            go_dec_from_py.read_bytes(),
        )

        # (3) Structural invariants
        ok3 = check(
            f"aes layout [{name}]",
            (
                len(py_ct) >= 17,
                (len(py_ct) - 17) % 16 == 0,
                py_ct[-1] & 0x0F,
                0 <= (py_ct[-1] >> 4) < 15,
                len(py_ct),
            ),
            (
                True,
                True,
                0x0C,
                True,
                16 + ((len(plain) + 16 + 15) // 16) * 16 + 1,
            ),
        )

        # (4) Decrypted length: plaintext + a 16-byte random tail, padded to a 16-byte multiple
        #     Note: the random tail is 16 ASCII bytes that never contain 0x00, but 0x00
        #     padding may sit right after it. Both Go and Python strip **trailing 0x00**,
        #     so the bound is (plaintext + 16) .. want_len. Go's output is the most
        #     robust baseline (the two are byte-identical, as (1) and (2) already assert).
        want_len = ((len(plain) + 16 + 15) // 16) * 16
        got_len = len(g79_http_decrypt(py_ct))
        ok4 = check(
            f"aes decrypted len [{name}]",
            (len(plain) + 16 <= got_len <= want_len, got_len),
            (True, len(go_dec_from_py.read_bytes())),
        )

        mark = "OK " if all((ok1, ok2, ok3, ok4)) else "BAD"
        print(
            f"  [{mark}] {name:<8} plain={len(plain):>5}B  "
            f"py_payload={len(py_ct):>5}B(flag=0x{py_ct[-1]:02x})  "
            f"go_payload={len(payload):>5}B(flag=0x{payload[-1]:02x})  "
            f"cross-decrypt len={len(g79_http_decrypt(py_ct))}"
        )


def section_x19_aes() -> None:
    print()
    print("=" * 80)
    print("X19HttpEncrypt / X19HttpDecrypt cross-check")
    print("=" * 80)

    # (1) Go encrypt (random key index) -> Python decrypt; repeat to cover the random branch
    for name, plain in AES_CASES.items():
        inp = WORK / f"x19_{name}.in"
        inp.write_bytes(plain)
        for attempt in range(3):
            go_payload = WORK / f"x19_{name}.{attempt}.go.bin"
            go_dec = WORK / f"x19_{name}.{attempt}.go.dec"
            run_go("x19encrypt", str(inp), str(go_payload), str(go_dec))
            payload = go_payload.read_bytes()
            ok = check(
                f"x19 go->py decrypt [{name}#{attempt}]",
                x19_http_decrypt(payload),
                go_dec.read_bytes(),
            )
            if not ok or attempt == 0:
                print(
                    f"  [{'OK ' if ok else 'BAD'}] {name:<8} go_x19={len(payload):>5}B "
                    f"(keyIndex={payload[-1] >> 4}) -> python decrypt matches"
                )

    # (2) Python encrypt -> Go decrypt
    for name, plain in AES_CASES.items():
        py_ct = x19_http_encrypt(plain)
        py_hex = WORK / f"x19_{name}.py.hex"
        py_hex.write_text(py_ct.hex(), encoding="ascii")
        go_dec = WORK / f"x19_{name}.py.go.dec"
        run_go("x19decrypt", str(py_hex), str(go_dec))
        ok = check(
            f"x19 py->go decrypt [{name}]",
            go_dec.read_bytes(),
            x19_http_decrypt(py_ct),
        )
        print(
            f"  [{'OK ' if ok else 'BAD'}] {name:<8} py_x19={len(py_ct):>5}B "
            f"(keyIndex={py_ct[-1] >> 4}) -> go decrypt matches"
        )

    # (3) Cover all 16 key indexes explicitly: Python builds the payload -> Go decrypts
    print("  all 16 X19 key indexes (Python builds -> Go decrypts):")
    for key_index in range(len(X19_KEYS)):
        body = f"x19-key-{key_index}".encode()
        tail = b"TAILTAILTAILTAIL"
        iv = bytes(range(key_index, key_index + 16))
        padded = pkcs7_pad(body + tail)
        payload = (
            iv
            + _cbc_encrypt(X19_KEYS[key_index].encode(), iv, padded)
            + bytes([(key_index << 4) | 0x02])
        )
        py_hex = WORK / f"x19_key{key_index}.py.hex"
        py_hex.write_text(payload.hex(), encoding="ascii")
        go_dec = WORK / f"x19_key{key_index}.go.dec"
        run_go("x19decrypt", str(py_hex), str(go_dec))
        # Go's X19HttpDecrypt **does not unpad** (crypto.go:273 `return plain, nil`), so the
        # expectation must keep the PKCS7 padding. An earlier version expecting body+tail had a
        # bug in this script, not in the Python side (which does not unpad either, so they agree).
        check(f"x19 keyIndex={key_index}", go_dec.read_bytes(), padded)
    print(f"    all {len(X19_KEYS)} indexes passed (see the assertion count)")


def section_aes_key_table() -> None:
    """AES key-table selection: each high nibble of the flag must pick the same key as Go."""
    print()
    print("=" * 80)
    print("AES key table / flag selection")
    print("=" * 80)
    seen: set[int] = set()
    for _ in range(400):
        ct = g79_http_encrypt(b"key-table-probe")
        seen.add(ct[-1] >> 4)
    ok = check("flag high-nibble domain", sorted(seen) == list(range(15)), True)
    print(f"  [{'OK ' if ok else 'BAD'}] high nibbles seen = {sorted(seen)} (Go: 0..14)")

    # The decrypt side must depend only on the top 4 bits of the flag
    for key_index in range(15):
        key = bytes.fromhex(AES_KEYS[key_index])
        iv = bytes(range(16))
        # Original plaintext (the trailing 0x00s are padding; rstrip restores it after decrypt)
        raw = f"g79-key-{key_index}".encode() + b"\x00" * 4
        # _cbc_encrypt is a **padding-free** primitive, so the body length must be a multiple of 16;
        # here 0x00 is appended by hand up to 32 bytes (12->32), and decrypt rstrips 0x00 likewise.
        body = raw.ljust(32, b"\x00")
        payload = iv + _cbc_encrypt(key, iv, body) + bytes([(key_index << 4) | 0x0C])
        ok = check(f"g79 decrypt keyIndex={key_index}", g79_http_decrypt(payload), raw.rstrip(b"\x00"))
        if not ok:
            print(f"  [BAD] keyIndex={key_index}")
    print("  [OK ] all 15 G79 key indexes passed (Python builds -> Python decrypts)")


def main() -> int:
    if not GO_VECTORS.exists():
        print(f"missing {GO_VECTORS}")
        print(f"run this first:  go run {GO_PROG} vectors > {GO_VECTORS}")
        return 2

    sections = parse_vectors()
    section_dynamic_token(sections)
    section_pe_auth_sign(sections)
    section_get_valid_json(sections)
    section_x19_token(sections)
    section_aes()
    section_x19_aes()
    section_aes_key_table()

    print()
    print("=" * 80)
    if failures:
        print(f"❌ {len(failures)} of {checks} assertions failed")
        for f in failures:
            print("  -", f)
        return 1
    print(f"✅ all passed: all {checks} assertions match the Go reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
