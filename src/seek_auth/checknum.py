"""SeekAuth — anti-cheat check number (transferCheckNum).

Corresponds to FateArk's `/api/noahs-ark/common/transfer-check-num`. The client sends
``[mcpHex, val, uniqueID]`` and the server must produce the same check values as the real game.

## Where the algorithm comes from

`mcpHex` is the ``vanilla.mcp`` FateArk downloads from NetEase -- encrypted Python 2.7 bytecode
containing ``GetCheckNum`` from ``c_DyBasic.py``. This module replays that flow:

1. **Decrypt the MCP** (rotor -> zlib -> reverse -> marshal repair) to obtain a ``.pyc``.
2. **Extract the salts** ``s1``/``s2``: the source holds ``message = '<s1>' + data + '<s2>'``.
   **The salts change with the mcp version** (several seen in practice, e.g. ``?hqoj/d2z`` or
   ``wy!mt9!7opw+s/a!8``), so they must be extracted dynamically; hardcoding always breaks.
3. ``CalcCheckNum(data) = md5(s1 + data + s2)``
4. Assemble the ``tmps`` list -> ``tmpsNum``, ``valM``, ``sign``, and output a JSON array.

## About c (launch time)

In the reference implementation ``GetStaticCheckNumClient``, ``c`` prefers
``chat_ctrl._recent_fid``, falls back to ``log_mgr._rn_launcher_time``, and is ``0`` when
neither exists. A pure bot has no game process, so it takes ``0`` -- as the reference does.
"""

from __future__ import annotations

import hashlib
import json
import re
import zlib
from dataclasses import dataclass
from typing import Any

from .logging_setup import get_logger
from .pymarshal import pyc_repairer
from .rotor import Rotor

log = get_logger(__name__)

# Rotor key material (identical to unmcpk/main.go)
_ROTOR_KEY = (
    "j2h56ogodh3sk" * 4
    + ("=dziaq;" + "j2h56ogodh3sk" + "|`o=5v7!\"-276") * 5
    + "$@"
    + "=dziaq;" * 7
    + "|`o=5v7!\"-276" * 2
    + "&]`"
)
_ROTOR_COUNT = 6

# Pattern of the salts in the source
_SALT_RE = re.compile(r"message = '([^']*)' \+ data \+ '([^']*)'")


class CheckNumError(Exception):
    """Check number computation failed."""


@dataclass(frozen=True)
class Salts:
    """The two salts extracted from the MCP source."""

    s1: str
    s2: str


# ─────────────────────── MCP decryption ───────────────────────


def _reverse_data(data: bytearray) -> bytearray:
    """reverseData from unmcpk/main.go: XOR the first 130 bytes with 0x9C, then reverse it all."""
    for i in range(min(130, len(data))):
        data[i] ^= 156
    data.reverse()
    return data


def decrypt_mcp(mcp_bytes: bytes) -> bytes:
    """Decrypt ``vanilla.mcp`` and return the repaired Python 2.7 bytecode.

    Flow (matching ``unmcpk.DecryptDynamicMCP``):
    rotor decrypt -> zlib decompress -> ``reverseData`` -> marshal repair.
    """
    buf = bytearray(mcp_bytes)
    Rotor(_ROTOR_COUNT, _ROTOR_KEY).d_region(buf, True)

    try:
        unzipped = zlib.decompress(bytes(buf))
    except zlib.error as e:
        raise CheckNumError(f"zlib decompression failed: {e}") from e

    reversed_data = _reverse_data(bytearray(unzipped))

    try:
        return pyc_repairer(bytes(reversed_data), True)
    except Exception as e:  # noqa: BLE001 - pymarshal raises assorted error types
        raise CheckNumError(f"marshal repair failed: {e}") from e


def extract_salts_from_source(source: str) -> Salts:
    """Extract the salts from decompiled / repaired source text.

    Note: the repaired ``.pyc`` is **bytecode**; its string constants appear in plain text, so a
    plain regex works here and no decompilation is needed.
    """
    m = _SALT_RE.search(source)
    if not m:
        raise CheckNumError("no CalcCheckNum salts found")
    return Salts(s1=m.group(1), s2=m.group(2))


def extract_salts(repaired: bytes) -> Salts:
    """Extract the two ``CalcCheckNum`` salts from the repaired Python 2.7 bytecode.

    A source-text regex **cannot** be used here -- the repaired artifact is **bytecode**: there is
    no ``message = '...' + data + '...'`` expression, only string constants.

    The reference implementation (``unmcpk/checknum.go: extractS1S2FromRepairedByRegex``) uses a
    byte-offset heuristic, ported faithfully here:

    1. start at the fixed offset ``251`` and scan forward to the first ``0x28`` (marshal's
       ``TYPE_TUPLE`` marker); the span between them is the target region;
    2. in that region find the first ``s`` + any byte + three 0x00 bytes -- that is marshal's
       ``TYPE_STRING``(0x73) + 4-byte LE length (top 3 bytes 0 for a short string);
    3. what lies **before** that marker is ``s1``, what lies **after** it is ``s2``.

    Observed layout (for the ``?hqoj``/``d2z`` version)::

        ... Ni ff ff ff ff | '?hqoj' s 03 00 00 00 'd2z' | 28 ...
                    ^251                              ^endIndex

    ``s1``'s own length prefix sits before 251, so the first marker nearby belongs to ``s2``.

    The offset ``251`` is a **version-dependent** hardcoded value (inherited from the reference
    implementation). If NetEase changes the bytecode layout this extracts nonsense, and
    :func:`_salts_look_valid` detects that and falls back to :func:`_scan_all_string_markers`.
    """
    s1, s2 = _extract_by_reference_offset(repaired)
    if _salts_look_valid(s1, s2):
        return Salts(s1=s1, s2=s2)

    # Fallback: scan every TYPE_STRING marker in the whole bytecode for the CalcCheckNum pair
    scanned = _scan_all_string_markers(repaired)
    if scanned is not None:
        log.warning(
            "offset heuristic failed, switching to a full-file scan",
            ref_s1=s1[:24],
            ref_s2=s2[:24],
            scan_s1=scanned.s1,
            scan_s2=scanned.s2,
        )
        return scanned

    raise CheckNumError("no CalcCheckNum salts found (the bytecode layout may have changed)")


# marshal TYPE_STRING marker: 's' + 4-byte little-endian length (top 3 bytes are 0 if short)
_MARKER_RE = re.compile(rb"s.\x00{3}", re.DOTALL)
# marshal TYPE_TUPLE marker
_TUPLE = 0x28


def _extract_by_reference_offset(repaired: bytes) -> tuple[str, str]:
    """The reference implementation's byte-offset heuristic (faithful port)."""
    start = 251
    end = -1
    for i in range(start, len(repaired)):
        if repaired[i] == _TUPLE:
            end = i
            break
    if end <= start:
        return "", ""

    target = repaired[start:end]
    m = _MARKER_RE.search(target)
    if m is None:
        return "", ""

    s1 = target[: m.start()].decode("latin-1")
    s2 = target[m.end() :].decode("latin-1")
    return s1, s2


def _salts_look_valid(s1: str, s2: str) -> bool:
    """Decide whether the extracted salts look sane (non-empty, short, printable ASCII)."""
    if not s1 or not s2:
        return False
    if len(s1) > 32 or len(s2) > 64:
        return False
    return all(0x20 <= ord(c) < 0x7F for c in s1 + s2)


def _scan_all_string_markers(repaired: bytes) -> Salts | None:
    """Fallback: scan every TYPE_STRING for the short constant pair near ``CalcCheckNum``.

    More robust than the offset method: it does not rely on the fixed 251. It locates the known
    ``c_DyBasic``/``CalcCheckNum`` symbols and hunts two adjacent short constants before them.
    """
    # The known symbols appear in plain text inside the bytecode
    anchor = repaired.find(b"CalcCheckNum")
    if anchor < 0:
        anchor = repaired.find(b"c_DyBasic")
    if anchor < 0:
        return None

    # Collect every TYPE_STRING constant in the 512-byte window before the anchor
    lo = max(0, anchor - 512)
    window = repaired[lo:anchor]
    found: list[str] = []
    for m in _MARKER_RE.finditer(window):
        # Length: 4 little-endian bytes right after the marker's first byte
        ln = int.from_bytes(window[m.start() + 1 : m.start() + 5], "little")
        if not (1 <= ln <= 64):
            continue
        val = window[m.end() : m.end() + ln]
        if len(val) != ln:
            continue
        try:
            text = val.decode("ascii")
        except UnicodeDecodeError:
            continue
        if text.isprintable():
            found.append(text)

    if len(found) >= 2:
        # Take the last two (the ones right next to CalcCheckNum's definition)
        return Salts(s1=found[-2], s2=found[-1])
    return None


# ─────────────────────── check number computation ───────────────────────


def _md5_hex(*parts: str) -> str:
    h = hashlib.md5(usedforsecurity=False)  # noqa: S324 - the protocol demands MD5
    for p in parts:
        h.update(p.encode())
    return h.hexdigest()


def calc_check_num(s1: str, s2: str, data: str) -> str:
    """``CalcCheckNum(data) = md5(s1 + data + s2)``."""
    return _md5_hex(s1, data, s2)


def generate_transfer_check_num(
    data: str,
    *,
    engine_version: str,
    patch_version: str,
    is_pc: bool = False,
) -> str:
    """Compute ``transferCheckNum``.

    :param data: the ``data`` field from the client (JSON array string ``[mcpHex, val, uniqueID]``)
    :param engine_version: engine version (e.g. ``3.6.5.281774``)
    :param patch_version: patch version (e.g. ``3.6.56.288487``)
    :param is_pc: PC client or not (affects ``osname``/``sys.platform``/``RUNTIME_PLATFORM``)
    :returns: a JSON array string that can go straight into the response

    The output looks like::

        ["<valM>","<sign>",false,[],"","",3,"<tmpsNum>"]

    where ``false`` is ``is_nolauncher() and not is_pccocos()``, ``[]`` is the memcheck result
    and the two ``""`` are pkgname/pkgsign. With a genuine build plus a loaded ``libunisec.so``
    these really are empty -- only a stripped / hardened package reports a package name and
    signature.
    """
    try:
        arr = json.loads(data)
    except json.JSONDecodeError as e:
        raise CheckNumError(f"data is not valid JSON: {e}") from e

    if not isinstance(arr, list) or len(arr) < 3:
        raise CheckNumError("data must be an array of length >= 3")

    mcp_hex, val, unique_raw = arr[0], arr[1], arr[2]
    if not isinstance(mcp_hex, str) or not isinstance(val, str):
        raise CheckNumError("data[0]/data[1] must be strings")

    try:
        unique_id = int(unique_raw)
    except (TypeError, ValueError) as e:
        raise CheckNumError(f"data[2] is not an integer: {unique_raw!r}") from e

    try:
        mcp_bytes = bytes.fromhex(mcp_hex)
    except ValueError as e:
        raise CheckNumError(f"mcpHex is not valid hex: {e}") from e

    repaired = decrypt_mcp(mcp_bytes)
    salts = extract_salts(repaired)
    log.debug(
        "mcp decrypted",
        mcp_bytes=len(mcp_bytes),
        repaired=len(repaired),
        s1_len=len(salts.s1),
        s2_len=len(salts.s2),
    )

    # c: a pure bot scenario has no game process, so use 0 (as GetStaticCheckNumClient does)
    c = "0"
    val_m = calc_check_num(salts.s1, salts.s2, val + c)

    # tmps: expand valM character by character, then append the platform-specific fields
    tmps: list[str] = [str((ord(ch) * 2 + 5) ^ 255) for ch in val_m]

    if is_pc:
        tmps.extend(
            [engine_version, "windows", engine_version, "win32", "0", "12", str(unique_id)]
        )
    else:
        tmps.extend(
            [engine_version, "android", patch_version, "android", "2", "12", str(unique_id)]
        )

    tmps_str = "".join(tmps)
    tmps_num = calc_check_num(salts.s1, salts.s2, tmps_str)

    # sign = md5(s1 + (valM[16:] + params + valM[:16]) + s2)
    # params is [false, [], "", "", 3]
    raw = val_m[16:] + "False" + "[]" + "" + "" + "3" + tmps_num + val_m[:16]
    sign = calc_check_num(salts.s1, salts.s2, raw)

    out: list[Any] = [val_m, sign, False, [], "", "", 3, tmps_num]
    return json.dumps(out, separators=(",", ":"))


def describe(data: str) -> dict[str, Any]:
    """For diagnostics: return the intermediate decrypt and salt-extraction results."""
    arr = json.loads(data)
    mcp_bytes = bytes.fromhex(arr[0])
    repaired = decrypt_mcp(mcp_bytes)
    salts = extract_salts(repaired)
    return {
        "mcp_bytes": len(mcp_bytes),
        "repaired_bytes": len(repaired),
        "s1": salts.s1,
        "s2": salts.s2,
        "s1_len": len(salts.s1),
        "s2_len": len(salts.s2),
    }
