"""NetEase custom Python 2.7 marshal codec -- faithful port of the Go package
``github.com/Yeah114/unmcpk/pymarshal``.

NetEase ships its anti-cheat logic as a compiled Python 2.7 code object wrapped
in a proprietary container (``vanilla.mcp`` / the ``mcpHex`` blob the client
hands to the server during transfer-check-num).  The payload is not plain
``marshal`` output: NetEase replaced the CPython marshal type tags with its own
("NetEase string v0/v1/v2", "NetEase code v0/v1/v2"), encrypts the string
bodies (XOR 0x8d or one of two RC4 keys), permutes the code object field order,
and remaps the bytecode opcodes through one of three shuffle tables.

:func:`pyc_repairer` reverses all of that and emits a stock CPython 2.7
``.pyc`` body (``PYC_HEADER`` + marshal stream) that ``uncompyle6`` can read.
:func:`pyc_encryptor` performs the inverse, turning a standard marshal payload
back into the NetEase dialect.

This module is a *mechanical* port: the byte-level logic, switch/case ordering,
integer wraparound, read/write ordering and error conditions of the Go original
are preserved exactly, including its quirks (for example, ``copyDict`` is
effectively unreachable in the original because ``ErrNull`` is never actually
returned by ``RepairMarshal``, and ``bytes.Reader.Read`` short reads silently
zero-pad rather than failing).  Do not "clean up" behaviour here without
re-validating against the Go reference.

No third-party dependencies; standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PymarshalError(Exception):
    """Raised where the Go original returns a non-nil ``error``.

    A few sites in the Go code panic instead of returning (``make([]byte, n)``
    with a negative ``n``, slice bounds, map index out of range); those raise
    this same exception, carrying an equivalent message.
    """


#: Sentinel equivalent to Go's ``ErrNull``.  Compared by identity, mirroring
#: ``errors.Is(err, ErrNull)``.
ErrNull = PymarshalError("null object")

#: Equivalent to Go's ``ErrUnsupportedStringVersion``.
ErrUnsupportedStringVersion = PymarshalError("unsupported netease string version")

#: Equivalent to Go's ``ErrUnsupportedCodeVersion``.
ErrUnsupportedCodeVersion = PymarshalError("unsupported netease code version")


PYC_HEADER: bytes = b"\x03\xf3\r\n\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# Stock CPython 2.x marshal type tags (types.go)
# ---------------------------------------------------------------------------

TYPE_NULL = 0x30  # '0'
TYPE_NONE = 0x4E  # 'N'
TYPE_FALSE = 0x46  # 'F'
TYPE_TRUE = 0x54  # 'T'
TYPE_STOPITER = 0x53  # 'S'
TYPE_ELLIPSIS = 0x2E  # '.'
TYPE_INT = 0x69  # 'i'
TYPE_INT64 = 0x49  # 'I'
TYPE_FLOAT = 0x66  # 'f'
TYPE_BINARY_FLOAT = 0x67  # 'g'
TYPE_COMPLEX = 0x78  # 'x'
TYPE_BINARY_COMPLEX = 0x79  # 'y'
TYPE_LONG = 0x6C  # 'l'
TYPE_STRING = 0x73  # 's'
TYPE_INTERNED = 0x74  # 't'
TYPE_STRINGREF = 0x52  # 'R'
TYPE_TUPLE = 0x28  # '('
TYPE_LIST = 0x5B  # '['
TYPE_DICT = 0x7B  # '{'
TYPE_CODE = 0x63  # 'c'
TYPE_UNICODE = 0x75  # 'u'
TYPE_UNKNOWN = 0x3F  # '?'
TYPE_SET = 0x3C  # '<'
TYPE_FROZENSET = 0x3E  # '>'


# ---------------------------------------------------------------------------
# NetEase-specific marshal type tags (netease_types.go)
# ---------------------------------------------------------------------------

TYPE_NETEASE_CODE_0 = 0x61
TYPE_NETEASE_CODE_1 = 0x6F
TYPE_NETEASE_CODE_2 = 0x4D

TYPE_NETEASE_STRING_0 = 0x08
TYPE_NETEASE_INTERNED_0 = 0x0F
TYPE_NETEASE_UNICODE_0 = 0x0E

# before 2.7
TYPE_NETEASE_STRING_1 = 0x17
TYPE_NETEASE_INTERNED_1 = 0x1A
TYPE_NETEASE_UNICODE_1 = 0x1D

# after 2.7
TYPE_NETEASE_STRING_2 = 0x6D
TYPE_NETEASE_INTERNED_2 = 0x62
TYPE_NETEASE_UNICODE_2 = 0x31


# ---------------------------------------------------------------------------
# Fixed-width integer helpers
#
# Go's int8/int16/int32/uint8/uint16/uint32 wrap silently; Python ints do not.
# Every arithmetic site that relies on that wraparound goes through one of
# these.
# ---------------------------------------------------------------------------

_MASK32 = 0xFFFFFFFF
_MASK16 = 0xFFFF
_MASK8 = 0xFF


def _i8(v: int) -> int:
    """Wrap to a signed 8-bit value."""
    v &= _MASK8
    return v - 0x100 if v >= 0x80 else v


def _i16(v: int) -> int:
    """Wrap to a signed 16-bit value."""
    v &= _MASK16
    return v - 0x10000 if v >= 0x8000 else v


def _i32(v: int) -> int:
    """Wrap to a signed 32-bit value."""
    v &= _MASK32
    return v - 0x100000000 if v >= 0x80000000 else v


def _u8(v: int) -> int:
    return v & _MASK8


def _u16(v: int) -> int:
    return v & _MASK16


def _u32(v: int) -> int:
    return v & _MASK32


def _trunc_div(a: int, b: int) -> int:
    """Go integer division: truncates toward zero (Python's ``//`` floors)."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _trunc_mod(a: int, b: int) -> int:
    """Go integer remainder: sign follows the dividend."""
    return a - _trunc_div(a, b) * b


def _abs_i32(n: int) -> int:
    """utility.go ``absInt32`` -- including its int32 negation wraparound."""
    if n < 0:
        return _i32(-n)
    return n


def _pack_i32(n: int) -> bytes:
    return struct.pack("<i", _i32(n))


def _pack_i16(n: int) -> bytes:
    return struct.pack("<h", _i16(n))


def _pack_u32(n: int) -> bytes:
    return struct.pack("<I", _u32(n))


def _make_slice(size: int) -> int:
    """Stand-in for Go's ``make([]byte, size)``, which panics when size < 0."""
    if size < 0:
        raise PymarshalError("makeslice: len out of range")
    return size


# ---------------------------------------------------------------------------
# RC4 (Go's crypto/rc4)
# ---------------------------------------------------------------------------

def _rc4_xor(key: bytes, data: bytes) -> bytes:
    """RC4 keystream XOR, identical to ``rc4.NewCipher(key).XORKeyStream``."""
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & _MASK8
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = 0
    j = 0
    for n in range(len(data)):
        i = (i + 1) & _MASK8
        j = (j + s[i]) & _MASK8
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & _MASK8]
    return bytes(out)


_RC4_KEY_V1 = bytes([0xA7, 0x0D, 0x37, 0x7A])
_RC4_KEY_V2 = bytes([0x8D, 0x06, 0xE8, 0xC8, 0xB7, 0xD7, 0xB7,
                     0x28, 0x46, 0x51, 0xAE, 0x04])


# ---------------------------------------------------------------------------
# Byte stream primitives
#
# Two distinct read semantics exist in the Go code and they are NOT
# interchangeable:
#
#   * ``reader.Read(buf)`` on a ``bytes.Reader`` performs a *short* read: it
#     returns as soon as the underlying slice is exhausted, with a nil error as
#     long as at least one byte was available.  Callers pass a freshly zeroed
#     buffer, so a short read silently zero-pads.  -> :meth:`_Reader.read_into`
#
#   * ``binary.Read`` / ``io.ReadFull`` demand the full width and fail with
#     ``ErrUnexpectedEOF`` otherwise.  -> :meth:`_Reader.read_full`
#
# Collapsing these into one helper would change output on truncated input.
# ---------------------------------------------------------------------------

class _Reader:
    """Minimal ``bytes.Reader`` clone with the same read semantics."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def len(self) -> int:
        """Go ``bytes.Reader.Len()``."""
        return len(self._data) - self._pos

    def size(self) -> int:
        """Go ``bytes.Reader.Size()``."""
        return len(self._data)

    def read_byte(self) -> int:
        if self._pos >= len(self._data):
            raise PymarshalError("EOF")
        b = self._data[self._pos]
        self._pos += 1
        return b

    def try_read_byte(self) -> int:
        """``type1, _ := reader.ReadByte()`` -- the error is discarded, so an
        exhausted reader yields 0."""
        if self._pos >= len(self._data):
            return 0
        b = self._data[self._pos]
        self._pos += 1
        return b

    def unread_byte(self) -> None:
        if self._pos <= 0:
            raise PymarshalError("bytes.Reader.UnreadByte: at beginning of slice")
        self._pos -= 1

    def read_into(self, size: int) -> bytes:
        """``reader.Read(make([]byte, size))``.

        Returns exactly ``size`` bytes; any tail the underlying slice cannot
        supply stays zero.  Raises only when *no* byte at all was available
        (Go returns ``io.EOF`` in that case).
        """
        if size < 0:
            raise PymarshalError("makeslice: len out of range")
        if size == 0:
            # bytes.Reader.Read with a zero-length buffer still reports EOF
            # once exhausted; copyBytes guards size == 0 before getting here.
            if self._pos >= len(self._data):
                raise PymarshalError("EOF")
            return b""
        if self._pos >= len(self._data):
            raise PymarshalError("EOF")
        n = min(size, len(self._data) - self._pos)
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        if n < size:
            chunk = chunk + b"\x00" * (size - n)
        return chunk

    def read_full(self, size: int) -> bytes:
        """``io.ReadFull(reader, make([]byte, size))``."""
        if size < 0:
            raise PymarshalError("makeslice: len out of range")
        if size == 0:
            return b""
        if self._pos >= len(self._data):
            raise PymarshalError("EOF")
        n = min(size, len(self._data) - self._pos)
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        if n < size:
            raise PymarshalError("unexpected EOF")
        return chunk

    def read_i32(self) -> int:
        """``binary.Read(reader, binary.LittleEndian, &n)`` for an int32."""
        # struct.unpack returns a tuple of Any, so take the element out explicitly
        value: int = struct.unpack("<i", self.read_full(4))[0]
        return value

    def read_u32(self) -> int:
        value: int = struct.unpack("<I", self.read_full(4))[0]
        return value

    def read_i16(self) -> int:
        value: int = struct.unpack("<h", self.read_full(2))[0]
        return value


class _Writer:
    """Minimal ``bytes.Buffer`` clone.  Writes never fail."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf += data

    def write_byte(self, b: int) -> None:
        self._buf.append(b & _MASK8)

    def bytes(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)


# ---------------------------------------------------------------------------
# Opcode tables, generated verbatim from opcode.go / netease_opcode.go
# ---------------------------------------------------------------------------

OPCODES = {
    "POP_TOP": 1,
    "ROT_TWO": 2,
    "ROT_THREE": 3,
    "DUP_TOP": 4,
    "ROT_FOUR": 5,
    "NOP": 9,
    "UNARY_POSITIVE": 10,
    "UNARY_NEGATIVE": 11,
    "UNARY_NOT": 12,
    "UNARY_CONVERT": 13,
    "UNARY_INVERT": 15,
    "BINARY_POWER": 19,
    "BINARY_MULTIPLY": 20,
    "BINARY_DIVIDE": 21,
    "BINARY_MODULO": 22,
    "BINARY_ADD": 23,
    "BINARY_SUBTRACT": 24,
    "BINARY_SUBSCR": 25,
    "BINARY_FLOOR_DIVIDE": 26,
    "BINARY_TRUE_DIVIDE": 27,
    "INPLACE_FLOOR_DIVIDE": 28,
    "INPLACE_TRUE_DIVIDE": 29,
    "SLICE_0": 30,
    "SLICE_1": 31,
    "SLICE_2": 32,
    "SLICE_3": 33,
    "STORE_SLICE_0": 40,
    "STORE_SLICE_1": 41,
    "STORE_SLICE_2": 42,
    "STORE_SLICE_3": 43,
    "DELETE_SLICE_0": 50,
    "DELETE_SLICE_1": 51,
    "DELETE_SLICE_2": 52,
    "DELETE_SLICE_3": 53,
    "STORE_MAP": 54,
    "INPLACE_ADD": 55,
    "INPLACE_SUBTRACT": 56,
    "INPLACE_MULTIPLY": 57,
    "INPLACE_DIVIDE": 58,
    "INPLACE_MODULO": 59,
    "STORE_SUBSCR": 60,
    "DELETE_SUBSCR": 61,
    "BINARY_LSHIFT": 62,
    "BINARY_RSHIFT": 63,
    "BINARY_AND": 64,
    "BINARY_XOR": 65,
    "BINARY_OR": 66,
    "INPLACE_POWER": 67,
    "GET_ITER": 68,
    "PRINT_EXPR": 70,
    "PRINT_ITEM": 71,
    "PRINT_NEWLINE": 72,
    "PRINT_ITEM_TO": 73,
    "PRINT_NEWLINE_TO": 74,
    "INPLACE_LSHIFT": 75,
    "INPLACE_RSHIFT": 76,
    "INPLACE_AND": 77,
    "INPLACE_XOR": 78,
    "INPLACE_OR": 79,
    "BREAK_LOOP": 80,
    "WITH_CLEANUP": 81,
    "LOAD_LOCALS": 82,
    "RETURN_VALUE": 83,
    "IMPORT_STAR": 84,
    "EXEC_STMT": 85,
    "YIELD_VALUE": 86,
    "POP_BLOCK": 87,
    "END_FINALLY": 88,
    "BUILD_CLASS": 89,
    "STORE_NAME": 90,
    "DELETE_NAME": 91,
    "UNPACK_SEQUENCE": 92,
    "FOR_ITER": 93,
    "LIST_APPEND": 94,
    "STORE_ATTR": 95,
    "DELETE_ATTR": 96,
    "STORE_GLOBAL": 97,
    "DELETE_GLOBAL": 98,
    "DUP_TOPX": 99,
    "LOAD_CONST": 100,
    "LOAD_NAME": 101,
    "BUILD_TUPLE": 102,
    "BUILD_LIST": 103,
    "BUILD_SET": 104,
    "BUILD_MAP": 105,
    "LOAD_ATTR": 106,
    "COMPARE_OP": 107,
    "IMPORT_NAME": 108,
    "IMPORT_FROM": 109,
    "JUMP_FORWARD": 110,
    "JUMP_IF_FALSE_OR_POP": 111,
    "JUMP_IF_TRUE_OR_POP": 112,
    "JUMP_ABSOLUTE": 113,
    "POP_JUMP_IF_FALSE": 114,
    "POP_JUMP_IF_TRUE": 115,
    "LOAD_GLOBAL": 116,
    "CONTINUE_LOOP": 119,
    "SETUP_LOOP": 120,
    "SETUP_EXCEPT": 121,
    "SETUP_FINALLY": 122,
    "LOAD_FAST": 124,
    "STORE_FAST": 125,
    "DELETE_FAST": 126,
    "RAISE_VARARGS": 130,
    "CALL_FUNCTION": 131,
    "MAKE_FUNCTION": 132,
    "BUILD_SLICE": 133,
    "MAKE_CLOSURE": 134,
    "LOAD_CLOSURE": 135,
    "LOAD_DEREF": 136,
    "STORE_DEREF": 137,
    "CALL_FUNCTION_VAR": 140,
    "CALL_FUNCTION_KW": 141,
    "CALL_FUNCTION_VAR_KW": 142,
    "SETUP_WITH": 143,
    "EXTENDED_ARG": 145,
    "SET_ADD": 146,
    "MAP_ADD": 147,
}

NETEASE_OPCODES = {
    0xca49b20f: {
        0x6e: "DUP_TOPX",
        0x5c: "BINARY_AND",
        0x47: "INPLACE_TRUE_DIVIDE",
        0x87: "DELETE_NAME",
        0x0a: "INPLACE_MODULO",
        0x34: "ROT_THREE",
        0x40: "DELETE_SLICE_2",
        0x2f: "PRINT_ITEM_TO",
        0x66: "EXTENDED_ARG",
        0x1c: "SLICE_1",
        0xd1: "SETUP_EXCEPT",
        0x1a: "WITH_CLEANUP",
        0x18: "INPLACE_MULTIPLY",
        0xd4: "STORE_ATTR",
        0x1e: "SLICE_3",
        0xd0: "SETUP_LOOP",
        0x53: "POP_TOP",
        0x88: "LOAD_GLOBAL",
        0x6b: "FOR_ITER",
        0x36: "BINARY_SUBTRACT",
        0xd5: "JUMP_IF_TRUE_OR_POP",
        0xbd: "SET_ADD",
        0x42: "UNARY_CONVERT",
        0x14: "STORE_MAP",
        0xb6: "RAISE_VARARGS",
        0x03: "UNARY_INVERT",
        0x1f: "BINARY_RSHIFT",
        0x0f: "GET_ITER",
        0xfa: "IMPORT_NAME",
        0x12: "YIELD_VALUE",
        0x07: "STORE_SLICE_3",
        0x08: "BINARY_SUBSCR",
        0x29: "INPLACE_AND",
        0x79: "JUMP_FORWARD",
        0xa1: "BUILD_MAP",
        0x17: "PRINT_ITEM",
        0x8c: "LOAD_FAST",
        0x52: "IMPORT_STAR",
        0x04: "STORE_SLICE_0",
        0xda: "POP_JUMP_IF_FALSE",
        0x51: "RETURN_VALUE",
        0xc3: "JUMP_IF_FALSE_OR_POP",
        0x0b: "BINARY_POWER",
        0x10: "INPLACE_SUBTRACT",
        0x3b: "BINARY_LSHIFT",
        0xd8: "LIST_APPEND",
        0xdf: "MAP_ADD",
        0xfe: "UNPACK_SEQUENCE",
        0x44: "INPLACE_OR",
        0x09: "PRINT_NEWLINE",
        0x6f: "BUILD_SET",
        0x01: "ROT_FOUR",
        0x0d: "INPLACE_LSHIFT",
        0xe9: "CALL_FUNCTION_VAR",
        0xd6: "LOAD_CLOSURE",
        0x2e: "BREAK_LOOP",
        0x2c: "UNARY_POSITIVE",
        0x28: "END_FINALLY",
        0x89: "LOAD_ATTR",
        0x5a: "NOP",
        0xea: "CALL_FUNCTION_KW",
        0x23: "STORE_SUBSCR",
        0x3e: "DELETE_SLICE_0",
        0x84: "LOAD_NAME",
        0x35: "LOAD_LOCALS",
        0x9f: "STORE_FAST",
        0xc2: "SETUP_WITH",
        0x0e: "BINARY_TRUE_DIVIDE",
        0x56: "UNARY_NOT",
        0x4d: "INPLACE_ADD",
        0xfc: "BUILD_SLICE",
        0x58: "PRINT_NEWLINE_TO",
        0x60: "STORE_DEREF",
        0x11: "POP_BLOCK",
        0xc9: "STORE_NAME",
        0xa7: "CONTINUE_LOOP",
        0x46: "UNARY_NEGATIVE",
        0x1d: "SLICE_2",
        0xeb: "CALL_FUNCTION_VAR_KW",
        0x13: "INPLACE_FLOOR_DIVIDE",
        0xe1: "DELETE_ATTR",
        0x50: "ROT_TWO",
        0x33: "INPLACE_POWER",
        0x31: "PRINT_EXPR",
        0xa3: "IMPORT_FROM",
        0x85: "LOAD_DEREF",
        0x4e: "BINARY_OR",
        0x4b: "BINARY_MODULO",
        0x1b: "SLICE_0",
        0xf3: "POP_JUMP_IF_TRUE",
        0xde: "LOAD_CONST",
        0x3f: "DELETE_SLICE_1",
        0x06: "STORE_SLICE_2",
        0x48: "BINARY_XOR",
        0x05: "STORE_SLICE_1",
        0xf7: "MAKE_FUNCTION",
        0xe5: "BUILD_TUPLE",
        0x15: "BINARY_MULTIPLY",
        0xf0: "DELETE_GLOBAL",
        0xa2: "DELETE_FAST",
        0xaf: "BUILD_LIST",
        0x74: "SETUP_FINALLY",
        0x59: "DELETE_SUBSCR",
        0x43: "BUILD_CLASS",
        0x2a: "BINARY_DIVIDE",
        0x7b: "JUMP_ABSOLUTE",
        0x4f: "EXEC_STMT",
        0xa6: "MAKE_CLOSURE",
        0x90: "CALL_FUNCTION",
        0x2b: "DUP_TOP",
        0x86: "STORE_GLOBAL",
        0x27: "INPLACE_DIVIDE",
        0x02: "INPLACE_RSHIFT",
        0x41: "DELETE_SLICE_3",
        0x3c: "INPLACE_XOR",
        0x57: "BINARY_FLOOR_DIVIDE",
        0x49: "BINARY_ADD",
        0xe4: "COMPARE_OP",
    },
    0x00000000: {
        0x01: "UNARY_INVERT",
        0xb7: "STORE_GLOBAL",
        0xca: "DUP_TOPX",
        0x87: "LOAD_ATTR",
        0x83: "SET_ADD",
        0x27: "ROT_THREE",
        0x3b: "RETURN_VALUE",
        0x3e: "IMPORT_STAR",
        0xea: "MAP_ADD",
        0x82: "COMPARE_OP",
        0xc7: "JUMP_FORWARD",
        0xa0: "POP_JUMP_IF_FALSE",
        0x35: "ROT_TWO",
        0x26: "WITH_CLEANUP",
        0xe7: "BUILD_MAP",
        0x96: "LOAD_GLOBAL",
        0xeb: "RAISE_VARARGS",
        0x77: "CALL_FUNCTION",
        0x08: "UNARY_NEGATIVE",
        0x41: "END_FINALLY",
        0xf0: "BUILD_SET",
        0x66: "STORE_FAST",
        0x54: "UNARY_POSITIVE",
        0x38: "BINARY_MULTIPLY",
        0x09: "BINARY_SUBTRACT",
        0x4a: "SLICE_3",
        0x14: "DELETE_SLICE_0",
        0x5f: "SETUP_FINALLY",
        0x65: "SETUP_WITH",
        0x43: "DELETE_SUBSCR",
        0x12: "BINARY_TRUE_DIVIDE",
        0x05: "STORE_SLICE_1",
        0x34: "PRINT_NEWLINE",
        0xc2: "CALL_FUNCTION_VAR_KW",
        0x7a: "BUILD_TUPLE",
        0x5a: "NOP",
        0x15: "DELETE_SLICE_1",
        0x17: "DELETE_SLICE_3",
        0x58: "INPLACE_ADD",
        0x45: "BINARY_AND",
        0x39: "POP_BLOCK",
        0x37: "BUILD_CLASS",
        0xd3: "POP_JUMP_IF_TRUE",
        0xad: "LOAD_DEREF",
        0xc0: "CALL_FUNCTION_VAR",
        0x1e: "PRINT_ITEM_TO",
        0x11: "EXEC_STMT",
        0x2d: "INPLACE_OR",
        0x56: "POP_TOP",
        0x1f: "BINARY_MODULO",
        0x48: "SLICE_1",
        0x16: "DELETE_SLICE_2",
        0x1c: "INPLACE_MODULO",
        0x5b: "INPLACE_POWER",
        0x4e: "INPLACE_RSHIFT",
        0x4b: "BINARY_LSHIFT",
        0x32: "GET_ITER",
        0x5c: "PRINT_ITEM",
        0x04: "STORE_SLICE_0",
        0x07: "STORE_SLICE_3",
        0x46: "INPLACE_MULTIPLY",
        0x4f: "STORE_SUBSCR",
        0x1b: "PRINT_EXPR",
        0xc5: "JUMP_IF_FALSE_OR_POP",
        0x86: "STORE_DEREF",
        0x50: "DUP_TOP",
        0x98: "DELETE_FAST",
        0x06: "STORE_SLICE_2",
        0x30: "BINARY_XOR",
        0x74: "DELETE_NAME",
        0x2f: "INPLACE_AND",
        0x8c: "STORE_ATTR",
        0x5d: "LOAD_CONST",
        0xe2: "LOAD_FAST",
        0x2e: "BINARY_RSHIFT",
        0xfa: "JUMP_ABSOLUTE",
        0x03: "INPLACE_SUBTRACT",
        0x10: "INPLACE_XOR",
        0xfc: "BUILD_LIST",
        0x7b: "MAKE_CLOSURE",
        0xc1: "CALL_FUNCTION_KW",
        0x1a: "INPLACE_DIVIDE",
        0x3c: "BREAK_LOOP",
        0xf7: "CONTINUE_LOOP",
        0x2a: "BINARY_FLOOR_DIVIDE",
        0x59: "INPLACE_TRUE_DIVIDE",
        0x25: "YIELD_VALUE",
        0xc6: "MAKE_FUNCTION",
        0x9e: "LOAD_CLOSURE",
        0x2c: "BINARY_SUBSCR",
        0xd4: "SETUP_EXCEPT",
        0x72: "STORE_NAME",
        0x99: "SETUP_LOOP",
        0xe6: "JUMP_IF_TRUE_OR_POP",
        0x40: "BINARY_DIVIDE",
        0x0d: "BINARY_OR",
        0x1d: "UNARY_NOT",
        0x47: "SLICE_0",
        0x8b: "IMPORT_FROM",
        0x52: "UNARY_CONVERT",
        0x24: "BINARY_POWER",
        0x8a: "UNPACK_SEQUENCE",
        0xd2: "LIST_APPEND",
        0x94: "IMPORT_NAME",
        0xcc: "EXTENDED_ARG",
        0x2b: "STORE_MAP",
        0x29: "INPLACE_LSHIFT",
        0x0f: "LOAD_LOCALS",
        0x90: "DELETE_ATTR",
        0xcf: "DELETE_GLOBAL",
        0x6b: "BUILD_SLICE",
        0x31: "ROT_FOUR",
        0x49: "SLICE_2",
        0x00: "PRINT_NEWLINE_TO",
        0x64: "FOR_ITER",
        0xe8: "LOAD_NAME",
        0x3f: "BINARY_ADD",
        0x02: "INPLACE_FLOOR_DIVIDE",
    },
    0xbc58dbd5: {
        0x94: "JUMP_FORWARD",
        0x0c: "NOP",
        0x72: "EXTENDED_ARG",
        0xf4: "LOAD_FAST",
        0xdf: "LOAD_CONST",
        0x44: "POP_TOP",
        0x17: "ROT_TWO",
        0x33: "ROT_THREE",
        0x4e: "ROT_FOUR",
        0x22: "DUP_TOP",
        0x66: "DUP_TOPX",
        0xd5: "COMPARE_OP",
        0xb0: "POP_JUMP_IF_FALSE",
        0xe8: "JUMP_ABSOLUTE",
        0xf2: "POP_JUMP_IF_TRUE",
        0xf3: "JUMP_IF_FALSE_OR_POP",
        0xc4: "JUMP_IF_TRUE_OR_POP",
        0x15: "GET_ITER",
        0xee: "FOR_ITER",
        0xc0: "STORE_FAST",
        0x9e: "UNPACK_SEQUENCE",
        0x4a: "UNARY_POSITIVE",
        0x10: "UNARY_NEGATIVE",
        0x32: "UNARY_NOT",
        0x1b: "UNARY_CONVERT",
        0x41: "UNARY_INVERT",
        0x51: "BINARY_POWER",
        0x2c: "BINARY_MULTIPLY",
        0x1a: "BINARY_DIVIDE",
        0x31: "BINARY_TRUE_DIVIDE",
        0x46: "BINARY_FLOOR_DIVIDE",
        0x35: "BINARY_MODULO",
        0x0f: "BINARY_ADD",
        0x4c: "BINARY_SUBTRACT",
        0x47: "BINARY_SUBSCR",
        0x04: "BINARY_LSHIFT",
        0x1c: "BINARY_RSHIFT",
        0x58: "BINARY_AND",
        0x2b: "BINARY_XOR",
        0x1f: "BINARY_OR",
        0xf7: "LIST_APPEND",
        0xc6: "SET_ADD",
        0x39: "INPLACE_POWER",
        0x25: "INPLACE_MULTIPLY",
        0x3b: "INPLACE_DIVIDE",
        0x20: "INPLACE_TRUE_DIVIDE",
        0x40: "INPLACE_FLOOR_DIVIDE",
        0x48: "INPLACE_MODULO",
        0x0e: "INPLACE_ADD",
        0x2e: "INPLACE_SUBTRACT",
        0x14: "INPLACE_LSHIFT",
        0x59: "INPLACE_RSHIFT",
        0x28: "INPLACE_AND",
        0x5c: "INPLACE_XOR",
        0x2a: "INPLACE_OR",
        0x09: "SLICE_1",
        0x0a: "SLICE_2",
        0x0b: "SLICE_3",
        0x08: "SLICE_0",
        0x3d: "STORE_SLICE_1",
        0x3e: "STORE_SLICE_2",
        0x3f: "STORE_SLICE_3",
        0x3c: "STORE_SLICE_0",
        0x55: "DELETE_SLICE_1",
        0x56: "DELETE_SLICE_2",
        0x57: "DELETE_SLICE_3",
        0x54: "DELETE_SLICE_0",
        0x2f: "STORE_SUBSCR",
        0x43: "DELETE_SUBSCR",
        0x2d: "PRINT_EXPR",
        0x5b: "PRINT_ITEM_TO",
        0x30: "PRINT_ITEM",
        0x05: "PRINT_NEWLINE_TO",
        0x45: "PRINT_NEWLINE",
        0xbc: "RAISE_VARARGS",
        0x12: "LOAD_LOCALS",
        0x01: "RETURN_VALUE",
        0x23: "EXEC_STMT",
        0x24: "POP_BLOCK",
        0x37: "BUILD_CLASS",
        0x95: "STORE_NAME",
        0xdd: "DELETE_NAME",
        0x82: "STORE_ATTR",
        0xca: "DELETE_ATTR",
        0xd4: "STORE_GLOBAL",
        0xbe: "DELETE_GLOBAL",
        0xcc: "LOAD_NAME",
        0xfd: "LOAD_GLOBAL",
        0x99: "DELETE_FAST",
        0xd9: "LOAD_CLOSURE",
        0xcd: "LOAD_DEREF",
        0x5e: "STORE_DEREF",
        0xaf: "BUILD_TUPLE",
        0xe5: "BUILD_LIST",
        0xd1: "BUILD_SET",
        0x61: "BUILD_MAP",
        0x26: "STORE_MAP",
        0xbb: "MAP_ADD",
        0xd2: "LOAD_ATTR",
        0xeb: "IMPORT_NAME",
        0x4d: "IMPORT_STAR",
        0xdb: "IMPORT_FROM",
        0x49: "BREAK_LOOP",
        0xd6: "CONTINUE_LOOP",
        0xb9: "SETUP_FINALLY",
        0x78: "SETUP_EXCEPT",
        0xe9: "SETUP_LOOP",
        0xdc: "SETUP_WITH",
        0x02: "WITH_CLEANUP",
        0x4f: "END_FINALLY",
        0x74: "CALL_FUNCTION",
        0x8e: "CALL_FUNCTION_KW",
        0x8f: "CALL_FUNCTION_VAR_KW",
        0x8d: "CALL_FUNCTION_VAR",
        0xc2: "MAKE_FUNCTION",
        0xac: "MAKE_CLOSURE",
        0x8b: "BUILD_SLICE",
        0x38: "YIELD_VALUE",
    },
}


# ---------------------------------------------------------------------------
# Package-level mutable state (convert.go)
#
# These are genuine module globals in the Go package, shared by every call and
# every goroutine.  They are kept as module globals here for identical
# observable behaviour, and are reset at the top of :func:`pyc_repairer`
# exactly as the Go code does.
# ---------------------------------------------------------------------------

#: Interned string pool, in encounter order.  ``[][]byte`` in Go.
strings: List[bytes] = []

#: Nesting depth of NetEase code objects.  ``int`` in Go.
depth: int = 0


# ---------------------------------------------------------------------------
# convert.go
# ---------------------------------------------------------------------------

def pyc_repairer(data: bytes, strip: bool) -> bytes:
    """Go ``PycRepairer``: repair a NetEase marshal stream into stock CPython
    2.7 ``.pyc`` body bytes (``PYC_HEADER`` followed by a marshal stream)."""
    global depth, strings

    if not strip:
        depth = 1000
    else:
        depth = 0

    strings = []

    writer = _Writer()
    writer.write(PYC_HEADER)

    reader = _Reader(data)
    _repair_marshal(reader, writer)

    return writer.bytes()


def _repair_marshal(reader: _Reader, writer: _Writer) -> None:
    """Go ``RepairMarshal``."""
    global depth

    tag_type = reader.read_byte()

    skip = True
    if tag_type == TYPE_NETEASE_STRING_0:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string0(reader, writer, True)
    elif tag_type == TYPE_NETEASE_UNICODE_0:
        writer.write_byte(TYPE_UNICODE)
        _repair_netease_string0(reader, writer, True)
    elif tag_type == TYPE_NETEASE_INTERNED_0:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string0(reader, writer, False)
    elif tag_type == TYPE_NETEASE_INTERNED_1:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string1(reader, writer, False)
    elif tag_type == TYPE_NETEASE_UNICODE_1:
        writer.write_byte(TYPE_UNICODE)
        _repair_netease_string1(reader, writer, True)
    elif tag_type == TYPE_NETEASE_STRING_1:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string1(reader, writer, True)
    elif tag_type == TYPE_NETEASE_INTERNED_2:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string2(reader, writer, False)
    elif tag_type == TYPE_NETEASE_UNICODE_2:
        writer.write_byte(TYPE_UNICODE)
        _repair_netease_string2(reader, writer, True)
    elif tag_type == TYPE_NETEASE_STRING_2:
        writer.write_byte(TYPE_STRING)
        _repair_netease_string2(reader, writer, True)
    elif tag_type == TYPE_NETEASE_CODE_0:
        depth += 1
        writer.write_byte(TYPE_CODE)
        try:
            _repair_netease_code0(reader, writer)
        finally:
            depth -= 1
    elif tag_type == TYPE_NETEASE_CODE_1:
        depth += 1
        writer.write_byte(TYPE_CODE)
        try:
            _repair_netease_code1(reader, writer)
        finally:
            depth -= 1
    elif tag_type == TYPE_NETEASE_CODE_2:
        depth += 1
        writer.write_byte(TYPE_CODE)
        try:
            _repair_netease_code2(reader, writer)
        finally:
            depth -= 1
    elif tag_type == TYPE_INTERNED:
        writer.write_byte(TYPE_STRING)
        _copy_string_interned(reader, writer)
    elif tag_type == TYPE_STRINGREF:
        writer.write_byte(TYPE_STRING)
        n = reader.read_i32()
        if n < 0 or n >= len(strings):
            # Go panics here ("index out of range"); surface it as an error.
            raise PymarshalError(f"index out of range [{n}] with length {len(strings)}")
        s = strings[n]
        writer.write(_pack_i32(len(s)))
        writer.write(s)
    else:
        skip = False

    if skip:
        return

    writer.write_byte(tag_type)

    # The types below carry no extra data.
    if tag_type in (TYPE_NULL, TYPE_NONE, TYPE_STOPITER, TYPE_ELLIPSIS,
                    TYPE_FALSE, TYPE_TRUE):
        return

    # The types below carry extra data.
    if tag_type == TYPE_INT:
        _copy_bytes(reader, writer, 4)
    elif tag_type == TYPE_INT64:
        _copy_bytes(reader, writer, 8)
    elif tag_type == TYPE_LONG:
        _copy_py_long(reader, writer)
    elif tag_type == TYPE_FLOAT:
        _copy_float(reader, writer)
    elif tag_type == TYPE_BINARY_FLOAT:
        _copy_bytes(reader, writer, 8)
    elif tag_type == TYPE_COMPLEX:
        _copy_float(reader, writer)
        _copy_float(reader, writer)
    elif tag_type == TYPE_BINARY_COMPLEX:
        _copy_bytes(reader, writer, 16)
    elif tag_type in (TYPE_UNICODE, TYPE_STRING):
        _copy_string(reader, writer)
    elif tag_type in (TYPE_TUPLE, TYPE_SET, TYPE_FROZENSET, TYPE_LIST):
        _copy_list(reader, writer)
    elif tag_type == TYPE_DICT:
        _copy_dict(reader, writer)
    elif tag_type == TYPE_CODE:
        _copy_bytes(reader, writer, 4 * 4)
        _repair_opcode(reader, writer, 0)
        for _ in range(7):
            _repair_marshal(reader, writer)
        _copy_bytes(reader, writer, 4)
        _repair_marshal(reader, writer)
    else:
        raise PymarshalError(f"unknown type: {tag_type:02x}")


def _copy_bytes(reader: _Reader, writer: _Writer, size: int) -> None:
    if size == 0:
        return
    _make_slice(size)
    writer.write(reader.read_into(size))


def _copy_float(reader: _Reader, writer: _Writer) -> None:
    size = reader.read_byte()
    writer.write_byte(size)
    _copy_bytes(reader, writer, size)


def _copy_string(reader: _Reader, writer: _Writer) -> None:
    n = reader.read_i32()
    writer.write(_pack_i32(n))
    _copy_bytes(reader, writer, n)


def _copy_string_interned(reader: _Reader, writer: _Writer) -> None:
    global strings

    n = reader.read_i32()
    writer.write(_pack_i32(n))

    _make_slice(n)
    data = reader.read_into(n)
    writer.write(data)

    strings.append(data)


def _copy_list(reader: _Reader, writer: _Writer) -> None:
    n = reader.read_i32()
    writer.write(_pack_i32(n))

    i = 0
    while i < n:
        try:
            _repair_marshal(reader, writer)
        except PymarshalError as exc:
            if exc is not ErrNull:
                raise
        i += 1


def _copy_dict(reader: _Reader, writer: _Writer) -> None:
    # Read until the key is a null object.
    #
    # NOTE: faithfully ported, quirk included.  ``RepairMarshal`` never
    # actually returns ``ErrNull`` (the assignment is commented out in the Go
    # source), so the ``break`` below is unreachable and this loop only ever
    # terminates by propagating a non-ErrNull error.
    while True:
        try:
            _repair_marshal(reader, writer)
        except PymarshalError as exc:
            if exc is ErrNull:
                break
            raise

        try:
            _repair_marshal(reader, writer)
        except PymarshalError as exc:
            if exc is not ErrNull:
                raise


def _copy_py_long(reader: _Reader, writer: _Writer) -> None:
    n = reader.read_i32()
    writer.write(_pack_i32(n))

    if n == 0:
        return

    py_long_marshal_ratio = 15
    py_long_marshal_base = 32767
    py_long_marshal_shift = 2

    # ``absInt32(n) - 1`` is int32 arithmetic in Go and therefore wraps.
    a = _i32(_abs_i32(n) - 1)
    size = _i32(1 + _trunc_div(a, py_long_marshal_ratio))
    shorts_in_top_digit = _i32(1 + _trunc_mod(a, py_long_marshal_ratio))

    if n < 0:
        size = _i32(-size)

    d = 0
    i = 0
    limit = _i32(size - 1)
    while i < limit:
        d = 0
        for j in range(py_long_marshal_ratio):
            md = reader.read_i16()
            writer.write(_pack_i16(md))

            if md < 0 or md > py_long_marshal_base:
                raise PymarshalError("bad marshal data (digit out of range in long)")
            # ``d`` is written but never read in the Go original; the int32
            # shift wraparound is reproduced anyway.
            d = _i32(d + _i32(_i32(md) << (j * py_long_marshal_shift)))
        i += 1

    d = 0
    j = 0
    while j < shorts_in_top_digit:
        md = reader.read_i16()
        writer.write(_pack_i16(md))

        if md < 0 or md > py_long_marshal_base:
            raise PymarshalError("bad marshal data (digit out of range in long)")

        if md == 0 and j == shorts_in_top_digit - 1:
            raise PymarshalError("bad marshal data (unnormalized long data)")
        d = _i32(d + _i32(_i32(md) << (j * py_long_marshal_shift)))
        j += 1


# ---------------------------------------------------------------------------
# netease_types.go
# ---------------------------------------------------------------------------

def _repair_netease_string1(reader: _Reader, writer: _Writer, write: bool) -> None:
    global strings

    n = reader.read_i32()
    writer.write(_pack_i32(n))

    _make_slice(n)
    data = reader.read_into(n)

    decrypt = _rc4_xor(_RC4_KEY_V1, data)

    writer.write(decrypt)

    if not write:
        strings.append(decrypt)


def _repair_netease_string2(reader: _Reader, writer: _Writer, write: bool) -> None:
    global strings

    n = reader.read_i32()
    writer.write(_pack_i32(n))

    _make_slice(n)
    data = reader.read_into(n)

    decrypt = _rc4_xor(_RC4_KEY_V2, data)

    writer.write(decrypt)

    if not write:
        strings.append(decrypt)


def _repair_netease_string0(reader: _Reader, writer: _Writer, write: bool) -> None:
    global strings

    n = reader.read_i32()
    writer.write(_pack_i32(n))

    _make_slice(n)
    data = bytearray(reader.read_into(n))

    for i in range(len(data)):
        data[i] ^= 0x8D

    writer.write(bytes(data))

    if not write:
        strings.append(bytes(data))


def _repair_opcode(reader: _Reader, writer: _Writer, id: int) -> None:
    _copy_bytes(reader, writer, 1)

    n = reader.read_i32()
    writer.write(_pack_i32(n))

    _make_slice(n)
    data = bytearray(reader.read_into(n))

    opcode_map = NETEASE_OPCODES.get(_u32(id))
    if opcode_map is None:
        raise PymarshalError("no opcode map found")

    index = 0
    while index < len(data):
        q = opcode_map.get(data[index], "")
        if q != "":
            p = OPCODES.get(q)
            if p is not None:
                data[index] = p
                if p >= 90:
                    index += 2
        index += 1

    writer.write(bytes(data))


def _write_code_object(argcount: bytes, locals_: bytes, stacksize: bytes,
                       flags: bytes, ncode: bytes, consts: bytes, names: bytes,
                       varnames: bytes, freevars: bytes, cellvars: bytes,
                       filename: bytes, name: bytes, firstlineno: bytes,
                       lnotab: bytes, writer: _Writer) -> None:
    writer.write(argcount)
    writer.write(locals_)
    writer.write(stacksize)
    writer.write(flags)
    writer.write(ncode)
    writer.write(consts)
    writer.write(names)
    writer.write(varnames)
    writer.write(freevars)
    writer.write(cellvars)
    writer.write(filename)
    writer.write(name)
    writer.write(firstlineno)
    writer.write(lnotab)


# ---------------------------------------------------------------------------
# netease_code_0.go / netease_code_1.go / netease_code_2.go
# ---------------------------------------------------------------------------

def _repair_netease_code0(reader: _Reader, writer: _Writer) -> None:
    """Go ``repairNetEaseCode0``."""
    global depth

    lnotab = _Writer()
    _repair_marshal(reader, lnotab)

    varnames = _Writer()
    _repair_marshal(reader, varnames)

    flags = reader.read_into(4)

    freevars = _Writer()
    _repair_marshal(reader, freevars)

    cellvars = _Writer()
    _repair_marshal(reader, cellvars)

    filename = _Writer()
    _repair_marshal(reader, filename)

    stacksize = reader.read_into(4)
    firstlineno = reader.read_into(4)

    consts = _Writer()
    removed_code = False
    if depth == 1:
        # Clean up the constant pool.
        type1 = reader.try_read_byte()
        if type1 == TYPE_TUPLE:
            n = reader.read_i32()
            _make_slice(n)

            pool = [_Writer() for _ in range(n)]
            code_index = -1

            i = 0
            while i < n:
                _repair_marshal(reader, pool[i])

                chunk = pool[i].bytes()
                if not chunk:
                    raise PymarshalError("index out of range [0] with length 0")
                if chunk[0] == TYPE_CODE:
                    code_index = i
                i += 1

            consts.write_byte(TYPE_TUPLE)
            consts.write(_pack_i32(n))

            for i in range(len(pool)):
                if i == code_index:
                    consts.write(bytes([TYPE_NONE]))
                    removed_code = True
                else:
                    consts.write(pool[i].bytes())
        else:
            raise PymarshalError(f"invalid constant pool type: {type1:02x}")
    else:
        _repair_marshal(reader, consts)

    argcount = reader.read_into(4)

    code = _Writer()
    _repair_marshal(reader, code)

    locals_ = reader.read_into(4)

    name = _Writer()
    _repair_marshal(reader, name)

    names = _Writer()
    _repair_marshal(reader, names)

    opcode_type = reader.read_u32()

    opcode_map = NETEASE_OPCODES.get(_u32(opcode_type))
    if opcode_map is not None:
        data = bytearray(code.bytes())
        index = 5
        while index < len(data):
            q = opcode_map.get(data[index], "")
            if q != "":
                p = OPCODES.get(q)
                if p is not None:
                    data[index] = p
                    if p >= 90:
                        index += 2
            index += 1

        if depth == 1 and removed_code:
            if len(data) < 10:
                raise PymarshalError("slice bounds out of range")
            data = data[:len(data) - 3 * 3 - 1] + bytes([data[len(data) - 1]])
            if len(data) < 5:
                raise PymarshalError("slice bounds out of range")
            n = struct.unpack_from("<i", data, 1)[0]
            data[1:5] = _pack_i32(_i32(n - 3 * 3))

        code = _Writer()
        code.write(bytes(data))

    _write_code_object(argcount, locals_, stacksize, flags, code.bytes(),
                       consts.bytes(), names.bytes(), varnames.bytes(),
                       freevars.bytes(), cellvars.bytes(), filename.bytes(),
                       name.bytes(), firstlineno, lnotab.bytes(), writer)


def _repair_netease_code1(reader: _Reader, writer: _Writer) -> None:
    """Go ``repairNetEaseCode1``."""
    locals_ = reader.read_into(4)

    flags = reader.read_into(4)

    consts = _Writer()
    _repair_marshal(reader, consts)

    stacksize = reader.read_into(4)

    varnames = _Writer()
    _repair_marshal(reader, varnames)

    argcount = reader.read_into(4)

    freevars = _Writer()
    _repair_marshal(reader, freevars)

    names = _Writer()
    _repair_marshal(reader, names)

    cellvars = _Writer()
    _repair_marshal(reader, cellvars)

    name = _Writer()
    _repair_marshal(reader, name)

    code = _Writer()
    _repair_marshal(reader, code)

    firstlineno = reader.read_into(4)

    lnotab = _Writer()
    _repair_marshal(reader, lnotab)

    opcode_type = reader.read_u32()

    ncode = _Writer()
    _repair_opcode(_Reader(code.bytes()), ncode, opcode_type)

    filename = _Writer()
    _repair_marshal(reader, filename)

    _write_code_object(argcount, locals_, stacksize, flags, ncode.bytes(),
                       consts.bytes(), names.bytes(), varnames.bytes(),
                       freevars.bytes(), cellvars.bytes(), filename.bytes(),
                       name.bytes(), firstlineno, lnotab.bytes(), writer)


def _repair_netease_code2(reader: _Reader, writer: _Writer) -> None:
    """Go ``repairNetEaseCode2``."""
    global depth

    argcount = reader.read_into(4)

    lnotab = _Writer()
    _repair_marshal(reader, lnotab)

    cellvars = _Writer()
    _repair_marshal(reader, cellvars)

    firstlineno = reader.read_into(4)

    varnames = _Writer()
    _repair_marshal(reader, varnames)

    consts = _Writer()
    removed_code = False
    if depth == 1:
        # Clean up the constant pool.
        type1 = reader.try_read_byte()
        if type1 == TYPE_TUPLE:
            n = reader.read_i32()
            _make_slice(n)

            pool = [_Writer() for _ in range(n)]
            code_index = -1

            i = 0
            while i < n:
                _repair_marshal(reader, pool[i])

                chunk = pool[i].bytes()
                if not chunk:
                    raise PymarshalError("index out of range [0] with length 0")
                if chunk[0] == TYPE_CODE:
                    code_index = i
                i += 1

            consts.write_byte(TYPE_TUPLE)
            consts.write(_pack_i32(n))

            for i in range(len(pool)):
                if i == code_index:
                    consts.write(bytes([TYPE_NONE]))
                    removed_code = True
                else:
                    consts.write(pool[i].bytes())
        else:
            raise PymarshalError(f"invalid constant pool type: {type1:02x}")
    else:
        _repair_marshal(reader, consts)

    name = _Writer()
    _repair_marshal(reader, name)

    stacksize = reader.read_into(4)

    freevars = _Writer()
    _repair_marshal(reader, freevars)

    names = _Writer()
    _repair_marshal(reader, names)

    code = _Writer()
    _repair_marshal(reader, code)

    flags = reader.read_into(4)

    filename = _Writer()
    _repair_marshal(reader, filename)

    locals_ = reader.read_into(4)

    opcode_type = reader.read_u32()

    opcode_map = NETEASE_OPCODES.get(_u32(opcode_type))
    if opcode_map is not None:
        data = bytearray(code.bytes())
        index = 5
        while index < len(data):
            q = opcode_map.get(data[index], "")
            if q != "":
                p = OPCODES.get(q)
                if p is not None:
                    data[index] = p
                    if p >= 90:
                        index += 2
            index += 1

        if depth == 1 and removed_code:
            if len(data) < 10:
                raise PymarshalError("slice bounds out of range")
            data = data[:len(data) - 3 * 3 - 1] + bytes([data[len(data) - 1]])
            if len(data) < 5:
                raise PymarshalError("slice bounds out of range")
            n = struct.unpack_from("<i", data, 1)[0]
            data[1:5] = _pack_i32(_i32(n - 3 * 3))

        code = _Writer()
        code.write(bytes(data))

    _write_code_object(argcount, locals_, stacksize, flags, code.bytes(),
                       consts.bytes(), names.bytes(), varnames.bytes(),
                       freevars.bytes(), cellvars.bytes(), filename.bytes(),
                       name.bytes(), firstlineno, lnotab.bytes(), writer)


# ---------------------------------------------------------------------------
# encrypt.go
# ---------------------------------------------------------------------------

@dataclass
class EncryptOptions:
    """Go ``EncryptOptions``.

    ``string_version`` selects which NetEase string codec to use:
    0 => XOR 0x8d, 1 => RC4(0xA7,0x0D,0x37,0x7A), 2 => RC4(long key).

    ``code_version`` selects which NetEase code object layout to emit:
    0 => TYPE_NETEASE_CODE_0, 1 => TYPE_NETEASE_CODE_1, 2 => TYPE_NETEASE_CODE_2.

    ``opcode_type`` selects the NetEase opcode table ID used to scramble
    bytecode.
    """

    string_version: int = 2
    code_version: int = 1
    opcode_type: int = 0


def _normalize_options(opts: EncryptOptions) -> EncryptOptions:
    """Go ``EncryptOptions.normalize``."""
    if opts.string_version < 0 or opts.string_version > 2:
        raise ErrUnsupportedStringVersion
    if opts.code_version < 0 or opts.code_version > 2:
        raise ErrUnsupportedCodeVersion
    return opts


def pyc_encryptor(pyc_or_marshal: bytes, opts: EncryptOptions) -> bytes:
    """Go ``PycEncryptor``: convert a standard Python 2.x marshal payload
    (optionally carrying a ``PYC_HEADER`` prefix) into the NetEase-encrypted
    marshal format understood by :func:`pyc_repairer`."""
    opts = _normalize_options(opts)

    payload = pyc_or_marshal
    if len(payload) >= len(PYC_HEADER) and payload[:len(PYC_HEADER)] == PYC_HEADER:
        payload = payload[len(PYC_HEADER):]

    return marshal_encrypt(payload, opts)


def marshal_encrypt(marshal: bytes, opts: EncryptOptions) -> bytes:
    """Go ``MarshalEncrypt``."""
    opts = _normalize_options(opts)

    state = _EncryptState(
        opts=opts,
        interned_strings=[],
        opcode_name_by_py={v: k for k, v in OPCODES.items()},
    )

    reader = _Reader(marshal)
    out = _Writer()
    state.encrypt_object(reader, out)
    if reader.len() != 0:
        raise PymarshalError(f"trailing bytes after marshal object: {reader.len()}")
    return out.bytes()


class _EncryptState:
    """Go ``encryptState``."""

    __slots__ = ("opts", "interned_strings", "opcode_name_by_py")

    def __init__(self, opts: EncryptOptions, interned_strings: List[bytes],
                 opcode_name_by_py: Dict[int, str]) -> None:
        self.opts = opts
        self.interned_strings = interned_strings
        self.opcode_name_by_py = opcode_name_by_py

    # -- encryptObject ----------------------------------------------------

    def encrypt_object(self, reader: _Reader, writer: _Writer) -> None:
        tag_type = reader.read_byte()

        if tag_type == TYPE_NULL:
            # Marshal "null object" sentinel used to terminate dicts.
            writer.write_byte(TYPE_NULL)
            raise ErrNull
        elif tag_type in (TYPE_NONE, TYPE_STOPITER, TYPE_ELLIPSIS,
                          TYPE_FALSE, TYPE_TRUE):
            writer.write_byte(tag_type)
        elif tag_type == TYPE_INT:
            writer.write_byte(TYPE_INT)
            _copy_bytes(reader, writer, 4)
        elif tag_type == TYPE_INT64:
            writer.write_byte(TYPE_INT64)
            _copy_bytes(reader, writer, 8)
        elif tag_type == TYPE_LONG:
            writer.write_byte(TYPE_LONG)
            _copy_py_long(reader, writer)
        elif tag_type == TYPE_FLOAT:
            writer.write_byte(TYPE_FLOAT)
            _copy_float(reader, writer)
        elif tag_type == TYPE_BINARY_FLOAT:
            writer.write_byte(TYPE_BINARY_FLOAT)
            _copy_bytes(reader, writer, 8)
        elif tag_type == TYPE_COMPLEX:
            writer.write_byte(TYPE_COMPLEX)
            _copy_float(reader, writer)
            _copy_float(reader, writer)
        elif tag_type == TYPE_BINARY_COMPLEX:
            writer.write_byte(TYPE_BINARY_COMPLEX)
            _copy_bytes(reader, writer, 16)
        elif tag_type == TYPE_STRING:
            self.encrypt_string_like(reader, writer, False, False)
        elif tag_type == TYPE_UNICODE:
            self.encrypt_string_like(reader, writer, True, False)
        elif tag_type == TYPE_INTERNED:
            self.encrypt_string_like(reader, writer, False, True)
        elif tag_type == TYPE_STRINGREF:
            self.encrypt_string_ref(reader, writer)
        elif tag_type in (TYPE_TUPLE, TYPE_LIST, TYPE_SET, TYPE_FROZENSET):
            writer.write_byte(tag_type)
            self.encrypt_list_like(reader, writer)
        elif tag_type == TYPE_DICT:
            writer.write_byte(TYPE_DICT)
            self.encrypt_dict(reader, writer)
        elif tag_type == TYPE_CODE:
            self.encrypt_code_object(reader, writer)
        else:
            raise PymarshalError(f"unsupported marshal tag: {tag_type:02x}")

    # -- containers -------------------------------------------------------

    def encrypt_list_like(self, reader: _Reader, writer: _Writer) -> None:
        n = reader.read_i32()
        writer.write(_pack_i32(n))

        i = 0
        while i < n:
            self.encrypt_object(reader, writer)
            i += 1

    def encrypt_dict(self, reader: _Reader, writer: _Writer) -> None:
        while True:
            nxt = reader.read_byte()
            if nxt == TYPE_NULL:
                writer.write_byte(TYPE_NULL)
                return
            reader.unread_byte()

            self.encrypt_object(reader, writer)
            try:
                self.encrypt_object(reader, writer)
            except PymarshalError as exc:
                if exc is ErrNull:
                    # from None: the semantics are being rewritten, not propagated
                    raise PymarshalError("invalid marshal dict: null value") from None
                raise

    # -- strings ----------------------------------------------------------

    def encrypt_string_ref(self, reader: _Reader, writer: _Writer) -> None:
        idx = reader.read_i32()
        if idx < 0 or idx >= len(self.interned_strings):
            raise PymarshalError(f"stringref out of range: {idx}")
        self.write_netease_string(writer, self.interned_strings[idx], False, False)

    def encrypt_string_like(self, reader: _Reader, writer: _Writer,
                            is_unicode: bool, is_interned: bool) -> None:
        n = reader.read_i32()
        if n < 0:
            raise PymarshalError(f"negative string length: {n}")
        data = reader.read_full(n)

        if is_interned:
            self.interned_strings.append(data)

        self.write_netease_string(writer, data, is_unicode, is_interned)

    def write_netease_string(self, writer: _Writer, plain: bytes,
                             is_unicode: bool, is_interned: bool) -> None:
        tag = self.netease_string_tag(is_unicode, is_interned)
        writer.write_byte(tag)
        writer.write(_pack_i32(len(plain)))

        encrypted = bytearray(plain)

        if self.opts.string_version == 0:
            for i in range(len(encrypted)):
                encrypted[i] ^= 0x8D
        elif self.opts.string_version == 1:
            encrypted = bytearray(_rc4_xor(_RC4_KEY_V1, bytes(encrypted)))
        elif self.opts.string_version == 2:
            encrypted = bytearray(_rc4_xor(_RC4_KEY_V2, bytes(encrypted)))
        else:
            raise ErrUnsupportedStringVersion

        writer.write(bytes(encrypted))

    def netease_string_tag(self, is_unicode: bool, is_interned: bool) -> int:
        if self.opts.string_version == 0:
            if is_unicode:
                return TYPE_NETEASE_UNICODE_0
            elif is_interned:
                return TYPE_NETEASE_INTERNED_0
            return TYPE_NETEASE_STRING_0
        elif self.opts.string_version == 1:
            if is_unicode:
                return TYPE_NETEASE_UNICODE_1
            elif is_interned:
                return TYPE_NETEASE_INTERNED_1
            return TYPE_NETEASE_STRING_1
        elif self.opts.string_version == 2:
            if is_unicode:
                return TYPE_NETEASE_UNICODE_2
            elif is_interned:
                return TYPE_NETEASE_INTERNED_2
            return TYPE_NETEASE_STRING_2
        raise ErrUnsupportedStringVersion

    # -- code objects -----------------------------------------------------

    def encrypt_code_object(self, reader: _Reader, writer: _Writer) -> None:
        try:
            argcount = reader.read_full(4)
        except PymarshalError as exc:
            raise PymarshalError(f"read code.argcount: {exc}") from None
        try:
            locals_ = reader.read_full(4)
        except PymarshalError as exc:
            raise PymarshalError(f"read code.locals: {exc}") from None
        try:
            stacksize = reader.read_full(4)
        except PymarshalError as exc:
            raise PymarshalError(f"read code.stacksize: {exc}") from None
        try:
            flags = reader.read_full(4)
        except PymarshalError as exc:
            raise PymarshalError(f"read code.flags: {exc}") from None

        try:
            code_plain = self.read_plain_marshal_string(reader)
        except PymarshalError as exc:
            raise PymarshalError(f"read code bytes: {exc}") from None
        code_netease = self.encode_opcode_bytes(code_plain, self.opts.opcode_type)
        code_buf = _Writer()
        self.write_netease_string(code_buf, code_netease, False, False)

        consts = _Writer()
        self.encrypt_object(reader, consts)
        names = _Writer()
        self.encrypt_object(reader, names)
        varnames = _Writer()
        self.encrypt_object(reader, varnames)
        freevars = _Writer()
        self.encrypt_object(reader, freevars)
        cellvars = _Writer()
        self.encrypt_object(reader, cellvars)
        filename = _Writer()
        self.encrypt_object(reader, filename)
        name = _Writer()
        self.encrypt_object(reader, name)

        try:
            firstlineno = reader.read_full(4)
        except PymarshalError as exc:
            raise PymarshalError(f"read code.firstlineno: {exc}") from None

        lnotab = _Writer()
        self.encrypt_object(reader, lnotab)

        opcode_type_bytes = _pack_u32(self.opts.opcode_type)

        if self.opts.code_version == 0:
            writer.write_byte(TYPE_NETEASE_CODE_0)
            writer.write(lnotab.bytes())
            writer.write(varnames.bytes())
            writer.write(flags)
            writer.write(freevars.bytes())
            writer.write(cellvars.bytes())
            writer.write(filename.bytes())
            writer.write(stacksize)
            writer.write(firstlineno)
            writer.write(consts.bytes())
            writer.write(argcount)
            writer.write(code_buf.bytes())
            writer.write(locals_)
            writer.write(name.bytes())
            writer.write(names.bytes())
            writer.write(opcode_type_bytes)
        elif self.opts.code_version == 1:
            writer.write_byte(TYPE_NETEASE_CODE_1)
            writer.write(locals_)
            writer.write(flags)
            writer.write(consts.bytes())
            writer.write(stacksize)
            writer.write(varnames.bytes())
            writer.write(argcount)
            writer.write(freevars.bytes())
            writer.write(names.bytes())
            writer.write(cellvars.bytes())
            writer.write(name.bytes())
            writer.write(code_buf.bytes())
            writer.write(firstlineno)
            writer.write(lnotab.bytes())
            writer.write(opcode_type_bytes)
            writer.write(filename.bytes())
        elif self.opts.code_version == 2:
            writer.write_byte(TYPE_NETEASE_CODE_2)
            writer.write(argcount)
            writer.write(lnotab.bytes())
            writer.write(cellvars.bytes())
            writer.write(firstlineno)
            writer.write(varnames.bytes())
            writer.write(consts.bytes())
            writer.write(name.bytes())
            writer.write(stacksize)
            writer.write(freevars.bytes())
            writer.write(names.bytes())
            writer.write(code_buf.bytes())
            writer.write(flags)
            writer.write(filename.bytes())
            writer.write(locals_)
            writer.write(opcode_type_bytes)
        else:
            raise ErrUnsupportedCodeVersion

    def read_plain_marshal_string(self, reader: _Reader) -> bytes:
        tag = reader.read_byte()

        if tag in (TYPE_STRING, TYPE_UNICODE, TYPE_INTERNED):
            n = reader.read_i32()
            if n < 0:
                raise PymarshalError(f"negative string length: {n}")
            data = reader.read_full(n)
            if tag == TYPE_INTERNED:
                self.interned_strings.append(data)
            return data
        elif tag == TYPE_STRINGREF:
            idx = reader.read_i32()
            if idx < 0 or idx >= len(self.interned_strings):
                raise PymarshalError(f"stringref out of range: {idx}")
            return self.interned_strings[idx]
        raise PymarshalError(f"expected string-like object, got tag {tag:02x}")

    def encode_opcode_bytes(self, py_bytecode: bytes, opcode_type: int) -> bytes:
        opcode_map = NETEASE_OPCODES.get(_u32(opcode_type))
        if opcode_map is None:
            raise PymarshalError(f"no opcode map found: {_u32(opcode_type):x}")

        name_to_net: Dict[str, int] = {}
        for b, net_name in opcode_map.items():
            if net_name == "":
                continue
            name_to_net[net_name] = b

        out = bytearray(py_bytecode)

        i = 0
        while i < len(out):
            py_op = out[i]
            py_name: str | None = self.opcode_name_by_py.get(py_op)
            if py_name is None:
                raise PymarshalError(f"unknown python opcode: {py_op}")
            net_op = name_to_net.get(py_name)
            if net_op is None:
                raise PymarshalError(
                    f'no netease opcode for "{py_name}" (python={py_op})')
            out[i] = net_op

            if py_op >= 90:
                i += 3
            else:
                i += 1

        return bytes(out)


__all__ = [
    "PYC_HEADER",
    "PymarshalError",
    "ErrNull",
    "ErrUnsupportedStringVersion",
    "ErrUnsupportedCodeVersion",
    "EncryptOptions",
    "pyc_repairer",
    "pyc_encryptor",
    "marshal_encrypt",
    "OPCODES",
    "NETEASE_OPCODES",
    "strings",
    "depth",
]
