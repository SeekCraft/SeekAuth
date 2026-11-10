"""SeekAuth — the NetEase MCP rotor machine.

This is the **custom stream cipher** NetEase uses to encrypt `vanilla.mcp` (Python 2.7
bytecode). It is a faithful port of the algorithm in `unmcpk/mcpk/rotor.go`.

At its core is a "rotor machine" (an image borrowed from Enigma): several 256-entry
permutation tables, a position vector and an advance vector. Each byte processed advances
the positions along the advance vector, producing a position-dependent permutation.

It **must match byte for byte**, otherwise `c_DyBasic.py` cannot be decrypted and the
check number comes out wrong. Three points matter in the port:

1. The five seeds in ``setKey`` use **int16 wrap-around** arithmetic (Go's ``int16``)
   and are then stored in the ``key`` array; Python ints do not wrap on their own, so it
   has to be done explicitly.
2. ``rRandom`` is a three-way Wichmann-Hill linear congruential generator returning a
   ``[0,1)`` float.
   Intermediate values can go negative; they must be brought back the way Go does it.
3. ``rRand(s)`` returns ``int(floor(rRandom()*s)) % s``, as an **int16**.
4. In ``DChar`` the result of ``positions[i] ^ dRotor[...]`` is masked with ``sizeMask``.
"""

from __future__ import annotations

import math

SIZE = 256
SIZE_MASK = SIZE - 1


def _to_int16(v: int) -> int:
    """Truncate an integer to a signed 16-bit value with Go's int16 semantics."""
    v &= 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


def _trunc_div(a: int, b: int) -> int:
    """Go's integer division: truncation toward zero.

    Python's ``//`` floors, which differs for negative operands (``-5 // 177 == -1``
    in Python, while Go's ``-5 / 177 == 0``), so this has to be written out explicitly.
    """
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def _trunc_mod(a: int, b: int) -> int:
    """Go's modulo: the result takes the sign of the **dividend**.

    This is the easiest place to get the port wrong — ``rRandom``'s seeds can be negative,
    and Python's ``%`` turns them positive, sending the pseudo-random sequence off course
    (the symptom: rotor permutation tables stop matching the reference implementation).
    """
    return a - _trunc_div(a, b) * b


class Rotor:
    """The NetEase MCP rotor machine.

    :param num_rotors: number of rotors (vanilla.mcp uses 6)
    :param key: key string
    """

    def __init__(self, num_rotors: int, key: str) -> None:
        self.key: list[int] = [0] * 5
        self.seed: list[int] = [0, 0, 0]
        self.size = SIZE
        self.size_mask = SIZE_MASK
        self.rotors = num_rotors

        self.e_rotor = bytearray(num_rotors * SIZE)
        self.d_rotor = bytearray(num_rotors * SIZE)
        self.positions = bytearray(num_rotors)
        self.advances = bytearray(num_rotors)

        self.is_inited = False

        self._set_key(key)

    # ────────────── Key and seeds ──────────────

    def _set_key(self, key: str) -> None:
        k1, k2, k3, k4, k5 = 995, 576, 767, 671, 463

        for ch in key:
            ki = ord(ch) & 0xFF

            # Note: Go does ((k << 3) | (k >> 13)) first, then +/^/- with ki;
            # bitwise-or binds looser than shift, so this spells out Go's actual semantics.
            k1 = (((k1 << 3) | (k1 >> 13)) + ki) & 0xFFFF
            k2 = (((k2 << 3) | (k2 >> 13)) ^ ki) & 0xFFFF
            k3 = (((k3 << 3) | (k3 >> 13)) - ki) & 0xFFFF
            k4 = (ki - ((k4 << 3) | (k4 >> 13))) & 0xFFFF
            k5 = (((k5 << 3) | (k5 >> 13)) ^ (~ki & 0xFFFF)) & 0xFFFF

        self.key[0] = _to_int16(k1)
        self.key[1] = _to_int16(k2 | 1)
        self.key[2] = _to_int16(k3)
        self.key[3] = _to_int16(k4)
        self.key[4] = _to_int16(k5)

        self._set_seed()

    def _set_seed(self) -> None:
        self.seed[0] = self.key[0]
        self.seed[1] = self.key[1]
        self.seed[2] = self.key[2]
        self.is_inited = False

    def _r_random(self) -> float:
        """Wichmann-Hill pseudo-random number in ``[0.0, 1.0)``.

        ⚠️ Must use Go-semantics ``/`` and ``%``: seeds can be negative, and Python's
        ``//``/``%`` behave differently on negatives, which sends the sequence off course.
        """
        x, y, z = self.seed[0], self.seed[1], self.seed[2]

        x = 171 * _trunc_mod(x, 177) - 2 * _trunc_div(x, 177)
        y = 172 * _trunc_mod(y, 176) - 35 * _trunc_div(y, 176)
        z = 170 * _trunc_mod(z, 178) - 63 * _trunc_div(z, 178)

        if x < 0:
            x += 30269
        if y < 0:
            y += 30307
        if z < 0:
            z += 30323

        self.seed[0], self.seed[1], self.seed[2] = x, y, z

        term = x / 30269.0 + y / 30307.0 + z / 30323.0
        val = term - math.floor(term)

        if val >= 1.0:
            val = 0.0
        return val

    def _r_rand(self, s: int) -> int:
        """Return an integer in ``[0, s)`` (int16 semantics)."""
        v = math.floor(self._r_random() * s) % s
        return _to_int16(v)

    # ────────────── Rotor initialisation ──────────────

    @staticmethod
    def _make_id_rotor(rtr: bytearray, offset: int) -> None:
        for j in range(SIZE):
            rtr[offset + j] = j

    def _e_rotors(self) -> None:
        for i in range(self.rotors):
            self._make_id_rotor(self.e_rotor, i * SIZE)

    def _d_rotors(self) -> None:
        for i in range(self.rotors):
            for j in range(SIZE):
                self.d_rotor[i * SIZE + j] = j

    def _positions(self) -> None:
        for i in range(self.rotors):
            self.positions[i] = 1

    def _advances(self) -> None:
        for i in range(self.rotors):
            self.advances[i] = 1

    def _permute_rotor(self, e_off: int, d_off: int) -> None:
        """Fisher-Yates shuffle an E rotor and set the matching D rotor to its inverse."""
        i = SIZE
        self._make_id_rotor(self.e_rotor, e_off)
        while i >= 2:
            q = self._r_rand(i) & 0xFF
            i -= 1
            j = self.e_rotor[e_off + q]
            self.e_rotor[e_off + q] = self.e_rotor[e_off + i]
            self.e_rotor[e_off + i] = j
            self.d_rotor[d_off + j] = i & 0xFF

        self.d_rotor[d_off + self.e_rotor[e_off]] = 0

    def init(self) -> None:
        """Initialise the rotor machine from the current key."""
        self._set_seed()
        self._positions()
        self._advances()
        self._e_rotors()
        self._d_rotors()
        for i in range(self.rotors):
            self.positions[i] = self._r_rand(self.size) & 0xFF
            self.advances[i] = (1 + 2 * self._r_rand(self.size // 2)) & 0xFF
            self._permute_rotor(i * SIZE, i * SIZE)
        self.is_inited = True

    # ────────────── Stepping and single-byte en/decryption ──────────────

    def _advance(self) -> None:
        if self.size_mask != 0:
            for i in range(self.rotors):
                temp = self.positions[i] + self.advances[i]
                self.positions[i] = temp & self.size_mask
                if temp >= self.size and i < self.rotors - 1:
                    self.positions[i + 1] = (1 + self.positions[i + 1]) & 0xFF
        else:
            for i in range(self.rotors):
                temp = self.positions[i] + self.advances[i]
                self.positions[i] = temp & self.size
                if temp >= self.size and i < self.rotors - 1:
                    self.positions[i + 1] = (1 + self.positions[i + 1]) & 0xFF

    def e_char(self, p: int) -> int:
        """Encrypt one byte."""
        tp = p
        if self.size_mask != 0:
            for i in range(self.rotors):
                tp = self.e_rotor[i * SIZE + ((self.positions[i] ^ tp) & self.size_mask)]
        else:
            for i in range(self.rotors):
                tp = self.e_rotor[i * SIZE + ((self.positions[i] ^ tp) % self.size)]
        self._advance()
        return tp

    def d_char(self, c: int) -> int:
        """Decrypt one byte."""
        tc = c
        if self.size_mask != 0:
            for i in range(self.rotors - 1, -1, -1):
                tc = (self.positions[i] ^ self.d_rotor[i * SIZE + tc]) & self.size_mask
        else:
            for i in range(self.rotors - 1, -1, -1):
                tc = (self.positions[i] ^ self.d_rotor[i * SIZE + tc]) % self.size
        self._advance()
        return tc

    # ────────────── Region operations ──────────────

    def e_region(self, data: bytearray, do_init: bool) -> None:
        """Encrypt a whole buffer in place."""
        if do_init or not self.is_inited:
            self.init()
        for i in range(len(data)):
            data[i] = self.e_char(data[i])

    def d_region(self, data: bytearray, do_init: bool) -> None:
        """Decrypt a whole buffer in place."""
        if do_init or not self.is_inited:
            self.init()
        for i in range(len(data)):
            data[i] = self.d_char(data[i])
