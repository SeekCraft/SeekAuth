"""SeekAuth — rental server line probing and selection.

NetEase's ``rental-server-world-enter/get`` returns 4 lines: the default line plus dedicated
China Mobile / Telecom / Unicom lines. Measured (for 48285363):

* all four lines are **reachable** and can complete the RakNet handshake;
* the default line intermittently degrades to **147-164ms**, dedicated ones hold **30-40ms**;
* **do not probe with RakNet unconnected ping (0x01)** -- NetEase does not answer that packet,
  which misjudges all four lines as unreachable (a trap we actually fell into).

The right approach is to replay the client's first handshake packet ``OPEN_CONNECTION_REQUEST_1``:

.. code-block:: text

    b[0]    = 0x05
    b[1:17] = MAGIC (00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78)
    b[17]   = RakNet protocol number  <- NetEase wants 8, not Minecraft's 898
    b[18:]  = 0x00 padding up to MTU-28

If the protocol number is wrong the server replies ``0x19 INCOMPATIBLE_PROTOCOL_VERSION``,
whose ``data[1]`` is the protocol number the server requires.

The implementation uses ``asyncio`` UDP, probes all candidate lines concurrently and takes the
lowest-latency reachable ISP line; when no ISP line is reachable it falls back to the default one.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass

from .logging_setup import get_logger

log = get_logger(__name__)

# RakNet offline-message magic
MAGIC = bytes(
    [0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
     0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78]
)

ID_OPEN_CONNECTION_REQUEST_1 = 0x05
ID_OPEN_CONNECTION_REPLY_1 = 0x06
ID_INCOMPATIBLE_PROTOCOL_VERSION = 0x19

# RakNet protocol number NetEase rental servers require (read from data[1] of an INCOMPATIBLE reply)
RAKNET_PROTOCOL = 8
PROBE_MTU = 1400
DEFAULT_TIMEOUT = 2.0
# How many times to probe each line by default. One packet's RTT cannot separate a line that
# works from one that drops it (ISP lines: 30-40ms); multi-packet success rate is meaningful.
DEFAULT_ATTEMPTS = 3


@dataclass(frozen=True)
class ProbeResult:
    """Probe result for a single line."""

    address: str
    ok: bool
    rtt_ms: float
    note: str
    is_isp: bool


def _build_probe_packet(protocol: int = RAKNET_PROTOCOL, mtu: int = PROBE_MTU) -> bytes:
    """Build an ``OPEN_CONNECTION_REQUEST_1`` probe packet."""
    buf = bytearray(mtu - 28)
    buf[0] = ID_OPEN_CONNECTION_REQUEST_1
    buf[1:17] = MAGIC
    buf[17] = protocol
    return bytes(buf)


class _ProbeProtocol(asyncio.DatagramProtocol):
    """One-shot UDP probe protocol: record the reply, then finish."""

    def __init__(self, address: str, future: asyncio.Future[tuple[bool, str]]) -> None:
        self.address = address
        self.future = future
        self.transport: asyncio.DatagramTransport | None = None
        self.started = time.perf_counter()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # asyncio only promises BaseTransport; for a UDP endpoint it really is a DatagramTransport
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport
        host, port = self.address.rsplit(":", 1)
        transport.sendto(_build_probe_packet(), (host, int(port)))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.future.done():
            return
        if not data:
            self.future.set_result((False, "empty reply"))
            return
        first = data[0]
        if first == ID_OPEN_CONNECTION_REPLY_1:
            self.future.set_result((True, "REPLY_1"))
        elif first == ID_INCOMPATIBLE_PROTOCOL_VERSION:
            want = data[1] if len(data) > 1 else None
            self.future.set_result(
                (False, f"INCOMPATIBLE_PROTOCOL_VERSION (server wants {want})")
            )
        else:
            self.future.set_result((False, f"unexpected id=0x{first:02x}"))

    def error_received(self, exc: Exception) -> None:
        # ICMP port-unreachable and friends land here; treating it as unreachable is enough
        if not self.future.done():
            self.future.set_result((False, f"error: {exc}"))

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.future.done():
            self.future.set_result((False, "connection lost"))


async def probe_line(
    address: str, *, timeout: float = DEFAULT_TIMEOUT, attempts: int = 1
) -> tuple[bool, float, str]:
    """Probe a single line.

    :param attempts: consecutive probes. 1 equals a single-packet probe; with >1 all must succeed
        for the line to count as reachable; the **median** RTT is returned instead.
    :returns: ``(reachable, round-trip milliseconds, note)``

    Why several probes: one successful packet only proves the link works right now, but a real
    server join needs the line to hold up for a whole RakNet session. All four ISP lines measured
    about 30-40ms per packet, yet one dropped its session seconds later: success rate beats RTT.
    """
    if attempts <= 1:
        return await _probe_once(address, timeout=timeout)

    rtts: list[float] = []
    last_note = ""
    for _ in range(attempts):
        ok, rtt, note = await _probe_once(address, timeout=timeout)
        if not ok:
            # One failure means unreachable: sessions need lasting availability, not a lucky ping
            return False, rtt, note
        rtts.append(rtt)
        last_note = note

    rtts.sort()
    mid = len(rtts) // 2
    median = rtts[mid] if len(rtts) % 2 else (rtts[mid - 1] + rtts[mid]) / 2
    return True, median, f"{last_note} x{attempts}"


async def _probe_once(address: str, *, timeout: float) -> tuple[bool, float, str]:
    """Send one ``OPEN_CONNECTION_REQUEST_1`` and wait for ``REPLY_1``."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future[tuple[bool, str]] = loop.create_future()
    started = time.perf_counter()

    try:
        host, port = address.rsplit(":", 1)
        int(port)  # validate the port
    except (ValueError, AttributeError):
        return False, 0.0, f"bad address format: {address}"

    transport: asyncio.DatagramTransport | None = None
    try:
        # getaddrinfo supports hostnames, though the addresses are usually IPs
        infos = await loop.getaddrinfo(
            host, int(port), family=socket.AF_INET, type=socket.SOCK_DGRAM
        )
        if not infos:
            return False, 0.0, "DNS resolution failed"
        # socktype/proto/canonname are unused for a UDP probe, but the unpacking shape has to
        # match the getaddrinfo 5-tuple definition
        family, _, _, _, sockaddr = infos[0]
        # the sockaddr returned by getaddrinfo may be (ip,port) / (ip,port,flow,scope) /
        # (int,bytes); a UDP IPv4 endpoint only wants (ip, port), and an extra field here raises
        # TypeError -- caught below as "unreachable", meaning the same as a probe timeout.
        remote: tuple[str, int] | str | None = (str(sockaddr[0]), int(sockaddr[1]))

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ProbeProtocol(address, future),
            remote_addr=remote,
            family=family,
        )
        await asyncio.wait_for(future, timeout=timeout)
        ok, note = future.result()
        rtt = (time.perf_counter() - started) * 1000
        return ok, rtt, note
    except TimeoutError:
        return False, (time.perf_counter() - started) * 1000, "TIMEOUT (no REPLY_1)"
    except Exception as e:  # noqa: BLE001 - a failed probe must not be raised to the caller
        return False, (time.perf_counter() - started) * 1000, f"{type(e).__name__}: {e}"
    finally:
        if transport is not None:
            transport.close()


async def probe_all(
    candidates: list[str], *, timeout: float = DEFAULT_TIMEOUT, attempts: int = 1
) -> list[ProbeResult]:
    """Probe every candidate line concurrently.

    ``candidates[0]`` is treated as the default line and the rest as ISP lines (matching the order
    of :meth:`RentalServerWorldEntity.candidate_addresses`).

    :param attempts: consecutive probes per line, passed through to :func:`probe_line`.
    """
    if not candidates:
        return []

    async def one(idx: int, addr: str) -> ProbeResult:
        ok, rtt, note = await probe_line(addr, timeout=timeout, attempts=attempts)
        return ProbeResult(
            address=addr, ok=ok, rtt_ms=rtt, note=note, is_isp=idx > 0
        )

    return list(await asyncio.gather(*(one(i, a) for i, a in enumerate(candidates))))


def pick_best(results: list[ProbeResult], candidates: list[str]) -> tuple[str, str]:
    """Pick the best line from the probe results.

    Rule: **prefer a reachable ISP line** (latency only breaks ties between ISP lines); when no ISP
    line is reachable, fall back to the default line.

    :returns: ``(chosen address, human-readable note)``
    """
    if not results:
        return (candidates[0] if candidates else "", "no candidate lines")

    reachable = [r for r in results if r.ok]
    best: ProbeResult | None = None
    for r in reachable:
        if best is None:
            best = r
        elif r.is_isp and not best.is_isp:
            best = r  # an ISP line beats the default line
        elif r.is_isp == best.is_isp and r.rtt_ms < best.rtt_ms:
            best = r

    summary = ", ".join(
        f"{r.address}[{'isp' if r.is_isp else 'default'}]="
        + (f"{r.rtt_ms:.0f}ms" if r.ok else f"FAIL({r.note})")
        for r in results
    )

    if best is None:
        fallback = candidates[0] if candidates else ""
        return fallback, f"no reachable line, falling back to default; {summary}"

    kind = "isp" if best.is_isp else "default"
    return best.address, f"chose {kind} line; {summary}"


async def select_line(
    candidates: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    attempts: int = DEFAULT_ATTEMPTS,
    override: str | None = None,
) -> tuple[str, str]:
    """Probe and select a line. A non-empty ``override`` is used as-is (for debugging).

    :param attempts: how many times to probe each line; see :func:`probe_line`. Defaults to
        :data:`DEFAULT_ATTEMPTS` (3) -- a single-packet probe misses lines that drop sessions.
    """
    if not candidates:
        return (override or "", "no candidate lines")
    if override:
        return override, f"using ARK_ADDR_OVERRIDE={override}"
    if len(candidates) == 1:
        return candidates[0], "only one candidate line"

    results = await probe_all(candidates, timeout=timeout, attempts=attempts)
    return pick_best(results, candidates)
