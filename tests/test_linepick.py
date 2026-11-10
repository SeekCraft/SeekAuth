"""Upstream line-selection regression test (no network).

Covers two concrete defects:

1. **The login cache must not freeze line selection** -- on a cache hit the line has to be
   re-probed, otherwise a transient ISP fault is locked in for the whole TTL (hit in testing).
2. **Success-rate criterion for multi-packet probing** -- one packet cannot spot a flaky line.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from seek_auth.linepick import pick_best, probe_line  # noqa: E402
from seek_auth.upstream import _pick_address  # noqa: E402

# ─────────────────────────── probe criteria ───────────────────────────


def _results(spec: dict[str, tuple[bool, float]]) -> list:
    """Build a ProbeResult list from ``{address: (reachable, rtt_ms)}``."""
    from seek_auth.linepick import ProbeResult

    return [
        ProbeResult(address=a, ok=ok, rtt_ms=rtt, note="", is_isp=(i > 0))
        for i, (a, (ok, rtt)) in enumerate(spec.items())
    ]


def test_multi_packet_failure_marks_line_dead() -> None:
    """A single failure among several probes must mark the line unreachable.

    A session needs sustained availability; "works occasionally" cannot carry a server join.
    """

    async def scenario() -> None:
        # Replace the real network with a controllable fake _probe_once, focus on the decision
        import seek_auth.linepick as lp

        seq = [(True, 30.0, "ok"), (False, 30.0, "timeout"), (True, 30.0, "ok")]
        calls: list[str] = []

        async def fake_once(address: str, *, timeout: float):
            calls.append(address)
            return seq[len(calls) - 1]

        orig = lp._probe_once
        lp._probe_once = fake_once  # type: ignore[assignment]
        try:
            ok, _, note = await probe_line("1.2.3.4:1234", attempts=3)
        finally:
            lp._probe_once = orig  # type: ignore[assignment]

        assert ok is False, "one failure must mark the line unreachable"
        assert "timeout" in note

    asyncio.run(scenario())


def test_probe_median_rtt_reported() -> None:
    """On multi-packet success take the median RTT, so one spike cannot skew the result."""

    async def scenario() -> None:
        import seek_auth.linepick as lp

        seq = [(True, 90.0, "ok"), (True, 30.0, "ok"), (True, 40.0, "ok")]
        calls: list[str] = []

        async def fake_once(address: str, *, timeout: float):
            calls.append(address)
            return seq[len(calls) - 1]

        orig = lp._probe_once
        lp._probe_once = fake_once  # type: ignore[assignment]
        try:
            ok, rtt, _ = await probe_line("1.2.3.4:1234", attempts=3)
        finally:
            lp._probe_once = orig  # type: ignore[assignment]

        assert ok is True
        assert rtt == 40.0, f"median should be 40ms, got {rtt}"

    asyncio.run(scenario())


def test_isp_preferred_and_rtt_breaks_ties() -> None:
    """An ISP line beats the default line; between ISP lines the lower RTT wins."""
    picked, detail = pick_best(
        _results({
            "1.1.1.1:14346": (True, 20.0),
            "2.2.2.2:14346": (True, 50.0),
            "3.3.3.3:14346": (True, 30.0),
        }),
        ["1.1.1.1:14346", "2.2.2.2:14346", "3.3.3.3:14346"],
    )
    assert picked == "3.3.3.3:14346"
    assert "isp" in detail


def test_falls_back_to_default_when_all_isp_dead() -> None:
    """When every ISP line is dead, fall back to the default line instead of returning empty."""
    picked, detail = pick_best(
        _results({
            "1.1.1.1:14346": (True, 200.0),
            "2.2.2.2:14346": (False, 100.0),
        }),
        ["1.1.1.1:14346", "2.2.2.2:14346"],
    )
    assert picked == "1.1.1.1:14346"
    assert "no reachable line" not in detail


# ─────────────── cache must not freeze the line (real defect this round) ───────────────


class _FakeDB:
    """Only the parts _pick_address does not use -- it never touches the db at all."""


class _FakeState:
    """Provides only the settings attribute _pick_address uses."""

    def __init__(self, address_override: str | None, line_probe_attempts: int) -> None:
        self.settings = _FakeSettings(address_override, line_probe_attempts)


class _FakeSettings:
    def __init__(self, address_override: str | None, line_probe_attempts: int) -> None:
        self.address_override = address_override
        self.line_probe_attempts = line_probe_attempts


def test_pick_address_probes_every_call() -> None:
    """Probe even on a cache hit: routes change, so the previous verdict must not be reused."""

    async def scenario() -> None:
        import seek_auth.linepick as lp

        calls: list[list[str]] = []

        async def fake_probe_all(candidates, *, timeout=2.0, attempts=1):
            calls.append(list(candidates))
            assert attempts == 3, "production default should probe every line 3 times"
            from seek_auth.linepick import ProbeResult

            return [
                ProbeResult(address=c, ok=True, rtt_ms=35.0, note="", is_isp=(i > 0))
                for i, c in enumerate(candidates)
            ]

        orig = lp.probe_all
        lp.probe_all = fake_probe_all  # type: ignore[assignment]
        try:
            state = _FakeState(address_override=None, line_probe_attempts=3)
            cands = ["1.1.1.1:14346", "2.2.2.2:14346"]

            a1 = await _pick_address(state, cands)
            a2 = await _pick_address(state, cands)
        finally:
            lp.probe_all = orig  # type: ignore[assignment]

        assert len(calls) == 2, "every call must really probe"
        assert calls[0] == cands
        # Only one line is isp and reachable, so both calls must pick it
        assert a1 == a2 == "2.2.2.2:14346"

    asyncio.run(scenario())


def test_pick_address_empty_candidates_no_probe() -> None:
    """When upstream gives no candidates, return empty without probing."""

    async def scenario() -> None:
        import seek_auth.linepick as lp

        probed = False

        async def fake_probe_all(*a, **k):
            nonlocal probed
            probed = True
            return []

        orig = lp.probe_all
        lp.probe_all = fake_probe_all  # type: ignore[assignment]
        try:
            state = _FakeState(address_override=None, line_probe_attempts=3)
            got = await _pick_address(state, [])
        finally:
            lp.probe_all = orig  # type: ignore[assignment]

        assert got == ""
        assert probed is False

    asyncio.run(scenario())


def test_address_override_skips_probe() -> None:
    """address_override is a debug backdoor and must take effect directly."""

    async def scenario() -> None:
        import seek_auth.linepick as lp

        probed = False

        async def fake_probe_all(*a, **k):
            nonlocal probed
            probed = True
            return []

        orig = lp.probe_all
        lp.probe_all = fake_probe_all  # type: ignore[assignment]
        try:
            state = _FakeState(address_override="9.9.9.9:14346", line_probe_attempts=3)
            got = await _pick_address(state, ["1.1.1.1:14346", "2.2.2.2:14346"])
        finally:
            lp.probe_all = orig  # type: ignore[assignment]

        assert got == "9.9.9.9:14346"
        assert probed is False

    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
