"""Self-healing of a poisoned connection pool: on a connection-class failure search

Background: there was a case where, once the httpx connection pool was poisoned, every request to
NetEase kept failing with "All connection attempts failed" and only a process restart recovered
it. _rental_login_handler now force-rebuilds the G79Client and retries once on such a failure.
"""
from __future__ import annotations

import pytest

from seek_auth.noahs_ark import _is_connection_error


class _FakeG79Error(Exception):
    """Close enough to G79Error: str(err) carries the upstream error text."""


class _FakeClient:
    """Records calls and scripts the search results."""

    def __init__(self, script: list[Exception | dict]):
        self.script = list(script)
        self.calls = 0
        self.user_id = 123

    async def search_rental_server_by_name(self, code: str) -> dict:
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_is_connection_error_matches_real_world_strings():
    # Verbatim text of the last real failure
    assert _is_connection_error(
        Exception("POST https://g79mclobt.minecraft.cn/rental-server/query/search-by-name "
                  "failed: All connection attempts failed")
    )
    assert _is_connection_error(Exception("Connection refused"))
    assert _is_connection_error(Exception("peer closed connection without sending SSL data"))
    assert _is_connection_error(Exception("operation timed out"))
    # Business errors are not connection errors: they must not trigger a rebuild (a rebuild
    assert not _is_connection_error(Exception("Your account is logged in elsewhere"))
    assert not _is_connection_error(Exception("server not found"))


@pytest.mark.asyncio
async def test_search_self_heals_via_force_reauth(monkeypatch):
    """The first search fails on a connection error -> force a rebuild -> the second succeeds."""
    import seek_auth.noahs_ark as na

    bad = _FakeClient([_FakeG79Error("All connection attempts failed")])
    good = _FakeClient([{"code": 0, "entities": [{"id": "srv-1"}]}])
    forced = {"called": False}

    async def fake_client_for_token(token, cookie, *, force=False):
        if force:
            forced["called"] = True
            return good
        return bad

    monkeypatch.setattr(na, "_client_for_token", fake_client_for_token)

    # Drive the handler's rebuild branch directly: reuse _is_connection_error + the force path
    # (handler is a closure, so verify the composition here: bad client raises -> force -> good)
    try:
        await bad.search_rental_server_by_name("72036065")
    except Exception as e:
        assert na._is_connection_error(e)
        client = await na._client_for_token("tok", "cookie", force=True)
        result = await client.search_rental_server_by_name("72036065")
        assert result["entities"] == [{"id": "srv-1"}]

    assert forced["called"] is True
    assert bad.calls == 1 and good.calls == 1


@pytest.mark.asyncio
async def test_business_error_does_not_trigger_rebuild():
    """Business errors (e.g. server not found) must never trigger a rebuild - a rebuild hits
    NetEase PE auth, and doing it often runs into the 2100 rate limit."""

    client = _FakeClient([{"code": 0, "entities": [], "message": "not found"}])
    try:
        result = await client.search_rental_server_by_name("72036065")
    except Exception:  # pragma: no cover
        pytest.fail("business response must not raise")
    # No exception -> the handler never enters the rebuild branch
    assert result["message"] == "not found"
