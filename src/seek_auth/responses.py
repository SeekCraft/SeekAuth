"""SeekAuth — HTTP response helpers.

Lives here rather than in :mod:`seek_auth.app` because :mod:`seek_auth.routes`
is imported by app, so routes needing the serialization helpers from app would
form a cycle. This module depends on no other module of the project, so it can
be imported safely from either side.

Why not ``ORJSONResponse``:

1. Recent FastAPI versions mark it deprecated (it emits
   ``FastAPIDeprecationWarning``), and it is only faster when a response model
   is declared — most responses here are hand-built dicts and hex strings, so
   that path is never taken.
2. The protocol layer imposes hard requirements on the response body shape (hex
   strings / ``{"success": ...}``); producing bytes directly skips one
   ``jsonable_encoder`` layer and makes it easier to keep the shape stable.
"""

from __future__ import annotations

from typing import Any

import orjson
from fastapi import Response

__all__ = ["json_response"]


def json_response(
    content: Any,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Serialize ``content`` with :mod:`orjson` and return a :class:`Response`.

    :param content: any object orjson can serialize.
    :param status_code: HTTP status code.
    :param headers: extra response headers (merged in, besides ``Content-Type``).
    """
    return Response(
        content=orjson.dumps(content, option=orjson.OPT_NON_STR_KEYS),
        status_code=status_code,
        media_type="application/json",
        headers=headers or {},
    )
