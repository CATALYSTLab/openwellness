"""hapi-parity response helpers and JavaScript value semantics (D-05).

Frame answers the event-handler routes through hapi 21 with
``routes: { security: true, cors: true }``. Every value here is taken from
the responses captured live from frame (10-RESEARCH.md, "Captured frame
responses"), so a caller cannot tell which side answered.

Starlette notes the helpers depend on:

- ``JSONResponse`` defaults to ``application/json`` with no charset. hapi
  sends ``application/json; charset=utf-8``, so :func:`boom` sets the full
  media type explicitly.
- ``JSONResponse`` renders compact separators, matching ``JSON.stringify``.
- Starlette omits ``content-length`` on a 204 and sends ``content-length: 0``
  on an empty 200, matching hapi's ``return null`` and ``h.close`` only when
  no media type is set on those responses.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from collections.abc import Callable
from json import decoder as _json_decoder
from json.scanner import NUMBER_RE
from typing import Any, Final
from urllib.parse import unquote

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

JSON_UTF8: Final = "application/json; charset=utf-8"
HTML_UTF8: Final = "text/html; charset=utf-8"

# Verbatim from the captured frame responses. Omitted on the h.close path.
HAPI_HEADERS: Final[dict[str, str]] = {
    "vary": "origin",
    "access-control-expose-headers": "WWW-Authenticate,Server-Authorization",
    "strict-transport-security": "max-age=15768000",
    "x-frame-options": "DENY",
    "x-xss-protection": "0",
    "x-download-options": "noopen",
    "x-content-type-options": "nosniff",
    "cache-control": "no-cache",
}

# Boom's own phrase table (@hapi/boom ``internals.codes``), copied into
# ``error``. It is neither Node's http.STATUS_CODES nor Python's HTTPStatus:
# frame's live 413 reads "Request Entity Too Large", where Node and Python
# both say "Payload Too Large"/"Content Too Large". Covers every status the
# event handlers, the participants route and the Google Health internal links
# route (opserver Phase 16) emit.
_REASON: Final[dict[int, str]] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
    503: "Service Unavailable",
}

INVALID_JSON_MESSAGE: Final = "Invalid request payload JSON format"

# hapi route payload defaults (no override in frame's manifest.js).
MAX_BYTES: Final = 1024 * 1024
DEFAULT_CONTENT_TYPE: Final = "application/json"
TOO_LARGE_MESSAGE: Final = f"Payload content length greater than maximum allowed: {MAX_BYTES}"


class HapiReply(Exception):
    """Short-circuits a handler with a ready hapi response (a thrown Boom)."""

    def __init__(self, response: Response) -> None:
        super().__init__(response.status_code)
        self.response = response


def boom(status: int, message: str) -> JSONResponse:
    """A Boom error: ``{"statusCode","error","message"}`` in that key order."""
    return JSONResponse(
        {"statusCode": status, "error": _REASON[status], "message": message},
        status_code=status,
        headers=HAPI_HEADERS,
        media_type=JSON_UTF8,
    )


def internal() -> JSONResponse:
    """hapi's rendering of any uncaught handler error."""
    return boom(500, "An internal server error occurred")


def empty_null() -> Response:
    """Handler ``return null``: 204, no content-type, no content-length."""
    return Response(status_code=204, headers=HAPI_HEADERS)


def empty_string() -> Response:
    """Handler ``return ''``: 204 with ``text/html; charset=utf-8``."""
    return Response(status_code=204, media_type=HTML_UTF8, headers=HAPI_HEADERS)


def closed() -> Response:
    """Pre-method ``return h.close``: bare 200, empty body, no extra headers."""
    return Response(status_code=200)


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #


# Every rule below is @hapi/subtext 8.1.3 + @hapi/content under hapi 21.4.10
# with frame's route defaults, and every one is pinned by a case captured live
# from frame (tests/fixtures/frame_payload_matrix.json). The order is hapi's:
#
# 1. body over ``maxBytes`` (1 MiB)             -> 413
# 2. content-type header parse (default JSON)   -> 400 "Invalid content-type header..."
# 3. ``multipart/form-data`` (multipart: false) -> 415
# 4. body by mime:
#    - application/octet-stream: the bytes, or null when empty
#    - text/*: the UTF-8 string (empty body is "")
#    - application/json, application/*+json: JSON.parse, null when empty,
#      400 on anything JSON.parse rejects or on any ``__proto__`` key
#      (Bourne ``protoAction: 'error'``)
#    - application/x-www-form-urlencoded: Node querystring.parse, {} when empty
#    - anything else: 415
#
# Not modelled: ``content-encoding`` (hapi gunzips/inflates; no SG or vendor
# caller compresses), and hapi's 415/400-before-413 order for a *chunked*
# oversized body (with a content-length header, 413 comes first, as here).


@dataclass(frozen=True)
class PayloadResult:
    """Either the payload frame's handler would see, or a ready hapi response.

    ``payload`` is a dict, list, str, int, float, bool, bytes (octet-stream)
    or ``None`` (hapi's null payload). It is meaningful only when
    ``response`` is ``None``.
    """

    payload: Any = None
    response: Response | None = None


_CONTENT_TYPE_RE: Final = re.compile(
    r"([A-Za-z0-9!#$%&'*+.^_`|~-]+/[A-Za-z0-9!#$%&'*+.^_`|~-]+)([ \t;][^\r\n]*)?\Z"
)
_CHARSET_RE: Final = re.compile(r';\s*charset=(?:"([^"]+)"|([^;"\s]+))', re.IGNORECASE)
_BOUNDARY_RE: Final = re.compile(r';\s*boundary=(?:"([^"]+)"|([^;"\s]+))', re.IGNORECASE)
_JSON_MIME_RE: Final = re.compile(r"application/(?:.+\+)?json\Z")
_TEXT_MIME_RE: Final = re.compile(r"text/.+\Z")

# Node querystring.parse's default ``maxKeys``: only the first 1000
# '&'-separated segments are read, empty segments included.
_QS_MAX_KEYS: Final = 1000


def _bad_request(message: str) -> PayloadResult:
    return PayloadResult(response=boom(400, message))


def _unsupported() -> PayloadResult:
    return PayloadResult(response=boom(415, "Unsupported Media Type"))


def too_large() -> JSONResponse:
    """Boom.entityTooLarge from subtext's content-length check or Wreck's read."""
    return boom(413, TOO_LARGE_MESSAGE)


def _duplicated(pattern: re.Pattern[str], params: str, match: re.Match[str]) -> bool:
    return pattern.search(params, match.end()) is not None


def _content_mime(header: str | None) -> str | PayloadResult:
    """@hapi/content ``type()``: the lower-cased mime, or hapi's 400."""
    value = header or DEFAULT_CONTENT_TYPE
    match = _CONTENT_TYPE_RE.match(value)
    if match is None:
        return _bad_request("Invalid content-type header")
    mime = match.group(1).lower()
    params = match.group(2) or ""
    if params:
        charset = _CHARSET_RE.search(params)
        if charset is not None and _duplicated(_CHARSET_RE, params, charset):
            return _bad_request("Invalid content-type header: duplicate parameter")
    if mime.startswith("multipart/"):
        boundary = _BOUNDARY_RE.search(params) if params else None
        if boundary is not None and _duplicated(_BOUNDARY_RE, params, boundary):
            return _bad_request("Invalid content-type header: duplicate parameter")
        if boundary is None or not (boundary.group(1) or boundary.group(2)):
            return _bad_request("Invalid content-type header: multipart missing boundary")
    return mime


def _reject_constant(name: str) -> Any:
    # JSON.parse rejects NaN / Infinity / -Infinity; Python accepts them.
    raise ValueError(f"invalid JSON constant {name}")


_JSON_WS: Final = re.compile(r"[ \t\n\r]*")

# The stdlib's C string scanner (strict: control characters rejected, as in
# JSON.parse). Untyped in typeshed, hence the getattr.
scanstring: Final[Callable[[str, int, bool], tuple[str, int]]] = getattr(
    _json_decoder, "scanstring"
)


# From 1e21 up, JSON.stringify writes an integral double in exponent form
# (``1e+21``), which a JSON reader (Celery's, downstream) reads as a float.
_JS_EXPONENT_FORM: Final = 1e21


def _json_number_literal(literal: str) -> int | float:
    """A JSON number token as ``JSON.parse`` sees it: always a double.

    ``float()`` rounds exactly as V8 does (9007199254740993 becomes
    9007199254740992; past the double range, Infinity). An integral result
    below 1e21 is returned as ``int``, so re-serialized task arguments read
    ``1`` for ``1.0`` and keep integer digits, as ``JSON.stringify`` writes
    them; larger or fractional values stay ``float``.
    """
    value = float(literal)
    if math.isfinite(value) and value.is_integer() and abs(value) < _JS_EXPONENT_FORM:
        return int(value)
    return value


def _json_number(match: re.Match[str]) -> int | float:
    integer, frac, exp = match.groups()
    return _json_number_literal(integer + (frac or "") + (exp or ""))


def _loads_iterative(text: str) -> Any:
    """``JSON.parse`` without recursion, for input nested past Python's limit.

    V8's parser is iterative: frame parsed a 100 000-deep array live, where
    ``json.loads`` raises ``RecursionError`` near depth 1000. Same grammar
    as ``json.loads`` in strict mode, minus the NaN/Infinity extensions.
    Raises ``ValueError`` on anything ``JSON.parse`` rejects.
    """
    n = len(text)

    def ws(i: int) -> int:
        match = _JSON_WS.match(text, i)
        assert match is not None
        return match.end()

    def key_at(i: int) -> tuple[str, int]:
        if i >= n or text[i] != '"':
            raise ValueError("expected a property name")
        key, i = scanstring(text, i + 1, True)
        i = ws(i)
        if i >= n or text[i] != ":":
            raise ValueError("expected ':'")
        return key, ws(i + 1)

    # Each frame is [container, pending key (objects only)].
    stack: list[list[Any]] = []
    i = ws(0)
    while True:
        # Parse one value starting at i.
        if i >= n:
            raise ValueError("unexpected end of JSON input")
        char = text[i]
        value: Any
        if char == "{":
            i = ws(i + 1)
            if i < n and text[i] == "}":
                value, i = {}, i + 1
            else:
                key, i = key_at(i)
                stack.append([{}, key])
                continue
        elif char == "[":
            i = ws(i + 1)
            if i < n and text[i] == "]":
                value, i = [], i + 1
            else:
                stack.append([[], None])
                continue
        elif char == '"':
            value, i = scanstring(text, i + 1, True)
        elif text.startswith("true", i):
            value, i = True, i + 4
        elif text.startswith("false", i):
            value, i = False, i + 5
        elif text.startswith("null", i):
            value, i = None, i + 4
        else:
            number = NUMBER_RE.match(text, i)
            if number is None:
                raise ValueError(f"unexpected token at {i}")
            value, i = _json_number(number), number.end()

        # Attach the finished value, closing containers as far as possible.
        while True:
            i = ws(i)
            if not stack:
                if i != n:
                    raise ValueError("unexpected data after JSON")
                return value
            frame = stack[-1]
            container = frame[0]
            closer = "}" if isinstance(container, dict) else "]"
            if isinstance(container, dict):
                container[frame[1]] = value
            else:
                container.append(value)
            if i < n and text[i] == ",":
                i = ws(i + 1)
                if isinstance(container, dict):
                    frame[1], i = key_at(i)
                break  # parse the next member
            if i < n and text[i] == closer:
                value, i = container, i + 1
                stack.pop()
                continue
            raise ValueError(f"expected ',' or '{closer}'")


def _has_proto_key(value: Any) -> bool:
    """Bourne's scan: any object, at any depth, owning a ``__proto__`` key."""
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "__proto__" in node:
                return True
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return False


def _parse_json(raw: bytes) -> PayloadResult:
    if not raw:
        return PayloadResult(payload=None)
    # Buffer.toString('utf8'): invalid sequences become U+FFFD, a BOM is kept
    # (so JSON.parse rejects it, as json.loads does).
    text = raw.decode("utf-8", errors="replace")
    try:
        try:
            value = json.loads(
                text,
                parse_constant=_reject_constant,
                parse_int=_json_number_literal,
                parse_float=_json_number_literal,
            )
        except RecursionError:
            value = _loads_iterative(text)
    except ValueError:
        return _bad_request(INVALID_JSON_MESSAGE)
    if _has_proto_key(value):
        return _bad_request(INVALID_JSON_MESSAGE)
    return PayloadResult(payload=value)


def _node_unescape(text: str) -> str:
    # querystring.unescape: decodeURIComponent, falling back to a byte-wise
    # decode that keeps malformed escapes and replaces invalid UTF-8.
    return unquote(text, encoding="utf-8", errors="replace")


def _parse_form(raw: bytes) -> PayloadResult:
    """Node ``querystring.parse``: flat keys, repeated keys become arrays."""
    if not raw:
        return PayloadResult(payload={})
    result: dict[str, Any] = {}
    for segment in raw.decode("utf-8", errors="replace").split("&")[:_QS_MAX_KEYS]:
        if not segment:
            continue
        name, _, value = segment.partition("=")
        key = _node_unescape(name.replace("+", " "))
        val = _node_unescape(value.replace("+", " "))
        if key not in result:
            result[key] = val
        elif isinstance(result[key], list):
            result[key].append(val)
        else:
            result[key] = [result[key], val]
    return PayloadResult(payload=result)


def parse_hapi_payload(content_type: str | None, raw: bytes) -> PayloadResult:
    """Interpret a request body exactly as hapi does for frame's routes."""
    if len(raw) > MAX_BYTES:
        return PayloadResult(response=too_large())
    mime = _content_mime(content_type)
    if isinstance(mime, PayloadResult):
        return mime
    if mime == "multipart/form-data":
        return _unsupported()
    if mime == "application/octet-stream":
        return PayloadResult(payload=raw if raw else None)
    if _TEXT_MIME_RE.match(mime):
        return PayloadResult(payload=raw.decode("utf-8", errors="replace"))
    if _JSON_MIME_RE.match(mime):
        return _parse_json(raw)
    if mime == "application/x-www-form-urlencoded":
        return _parse_form(raw)
    return _unsupported()


def _declared_length(header: str | None) -> int | None:
    # parseInt(contentLength, 10): leading digits only.
    if not header:
        return None
    match = re.match(r"\s*([+-]?\d+)", header)
    return int(match.group(1)) if match else None


async def read_hapi_payload(request: Request) -> PayloadResult:
    """Read and interpret the body without buffering more than hapi would.

    A declared content-length over the limit is refused before any read
    (subtext's first check); otherwise at most ``MAX_BYTES + 1`` bytes are
    read, so an oversized chunked body is refused without being held.
    """
    declared = _declared_length(request.headers.get("content-length"))
    if declared is not None and declared > MAX_BYTES:
        return PayloadResult(response=too_large())
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        # ASGI does not bound a chunk: keep only what can still count, so
        # the buffer never exceeds MAX_BYTES + 1 however large one chunk is.
        kept = chunk[: MAX_BYTES + 1 - size]
        chunks.append(kept)
        size += len(kept)
        if size > MAX_BYTES:
            break
    return parse_hapi_payload(request.headers.get("content-type"), b"".join(chunks))


# --------------------------------------------------------------------------- #
# JavaScript value semantics
# --------------------------------------------------------------------------- #


class _Undefined:
    """JavaScript ``undefined``: a missing property, distinct from ``null``."""

    _instance: _Undefined | None = None

    def __new__(cls) -> _Undefined:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNDEFINED"

    def __bool__(self) -> bool:
        return False


UNDEFINED: Final[Any] = _Undefined()

_MAX_SAFE_INTEGER: Final = 2**53


def _js_number(x: float) -> str:
    """ECMAScript ``Number::toString`` for a double."""
    if math.isnan(x):
        return "NaN"
    if x == 0:
        return "0"  # includes -0
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if x < 0:
        return "-" + _js_number(-x)
    # repr() is the shortest round-tripping digit string, as in JS.
    _, digit_tuple, exponent = Decimal(repr(x)).as_tuple()
    assert isinstance(exponent, int)
    digits = list(digit_tuple)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    s = "".join(str(d) for d in digits)
    k = len(s)
    n = exponent + k
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    exp = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return s + "e" + exp
    return s[0] + "." + s[1:] + "e" + exp


def js_string(value: object) -> str:
    """JavaScript ``String(value)`` for JSON-shaped values.

    Used wherever frame builds a message by string concatenation, so the
    bytes of 412 bodies match (``'Study (' + studyId + ...``).
    """
    if value is UNDEFINED:
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) <= _MAX_SAFE_INTEGER:
            return str(value)
        try:
            return _js_number(float(value))  # JSON.parse yields a double
        except OverflowError:
            return "Infinity" if value > 0 else "-Infinity"
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return ",".join(
            "" if item is None or item is UNDEFINED else js_string(item)
            for item in value
        )
    if isinstance(value, dict):
        return "[object Object]"
    return str(value)


def js_length(value: object) -> object:
    """JavaScript ``value.length`` for a non-null JSON value.

    Strings and arrays have a length; an object only through an own
    ``length`` key; numbers and booleans read ``undefined``.
    """
    if isinstance(value, (str, list, tuple)):
        return len(value)
    if isinstance(value, dict):
        return value.get("length", UNDEFINED)
    return UNDEFINED


def js_strict_equals_zero(value: object) -> bool:
    """JavaScript ``value === 0``."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value == 0
    )
