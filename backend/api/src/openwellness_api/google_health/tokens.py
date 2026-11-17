"""Link and state tokens, their Redis single-use markers, and the migration locks.

Contract: opserver ``docs/google-health.md``, "Link token, OAuth state and
browser binding" and invariant I3.

- The **link** (``t``) is an HS256 JWT signed with the link secret,
  ``aud="googleHealth:link"``, ``sub=<participantId>``, 72 h.
- The OAuth **state** is an HS256 JWT signed with the state secret,
  ``aud="googleHealth:state"``, 15 min, bound to the initiating browser by
  ``bh`` (SHA-256 of the ``gh_oauth`` cookie) and made single-use by the
  Redis nonce ``gh:state:<jti>``. It also carries the link's ``jti`` and
  ``exp`` (``lnk``, ``lx``), so finishAuth can claim the link.
- The **link claim** ``gh:link:claim:<jti>`` is taken before the code
  exchange and kept after the insert: it is the only consumed-link marker.
  It holds a per-request owner token. Until :meth:`commit_link` it lives
  only ``lock_ttl_ms``, so a claim whose release failed frees the link soon;
  the commit, just before the insert, extends it to the link's expiry.

``ow_api`` runs two uvicorn workers, so nothing lives in process memory.
Neither secret is the API's access-token secret; the ``aud`` values stop one
token being accepted as the other. Every failure raises a
:class:`GoogleHealthTokenError` subclass whose message is fixed: never a
token, a claim or the underlying library's message.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

import jwt

from .settings import GoogleHealthSettings

ISSUER: Final = "openwellness-api"
LINK_AUDIENCE: Final = "googleHealth:link"
STATE_AUDIENCE: Final = "googleHealth:state"
_ALGORITHM: Final = "HS256"

STATE_KEY: Final = "gh:state:{jti}"
LINK_CLAIM_KEY: Final = "gh:link:claim:{jti}"
PID_LOCK_KEY: Final = "gh:lock:pid:{participant_id}"
HU_LOCK_KEY: Final = "gh:lock:hu:{digest}"


class GoogleHealthTokenError(Exception):
    """A link or state was refused, or its Redis marker could not be used."""

    message = "token rejected"

    def __init__(self) -> None:
        super().__init__(self.message)


class TokenInvalid(GoogleHealthTokenError):
    message = "token invalid"


class StateBrowserMismatch(GoogleHealthTokenError):
    message = "state not bound to this browser"


class StateReplayed(GoogleHealthTokenError):
    message = "state already used"


class TokenStoreError(GoogleHealthTokenError):
    message = "token store unavailable"


@dataclass(frozen=True)
class LinkClaims:
    participant_id: str
    jti: str
    exp: int


@dataclass(frozen=True)
class StateClaims:
    participant_id: str
    jti: str
    link_jti: str
    link_exp: int


@dataclass(frozen=True)
class LinkClaim:
    """This request's hold on ``gh:link:claim:<jti>`` (I3)."""

    key: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class MigrationLocks:
    """The participant lock, then each account lock, one request holds (I3)."""

    keys: tuple[str, ...]
    token: str = field(repr=False)


def account_lock_key(health_user_id: str) -> str:
    """``gh:lock:hu:<first 32 hex of sha256(healthUserId)>``: never the raw id."""
    digest = hashlib.sha256(health_user_id.encode("utf-8")).hexdigest()[:32]
    return HU_LOCK_KEY.format(digest=digest)


class GoogleHealthTokens:
    """Mints and verifies the two tokens against one Redis."""

    def __init__(
        self,
        settings: GoogleHealthSettings,
        redis: Any,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._redis = redis
        self._clock = clock

    def _now(self) -> int:
        return int(self._clock())

    # --- link -------------------------------------------------------------

    def mint_link(self, participant_id: str) -> tuple[str, int]:
        now = self._now()
        exp = now + self._settings.link_ttl_seconds
        claims = {
            "iss": ISSUER,
            "aud": LINK_AUDIENCE,
            "sub": participant_id,
            "iat": now,
            "exp": exp,
            "jti": secrets.token_urlsafe(16),
        }
        return jwt.encode(claims, self._settings.link_secret, algorithm=_ALGORITHM), exp

    def verify_link(self, token: str | None) -> LinkClaims:
        claims = self._decode(token, self._settings.link_secret, LINK_AUDIENCE)
        return LinkClaims(
            participant_id=_str_claim(claims, "sub"),
            jti=_str_claim(claims, "jti"),
            exp=_int_claim(claims, "exp"),
        )

    # --- state ------------------------------------------------------------

    def mint_state(
        self, participant_id: str, link_jti: str, link_exp: int, browser_hash: str
    ) -> str:
        now = self._now()
        jti = secrets.token_urlsafe(16)
        ttl = self._settings.state_ttl_seconds
        claims = {
            "iss": ISSUER,
            "aud": STATE_AUDIENCE,
            "sub": participant_id,
            "iat": now,
            "exp": now + ttl,
            "jti": jti,
            "lnk": link_jti,
            "lx": link_exp,
            "bh": browser_hash,
        }
        try:
            stored = self._redis.set(STATE_KEY.format(jti=jti), "1", nx=True, ex=ttl)
        except Exception as exc:
            raise TokenStoreError() from exc
        if not stored:
            raise TokenStoreError()
        return jwt.encode(claims, self._settings.state_secret, algorithm=_ALGORITHM)

    def consume_state(self, token: str | None, browser_hash: str) -> StateClaims:
        """Verify ``token`` and its browser binding, then consume the nonce.

        The binding is checked before the nonce is touched, so a request from
        another browser cannot burn the legitimate browser's state.
        """
        claims = self._decode(token, self._settings.state_secret, STATE_AUDIENCE)
        bound = claims.get("bh")
        if not isinstance(bound, str) or not hmac.compare_digest(
            bound.encode("ascii", "replace"), browser_hash.encode("ascii", "replace")
        ):
            raise StateBrowserMismatch()
        state = StateClaims(
            participant_id=_str_claim(claims, "sub"),
            jti=_str_claim(claims, "jti"),
            link_jti=_str_claim(claims, "lnk"),
            link_exp=_int_claim(claims, "lx"),
        )
        try:
            deleted = self._redis.delete(STATE_KEY.format(jti=state.jti))
        except Exception as exc:
            raise TokenStoreError() from exc
        if deleted != 1:
            raise StateReplayed()
        return state

    # --- link claim (I3) --------------------------------------------------

    def claim_link(self, jti: str, exp: int) -> LinkClaim | None:
        """Take the link for this completion, pending until :meth:`commit_link`.

        ``None`` when the link has expired or is already claimed.
        """
        remaining_ms = (exp - self._now()) * 1000
        if remaining_ms <= 0:
            return None
        claim = LinkClaim(key=LINK_CLAIM_KEY.format(jti=jti), token=secrets.token_urlsafe(16))
        ttl_ms = min(remaining_ms, self._settings.lock_ttl_ms)
        try:
            taken = self._redis.set(claim.key, claim.token, nx=True, px=ttl_ms)
        except Exception as exc:
            raise TokenStoreError() from exc
        return claim if taken else None

    def commit_link(self, claim: LinkClaim, exp: int) -> bool:
        """Keep the claim until the link expires. ``False`` when it is no longer ours.

        Called just before the insert: a pending claim that expired and was
        taken by another request must not let this one write a record. The
        claim is kept for at least one lock lease, even past the link's
        expiry, so it cannot lapse while the bounded writes run.
        """
        remaining_ms = (exp - self._now()) * 1000
        if remaining_ms <= 0:
            return False
        ttl_ms = max(remaining_ms, self._settings.lock_ttl_ms)
        try:
            with self._redis.pipeline() as pipe:
                pipe.watch(claim.key)
                if not _owned(pipe.get(claim.key), claim.token):
                    pipe.unwatch()
                    return False
                pipe.multi()
                pipe.set(claim.key, claim.token, px=ttl_ms)
                pipe.execute()
                return True
        except Exception as exc:
            raise TokenStoreError() from exc

    def release_link(self, claim: LinkClaim) -> bool:
        """Give the link back after a failure before the insert.

        Only this request's claim is deleted. ``False`` when Redis failed: a
        pending claim then frees the link within ``lock_ttl_ms``.
        """
        return self._release_owned(claim.key, claim.token)

    def is_link_claimed(self, jti: str) -> bool:
        try:
            return bool(self._redis.exists(LINK_CLAIM_KEY.format(jti=jti)))
        except Exception as exc:
            raise TokenStoreError() from exc

    # --- migration locks (I3) --------------------------------------------

    def acquire_locks(
        self, participant_id: str, health_user_id: str, *more_health_user_ids: str
    ) -> MigrationLocks | None:
        """Take ``gh:lock:pid:<P>`` then one ``gh:lock:hu:<hash>`` per distinct
        account, in sorted key order, each ``SET NX PX`` with no waiting.

        finishAuth and the migration pass one account; the revoke route passes
        every account of the participant (opserver Phase 17.3, D-14). ``None``
        when any key is held elsewhere or Redis fails; every key taken before
        the refusal is given back.
        """
        token = secrets.token_urlsafe(16)
        ttl_ms = self._settings.lock_ttl_ms
        pid_key = PID_LOCK_KEY.format(participant_id=participant_id)
        hu_keys = sorted({account_lock_key(hu) for hu in (health_user_id, *more_health_user_ids)})
        taken: list[str] = []
        for key in (pid_key, *hu_keys):
            try:
                ok = bool(self._redis.set(key, token, nx=True, px=ttl_ms))
            except Exception:
                ok = False
            if not ok:
                for held in taken:
                    self._release_owned(held, token)
                return None
            taken.append(key)
        return MigrationLocks(keys=(pid_key, *hu_keys), token=token)

    def renew_locks(self, locks: MigrationLocks) -> bool:
        """Restart every lease at ``lock_ttl_ms``, only while each still holds
        this request's token. ``False`` when any was lost or Redis failed."""
        ttl_ms = self._settings.lock_ttl_ms
        try:
            with self._redis.pipeline() as pipe:
                pipe.watch(*locks.keys)
                if not all(_owned(pipe.get(key), locks.token) for key in locks.keys):
                    pipe.unwatch()
                    return False
                pipe.multi()
                for key in locks.keys:
                    pipe.pexpire(key, ttl_ms)
                return all(pipe.execute())
        except Exception:
            return False

    def holds_locks(self, locks: MigrationLocks) -> bool:
        """Whether every key still holds this request's token. ``False`` on a Redis failure."""
        try:
            return all(_owned(self._redis.get(key), locks.token) for key in locks.keys)
        except Exception:
            return False

    def release_locks(self, locks: MigrationLocks) -> None:
        """Delete each lock key only while it still holds this request's token."""
        for key in locks.keys:
            self._release_owned(key, locks.token)

    def _release_owned(self, key: str, token: str) -> bool:
        """Compare-and-delete under ``WATCH``; a key that expired and was
        re-taken by another request is left alone. ``False`` only when Redis
        failed: an unreleased key expires after ``lock_ttl_ms``."""
        try:
            with self._redis.pipeline() as pipe:
                pipe.watch(key)
                if _owned(pipe.get(key), token):
                    pipe.multi()
                    pipe.delete(key)
                    pipe.execute()
                else:
                    pipe.unwatch()
        except Exception:
            return False
        return True

    # --- helpers ----------------------------------------------------------

    def _decode(self, token: str | None, secret: str, audience: str) -> dict[str, Any]:
        if not token or not isinstance(token, str):
            raise TokenInvalid()
        try:
            return jwt.decode(
                token,
                secret,
                algorithms=[_ALGORITHM],
                audience=audience,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
            )
        except Exception as exc:
            raise TokenInvalid() from exc


def _owned(current: Any, token: str) -> bool:
    return current in (token, token.encode("ascii"))


def _str_claim(claims: dict[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise TokenInvalid()
    return value


def _int_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TokenInvalid()
    return value
