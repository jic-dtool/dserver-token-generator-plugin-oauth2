"""
OAuth 2.0 device authorization flow (RFC 8628) for command-line clients.

A command-line client (e.g. ``dtool dserver login``) cannot receive the
browser redirect of the regular login. Instead:

1. The client requests a device code: ``POST /auth/oauth2/device``. It gets
   a secret ``device_code`` and a short ``user_code`` with a verification URL
   (the webapp by default), which it shows to the user.
2. The user opens the verification URL in any browser (also on another
   machine), logs in as usual and approves the user code. The webapp calls
   ``GET /auth/oauth2/device/<user_code>`` and
   ``POST /auth/oauth2/device/<user_code>/approve`` (or ``/deny``),
   authenticated with the user's dserver token (Bearer).
3. Meanwhile the client polls ``POST /auth/oauth2/device/token`` with its
   device code and receives a dserver token once the request is approved.

The client's token inherits the login time (``auth_time``) of the approving
session, so a client session cannot outlive the browser session that
approved it, and cannot be used to extend a stale session.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

from .blueprint import get_config, get_jwt_generator, oauth2_bp
# Imported at startup so that database migrations create the table.
from .sql_models import DeviceAuthorization

logger = logging.getLogger(__name__)

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Consonants only: no vowels (no accidental words), no ambiguous characters
# such as 0/O or 1/I (RFC 8628, section 6.1).
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH = 8

# Increase of the polling interval on "slow_down" (RFC 8628, section 3.5)
SLOW_DOWN_SECONDS = 5

# Claims of the approving session passed on to the client's token
INHERITED_CLAIMS = ("email", "name", "provider", "provider_user_id")


def _now():
    """Return the current time as naive UTC, as stored in the database."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_device_code(device_code):
    return hashlib.sha256(device_code.encode()).hexdigest()


def _normalize_user_code(user_code):
    return user_code.replace("-", "").replace(" ", "").upper()


def _format_user_code(user_code):
    half = len(user_code) // 2
    return f"{user_code[:half]}-{user_code[half:]}"


def _generate_user_code():
    return "".join(secrets.choice(USER_CODE_ALPHABET)
                   for _ in range(USER_CODE_LENGTH))


def _error(error, description, status=400):
    """Return an OAuth 2.0 error response (RFC 6749, section 5.2)."""
    return jsonify({"error": error, "error_description": description}), status


def _session_from_bearer():
    """Return the verified claims of the request's Bearer token, or None."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return get_jwt_generator().verify_token(header[len("Bearer "):].strip())


def _session_auth_time(claims):
    return int(claims.get("auth_time", claims["iat"]))


def _find_pending(user_code):
    """Return the unexpired request for a user code, or None."""

    row = DeviceAuthorization.query.filter_by(
        user_code=_normalize_user_code(user_code)).first()
    if row is None or row.expires_at <= _now():
        return None
    return row


@oauth2_bp.route("/device", methods=["POST"])
def device_authorization():
    """Start a device login and return the device and user codes."""
    from dservercore import sql_db

    config = get_config()
    data = request.get_json(silent=True) or request.form or {}
    client_name = (data.get("client_name") or "").strip()[:80] or None

    device_code = secrets.token_urlsafe(32)
    while True:
        user_code = _generate_user_code()
        if DeviceAuthorization.query.filter_by(
                user_code=user_code).first() is None:
            break

    now = _now()
    sql_db.session.add(DeviceAuthorization(
        device_code_hash=_hash_device_code(device_code),
        user_code=user_code,
        client_name=client_name,
        created_at=now,
        expires_at=now + timedelta(
            seconds=config.device_code_lifetime_seconds),
        interval=config.device_poll_interval,
        status="pending",
    ))
    sql_db.session.commit()

    verification_uri = config.get_device_verification_url()
    formatted = _format_user_code(user_code)
    separator = "&" if "?" in verification_uri else "?"
    logger.info(f"Started device login {formatted} for {client_name!r}")
    return jsonify({
        "device_code": device_code,
        "user_code": formatted,
        "verification_uri": verification_uri,
        "verification_uri_complete":
            f"{verification_uri}{separator}user_code={formatted}",
        "expires_in": config.device_code_lifetime_seconds,
        "interval": config.device_poll_interval,
    })


@oauth2_bp.route("/device/token", methods=["POST"])
def device_token():
    """Return the token for an approved device code (polled by clients)."""
    from dservercore import sql_db

    data = request.get_json(silent=True) or request.form or {}
    if data.get("grant_type", DEVICE_CODE_GRANT_TYPE) != \
            DEVICE_CODE_GRANT_TYPE:
        return _error("unsupported_grant_type",
                      f"Expected grant_type {DEVICE_CODE_GRANT_TYPE}")
    device_code = data.get("device_code")
    if not device_code:
        return _error("invalid_request", "Missing device_code")

    row = DeviceAuthorization.query.filter_by(
        device_code_hash=_hash_device_code(device_code)).first()
    if row is None:
        return _error("invalid_grant", "Unknown or already used device code")

    now = _now()
    if row.expires_at <= now:
        sql_db.session.delete(row)
        sql_db.session.commit()
        return _error("expired_token", "The device code has expired")

    if row.status == "denied":
        sql_db.session.delete(row)
        sql_db.session.commit()
        return _error("access_denied", "The user denied the request")

    if row.status == "pending":
        too_fast = row.last_polled_at is not None and \
            now - row.last_polled_at < timedelta(seconds=row.interval)
        row.last_polled_at = now
        if too_fast:
            row.interval += SLOW_DOWN_SECONDS
            sql_db.session.commit()
            return _error("slow_down", "Polling too fast")
        sql_db.session.commit()
        return _error("authorization_pending",
                      "The user has not yet approved the request")

    # Approved: issue the token once.
    claims = row.claims or {}
    additional_claims = {
        key: claims[key] for key in ("provider", "provider_user_id")
        if key in claims
    }
    token = get_jwt_generator().generate_token(
        username=row.username,
        email=claims.get("email"),
        display_name=claims.get("name"),
        additional_claims=additional_claims or None,
        auth_time=row.auth_time,
    )
    sql_db.session.delete(row)
    sql_db.session.commit()

    token_claims = get_jwt_generator().verify_token(token) or {}
    expires_in = max(0, int(token_claims.get("exp", 0)
                            - datetime.now(timezone.utc).timestamp()))
    logger.info(f"Issued token to device login of {row.username}")
    return jsonify({
        "token": token,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    })


@oauth2_bp.route("/device/<user_code>", methods=["GET"])
def device_lookup(user_code):
    """Describe a pending request, for the webapp's approval dialog."""
    if _session_from_bearer() is None:
        return _error("invalid_token", "Missing or invalid token", 401)
    row = _find_pending(user_code)
    if row is None:
        return _error("not_found", "Unknown or expired code", 404)
    return jsonify({
        "user_code": _format_user_code(row.user_code),
        "client_name": row.client_name,
        "created_at": row.created_at.replace(
            tzinfo=timezone.utc).isoformat(),
        "expires_at": row.expires_at.replace(
            tzinfo=timezone.utc).isoformat(),
        "status": row.status,
    })


def _decide(user_code, approve):
    from dservercore import sql_db

    claims = _session_from_bearer()
    if claims is None:
        return _error("invalid_token", "Missing or invalid token", 401)

    auth_time = _session_auth_time(claims)
    max_age = timedelta(hours=get_config().jwt.max_session_hours)
    if datetime.now(timezone.utc) >= \
            datetime.fromtimestamp(auth_time, timezone.utc) + max_age:
        return _error("invalid_token",
                      "Session expired, please log in again", 401)

    row = _find_pending(user_code)
    if row is None:
        return _error("not_found", "Unknown or expired code", 404)
    if row.status != "pending":
        return _error("conflict", f"Request already {row.status}", 409)

    username = claims.get("username", claims["sub"])
    if approve:
        row.status = "approved"
        row.username = username
        row.auth_time = auth_time
        row.claims = {key: claims[key] for key in INHERITED_CLAIMS
                      if key in claims}
    else:
        row.status = "denied"
    sql_db.session.commit()

    logger.info(f"Device login {_format_user_code(row.user_code)} "
                f"{row.status} by {username}")
    return jsonify({"user_code": _format_user_code(row.user_code),
                    "status": row.status})


@oauth2_bp.route("/device/<user_code>/approve", methods=["POST"])
def device_approve(user_code):
    """Approve a pending request (authenticated with a Bearer token)."""
    return _decide(user_code, approve=True)


@oauth2_bp.route("/device/<user_code>/deny", methods=["POST"])
def device_deny(user_code):
    """Deny a pending request (authenticated with a Bearer token)."""
    return _decide(user_code, approve=False)
