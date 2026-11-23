"""Session lifetime of refreshed tokens, and removal of the API-key endpoint.

POST /auth/oauth2/refresh used to renew any unexpired token without limit,
so a token could be kept alive forever. Tokens now carry the time of the
original login ("auth_time"); refreshing keeps it and is refused once the
maximum session age (JWT_MAX_SESSION_HOURS) is exceeded.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from dserver_token_generator_plugin_oauth2.config import JwtConfig
from dserver_token_generator_plugin_oauth2.jwt_utils import JwtTokenGenerator

MAX_SESSION_HOURS = 48


@pytest.fixture
def generator(rsa_key_files):
    private_path, public_path = rsa_key_files
    return JwtTokenGenerator(JwtConfig(
        private_key_file=private_path,
        public_key_file=public_path,
        token_expiry_hours=24,
        max_session_hours=MAX_SESSION_HOURS,
    ))


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def _now():
    return datetime.now(timezone.utc)


def _signed(generator, **claims):
    """Sign arbitrary claims with the generator's key (e.g. old tokens)."""
    now = _now()
    payload = {
        "iss": "dserver",
        "aud": "dserver",
        "sub": "alice",
        "username": "alice",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
    }
    payload.update(claims)
    return jwt.encode(payload, generator.private_key, algorithm="RS256")


def test_config_max_session_hours_from_environment(monkeypatch):
    monkeypatch.delenv("JWT_MAX_SESSION_HOURS", raising=False)
    assert JwtConfig.from_env().max_session_hours == 168
    monkeypatch.setenv("JWT_MAX_SESSION_HOURS", "12")
    assert JwtConfig.from_env().max_session_hours == 12


def test_new_token_records_login_time(generator):
    before = int(_now().timestamp())
    claims = _claims(generator.generate_token(username="alice"))
    assert before <= claims["auth_time"] <= int(_now().timestamp())


def test_refresh_keeps_login_time_and_claims(generator):
    login = _now() - timedelta(hours=10)
    token = _signed(generator, auth_time=int(login.timestamp()),
                    email="alice@example.org", name="Alice",
                    provider="orcid", provider_user_id="0000-0001")

    claims = _claims(generator.refresh_token(token))

    assert claims["auth_time"] == int(login.timestamp())
    assert claims["sub"] == claims["username"] == "alice"
    assert claims["email"] == "alice@example.org"
    assert claims["name"] == "Alice"
    assert claims["provider"] == "orcid"
    assert claims["provider_user_id"] == "0000-0001"


def test_refresh_refused_after_max_session_age(generator):
    """Even a token whose own expiry is in the future cannot be refreshed
    once the session is older than the maximum session age."""
    login = _now() - timedelta(hours=MAX_SESSION_HOURS + 1)
    token = _signed(generator, auth_time=int(login.timestamp()))
    assert generator.refresh_token(token) is None


def test_token_expiry_capped_by_session_end(generator):
    """A refreshed token must not outlive the session."""
    login = _now() - timedelta(hours=MAX_SESSION_HOURS - 2)
    token = _signed(generator, auth_time=int(login.timestamp()))

    claims = _claims(generator.refresh_token(token))

    session_end = int(login.timestamp()) + MAX_SESSION_HOURS * 3600
    assert claims["exp"] <= session_end


def test_token_without_login_time_uses_issue_time(generator):
    """Tokens issued before this change have no auth_time; their issue time
    is the best available bound on the session start."""
    issued = _now() - timedelta(hours=MAX_SESSION_HOURS + 1)
    old = _signed(generator, iat=issued, nbf=issued)
    assert generator.refresh_token(old) is None

    issued = _now() - timedelta(hours=1)
    recent = _signed(generator, iat=issued, nbf=issued)
    assert _claims(generator.refresh_token(recent))["auth_time"] == \
        int(issued.timestamp())


def test_refresh_endpoint_refuses_expired_session(app, monkeypatch):
    monkeypatch.setenv("JWT_MAX_SESSION_HOURS", str(MAX_SESSION_HOURS))
    with app.app_context():
        from dserver_token_generator_plugin_oauth2.blueprint import (
            get_jwt_generator,
        )
        generator = get_jwt_generator()
    login = _now() - timedelta(hours=MAX_SESSION_HOURS + 1)
    token = _signed(generator, auth_time=int(login.timestamp()))

    response = app.test_client().post(
        "/auth/oauth2/refresh", json={"token": token})

    assert response.status_code == 401
    assert "token" not in response.get_json()


def test_refresh_endpoint_renews_valid_session(app):
    with app.app_context():
        from dserver_token_generator_plugin_oauth2.blueprint import (
            get_jwt_generator,
        )
        token = get_jwt_generator().generate_token(username="alice")

    response = app.test_client().post(
        "/auth/oauth2/refresh", json={"token": token})

    assert response.status_code == 200
    assert _claims(response.get_json()["token"])["sub"] == "alice"


def test_api_key_token_endpoint_removed(app, monkeypatch):
    """POST /auth/oauth2/token issued a token for any username to whoever
    knew the shared OAUTH2_API_KEY, including admin users."""
    monkeypatch.setenv("OAUTH2_API_KEY", "shared-secret")

    response = app.test_client().post(
        "/auth/oauth2/token",
        json={"api_key": "shared-secret", "username": "admin"})

    assert response.status_code == 405
    assert b"eyJ" not in response.data
