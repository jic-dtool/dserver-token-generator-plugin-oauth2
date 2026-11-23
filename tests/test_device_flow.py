"""OAuth 2.0 device authorization flow (RFC 8628) for command-line clients.

The CLI requests a device code, the user approves its short user code in the
webapp (authenticated with their dserver token), and the CLI polls for a
token. The CLI's token inherits the approver's login time (auth_time), so a
CLI session cannot outlive the browser session that approved it.
"""

import re
from datetime import datetime, timedelta, timezone

import jwt
import pytest

FRONTEND = "http://127.0.0.1:8080"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def _generator():
    from dserver_token_generator_plugin_oauth2.blueprint import (
        get_jwt_generator,
    )
    return get_jwt_generator()


def _approver_token(username="alice", **kwargs):
    return _generator().generate_token(
        username=username, email="alice@example.org", display_name="Alice",
        additional_claims={"provider": "orcid",
                           "provider_user_id": "0000-0001"},
        **kwargs)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _start(client, **body):
    response = client.post("/auth/oauth2/device", json=body or None)
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()


def _poll(client, device_code):
    return client.post("/auth/oauth2/device/token", json={
        "grant_type": GRANT_TYPE, "device_code": device_code})


def _row(user_code):
    from dserver_token_generator_plugin_oauth2.sql_models import (
        DeviceAuthorization,
    )
    return DeviceAuthorization.query.filter_by(
        user_code=user_code.replace("-", "")).one()


@pytest.fixture
def client(db_app):
    return db_app.test_client()


def test_start_returns_codes_and_verification_url(client):
    data = _start(client)

    assert len(data["device_code"]) >= 32
    assert re.fullmatch(r"[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}",
                        data["user_code"])
    assert data["verification_uri"] == FRONTEND
    assert data["verification_uri_complete"] == \
        f"{FRONTEND}?user_code={data['user_code']}"
    assert data["expires_in"] == 600
    assert data["interval"] == 0


def test_verification_url_configurable(db_app, monkeypatch):
    monkeypatch.setenv("OAUTH2_DEVICE_VERIFICATION_URL",
                       "https://webapp.example/device")
    import dserver_token_generator_plugin_oauth2.blueprint as bp_module
    monkeypatch.setattr(bp_module, "_config", None)

    data = _start(db_app.test_client())
    assert data["verification_uri"] == "https://webapp.example/device"


def test_device_code_stored_hashed(client):
    data = _start(client)
    row = _row(data["user_code"])
    assert data["device_code"] not in row.device_code_hash


def test_poll_pending_until_approved(client):
    data = _start(client)
    response = _poll(client, data["device_code"])
    assert response.status_code == 400
    assert response.get_json()["error"] == "authorization_pending"


def test_poll_faster_than_interval_slows_down(client, monkeypatch):
    monkeypatch.setenv("OAUTH2_DEVICE_POLL_INTERVAL", "5")
    data = _start(client)
    assert _poll(client, data["device_code"]).get_json()["error"] == \
        "authorization_pending"
    response = _poll(client, data["device_code"])
    assert response.get_json()["error"] == "slow_down"


def test_poll_unknown_device_code(client):
    response = _poll(client, "not-a-device-code")
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_grant"


def test_poll_requires_device_code_grant_type(client):
    data = _start(client)
    response = client.post("/auth/oauth2/device/token", json={
        "grant_type": "password", "device_code": data["device_code"]})
    assert response.status_code == 400
    assert response.get_json()["error"] == "unsupported_grant_type"


def test_lookup_requires_valid_token(client):
    data = _start(client)
    url = f"/auth/oauth2/device/{data['user_code']}"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=_auth("garbage")).status_code == 401


def test_lookup_shows_pending_request(client):
    data = _start(client, client_name="dtool on laptop")
    response = client.get(f"/auth/oauth2/device/{data['user_code']}",
                          headers=_auth(_approver_token()))
    assert response.status_code == 200
    info = response.get_json()
    assert info["user_code"] == data["user_code"]
    assert info["client_name"] == "dtool on laptop"
    assert info["status"] == "pending"


def test_lookup_unknown_code(client):
    response = client.get("/auth/oauth2/device/BBBB-CCCC",
                          headers=_auth(_approver_token()))
    assert response.status_code == 404


def test_approve_then_poll_issues_token_once(client):
    login = int((datetime.now(timezone.utc)
                 - timedelta(hours=3)).timestamp())
    data = _start(client)
    response = client.post(
        f"/auth/oauth2/device/{data['user_code']}/approve",
        headers=_auth(_approver_token(auth_time=login)))
    assert response.status_code == 200, response.get_data(as_text=True)

    response = _poll(client, data["device_code"])
    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"] == body["token"]
    claims = _claims(body["token"])
    assert claims["sub"] == "alice"
    assert claims["aud"] == claims["iss"] == "dserver"
    assert claims["auth_time"] == login
    assert claims["provider"] == "orcid"

    # The device code can only be redeemed once.
    response = _poll(client, data["device_code"])
    assert response.get_json()["error"] == "invalid_grant"


def test_user_code_case_and_dash_insensitive(client):
    data = _start(client)
    code = data["user_code"].replace("-", "").lower()
    response = client.post(f"/auth/oauth2/device/{code}/approve",
                           headers=_auth(_approver_token()))
    assert response.status_code == 200


def test_poll_accepts_form_encoding(client):
    """RFC 8628 clients send the token request form-encoded."""
    data = _start(client)
    client.post(f"/auth/oauth2/device/{data['user_code']}/approve",
                headers=_auth(_approver_token()))
    response = client.post("/auth/oauth2/device/token", data={
        "grant_type": GRANT_TYPE, "device_code": data["device_code"]})
    assert response.status_code == 200


def test_deny(client):
    data = _start(client)
    response = client.post(f"/auth/oauth2/device/{data['user_code']}/deny",
                           headers=_auth(_approver_token()))
    assert response.status_code == 200
    response = _poll(client, data["device_code"])
    assert response.get_json()["error"] == "access_denied"


def test_approval_requires_token(client):
    data = _start(client)
    response = client.post(
        f"/auth/oauth2/device/{data['user_code']}/approve")
    assert response.status_code == 401
    assert _poll(client, data["device_code"]).get_json()["error"] == \
        "authorization_pending"


def test_cannot_approve_twice(client):
    data = _start(client)
    url = f"/auth/oauth2/device/{data['user_code']}/approve"
    assert client.post(url, headers=_auth(_approver_token())).status_code \
        == 200
    response = client.post(url, headers=_auth(_approver_token("mallory")))
    assert response.status_code == 409


def test_expired_request(client):
    from dservercore import sql_db

    data = _start(client)
    row = _row(data["user_code"])
    row.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) \
        - timedelta(seconds=1)
    sql_db.session.commit()

    response = client.post(
        f"/auth/oauth2/device/{data['user_code']}/approve",
        headers=_auth(_approver_token()))
    assert response.status_code == 404
    response = _poll(client, data["device_code"])
    assert response.get_json()["error"] == "expired_token"


def test_approval_cannot_extend_expired_session(client):
    """An approver token from a session older than the maximum session age
    must not mint a fresh CLI session."""
    from dserver_token_generator_plugin_oauth2.blueprint import get_config

    max_hours = get_config().jwt.max_session_hours
    now = datetime.now(timezone.utc)
    stale = jwt.encode({
        "iss": "dserver", "aud": "dserver", "sub": "alice",
        "username": "alice", "iat": now, "nbf": now,
        "exp": now + timedelta(hours=1),
        "auth_time": int((now - timedelta(hours=max_hours + 1)).timestamp()),
    }, _generator().private_key, algorithm="RS256")

    data = _start(client)
    response = client.post(
        f"/auth/oauth2/device/{data['user_code']}/approve",
        headers=_auth(stale))
    assert response.status_code == 401
