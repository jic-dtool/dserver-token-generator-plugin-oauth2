"""SQL models of the OAuth2 token generator plugin.

Tables live in dserver's SQL database and are created by the deployment's
database migrations (``flask db migrate`` / ``flask db upgrade``).
"""

from dservercore import sql_db as db


class DeviceAuthorization(db.Model):
    """Pending device authorization request (RFC 8628).

    Created when a command-line client starts a login, approved or denied
    by the user in the webapp, and deleted once the client has collected the
    result (or the request has expired).
    """

    __tablename__ = "oauth2_device_authorization"

    id = db.Column(db.Integer, primary_key=True)
    # SHA-256 of the device code; the code itself is only known to the client
    device_code_hash = db.Column(db.String(64), unique=True, nullable=False,
                                 index=True)
    # Normalized user code (upper case, without dash)
    user_code = db.Column(db.String(16), unique=True, nullable=False,
                          index=True)
    client_name = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    interval = db.Column(db.Integer, nullable=False)
    last_polled_at = db.Column(db.DateTime, nullable=True)
    # pending, approved or denied
    status = db.Column(db.String(16), nullable=False, default="pending")
    # Set on approval: the approving user and the claims of their session
    username = db.Column(db.String(255), nullable=True)
    auth_time = db.Column(db.Integer, nullable=True)
    claims = db.Column(db.JSON, nullable=True)
