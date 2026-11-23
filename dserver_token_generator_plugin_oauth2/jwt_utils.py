"""
JWT token generation utilities.

This module handles JWT token creation and signing for authenticated users.
"""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt

from .config import JwtConfig

logger = logging.getLogger(__name__)


class JwtTokenGenerator:
    """Generate and sign JWT tokens for authenticated users."""

    def __init__(self, config: JwtConfig):
        """
        Initialize the JWT token generator.

        Args:
            config: JWT configuration object
        """
        self.config = config
        self._private_key: Optional[str] = None
        self._public_key: Optional[str] = None

    @property
    def private_key(self) -> str:
        """Load and cache the private key."""
        if self._private_key is None:
            self._private_key = self._load_key(self.config.private_key_file)
        return self._private_key

    @property
    def public_key(self) -> str:
        """Load and cache the public key."""
        if self._public_key is None:
            self._public_key = self._load_key(self.config.public_key_file)
        return self._public_key

    @staticmethod
    def _load_key(path: str) -> str:
        """Load a key from file."""
        key_path = Path(path)
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        return key_path.read_text()

    def generate_token(
        self,
        username: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        permissions: Optional[list] = None,
        additional_claims: Optional[dict] = None,
        auth_time: Optional[int] = None,
    ) -> str:
        """
        Generate a JWT token for an authenticated user.

        Args:
            username: Unique username
            email: User's email address
            display_name: User's display name
            permissions: List of permissions/roles
            additional_claims: Any additional claims to include
            auth_time: Time of the original login (Unix timestamp); now if
                not given. The token never outlives the session, i.e. it
                expires at the latest max_session_hours after auth_time.

        Returns:
            Signed JWT token string
        """
        now = datetime.now(timezone.utc)
        if auth_time is None:
            auth_time = int(now.timestamp())
        session_end = datetime.fromtimestamp(auth_time, timezone.utc) + \
            timedelta(hours=self.config.max_session_hours)
        expiry = min(now + timedelta(hours=self.config.token_expiry_hours),
                     session_end)

        payload = {
            # Standard JWT claims
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "sub": username,
            "iat": now,
            "exp": expiry,
            "nbf": now,
            # Time of the original login (OpenID Connect "auth_time")
            "auth_time": auth_time,

            # Custom claims for dserver
            "username": username,
        }

        # Add optional claims
        if email:
            payload["email"] = email

        if display_name:
            payload["name"] = display_name

        if permissions:
            payload["permissions"] = permissions

        # Add any additional claims
        if additional_claims:
            payload.update(additional_claims)

        # Sign the token
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.config.algorithm
        )

        logger.info(f"Generated JWT token for user: {username}")
        return token

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
        return None

    def refresh_token(self, token: str) -> Optional[str]:
        """
        Refresh an existing valid token.

        Args:
            token: Existing JWT token

        Returns:
            New token with extended expiry, or None if original is invalid
        """
        payload = self.verify_token(token)
        if payload is None:
            return None

        # The session starts at the original login. Tokens issued before
        # auth_time was recorded fall back to their issue time.
        auth_time = int(payload.get("auth_time", payload["iat"]))
        session_end = auth_time + self.config.max_session_hours * 3600
        if datetime.now(timezone.utc).timestamp() >= session_end:
            logger.warning(
                f"Refusing to refresh token of {payload['username']}: "
                f"session older than {self.config.max_session_hours} hours")
            return None

        # Generate new token with same claims and session start
        additional_claims = {
            key: payload[key]
            for key in ("provider", "provider_user_id")
            if key in payload
        }
        return self.generate_token(
            username=payload["username"],
            email=payload.get("email"),
            display_name=payload.get("name"),
            permissions=payload.get("permissions"),
            additional_claims=additional_claims or None,
            auth_time=auth_time,
        )
