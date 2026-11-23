"""Tokens carry the audience and issuer dserver checks.

The plugin runs inside dserver, which requires the audience and issuer in
JWT_DECODE_AUDIENCE / JWT_DECODE_ISSUER (default "dserver"). Unless
JWT_AUDIENCE / JWT_ISSUER are set, the plugin issues tokens with those values.
"""

import pytest

from dserver_token_generator_plugin_oauth2.config import JwtConfig

KEYS = ("JWT_AUDIENCE", "JWT_ISSUER",
        "JWT_DECODE_AUDIENCE", "JWT_DECODE_ISSUER")


@pytest.fixture
def env(monkeypatch):
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)

    def set_env(**values):
        for key, value in values.items():
            monkeypatch.setenv(key, value)
        return JwtConfig.from_env()

    return set_env


def test_default_is_dserver(env):
    config = env()
    assert config.audience == "dserver"
    assert config.issuer == "dserver"


def test_follows_what_dserver_requires(env):
    config = env(JWT_DECODE_AUDIENCE="my-dserver",
                 JWT_DECODE_ISSUER="https://login.example.org")
    assert config.audience == "my-dserver"
    assert config.issuer == "https://login.example.org"


def test_own_setting_takes_precedence(env):
    config = env(JWT_DECODE_AUDIENCE="my-dserver", JWT_DECODE_ISSUER="idp",
                 JWT_AUDIENCE="other-audience", JWT_ISSUER="other-issuer")
    assert config.audience == "other-audience"
    assert config.issuer == "other-issuer"


@pytest.mark.parametrize("value", ["", "  "])
def test_blank_values_fall_back(env, value):
    """dserver's checks disabled (blank JWT_DECODE_*): still issue "dserver",
    which any dserver configuration accepts by default."""
    config = env(JWT_DECODE_AUDIENCE=value, JWT_DECODE_ISSUER=value,
                 JWT_AUDIENCE=value, JWT_ISSUER=value)
    assert config.audience == "dserver"
    assert config.issuer == "dserver"
