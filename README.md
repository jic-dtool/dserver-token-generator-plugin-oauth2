# dserver-token-generator-plugin-oauth2

A generic OAuth 2.0 / OpenID Connect token generator plugin for dserver that provides Single Sign-On (SSO) authentication with any OAuth2/OIDC compliant Identity Provider.

## Features

- **OAuth 2.0 Authorization Code flow** with PKCE support
- **OpenID Connect** support for providers that offer it
- **JWT token generation** after successful authentication
- **User lookup** in dserver: users must be registered in dserver beforehand; their display name is filled in from the provider
- **Device authorization flow** ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for command-line clients such as `dtool dserver login`
- **Bounded sessions**: tokens can be refreshed, but at most `JWT_MAX_SESSION_HOURS` after the original login
- **Flexible attribute mapping** to adapt to any provider's response format
- **Built-in presets** for popular providers

## Installation

```bash
pip install dserver-token-generator-plugin-oauth2
```

Or for development:

```bash
pip install -e .
```

## Quick Start

1. Choose your OAuth2 provider and register an application to get client credentials
2. Configure the environment variables (see Configuration below)
3. Run the database migrations (`flask db migrate` / `flask db upgrade`) for the device-login table
4. Register users in dserver (see [Users](#users)) and restart dserver
5. Users can authenticate in the browser at `/auth/oauth2/login`, and on the command line with `dtool dserver login <server>` (from [dtool-dserver](https://github.com/jic-dtool/dtool-dserver))

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `OAUTH2_AUTHORIZATION_URL` | Provider's authorization endpoint |
| `OAUTH2_TOKEN_URL` | Provider's token endpoint |
| `OAUTH2_CLIENT_ID` | Your application's client ID |
| `OAUTH2_CLIENT_SECRET` | Your application's client secret |

**Security Note**: For credentials (`OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET`), use a `.env` file instead of hardcoding them in `docker-compose.yml`:

```bash
# Copy the template
cp .env.template .env

# Edit with your credentials
nano .env
```

The `docker-compose.yml` uses variable substitution to read these values:
```yaml
OAUTH2_CLIENT_ID: "${OAUTH2_CLIENT_ID:-}"
OAUTH2_CLIENT_SECRET: "${OAUTH2_CLIENT_SECRET:-}"
```

### Optional Environment Variables

#### Provider Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_PROVIDER_NAME` | Identifier for the provider | `oauth2` |
| `OAUTH2_BASE_URL` | Base URL of your dserver instance | `http://localhost:5000` |
| `OAUTH2_USERINFO_URL` | OIDC userinfo endpoint | (none) |
| `OAUTH2_SCOPE` | OAuth2 scopes to request | `openid` |
| `OAUTH2_REDIRECT_URI` | Callback URL | `{OAUTH2_BASE_URL}/auth/oauth2/callback` |

#### Attribute Mapping

The plugin needs to know how to extract user information from the OAuth2 provider's response. Different providers return user data in different formats.

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_ATTRIBUTE_MAP` | Maps provider fields to internal fields | `sub:user_id,email:email,name:display_name` |
| `OAUTH2_USERNAME_FIELD` | Which internal field to use as username | `user_id` |

**Format**: `provider_field:internal_field,provider_field2:internal_field2`

**Internal fields**:
- `user_id` - Unique identifier from the provider
- `username` - Username (if different from user_id)
- `email` - Email address
- `display_name` - Full display name
- `given_name` - First name
- `surname` - Last name

#### JWT Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_PRIVATE_KEY_FILE` | Path to RSA private key | `/app/jwt/jwt_key` |
| `JWT_PUBLIC_KEY_FILE` | Path to RSA public key | `/app/jwt/jwt_key.pub` |
| `JWT_ALGORITHM` | Signing algorithm | `RS256` |
| `JWT_ISSUER` | Token issuer claim; must match dserver's `JWT_DECODE_ISSUER` | dserver's `JWT_DECODE_ISSUER`, else `dserver` |
| `JWT_AUDIENCE` | Token audience claim; must match dserver's `JWT_DECODE_AUDIENCE` | dserver's `JWT_DECODE_AUDIENCE`, else `dserver` |
| `JWT_TOKEN_EXPIRY_HOURS` | Token validity period | `24` |
| `JWT_MAX_SESSION_HOURS` | Maximum session age: tokens can be refreshed until this long after the original login (recorded in the `auth_time` claim), then the user must log in again | `168` |

#### Users

Users are **not** created on login: register them in dserver beforehand, with
the username the provider reports (e.g. the ORCID iD), and grant permissions:

```bash
flask user add 0000-0002-1825-0097
flask user search_permission 0000-0002-1825-0097 s3://my-bucket
```

A login of an unregistered user yields a token that dserver rejects.
(`OAUTH2_AUTO_PROVISION_USERS` and `OAUTH2_DEFAULT_USER_PERMISSIONS` are read
but have no effect.)

#### Device Authorization (command-line login)

Command-line clients such as `dtool dserver login` use the device authorization
flow: the client shows a short code, the user approves it in the webapp, and
the client receives a token. Pending requests are stored in dserver's SQL
database (table `oauth2_device_authorization`), so run the database migrations
(`flask db migrate` / `flask db upgrade`) after installing or upgrading the
plugin.

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_DEVICE_VERIFICATION_URL` | Page at which users approve device logins (the webapp, which opens its approval dialog for `?user_code=...`) | `OAUTH2_FRONTEND_URL` if absolute, otherwise `OAUTH2_BASE_URL` |
| `OAUTH2_DEVICE_CODE_LIFETIME_SECONDS` | Time to approve a device login | `600` |
| `OAUTH2_DEVICE_POLL_INTERVAL` | Minimum polling interval of clients in seconds | `5` |

#### Redirect URLs

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_FRONTEND_URL` | Frontend base URL | `/` |
| `OAUTH2_LOGIN_SUCCESS_REDIRECT` | Redirect after successful login | `/` |
| `OAUTH2_LOGIN_ERROR_REDIRECT` | Redirect after failed login | `/login?error=auth_failed` |
| `OAUTH2_DELIVER_TOKEN_IN_FRAGMENT` | Deliver the JWT in the redirect URL fragment (`#token=...`). Set to `false` for session-only delivery: the token never appears in any URL and the (same-origin) webapp fetches it from `GET /auth/oauth2/token` using the session cookie | `true` |

## API Endpoints

All endpoints are under the `/auth/oauth2` prefix.

### Authentication Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/oauth2/login` | GET | Initiates OAuth2 flow, redirects to provider |
| `/auth/oauth2/callback` | GET | Receives authorization code, exchanges for token |
| `/auth/oauth2/logout` | GET/POST | Clears the server-side session; redirects browsers to the frontend, returns JSON to clients that request it |

### Token Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/oauth2/token` | GET | Returns current user's JWT token |
| `/auth/oauth2/refresh` | POST | Refresh an existing JWT token, at most until `JWT_MAX_SESSION_HOURS` after the original login |
| `/auth/oauth2/verify` | POST | Verify a token and return its claims |

### Device Authorization (RFC 8628)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/oauth2/device` | POST | Start a device login; returns `device_code`, `user_code`, `verification_uri(_complete)`, `expires_in`, `interval`. Optional body: `{"client_name": "..."}` |
| `/auth/oauth2/device/token` | POST | Poll with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and `device_code` (JSON or form). Returns `authorization_pending`, `slow_down`, `access_denied` or `expired_token` errors until approved, then the token (once) |
| `/auth/oauth2/device/<user_code>` | GET | Describe a pending request (requires `Authorization: Bearer <token>`) |
| `/auth/oauth2/device/<user_code>/approve` | POST | Approve a request (requires `Authorization: Bearer <token>`) |
| `/auth/oauth2/device/<user_code>/deny` | POST | Deny a request (requires `Authorization: Bearer <token>`) |

The token issued to the device inherits the login time (`auth_time`) of the
approving session, so a device session ends when the approving browser
session would, and approving cannot extend an expired session.

### Information

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/oauth2/info` | GET | Returns configured provider information |

### Response Examples

**GET /auth/oauth2/token** (authenticated user):
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "username": "user@example.com",
  "provider": "oauth2",
  "token_type": "Bearer"
}
```

**GET /auth/oauth2/info**:
```json
{
  "provider": "orcid",
  "login_url": "http://localhost:5000/auth/oauth2/login",
  "configured": true
}
```

## CLI Commands

The plugin provides Flask CLI commands for management and debugging:

```bash
# Display current configuration
flask oauth2 show-config

# List available provider presets
flask oauth2 list-presets

# Show environment variables for a specific preset
flask oauth2 show-preset <provider>

# Validate the current configuration
flask oauth2 validate-config

# Test connectivity to the OAuth2 provider
flask oauth2 test-connection

# Generate a test JWT token
flask oauth2 test-jwt --username test@example.com
```

## How It Works

The plugin implements the standard OAuth 2.0 Authorization Code flow:

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User    │     │  dserver │     │ OAuth2   │     │ Frontend │
│ Browser  │     │  Plugin  │     │ Provider │     │  App     │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Click Login │                │                │
     │───────────────>│                │                │
     │                │                │                │
     │ 2. Redirect to Provider         │                │
     │<───────────────│                │                │
     │                │                │                │
     │ 3. Authenticate│                │                │
     │────────────────────────────────>│                │
     │                │                │                │
     │ 4. Authorization Code           │                │
     │<────────────────────────────────│                │
     │                │                │                │
     │ 5. Code to Plugin               │                │
     │───────────────>│                │                │
     │                │                │                │
     │                │ 6. Exchange Code for Token      │
     │                │───────────────>│                │
     │                │                │                │
     │                │ 7. Access Token + User Info     │
     │                │<───────────────│                │
     │                │                │                │
     │                │ 8. Generate JWT│                │
     │                │────────┐       │                │
     │                │        │       │                │
     │                │<───────┘       │                │
     │                │                │                │
     │ 9. Redirect with JWT Cookie     │                │
     │<───────────────│                │                │
     │                │                │                │
     │ 10. Access Frontend             │                │
     │─────────────────────────────────────────────────>│
     │                │                │                │
```

## Provider-Specific Documentation

See the `provider-docs/` directory for detailed setup guides:

- **[ORCID](provider-docs/orcid.md)** - Researcher identification (recommended for academic use)

## Security Considerations

1. **Always use HTTPS in production** - OAuth2 tokens are transmitted in URLs and headers
2. **Keep client secrets secure** - Never commit secrets to version control
3. **Validate redirect URIs** - Ensure they match exactly in provider configuration
4. **Use state parameter** - The plugin automatically handles CSRF protection via OAuth2 state
5. **Protect JWT keys** - Restrict file permissions on private key files
6. **Bounded sessions** - Tokens record the login time (`auth_time`); refresh and device approval never extend a session beyond `JWT_MAX_SESSION_HOURS` after the login. dserver cannot revoke tokens, so keep `JWT_TOKEN_EXPIRY_HOURS` and `JWT_MAX_SESSION_HOURS` as short as practical
7. **Audience and issuer** - Tokens carry `aud` and `iss`, which dserver verifies by default. They follow dserver's `JWT_DECODE_AUDIENCE` / `JWT_DECODE_ISSUER` (default `dserver`); set `JWT_AUDIENCE` / `JWT_ISSUER` only to issue other values

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=dserver_token_generator_plugin_oauth2
```

### Adding a New Provider Preset

Edit `config.py` and add to the `PROVIDER_PRESETS` dictionary:

```python
PROVIDER_PRESETS = {
    "your_provider": {
        "name": "your_provider",
        "authorization_url": "https://provider.com/oauth/authorize",
        "token_url": "https://provider.com/oauth/token",
        "userinfo_url": "https://provider.com/userinfo",  # if applicable
        "scope": "openid email profile",
        "attribute_map": {
            "sub": "user_id",
            "email": "email",
            "name": "display_name",
        },
        "username_field": "email",
    },
}
```

## License

MIT License
