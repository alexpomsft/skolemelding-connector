import base64
import hashlib
import math
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from .http import APP_VERSION, AUTHORIZE, HTTP, OIDC_TOKEN, ORIGIN
from .storage import ConnectorError, config_dir, locked, read_json, write_json

# Public native-client registration, not a client secret.
OIDC_CLIENT_ID = "d12dad8a-f092-4a96-8a37-371590825d22"
REDIRECT_URI = "com.cgi.oslomelding.foresatte://oauth"
APP_CLIENT_ID = "consoleAPP"


def required_text(value, label):
    if not isinstance(value, str) or not value or len(value) > 100_000:
        raise ConnectorError(f"Missing or invalid {label}.")
    return value


def normalize_tokens(response, previous=None):
    previous = previous or {}
    access = required_text(response.get("access_token"), "access token")
    refresh = required_text(
        response.get("refresh_token", previous.get("refresh_token")), "refresh token"
    )
    username = required_text(response.get("userName", previous.get("userName")), "token username")
    token_type = response.get("token_type", "bearer")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise ConnectorError("Unsupported token type.")
    # The app renews at 28 minutes. Prefer the actual provider lifetime when supplied.
    expires = response.get("expires_in", 28 * 60)
    if isinstance(expires, str) and expires.isdecimal():
        expires = int(expires)
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        raise ConnectorError("Invalid token lifetime.")
    if not math.isfinite(expires) or expires <= 0:
        raise ConnectorError("Invalid token lifetime.")
    return {
        "access_token": access,
        "refresh_token": refresh,
        "userName": username,
        "expires_at": time.time() + expires,
        "device_registered": previous.get("device_registered", False),
    }


class TokenStore:
    def __init__(self, directory=None, http=None):
        self.directory = directory if directory is not None else config_dir()
        self.path = self.directory / "tokens.json"
        self.lock_path = self.directory / "tokens.lock"
        self.http = http if http is not None else HTTP()

    def access_token(self, rejected=None, force=False):
        with locked(self.lock_path):
            tokens = read_json(self.path)
            if tokens.get("device_registered") is not True:
                raise ConnectorError("Native device setup is incomplete; run `skolemelding login`.")
            current = required_text(tokens.get("access_token"), "stored access token")
            expiry = tokens.get("expires_at")
            if not isinstance(expiry, (int, float)) or not math.isfinite(expiry):
                raise ConnectorError("Invalid stored token expiry; sign in again.")
            # Another process may already have replaced the token that received a 401.
            if (
                expiry > time.time() + 60
                and not force
                and (rejected is None or rejected != current)
            ):
                return current
            result = self.http.json(
                "POST",
                f"{ORIGIN}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": required_text(
                        tokens.get("refresh_token"), "stored refresh token"
                    ),
                    "username": required_text(tokens.get("userName"), "stored token username"),
                    "client_id": APP_CLIENT_ID,
                    "app_version": APP_VERSION,
                },
                headers={"Accept": "application/json"},
            )
            renewed = normalize_tokens(result, tokens)
            write_json(self.path, renewed)
            return renewed["access_token"]

    def begin_login(self):
        with locked(self.directory / "login.lock"):
            verifier = secrets.token_urlsafe(48)
            pending = {
                "state": secrets.token_urlsafe(32),
                "verifier": verifier,
                "created_at": time.time(),
                "device_scope": f"{secrets.token_hex(8)}|{int(time.time())}|Foresatte",
            }
            write_json(self.directory / "pending-login.json", pending)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
        return (
            AUTHORIZE
            + "?"
            + urlencode(
                {
                    "client_id": OIDC_CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": pending["state"],
                    "code_challenge": challenge.rstrip("="),
                    "code_challenge_method": "S256",
                    "ui_locales": "nb",
                    "prompt": "login",
                }
            )
        )

    def complete_login(self, callback):
        with locked(self.directory / "login.lock"):
            path = self.directory / "pending-login.json"
            pending = read_json(path)
            if not isinstance(pending.get("created_at"), (int, float)):
                raise ConnectorError("Invalid pending login.")
            if not 0 <= time.time() - pending["created_at"] <= 900:
                raise ConnectorError("Login expired; start a new login.")
            code = callback_code(callback, pending["state"])
            oidc = self.http.json(
                "POST",
                OIDC_TOKEN,
                data={
                    "grant_type": "authorization_code",
                    "client_id": OIDC_CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "code": code,
                    "code_verifier": pending["verifier"],
                },
            )
            exchange = self.http.json(
                "POST",
                f"{ORIGIN}/api/exchange-app-token",
                json={
                    "provider": "idporten",
                    "accessToken": required_text(
                        oidc.get("access_token"), "ID-porten access token"
                    ),
                },
            )
            with locked(self.lock_path):
                tokens = self.http.json(
                    "POST",
                    f"{ORIGIN}/token",
                    data={
                        "grant_type": "password",
                        "username": required_text(
                            exchange.get("authCode"), "app authorization code"
                        ),
                        "password": "code",
                        "scope": pending["device_scope"],
                        "client_id": APP_CLIENT_ID,
                        "app_version": APP_VERSION,
                    },
                )
                saved = normalize_tokens(tokens)
                write_json(self.path, saved)
                self._register_device(saved)
            path.unlink()

    def _register_device(self, tokens):
        # The provider rejects refresh tokens until this native-client setup step completes.
        status, _, _ = self.http.request(
            "POST",
            f"{ORIGIN}/api/deviceinfo/save",
            headers={"Authorization": "Bearer " + tokens["access_token"]},
            json={"OsVersion": "linux|skolemelding-connector", "AppVersion": APP_VERSION},
        )
        if not 200 <= status < 300:
            raise ConnectorError(f"Native device setup failed (HTTP {status}); sign in again.")
        tokens["device_registered"] = True
        write_json(self.path, tokens)


def callback_code(callback, state):
    if not isinstance(callback, str) or len(callback) > 100_000:
        raise ConnectorError("Invalid login callback.")
    parsed = urlsplit(callback.strip())
    target = urlsplit(REDIRECT_URI)
    if (
        parsed.scheme != target.scheme
        or parsed.netloc != target.netloc
        or parsed.path not in ("", "/")
        or parsed.fragment
    ):
        raise ConnectorError("Unexpected login callback destination.")
    fields = parse_qs(parsed.query, keep_blank_values=True)
    if fields.get("state") != [state]:
        raise ConnectorError("Login state does not match; start a new login.")
    if "error" in fields:
        raise ConnectorError("ID-porten rejected or cancelled the login.")
    if len(fields.get("code", [])) != 1:
        raise ConnectorError("Login callback must contain exactly one code.")
    return required_text(fields["code"][0], "authorization code")
