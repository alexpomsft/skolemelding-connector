import json

import httpx

from .storage import ConnectorError

ORIGIN = "https://portal.skoleplattform.no"
ISSUER = "https://idporten.no"
AUTHORIZE = "https://login.idporten.no/authorize"
OIDC_TOKEN = f"{ISSUER}/token"
APP_VERSION = "6.0.6"


class HTTP:
    def __init__(self, transport=None):
        self.client = httpx.Client(
            timeout=30, follow_redirects=False, trust_env=False, transport=transport
        )

    def close(self):
        self.client.close()

    def request(self, method, url, *, limit=2_000_000, **kwargs):
        try:
            # Cookies are deliberately never reused, including cookies set by /token.
            self.client.cookies.clear()
            with self.client.stream(method, url, **kwargs) as response:
                if 300 <= response.status_code < 400:
                    raise ConnectorError(
                        "Provider redirect refused; authentication may be required."
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > limit:
                        raise ConnectorError("Provider response exceeds the size limit.")
                return response.status_code, response.headers, bytes(content)
        except httpx.HTTPError:
            raise ConnectorError(
                "Provider network request failed; no automatic token retry."
            ) from None
        finally:
            self.client.cookies.clear()

    def json(self, method, url, **kwargs):
        status, headers, body = self.request(method, url, **kwargs)
        return decode_json(status, headers, body)


def decode_json(status, headers, body):
    if not 200 <= status < 300:
        if status in (400, 401, 403):
            raise ConnectorError(
                f"Authentication rejected (HTTP {status}); run `skolemelding login` again."
            )
        raise ConnectorError(f"Provider returned HTTP {status}.")
    if headers.get("content-type", "").split(";")[0].lower() != "application/json":
        raise ConnectorError("Provider did not return JSON.")
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError):
        raise ConnectorError("Provider returned invalid JSON.") from None
    if not isinstance(result, dict):
        raise ConnectorError("Provider JSON must be an object.")
    return result
