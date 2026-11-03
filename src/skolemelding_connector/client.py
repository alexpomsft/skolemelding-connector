import re
from urllib.parse import unquote, urljoin, urlsplit

from .auth import TokenStore, required_text
from .http import APP_VERSION, ORIGIN, decode_json
from .storage import ConnectorError


def attachment_url(value):
    if not isinstance(value, str) or "\\" in value or any(ord(c) < 32 for c in value):
        raise ConnectorError("Attachment URL rejected.")
    parsed = urlsplit(urljoin(ORIGIN, value))
    decoded = unquote(parsed.path)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "portal.skoleplattform.no"
        or parsed.fragment
        or not parsed.path.startswith("/globalassets/attachments/")
        or re.search(r"%2f|%5c|%2e|%25", parsed.path, re.I)
        or any(segment in (".", "..") for segment in decoded.split("/"))
    ):
        raise ConnectorError("Attachment URL rejected.")
    return parsed.geturl()


class Client:
    def __init__(self, store=None):
        self.store = store if store is not None else TokenStore()

    def _request(self, method, url, **kwargs):
        token = self.store.access_token()
        for attempt in range(2):
            status, headers, body = self.store.http.request(
                method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs
            )
            if status != 401 or attempt:
                return status, headers, body
            token = self.store.access_token(rejected=token)
        raise AssertionError("Unreachable")

    def profile(self):
        result = decode_json(
            *self._request("GET", f"{ORIGIN}/api/v1/mobilesettings?appVersion={APP_VERSION}")
        )
        if not isinstance(result.get("DomainUser"), dict):
            raise ConnectorError("Mobile profile contract changed.")
        if result["DomainUser"].get("Category") != "Guardian":
            raise ConnectorError("The authenticated account is not a guardian.")
        if not isinstance(result.get("DependantUsers"), list):
            raise ConnectorError("Mobile children contract changed.")
        return result

    def children(self):
        return children_from_profile(self.profile())

    def search(self, child_id, page):
        if type(page) is not int or not 1 <= page <= 100:
            raise ConnectorError("Search page must be between 1 and 100.")
        required_text(child_id, "child username")
        return decode_json(
            *self._request(
                "POST",
                f"{ORIGIN}/api/messagesearchmobile/",
                json={
                    "Page": page,
                    "PageSize": 15,
                    "SearchTerm": "",
                    "SearchInbox": True,
                    "FilterSender": [],
                    "FilterUnreadMessages": False,
                    "FilterFeedbackRequired": False,
                    "FilterFeedbackIsQuestion": False,
                    "FilterIsAbsentMessage": False,
                    "OnBehalfOf": child_id,
                    "AuthorUserCategory": None,
                    "FilterFavouriteMessages": False,
                    "SendHiddenMessages": False,
                },
            )
        )

    def pdf(self, url, limit=10_000_000):
        safe = attachment_url(url)
        status, headers, body = self._request("GET", safe, limit=limit)
        if not 200 <= status < 300:
            raise ConnectorError(f"Attachment request failed (HTTP {status}).")
        if headers.get("content-type", "").split(";")[0].lower() != "application/pdf":
            raise ConnectorError("Attachment is not a PDF.")
        if not body.startswith(b"%PDF-"):
            raise ConnectorError("Attachment has an invalid PDF signature.")
        return body


def children_from_profile(profile):
    result = []
    for entry in profile["DependantUsers"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("DomainUser"), dict):
            raise ConnectorError("Mobile child record contract changed.")
        child = entry["DomainUser"]
        result.append(
            {
                "username": required_text(child.get("UserName"), "child username"),
                "name": required_text(child.get("Name"), "child name"),
            }
        )
    return result


def select_child(profile, selector):
    if not isinstance(selector, str) or not selector.strip():
        raise ConnectorError("A child selector is required.")
    children = children_from_profile(profile)
    exact = [child for child in children if child["username"] == selector]
    matches = exact or [
        child for child in children if child["name"].split()[0].casefold() == selector.casefold()
    ]
    if len(matches) != 1:
        raise ConnectorError("Child selector is missing or ambiguous; use `skolemelding children`.")
    return matches[0]
