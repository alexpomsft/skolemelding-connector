import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from skolemelding_connector.auth import (
    OIDC_CLIENT_ID,
    REDIRECT_URI,
    TokenStore,
    callback_code,
    normalize_tokens,
)
from skolemelding_connector.client import Client, attachment_url, select_child
from skolemelding_connector.collector import collect, plain_text
from skolemelding_connector.http import HTTP, ORIGIN
from skolemelding_connector.storage import ConnectorError, locked, read_json, write_json


def tokens(**changes):
    return {
        "access_token": "fixture-access",
        "refresh_token": "fixture-refresh",
        "userName": "fixture-user",
        "expires_at": time.time() + 1800,
        "device_registered": True,
        **changes,
    }


def profile():
    return {
        "DomainUser": {"Category": "Guardian", "UserName": "guardian-id", "Name": "Test Guardian"},
        "DependantUsers": [
            {"DomainUser": {"UserName": "child-id", "Name": "Example Child"}},
            {"DomainUser": {"UserName": "other-id", "Name": "Other Child"}},
        ],
    }


def message(identity=1, **changes):
    return {
        "Id": identity,
        "Header": "School trip",
        "Body": "<p>Bring lunch.</p>",
        "Timestamp": "2026-10-01T10:00:00+02:00",
        "OnBehalfOfList": ["child-id"],
        "Attachments": [],
        "Threads": [],
        **changes,
    }


class FixtureClient:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else [message()]
        self.calls = []
        self.current_profile = profile()

    def profile(self):
        return copy.deepcopy(self.current_profile)

    def search(self, child, page):
        self.calls.append(page)
        return {"Result": self.rows[(page - 1) * 15 : page * 15], "TotalMatching": len(self.rows)}

    def pdf(self, url, limit):
        return b"%PDF-1.7\nsynthetic-only"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.http_clients = []
        self.addCleanup(lambda: [client.close() for client in self.http_clients])

    def store(self, handler):
        http = HTTP(httpx.MockTransport(handler))
        self.http_clients.append(http)
        return TokenStore(self.directory, http)

    def test_complete_native_login_and_required_registration(self):
        calls = []

        def handler(request):
            calls.append(request)
            if request.url.host == "idporten.no":
                body = parse_qs(request.content.decode())
                self.assertEqual(body["client_id"], [OIDC_CLIENT_ID])
                self.assertIn("code_verifier", body)
                return httpx.Response(200, json={"access_token": "fixture-oidc"})
            if request.url.path == "/api/exchange-app-token":
                self.assertEqual(
                    json.loads(request.content),
                    {"provider": "idporten", "accessToken": "fixture-oidc"},
                )
                return httpx.Response(200, json={"authCode": "fixture-code"})
            if request.url.path == "/token":
                body = parse_qs(request.content.decode())
                self.assertEqual(body["password"], ["code"])
                self.assertRegex(body["scope"][0], r"^[a-f0-9]{16}\|\d+\|Foresatte$")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "fixture-access",
                        "refresh_token": "fixture-refresh",
                        "userName": "fixture-user",
                        "expires_in": 1800,
                    },
                )
            self.assertEqual(request.url.path, "/api/deviceinfo/save")
            self.assertEqual(request.headers["Authorization"], "Bearer fixture-access")
            self.assertNotIn("Token", json.loads(request.content))
            return httpx.Response(204)

        store = self.store(handler)
        start = store.begin_login()
        fields = parse_qs(urlsplit(start).query)
        self.assertEqual(fields["code_challenge_method"], ["S256"])
        self.assertEqual(fields["scope"], ["openid profile"])
        callback = REDIRECT_URI + "?" + urlencode({"state": fields["state"][0], "code": "code"})
        store.complete_login(callback)
        self.assertEqual(len(calls), 4)
        self.assertTrue(read_json(store.path)["device_registered"])
        self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.directory / "pending-login.json").exists())

    def test_registration_failure_does_not_claim_usable_login(self):
        store = self.store(lambda request: httpx.Response(500))
        write_json(store.path, tokens(device_registered=False))
        with locked(store.lock_path), self.assertRaises(ConnectorError):
            store._register_device(read_json(store.path))
        with self.assertRaisesRegex(ConnectorError, "setup is incomplete"):
            store.access_token()

    def test_callback_rejects_wrong_destination_missing_state_and_duplicates(self):
        for callback in (
            "https://evil.invalid/?state=state&code=x",
            REDIRECT_URI + "?code=x",
            REDIRECT_URI + "?state=wrong&code=x",
            REDIRECT_URI + "?state=state&code=x&code=y",
            REDIRECT_URI + "/wrong?state=state&code=x",
            REDIRECT_URI + "?state=state&code=x#fragment",
        ):
            with self.subTest(callback=callback), self.assertRaises(ConnectorError):
                callback_code(callback, "state")
        self.assertEqual(callback_code(REDIRECT_URI + "?state=state&code=x", "state"), "x")

    def test_concurrent_stores_rotate_once_and_preserve_new_token(self):
        calls = []
        gate = threading.Barrier(2)

        def handler(request):
            calls.append(parse_qs(request.content.decode()))
            time.sleep(0.1)
            return httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "expires_in": 1800,
                },
            )

        first = self.store(handler)
        second = self.store(handler)
        write_json(first.path, tokens(expires_at=0))

        def refresh(store):
            gate.wait()
            return store.access_token()

        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(refresh, [first, second]))
        self.assertEqual(results, ["new-access", "new-access"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["username"], ["fixture-user"])
        self.assertEqual(read_json(first.path)["refresh_token"], "new-refresh")
        self.assertEqual(read_json(first.path)["userName"], "fixture-user")
        self.assertTrue(read_json(first.path)["device_registered"])

    def test_failed_refresh_does_not_destroy_tokens_or_leak_provider_body(self):
        store = self.store(
            lambda request: httpx.Response(
                400, json={"error": "invalid_grant", "error_description": "SECRET"}
            )
        )
        original = tokens(expires_at=0)
        write_json(store.path, original)
        with self.assertRaises(ConnectorError) as caught:
            store.access_token()
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertEqual(read_json(store.path), original)

    def test_refresh_response_without_rotation_preserves_refresh_token(self):
        result = normalize_tokens({"access_token": "new", "expires_in": "1800"}, tokens())
        self.assertEqual(result["refresh_token"], "fixture-refresh")
        for lifetime in (0, -1, True, float("nan"), "invalid"):
            with self.subTest(lifetime=lifetime), self.assertRaises(ConnectorError):
                normalize_tokens({"access_token": "new", "expires_in": lifetime}, tokens())

    def test_late_401_uses_already_rotated_token(self):
        store = self.store(lambda request: self.fail("Unexpected token request"))
        write_json(store.path, tokens(access_token="already-new"))
        self.assertEqual(store.access_token(rejected="older-token"), "already-new")

    def test_client_retries_401_once_with_refreshed_token(self):
        paths = []

        def handler(request):
            paths.append(request.url.path)
            if request.url.path == "/token":
                return httpx.Response(200, json={"access_token": "new", "expires_in": 1800})
            if request.headers["Authorization"] == "Bearer fixture-access":
                return httpx.Response(401)
            return httpx.Response(200, json=profile())

        store = self.store(handler)
        write_json(store.path, tokens())
        self.assertEqual(len(Client(store).children()), 2)
        self.assertEqual(paths, ["/api/v1/mobilesettings", "/token", "/api/v1/mobilesettings"])

    def test_redirects_and_cookies_are_not_followed_or_reused(self):
        calls = []

        def handler(request):
            calls.append(request)
            self.assertNotIn("cookie", request.headers)
            return httpx.Response(200, json={}, headers={"set-cookie": "session=fixture; Path=/"})

        http = self.store(handler).http
        http.json("GET", ORIGIN + "/first")
        http.json("GET", ORIGIN + "/second")
        self.assertEqual(len(calls), 2)
        redirected = self.store(
            lambda request: httpx.Response(302, headers={"location": "https://evil.invalid/"})
        )
        with self.assertRaisesRegex(ConnectorError, "redirect refused"):
            redirected.http.json("GET", ORIGIN + "/first")

    def test_lock_is_cross_process_and_released_after_exit(self):
        lock = self.directory / "test.lock"
        script = (
            "from pathlib import Path\n"
            "from skolemelding_connector.storage import locked, ConnectorError\n"
            "import sys\n"
            "try:\n"
            "    with locked(Path(sys.argv[1]), timeout=0.1): pass\n"
            "except ConnectorError:\n"
            "    sys.exit(7)\n"
        )
        with locked(lock):
            result = subprocess.run([sys.executable, "-c", script, str(lock)], check=False)
            self.assertEqual(result.returncode, 7)
        result = subprocess.run([sys.executable, "-c", script, str(lock)], check=False)
        self.assertEqual(result.returncode, 0)

    def test_private_state_rejects_symlinks_and_world_readable_files(self):
        path = self.directory / "state.json"
        write_json(path, {"test": 1})
        path.chmod(0o644)
        with self.assertRaises(ConnectorError):
            read_json(path)
        path.chmod(0o600)
        link = self.directory / "link.json"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            read_json(link)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class CollectorTests(unittest.TestCase):
    def test_mobile_child_scope_and_ambiguity(self):
        self.assertEqual(select_child(profile(), "Example")["username"], "child-id")
        ambiguous = profile()
        ambiguous["DependantUsers"][1]["DomainUser"]["Name"] = "Example Other"
        with self.assertRaises(ConnectorError):
            select_child(ambiguous, "Example")
        self.assertEqual(select_child(ambiguous, "child-id")["username"], "child-id")

    def test_pagination_redaction_and_changes(self):
        client = FixtureClient([message(index) for index in range(31)])
        client.rows[0]["Body"] = "<p>Hello Test Guardian, child-id.</p>"
        output, state = collect(client, "Example")
        self.assertEqual(output["status"], "ok")
        self.assertEqual(client.calls, [1, 2, 3])
        self.assertEqual(len(output["messages"]), 31)
        self.assertNotIn("guardian-id", json.dumps(output))
        self.assertNotIn("Test Guardian", json.dumps(output))
        self.assertNotIn("child-id", json.dumps(output))
        again, _ = collect(client, "Example", state)
        self.assertTrue(all(row["change"] == "unchanged" for row in again["messages"]))
        client.rows[0]["Body"] += "<p>Bring boots.</p>"
        changed, _ = collect(client, "Example", state)
        self.assertEqual(changed["messages"][0]["change"], "changed")
        self.assertEqual(
            changed["messages"][0]["timestamps"]["Timestamp"], client.rows[0]["Timestamp"]
        )

    def test_account_or_child_state_switch_is_rejected(self):
        client = FixtureClient()
        _, state = collect(client, "Example")
        with self.assertRaises(ConnectorError):
            collect(client, "Other", state)
        client.current_profile["DomainUser"]["UserName"] = "another-account"
        with self.assertRaises(ConnectorError):
            collect(client, "Example", state)

    def test_missing_message_scope_fails_and_other_children_are_excluded(self):
        with self.assertRaises(ConnectorError):
            collect(FixtureClient([message(OnBehalfOfList=None)]), "Example")
        output, _ = collect(FixtureClient([message(OnBehalfOfList=["other-id"])]), "Example")
        self.assertEqual(output["messages"], [])
        self.assertEqual(output["coverage"]["excludedOtherScope"], 1)

    def test_incomplete_pagination_is_explicit(self):
        client = FixtureClient()
        client.search = lambda child, page: {"Result": [message()], "TotalMatching": 2}
        output, _ = collect(client, "Example")
        self.assertEqual(output["status"], "partial")
        self.assertFalse(output["coverage"]["inboxCompleteByReportedCount"])

    def test_attachment_origins_and_encodings_are_rejected(self):
        for value in (
            "https://evil.invalid/globalassets/attachments/file.pdf",
            "https://portal.skoleplattform.no@evil.invalid/globalassets/attachments/file.pdf",
            "/globalassets/attachments/%2e%2e/file.pdf",
            "/globalassets/attachments/%252e%252e/file.pdf",
            "/globalassets/attachments/a%2fb.pdf",
            "/globalassets/attachments/file.pdf#fragment",
            "/globalassets/attachments/../../other.pdf",
        ):
            with self.subTest(value=value), self.assertRaises(ConnectorError):
                attachment_url(value)

    def test_pdf_text_and_visual_limitations(self):
        client = FixtureClient(
            [
                message(
                    Attachments=["/globalassets/attachments/synthetic.pdf"],
                    Threads=[{"Body": "<p>A reply</p>", "Attachments": []}],
                )
            ]
        )
        output, _ = collect(
            client,
            "Example",
            pdf_extractor=lambda data: {
                "pageCount": 2,
                "pages": [
                    {"page": 1, "text": "Week plan", "status": "text_extracted"},
                    {"page": 2, "text": "", "status": "image_only_or_blank"},
                ],
            },
        )
        self.assertEqual(output["status"], "partial")
        self.assertIn("incomplete_pdf_text", output["coverage"]["incompleteReasons"])
        self.assertEqual(output["messages"][0]["threads"][0]["bodyText"], "A reply")
        self.assertFalse(output["messages"][0]["attachments"][0]["visualContentChecked"])

    def test_unsupported_attachments_are_not_fetched(self):
        client = FixtureClient([message(Attachments=["https://evil.invalid/test.pdf"])])
        client.pdf = lambda *a, **k: self.fail("Unexpected download")
        output, _ = collect(client, "Example")
        self.assertEqual(output["status"], "partial")
        self.assertEqual(output["messages"][0]["attachments"][0]["status"], "unavailable")

    def test_html_is_text_not_instructions_or_active_content(self):
        self.assertEqual(
            plain_text("<p>A &amp; B</p><script>hidden</script><p>Bring boots<br>tomorrow</p>"),
            "A & B\n\nBring boots\ntomorrow",
        )


if __name__ == "__main__":
    unittest.main()
