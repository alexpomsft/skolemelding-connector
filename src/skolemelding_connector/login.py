import shutil
import tempfile
import time
from pathlib import Path

from .auth import REDIRECT_URI
from .storage import ConnectorError


def browser_login(store, executable=None):
    try:
        from playwright.sync_api import Error as BrowserError
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ConnectorError("Install the login extra: pip install -e '.[login]'.") from None
    executable = executable or shutil.which("chromium") or shutil.which("google-chrome")
    if not executable:
        raise ConnectorError("Chromium was not found; supply --browser or use login --start.")
    url = store.begin_login()
    callback = []

    def navigation(event):
        target = event.get("url", "")
        if target.startswith(REDIRECT_URI):
            callback.append(target)

    with tempfile.TemporaryDirectory(prefix="skolemelding-login-") as directory:
        Path(directory).chmod(0o700)
        try:
            with sync_playwright() as playwright:
                context = playwright.chromium.launch_persistent_context(
                    directory, executable_path=executable, headless=False
                )
                try:
                    page = context.pages[0]
                    session = context.new_cdp_session(page)
                    session.send("Page.enable")
                    session.send("Network.enable")
                    session.on("Page.frameRequestedNavigation", navigation)
                    session.on("Network.requestWillBeSent", lambda e: navigation(e["request"]))
                    page.goto(url, wait_until="domcontentloaded")
                    print(
                        "Complete ID-porten in the opened window. No credentials are recorded.",
                        flush=True,
                    )
                    deadline = time.monotonic() + 900
                    while not callback and time.monotonic() < deadline:
                        if page.is_closed():
                            raise ConnectorError("Login window was closed before completion.")
                        page.wait_for_timeout(200)
                    if not callback:
                        raise ConnectorError("Login timed out; run `skolemelding login` again.")
                finally:
                    context.close()
        except BrowserError:
            raise ConnectorError("Login browser failed or was closed; sign in again.") from None
    store.complete_login(callback[0])
