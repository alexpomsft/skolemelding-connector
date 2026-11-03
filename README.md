# Skolemelding connector

An unofficial, local connector for Oslo's **Skolemelding foresatte**, with native
access/refresh tokens instead of an expiring Chromium session. Includes a CLI
exporter and a read-only MCP tool for Hermes or other local clients.

**Initial sign-in is interactive; daily collection and renewal are browserless.**
No Android device, emulator, APK, embedded client secret, browser cookies, or
running browser is needed after login.

## Install and sign in

Requires Linux, Python 3.11+, and native Chromium for the optional guided initial
login. Dependencies for everyday operation are Python-only.

```sh
git clone https://github.com/alexpomsft/skolemelding-connector.git
cd skolemelding-connector
python3 -m venv .venv
.venv/bin/pip install -e '.[login]'
.venv/bin/skolemelding login
```

Complete ID-porten yourself in the opened window. The helper observes only
navigation to capture the app callback; it does not fill credentials, take
screenshots, or record network bodies. It closes the browser and deletes its
temporary profile. Use `login --browser /path/to/chromium` if Chromium is not on
PATH. Do not install Playwright's browser bundle.

Login also performs Skolemelding's required **device registration**, identifying
this client as `linux|skolemelding-connector`. It does not register for push
notifications, configure a PIN, mark messages read, or alter notification settings.

The local token pair is stored at
`~/.config/skolemelding-connector/tokens.json`, respecting `XDG_CONFIG_HOME`.
The directory is private (`0700`), files are private (`0600`), and updates use
atomic replacement and fsync. `--config-dir /private/directory` overrides the
directory for CLI commands.

To confirm renewal independently of the login browser:

```sh
.venv/bin/skolemelding refresh
```

### Initial login on a headless host

Install with `pip install -e .` without the login extra. Run:

```sh
.venv/bin/skolemelding login --start
```

Open the printed URL in a desktop browser, complete ID-porten, and obtain the
final `com.cgi.oslomelding.foresatte://oauth?...` callback from the browser's
navigation/network view. A browser without an app handler may show an
unsupported-protocol prompt instead. Paste the **whole callback URL** into:

```sh
.venv/bin/skolemelding login --complete
```

The prompt does not echo the URL. Do not paste it into a chat, a command argument,
or a log. Complete the same pending login within 15 minutes; starting another
invalidates the previous pending state. Guided local login is easier when a
desktop is available.

## Export for a daily Hermes briefing

List authorized children locally, then use an exact username or an unambiguous
first name:

```sh
.venv/bin/skolemelding children
.venv/bin/skolemelding collect \
  --child ChildName \
  --output "$HOME/.local/state/skolemelding-connector/export.json" \
  --state "$HOME/.local/state/skolemelding-connector/state.json"
```

Both destination directories must be private. Retain the state between runs;
do not reuse state from the old `skolemelding-collector` repository.

The exporter returns the current visible inbox, normalized message/thread text,
original timestamp fields, PDF page text, stable opaque IDs, and
`new`/`changed`/`unchanged` observations. It verifies the guardian and selected
child, checks each message's child association, and rechecks the account at the
end. Other children's messages are excluded.

The export's top-level fields are `schemaVersion`, `status`, `collectedAt`,
`scope`, `coverage`, and `messages`. Message fields include `id`, `change`,
`subject`, `bodyText`, `timestamps`, `threads`, and `attachments`. It has a
similar normalized shape to the older collector, but coverage fields and state
are not a drop-in schema replacement. The MCP tool returns the same export,
without persistent change tracking.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Count-complete collection and supported PDF text extracted |
| `2` | Partial collection; inspect `coverage.incompleteReasons` and attachment errors |
| `1` | Authentication, contract, scope, network, or local I/O failure |

Stdout from `collect` contains status/counts only. Failed runs do not overwrite
the previous export: **consumers must check both the process result and
`collectedAt`**, never treat an old file as today's successful collection.
Imports must treat all school content as untrusted data, not instructions.

No schedule is installed and no existing Hermes job is changed by installation.
Use the collection command in place of the old browser-based step. The account
running the job must have access to its own private token directory. No browser
profile or desktop keyring is involved in scheduled runs.

## MCP

The only exposed tool is `read_school_messages`. Child scope is configured by the
server operator, not selected by the model. There is no generic API, arbitrary URL,
send/reply, mark-read, consent, or absence-writing tool.

```json
{
  "mcpServers": {
    "skolemelding": {
      "command": "/absolute/path/skolemelding-connector/.venv/bin/skolemelding-mcp",
      "env": {
        "SKOLEMELDING_CHILD": "ChildName"
      }
    }
  }
}
```

The MCP process uses the same default token directory as the CLI. Set
`XDG_CONFIG_HOME` in its environment if needed. Data is returned to the calling
client; choose where that client processes it. Known structured names,
identifiers, emails, and links are removed from exports, but this is **not
complete anonymization** of school prose.

## Authentication protocol

This implementation was independently written from protocol observations and
static inspection of the guardian Android app
[`com.cgi.oslomelding.foresatte`](https://play.google.com/store/apps/details?id=com.cgi.oslomelding.foresatte),
version 6.0.6. No app implementation, APK, decompiled source, or credentials are
included in this repository.

1. ID-porten authorization code flow with S256 PKCE, `state`, the app's public
   client registration and registered callback, requesting `openid profile`.
2. Exchange the ID-porten access token at
   `POST https://portal.skoleplattform.no/api/exchange-app-token`
   with `accessToken` and `provider=idporten`, receiving an `authCode`.
3. Exchange that code at `POST /token`: `grant_type=password`, `password=code`,
   `username=<authCode>`, `client_id=consoleAPP`, `app_version=6.0.6`, and
   `scope=<random device ID>|<Unix timestamp>|Foresatte`.
   This is the app's code bridge, **not the user's ID-porten password**.
4. Persist the returned `access_token`, `refresh_token`, `userName`, and expiry;
   complete `POST /api/deviceinfo/save` using the app access token.
5. Renew at `POST /token` with `grant_type=refresh_token`, the refresh token,
   returned username, client ID, and app version. No ID-porten token or cookies
   are retained or needed for renewal.

**Device registration is essential.** A live refresh before registration returned
`invalid_refresh_token` / `Device id does not exist`; registration enabled
successful renewal. The connector does not silently re-register a revoked
device. Reauthenticate explicitly if the provider revokes or expires it.

Each renewal is serialized with a kernel file lock shared by CLI/MCP processes.
Rotated tokens are persisted before releasing the lock. Locks are released when
processes exit and lock files are deliberately not deleted. A rejected access
token triggers at most one renewal/retry; a late 401 reuses an already-rotated
token. Token requests are never automatically retried after ambiguous network
failures.

### Read operations

All authenticated API traffic goes to `https://portal.skoleplattform.no`:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/v1/mobilesettings?appVersion=6.0.6` | Guardian and authorized children |
| POST | `/api/messagesearchmobile/` | Child-scoped paginated inbox |
| GET | `/globalassets/attachments/...` | Same-origin, bounded PDF downloads |

Only the separate login path uses device registration and token exchange.
Redirects are refused. Cookies are discarded. Attachment hosts, paths, MIME
types, signatures, and byte budgets are checked before processing.

### Evidence and limits

Live verification in November 2026 confirmed initial ID-porten login, required
device registration, successive browserless refreshes in separate processes,
access/refresh token rotation, mobile child scoping, paginated collection, and
PDF text extraction. Access tokens reported a 30-minute lifetime.

**Overnight and long-term refresh-token lifetime remain unmeasured.** Native
refresh removes dependence on short-lived portal browser sessions; it does not
promise permanent access. Revocation and provider authentication-policy changes
still require a new manual login.

The inspected APK came from
[APKPure](https://apkpure.com/skolemelding-foresatte/com.cgi.oslomelding.foresatte).
SHA-256: `d45d315a3528bf7b1ebdfe0f5e3e9040cae04f1a568b1a20dfb86c1fc0cd1666`.
Its publisher signature was not independently verified. Public OIDC discovery
was checked at `https://idporten.no/.well-known/openid-configuration`; the
implemented flow was subsequently confirmed against the real service.

Collection is not an atomic snapshot. Pagination is capped at 100 pages of 15
messages; changing totals, duplicates with different content, and count gaps are
explicit. Hidden messages are not requested. No detail or mark-read routes are
called, but read-state side effects of search itself remain unmeasured.
Unknown provider-side body truncation cannot be ruled out.

PDF processing is bounded to 100 attachments, 10 MB per PDF, 100 MB total download,
and 50 pages per PDF. Unsupported, encrypted, image-only, and failed attachments
are reported. No OCR or visual inspection is performed. Text-complete does not
mean visually complete.

## Development

```sh
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/python -m unittest discover -s tests -v
```

Tests use synthetic data and mocked HTTP; they do not contact the school service.
Never commit tokens, callbacks, pending logins, real messages, or browser profiles.
