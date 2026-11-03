import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .client import attachment_url, select_child
from .storage import ConnectorError


def digest(value):
    data = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    )
    return hashlib.sha256(data).hexdigest()


class TextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "iframe", "object"}:
            self.hidden += 1
        elif tag in {"p", "div", "br", "li", "tr", "h1", "h2", "h3"} and not self.hidden:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "iframe", "object"}:
            self.hidden = max(0, self.hidden - 1)
        elif tag in {"p", "div", "li", "tr"} and not self.hidden:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def plain_text(html):
    if not isinstance(html, str):
        raise ConnectorError("Message body is not text.")
    parser = TextParser()
    parser.feed(html)
    return re.sub(r"\n{3,}", "\n\n", "".join(parser.parts)).replace("\xa0", " ").strip()


def redactor(profile):
    values = []
    for record in [
        profile["DomainUser"],
        *(entry["DomainUser"] for entry in profile["DependantUsers"]),
    ]:
        for key in ("UserName", "Name", "Email", "MobilePhone", "Upn"):
            value = record.get(key)
            if isinstance(value, str) and len(value) > 2:
                values.append(value)
    pattern = (
        re.compile(
            r"(?<!\w)(?:"
            + "|".join(re.escape(v) for v in sorted(set(values), key=len, reverse=True))
            + r")(?!\w)",
            re.I,
        )
        if values
        else None
    )

    def redact(text):
        if pattern:
            text = pattern.sub("[redacted]", text)
        text = re.sub(r"https?://[^\s<>\"']+", "[link omitted]", text)
        return re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]+\b", "[redacted]", text, flags=re.I)

    return redact


def extract_pdf(content):
    try:
        reader = PdfReader(io.BytesIO(content))
        if reader.is_encrypted:
            raise ConnectorError("PDF is encrypted.")
        pages = []
        for index, page in enumerate(reader.pages[:50], start=1):
            text = page.extract_text() or ""
            if len(text) > 200_000:
                raise ConnectorError("PDF page text exceeds the size limit.")
            pages.append(
                {
                    "page": index,
                    "text": text.strip(),
                    "status": "text_extracted" if text.strip() else "image_only_or_blank",
                }
            )
        return {"pageCount": len(reader.pages), "pages": pages}
    except (PdfReadError, ValueError, RecursionError):
        raise ConnectorError("PDF text extraction failed.") from None


def collect(client, selector, previous=None, pdf_extractor=extract_pdf):
    profile = client.profile()
    child = select_child(profile, selector)
    child_id = child["username"]
    previous = previous or {}
    if previous and (
        previous.get("schemaVersion") != 1
        or not isinstance(previous.get("namespace"), str)
        or not isinstance(previous.get("fingerprints"), dict)
    ):
        raise ConnectorError("Unsupported collector state.")
    namespace = previous.get("namespace", str(uuid.uuid4()))
    account = profile["DomainUser"].get("UserName")
    if not isinstance(account, str) or not account:
        raise ConnectorError("Guardian identity is missing from profile.")
    scope_hash = digest([namespace, account, child_id])
    if previous and previous.get("scopeHash") != scope_hash:
        raise ConnectorError("Account or child differs from the saved collector state.")
    rows = {}
    totals = []
    reasons = set()
    duplicate_count = 0
    reached_end = False
    for page in range(1, 101):
        result = client.search(child_id, page)
        batch, total = result.get("Result"), result.get("TotalMatching")
        if not isinstance(batch, list) or len(batch) > 15 or type(total) is not int or total < 0:
            raise ConnectorError("Mobile search response contract changed.")
        totals.append(total)
        for message in batch:
            if not isinstance(message, dict):
                raise ConnectorError("Invalid message record.")
            identity = message.get("Id")
            if type(identity) not in (str, int) or not str(identity):
                raise ConnectorError("Message identity is missing.")
            key = str(identity)
            if key in rows:
                duplicate_count += 1
                if rows[key] != message:
                    reasons.add("content_changed_during_pagination")
            rows[key] = message
        if len(batch) < 15 or len(rows) >= total:
            reached_end = True
            break
    if not reached_end:
        reasons.add("pagination_limit")
    if len(set(totals)) != 1:
        reasons.add("reported_total_changed")
    if len(rows) != totals[-1]:
        reasons.add("unique_count_differs_from_reported_total")
    redact = redactor(profile)
    messages = []
    fingerprints = {}
    attachment_count = 0
    attachment_bytes = 0
    image_count = 0
    excluded = 0
    thread_count = 0

    def attachments(paths):
        nonlocal attachment_count, attachment_bytes
        if not isinstance(paths, list):
            raise ConnectorError("Attachment list contract changed.")
        normalized = []
        for index, path in enumerate(paths):
            item = {"index": index, "text": None, "textCoverageComplete": False}
            normalized.append(item)
            attachment_count += 1
            try:
                safe = attachment_url(path)
                if not safe.split("?")[0].lower().endswith(".pdf"):
                    raise ConnectorError("Unsupported attachment type.")
                if attachment_count > 100 or attachment_bytes >= 100_000_000:
                    raise ConnectorError("Attachment budget exhausted.")
                data = client.pdf(safe, limit=min(10_000_000, 100_000_000 - attachment_bytes))
                attachment_bytes += len(data)
                extracted = pdf_extractor(data)
                item["contentHash"] = digest(data)
                item["pageCount"] = extracted["pageCount"]
                item["pages"] = [
                    {**page, "text": redact(page["text"])} for page in extracted["pages"]
                ]
                item["text"] = "\n\n".join(page["text"] for page in item["pages"])
                complete = (
                    len(item["pages"]) == item["pageCount"]
                    and item["pageCount"] > 0
                    and all(page["text"] for page in item["pages"])
                )
                item["textCoverageComplete"] = complete
                item["status"] = (
                    "text_extracted_visual_unverified" if complete else "partial_text_coverage"
                )
                item["visualContentChecked"] = False
                item["ocrPerformed"] = False
                if not complete:
                    reasons.add("incomplete_pdf_text")
            except ConnectorError as error:
                item["status"] = "unavailable"
                item["error"] = str(error)
                reasons.add("attachment_unavailable")
        return normalized

    def timestamps(record):
        found = {}
        for key, value in record.items():
            if (
                re.fullmatch(
                    r"Timestamp|Published|UnPublished|"
                    r"(Created|Updated|Modified|LastModified|LastUpdated|Publication|Publish)"
                    r"(At|On|Date|Time|Timestamp)?",
                    key,
                )
                and value is not None
            ):
                if not isinstance(value, str):
                    raise ConnectorError("Message timestamp contract changed.")
                found[key] = value
        return found

    def thread(record, depth=0):
        nonlocal thread_count, image_count
        thread_count += 1
        if depth > 6 or thread_count > 2000 or not isinstance(record, dict):
            raise ConnectorError("Message thread structure exceeds supported limits.")
        body = record.get("Body")
        if body is None:
            reasons.add("unrecognized_thread_content")
        elif not isinstance(body, str):
            raise ConnectorError("Invalid thread body.")
        image_count += len(re.findall(r"<img\b", body or "", re.I))
        children = []
        for key in ("Threads", "Replies", "Messages"):
            nested = record.get(key, [])
            if not isinstance(nested, list):
                raise ConnectorError("Invalid nested thread list.")
            children.extend(thread(value, depth + 1) for value in nested)
        return {
            "bodyText": redact(plain_text(body)) if body is not None else None,
            "timestamps": timestamps(record),
            "attachments": attachments(record.get("Attachments", [])),
            "children": children,
        }

    for key, message in rows.items():
        scope = message.get("OnBehalfOfList")
        if not isinstance(scope, list):
            raise ConnectorError("Message child scope is missing.")
        if child_id not in scope:
            excluded += 1
            continue
        if (
            not isinstance(message.get("Header"), str)
            or not isinstance(message.get("Body"), str)
            or not isinstance(message.get("Attachments"), list)
            or not isinstance(message.get("Threads"), list)
        ):
            raise ConnectorError("Message content contract changed.")
        content = thread(message)
        content["threads"] = content.pop("children")
        content["subject"] = redact(plain_text(message["Header"]))
        identity = "m_" + digest([namespace, key])[:24]
        fingerprint = digest(content)
        old = previous.get("fingerprints", {}).get(identity)
        content["id"] = identity
        content["change"] = (
            "new" if old is None else "unchanged" if old == fingerprint else "changed"
        )
        fingerprints[identity] = fingerprint
        messages.append(content)
    final = client.profile()
    if (
        final["DomainUser"].get("UserName") != account
        or select_child(final, child_id)["username"] != child_id
    ):
        raise ConnectorError("Account or child changed during collection.")
    now = datetime.now(timezone.utc).isoformat()
    state = {
        "schemaVersion": 1,
        "namespace": namespace,
        "scopeHash": scope_hash,
        "fingerprints": fingerprints,
        "firstVerifiedAt": previous.get("firstVerifiedAt", now),
        "lastVerifiedAt": now,
    }
    output = {
        "schemaVersion": 1,
        "status": "partial" if reasons else "ok",
        "collectedAt": now,
        "scope": {"guardianVerified": True, "intendedChildVerified": True},
        "coverage": {
            "inboxCompleteByReportedCount": reached_end
            and len(set(totals)) == 1
            and len(rows) == totals[-1],
            "pagesFetched": len(totals),
            "reportedTotals": totals,
            "uniqueInboxMessages": len(rows),
            "relevantMessages": len(messages),
            "excludedOtherScope": excluded,
            "duplicateRows": duplicate_count,
            "incompleteReasons": sorted(reasons),
            "attachmentIndicators": attachment_count,
            "attachmentBytes": attachment_bytes,
            "inlineImageIndicators": image_count,
            "limitations": [
                "non_atomic_paginated_snapshot",
                "unknown_provider_body_truncation",
                "unknown_unread_read_state_effects",
                "hidden_messages_not_requested",
                "visual_content_not_checked",
                "no_ocr",
                "automatic_redaction_not_complete_anonymization",
            ],
        },
        "messages": messages,
    }
    return output, state
