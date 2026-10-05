"""Supervised, credential-pipe-only IMAP/SMTP process. No automatic network retry."""

import base64
from datetime import date
from email import policy as mime_policy
from email.parser import BytesParser
from html.parser import HTMLParser
import imaplib
import json
from pathlib import Path
import re
import resource
import smtplib
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import MailError, encoded, fail, integer, line


class LiteralBound:
    def read(self, size):
        if size < 0 or size > self.literal_limit:
            fail("The IMAP server announced an oversized message literal.", "size")
        return super().read(size)


class SafeIMAPSSL(LiteralBound, imaplib.IMAP4_SSL):
    pass


class SafeIMAP(LiteralBound, imaplib.IMAP4):
    pass


def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def tls(config):
    context = ssl.create_default_context(cafile=config["ca_file"] or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden, self.parts = 0, []
    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"br", "p", "div", "li"}:
            self.parts.append("\n")
    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)
    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def parsed_message(raw, config, *, complete):
    message = BytesParser(policy=mime_policy.default).parsebytes(raw)
    result = {"from": str(message.get("From", ""))[:2048], "to": str(message.get("To", ""))[:2048],
        "subject": str(message.get("Subject", ""))[:2048], "date": str(message.get("Date", ""))[:256],
        "message_id": str(message.get("Message-ID", ""))[:512], "untrusted_content": True}
    if not complete:
        return result
    parts = []
    for part in message.walk():
        if len(parts) >= 200:
            fail("Message MIME structure exceeds 200 parts.", "size")
        parts.append(part)
    text_part = message.get_body(preferencelist=("plain", "html"))
    text, is_html = "", False
    if text_part is not None:
        data = text_part.get_payload(decode=True) or b""
        try:
            text = data.decode(text_part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
        is_html = text_part.get_content_type() == "text/html"
        if is_html:
            parser = HTMLText(); parser.feed(text); text = "".join(parser.parts)
    result.update(body=text[:config["max_body_chars"]], body_truncated=len(text) > config["max_body_chars"],
                  body_source="html_text_only" if is_html else "plain", attachments=[])
    attachment_bytes = 0
    for part in parts:
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        if len(result["attachments"]) >= config["max_attachments"]:
            fail("Message exceeds the configured attachment count.", "size")
        data = part.get_payload(decode=True)
        if data is None:
            fail("An embedded multipart attachment cannot be extracted in this version.", "format")
        attachment_bytes += len(data)
        if attachment_bytes > config["max_message_bytes"]:
            fail("Decoded attachments exceed the byte limit.", "size")
        result["attachments"].append({"filename": str(filename or "attachment")[:255],
            "content_type": part.get_content_type(), "bytes": len(data),
            **({"data": base64.b64encode(data).decode()} if config["extract_attachments"] else {})})
    return result


def read_mail(job):
    config, account, query = job["config"], job["account"], job["request"]
    client = None
    try:
        klass = SafeIMAPSSL if config["imap_tls"] == "ssl" else SafeIMAP
        # The limit is needed during constructor greeting/capability parsing too.
        klass.literal_limit = config["max_message_bytes"]
        options = {"timeout": config["timeout_sec"]}
        if config["imap_tls"] == "ssl":
            options["ssl_context"] = tls(config)
        client = klass(config["imap_host"], config["imap_port"], **options)
        if config["imap_tls"] == "starttls":
            client.starttls(ssl_context=tls(config))
        client.login(account["username"], account["password"])
        status, _ = client.select(quote(config["mailbox"]), readonly=True)
        if status != "OK":
            fail("The configured mailbox is unavailable.", "imap")
        def metadata(name):
            _, values = client.response(name)
            if not values or not values[0] or not re.fullmatch(rb"[0-9]{1,10}", values[0]):
                fail("The mailbox did not return stable UID metadata.", "imap")
            return integer(int(values[0]), 1, 4294967295)
        validity, next_uid = metadata("UIDVALIDITY"), metadata("UIDNEXT")
        if query.get("uidvalidity", validity) != validity:
            fail("Mailbox UIDVALIDITY changed; start a new search instead of reusing this cursor.", "conflict")
        if query["operation"] == "read":
            chosen = [query["uid"]]
            window = None
        else:
            start = query.get("after_uid", max(0, next_uid - 1 - config["max_scan_uids"])) + 1
            end = min(next_uid - 1, start + config["max_scan_uids"] - 1)
            if start > end:
                return {"uidvalidity": validity, "mailbox": config["mailbox"], "items": [], "scan_complete": True, "next_after_uid": max(0, next_uid - 1)}
            criteria = ["UID", f"{start}:{end}"]
            if query.get("unseen"):
                criteria.append("UNSEEN")
            for key in ("from", "subject"):
                if query.get(key):
                    criteria.extend([key.upper(), quote(query[key]).encode("utf-8")])
            if query.get("since"):
                when = date.fromisoformat(query["since"])
                month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[when.month - 1]
                criteria.extend(["SINCE", f"{when.day:02}-{month}-{when.year:04}"])
            status, rows = client.uid("SEARCH", "CHARSET", "UTF-8", *criteria)
            if status != "OK" or len(rows) != 1 or not isinstance(rows[0], bytes) or len(rows[0]) > 65536:
                fail("The bounded IMAP search was refused or returned an invalid result.", "imap")
            tokens = rows[0].split()
            if len(tokens) > config["max_scan_uids"] or any(not re.fullmatch(rb"[0-9]{1,10}", item) for item in tokens):
                fail("The IMAP search returned too many or invalid UIDs.", "imap")
            found = sorted({int(item) for item in tokens})
            if any(not start <= item <= end for item in found):
                fail("The IMAP server returned a UID outside the requested window.", "imap")
            chosen = found[:config["max_messages"]]
            cursor = chosen[-1] if len(found) > len(chosen) else end
            window = {"first_uid": start, "last_uid": end, "next_after_uid": cursor, "scan_complete": cursor >= next_uid - 1}
        result = {"uidvalidity": validity, "mailbox": config["mailbox"], "items": [], **(window or {})}
        for uid in chosen:
            complete = query["operation"] == "read"
            selector = "(UID RFC822.SIZE BODY.PEEK[])" if complete else "(UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])"
            status, rows = client.uid("FETCH", str(uid), selector)
            literals = [row for row in rows if isinstance(row, tuple)]
            if status != "OK" or len(literals) != 1 or not isinstance(literals[0][1], bytes):
                fail("The requested message disappeared or returned an invalid literal.", "imap")
            header, raw = literals[0]
            received_uid = re.search(rb"\bUID ([0-9]+)\b", header)
            size = re.search(rb"\bRFC822.SIZE ([0-9]+)\b", header)
            if not received_uid or int(received_uid[1]) != uid or not size:
                fail("The IMAP response does not match the requested UID.", "imap")
            if len(raw) > config["max_message_bytes"]:
                fail("Message exceeds the configured byte limit.", "size")
            result["items"].append({"uid": uid, "bytes": int(size[1]), **parsed_message(raw, config, complete=complete)})
        return result
    finally:
        if client is not None:
            try:
                client.shutdown()  # No CLOSE/EXPUNGE/STORE: this is read-only access.
            except Exception:
                pass


def send_mail(job):
    config, account = job["config"], job["account"]
    wire = base64.b64decode(job["wire"], validate=True)
    if len(wire) > config["max_message_bytes"]:
        fail("Prepared MIME message exceeds the configured byte limit.", "size")
    client, started_data = None, False
    try:
        if config["smtp_tls"] == "ssl":
            client = smtplib.SMTP_SSL(config["smtp_host"], config["smtp_port"], timeout=config["timeout_sec"], context=tls(config))
        else:
            client = smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=config["timeout_sec"])
            client.ehlo(); client.starttls(context=tls(config))
        code, _ = client.ehlo()
        if code != 250:
            fail("SMTP EHLO was refused.", "smtp")
        client.login(account["username"], account["password"])
        code, _ = client.mail(job["sender"])
        if code != 250:
            fail("SMTP rejected the approved sender.", "smtp_rejected")
        refused = []
        for recipient in job["recipients"]:
            code, _ = client.rcpt(recipient)
            if code not in (250, 251):
                refused.append(recipient)
        if refused:
            client.rset()
            fail("SMTP rejected at least one approved recipient; DATA was not sent to anyone.", "smtp_rejected")
        started_data = True
        code, reply = client.data(wire)
        if code != 250:
            raise MailError("smtp_rejected", "SMTP did not confirm message acceptance.", uncertain=not 400 <= code <= 599)
        safe_reply = reply.decode("utf-8", errors="replace")[:512]
        for secret in account.values():
            safe_reply = safe_reply.replace(secret, "[REDACTED]")
        return {"status": "accepted", "smtp_code": code, "smtp_reply": safe_reply}
    except smtplib.SMTPDataError:
        fail("SMTP refused DATA before accepting message content.", "smtp_rejected")
    except MailError:
        raise
    except Exception:
        raise MailError("smtp", "SMTP exchange failed; no automatic retry was attempted.", uncertain=started_data) from None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass  # An accepted DATA reply must not be undone by socket cleanup.


def main():
    try:
        job = json.loads(sys.stdin.buffer.read(33554433))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        limit = job["config"]["timeout_sec"] + 2
        resource.setrlimit(resource.RLIMIT_CPU, (limit, limit + 1))
        data = send_mail(job) if job["operation"] == "send" else read_mail(job)
        print(encoded({"ok": True, "data": data}, 33554432))
    except MailError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "detail": str(exc), "uncertain": exc.uncertain}))
    except Exception:
        print(json.dumps({"ok": False, "code": "mail", "detail": "Mail exchange failed; check TLS, credentials and server capabilities.", "uncertain": False}))


if __name__ == "__main__":
    main()
