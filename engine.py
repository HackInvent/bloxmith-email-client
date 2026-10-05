"""Per-node durable drafts, immutable MIME and no-retry mail execution."""

import base64
from datetime import date
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

from . import policy
from .policy import MailError, fail


def network(job, cancel):
    if cancel():
        raise MailError("cancelled", "Mail operation cancelled before starting.")
    raw = policy.encoded(job, 33554432).encode()
    try:
        child = subprocess.Popen([sys.executable, "-I", "-B", "-u", str(Path(__file__).with_name("mail_worker.py"))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"})
    except OSError:
        raise MailError("worker", "The mail process could not start; nothing was sent.") from None
    deadline, sending = time.monotonic() + job["config"]["timeout_sec"], job["operation"] == "send"
    try:
        first = True
        while True:
            if cancel() or time.monotonic() >= deadline:
                raise MailError("cancelled" if cancel() else "timeout", "Mail operation interrupted; no automatic retry.", uncertain=sending)
            try:
                output, _ = child.communicate(input=raw if first else None, timeout=min(.1, max(.001, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                first = False
        if child.returncode or len(output) > 33554432:
            raise MailError("worker", "The mail process did not return a complete bounded result.", uncertain=sending)
        try:
            result = policy.document(output.decode("utf-8"), 33554432)
        except (ValueError, UnicodeError):
            raise MailError("worker", "The mail process returned an invalid outcome.", uncertain=sending) from None
        if result.get("ok") is not True:
            raise MailError(str(result.get("code", "mail"))[:64], str(result.get("detail", "Mail exchange failed."))[:1024],
                            uncertain=bool(result.get("uncertain", sending)))
        if not isinstance(result.get("data"), dict):
            raise MailError("worker", "The mail process returned no structured outcome.", uncertain=sending)
        return result["data"]
    except (OSError, subprocess.SubprocessError):
        raise MailError("worker", "Mail process communication was interrupted; no automatic retry.", uncertain=sending) from None
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.communicate(timeout=.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=2)


def read_file(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail("Attachments must be bounded ordinary files.", "file")
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(content) > maximum or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            fail("The file changed while it was copied or exceeds the byte limit.", "file")
        return content


def put_file(path, content):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content); stream.flush(); os.fsync(stream.fileno())


def quota(directory, added, config):
    total = 0
    for parent, folders, names in os.walk(directory, followlinks=False):
        if any((Path(parent) / name).is_symlink() for name in folders):
            fail("Unexpected symbolic link in private mail storage.", "storage")
        for name in names:
            item = Path(parent) / name
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode) or item.is_symlink():
                fail("Unexpected file type in private mail storage.", "storage")
            total += info.st_size
            if total + added > config["max_storage_bytes"]:
                fail("Private mail storage limit reached; no files or deduplication history were deleted.", "storage")


def account_job(context, config, operation, request):
    prefix = "smtp" if operation == "send" else "imap"
    if not config[prefix + "_host"]:
        fail("Configure the " + prefix.upper() + " server first.")
    return {"config": config, "operation": operation, "request": request,
            "account": policy.credentials(context, config[prefix + "_secret_ref"])}


def approved_recipients(message, config):
    result = {}
    allowed = set(config["allowed_recipients"])
    for field in ("to", "cc", "bcc"):
        values = message.get(field, [])
        if not isinstance(values, (list, tuple)) or len(values) > 50:
            fail("Recipients require arrays of at most 50 exact addresses.")
        result[field] = [policy.address(value) for value in values]
    combined = result["to"] + result["cc"] + result["bcc"]
    if not combined or len(combined) > 50 or len(set(combined)) != len(combined):
        fail("Specify 1–50 distinct recipients across To, Cc and Bcc.")
    if set(combined) - allowed:
        fail("A recipient is outside the configured exact-address allowlist.", "scope")
    return result


def draft(request, config, storage):
    if not config["sender"] or not config["smtp_host"] or not config["smtp_secret_ref"]:
        fail("Configure sender, SMTP host and wallet reference before preparing a bound draft.")
    recipients = approved_recipients(request, config)
    subject = policy.line(request.get("subject"), 998)
    body = request.get("body")
    if not isinstance(body, str) or not body.strip() or len(body) > config["max_body_chars"] or "\x00" in body:
        fail("Draft body must be nonempty bounded plain text.")
    attachments = request.get("attachments", [])
    if not isinstance(attachments, list) or len(attachments) > config["max_attachments"]:
        fail("Too many attachments or invalid attachment list.")
    content, total = [], 0
    if attachments:
        if not config["attachment_root"]:
            fail("Configure an attachment directory before attaching local files.", "file")
        root = Path(config["attachment_root"]).expanduser().resolve(strict=True)
        if not root.is_dir() or root == Path(root.anchor):
            fail("Use a dedicated attachment directory, not a filesystem root.", "file")
        for name in attachments:
            name = policy.line(name, 4096)
            candidate = Path(name).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            if candidate.is_symlink():
                fail("Attachment symbolic links are not accepted.", "file")
            path = candidate.resolve(strict=True)
            if not path.is_relative_to(root):
                fail("Attachment path escapes the permitted directory.", "file")
            data = read_file(path, config["max_message_bytes"] - total)
            total += len(data)
            filename = policy.line(path.name, 255)
            content.append((filename, data))
    stamp = uuid.uuid4().hex
    message_id = "<" + stamp + "@" + config["sender"].split("@", 1)[1] + ">"
    message = EmailMessage(policy=SMTP)
    message["From"], message["Subject"], message["Message-ID"] = config["sender"], subject, message_id
    message["Date"] = formatdate(localtime=False, usegmt=True)
    for field in ("to", "cc"):
        if recipients[field]:
            message[field.title()] = ", ".join(recipients[field])
    message.set_content(body)
    for filename, data in content:
        message.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    wire = message.as_bytes()
    if len(wire) > config["max_message_bytes"]:
        fail("Encoded MIME message exceeds the byte limit, including attachments.", "size")
    quota(storage, len(wire) + total + 131072, config)
    directory = storage / ("draft-" + stamp)
    directory.mkdir(mode=0o700)
    wire_path = directory / "message.eml"
    put_file(wire_path, wire)
    previews = []
    for number, (filename, data) in enumerate(content, 1):
        copy = directory / f"attachment-{number:03}.bin"
        put_file(copy, data)
        previews.append({"filename": filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "path": str(copy)})
    preview = {"request_id": request["request_id"], "draft_id": stamp, "message_id": message_id,
               "sender": config["sender"], **recipients, "subject": subject, "body": body,
               "attachments": previews, "target": policy.target(config), "mime_sha256": hashlib.sha256(wire).hexdigest(),
               "message_path": str(wire_path), "expires_at": int(time.time()) + config["draft_lifetime_sec"]}
    preview["revision"] = policy.digest(preview)
    return preview


def request_data(raw, port, config):
    value = policy.document(raw)
    policy.identifier(value.get("request_id"))
    if port == "decision":
        if set(value) != {"request_id", "draft_id", "revision", "decision"} or value["decision"] not in ("approve", "reject"):
            fail("Decision requires the exact request_id, draft_id, revision and approve/reject value.")
        for key in ("draft_id", "revision"):
            if not isinstance(value[key], str) or not re_match_hex(value[key], 32 if key == "draft_id" else 64):
                fail("Invalid draft identifier or revision.")
        return value
    operation = value.get("operation")
    fields = {"draft": {"to", "cc", "bcc", "subject", "body", "attachments"},
              "search": {"after_uid", "uidvalidity", "unseen", "since", "from", "subject"},
              "read": {"uid", "uidvalidity"}, "status": set()}
    if not isinstance(operation, str) or operation not in fields or set(value) - {"request_id", "operation"} - fields[operation]:
        fail("Unknown operation or extra request fields.")
    if operation in {"search", "read"}:
        for name in ("uid", "uidvalidity", "after_uid"):
            if name in value:
                policy.integer(value[name], 0 if name == "after_uid" else 1, 4294967295)
        if operation == "read" and not {"uid", "uidvalidity"} <= set(value):
            fail("Read requires a UID and its mailbox UIDVALIDITY from a search.")
        if "after_uid" in value and "uidvalidity" not in value:
            fail("A search cursor requires its UIDVALIDITY.")
        if "unseen" in value and type(value["unseen"]) is not bool:
            fail("unseen must be a boolean.")
        if "since" in value:
            date.fromisoformat(policy.line(value["since"], 10))
        for key in ("subject", "from"):
            if key in value:
                value[key] = policy.line(value[key], 254)
    return value


def re_match_hex(value, length):
    return len(value) == length and all(char in "0123456789abcdef" for char in value)


def receipt(record, duplicate=False):
    phase = "uncertain" if record["phase"] == "sending" else record["phase"]
    if phase in {"reading", "preparing"}:
        phase = "interrupted"
    return {"request_id": record["request_id"], "status": phase, "uncertain": phase == "uncertain",
            "duplicate": duplicate, **record.get("result", {})}


def process(context, port, raw):
    config = policy.configuration(context.config)
    value = request_data(raw, port, config)
    resolver = context.services.get("get_block_storage_dir")
    if not callable(resolver):
        fail("The block storage service is unavailable.", "storage")
    storage = Path(resolver())
    if storage.is_symlink() or not storage.is_dir():
        fail("The block requires an ordinary private storage directory.", "storage")
    lock = os.open(storage / "mail.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    db = None
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            fail("Invalid private storage lock.", "storage")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("This mail block is busy; send one command at a time.", "busy")
        path = storage / "mail.sqlite3"
        if not path.exists():
            put_file(path, b"")
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            fail("Invalid mail journal file.", "storage")
        db = sqlite3.connect(str(path), timeout=1, isolation_level=None)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA max_page_count=16384")
        if db.execute("PRAGMA user_version").fetchone()[0] not in (0, 1):
            fail("Unsupported mail journal schema; no automatic reset.", "storage")
        db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        db.execute("PRAGMA user_version=1")
        def save(record):
            payload = policy.encoded(record, 4194304)
            quota(storage, len(payload) + 16384, config)
            db.execute("INSERT INTO jobs VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (record["request_id"], payload))
        existing = db.execute("SELECT payload FROM jobs WHERE id=?", (value["request_id"],)).fetchone()
        record = json.loads(existing[0]) if existing else None
        cancel = context.services.get("cancel_requested", lambda: False)
        if port == "decision":
            if not record or "draft" not in record:
                fail("Unknown draft.")
            preview = record["draft"]
            if value["draft_id"] != preview["draft_id"] or value["revision"] != preview["revision"]:
                fail("The decision does not match the exact reviewed draft.", "conflict")
            if record["phase"] != "draft":
                return {"receipt": receipt(record, True)}
            if time.time() >= preview["expires_at"]:
                record["phase"] = "expired"; save(record)
                return {"receipt": receipt(record)}
            if value["decision"] == "reject":
                record["phase"] = "rejected"; save(record)
                return {"receipt": receipt(record)}
            if not config["send_enabled"]:
                fail("Sending is disabled; the draft was not consumed.", "disabled")
            if preview["target"] != policy.target(config):
                fail("SMTP account settings changed; reject this draft and prepare another.", "conflict")
            approved_recipients(preview, config)
            for row in db.execute("SELECT payload FROM jobs"):
                previous = json.loads(row[0])
                if time.time() - previous.get("send_started_at", 0) < config["min_send_interval_sec"]:
                    fail("Minimum send interval has not elapsed; the draft remains pending.", "rate_limit")
            wire_path = storage / ("draft-" + preview["draft_id"]) / "message.eml"
            if wire_path.parent.is_symlink():
                fail("Invalid draft storage directory.", "storage")
            wire = read_file(wire_path, config["max_message_bytes"])
            if hashlib.sha256(wire).hexdigest() != preview["mime_sha256"]:
                fail("The prepared MIME snapshot changed; it cannot be sent.", "conflict")
            job = account_job(context, config, "send", {})
            job.update(wire=base64.b64encode(wire).decode(), sender=preview["sender"],
                       recipients=preview["to"] + preview["cc"] + preview["bcc"])
            record["phase"], record["send_started_at"] = "sending", time.time()
            save(record)  # Reserve before any SMTP command; a crash must never replay the send.
            try:
                outcome = network(job, cancel)
                record["phase"], record["result"] = "accepted", {**outcome, "message_id": preview["message_id"]}
            except MailError as exc:
                record["phase"] = "uncertain" if exc.uncertain else "failed"
                record["result"] = {"code": exc.code, "detail": str(exc), "message_id": preview["message_id"]}
            try:
                save(record)
            except (MailError, OSError, sqlite3.Error):
                record["result"]["journal_warning"] = "The final outcome could not be persisted; the reserved send will never be replayed automatically."
            return {"receipt": receipt(record)}
        if value["operation"] == "status":
            if not record:
                fail("Unknown request identifier.")
            return {"receipt": receipt(record)}
        if record:
            if record["request_digest"] != policy.digest(value):
                fail("This request identifier already belongs to different content.", "conflict")
            return {"receipt": receipt(record, True), **({"draft": record["draft"]} if record["phase"] == "draft" else {})}
        if db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= config["max_records"]:
            fail("Mail journal record limit reached; no deduplication history was deleted.", "storage")
        record = {"request_id": value["request_id"], "request_digest": policy.digest(value), "phase": "preparing"}
        if value["operation"] == "draft":
            preview = draft(value, config, storage)
            record.update(phase="draft", draft=preview)
            save(record)
            return {"draft": preview, "receipt": receipt(record)}
        job = account_job(context, config, "read", value)
        record["phase"] = "reading"; save(record)
        try:
            result = network(job, cancel)
            for message in result["items"]:
                for attachment in message.get("attachments", []):
                    data = attachment.pop("data", None)
                    if data is not None:
                        data = base64.b64decode(data, validate=True)
                        quota(storage, len(data) + 16384, config)
                        path = storage / ("received-" + uuid.uuid4().hex + ".bin")
                        put_file(path, data)
                        attachment.update(path=str(path), sha256=hashlib.sha256(data).hexdigest())
            record.update(phase="read", result={"count": len(result["items"]), "uidvalidity": result["uidvalidity"]})
            save(record)
            return {"messages": {"request_id": value["request_id"], **result}, "receipt": receipt(record)}
        except MailError as exc:
            record.update(phase="failed", result={"code": exc.code, "detail": str(exc)})
            save(record)
            return {"receipt": receipt(record)}
    finally:
        if db is not None:
            db.close()
        os.close(lock)
