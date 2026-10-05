"""FB1/FB2/FB3/FB4/FB5: real local TLS protocols, immutable approval and no-retry receipts."""

import json
from email.parser import BytesParser
from email import policy as mime_policy
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(Path(__file__).parent)]
from blocs.email_client import engine, policy
from mail_fixture import SECRET, mail_fixture, settings


def context(path, config, cancelled=lambda: False):
    path.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(config=config, services={"get_block_storage_dir": lambda: path,
        "resolve_secret": lambda reference: SECRET, "cancel_requested": cancelled})


def expect_error(fn, code=None):
    try:
        fn()
    except policy.MailError as exc:
        assert not code or exc.code == code, (exc.code, str(exc))
        return exc
    raise AssertionError("Expected a controlled refusal")


def prepare(ctx, ident="draft-1", **extra):
    return engine.process(ctx, "request", {"request_id": ident, "operation": "draft", "to": ["reader@example.test"],
        "subject": "Reviewed email", "body": "Approved plain text\n", **extra})["draft"]


def approve(ctx, item, **extra):
    return engine.process(ctx, "decision", {key: item[key] for key in ("request_id", "draft_id", "revision")} | {"decision": "approve", **extra})["receipt"]


def unit_policy():
    assert not policy.configuration({})["send_enabled"]
    for invalid in ({"token": "not-allowed"}, {"smtp_tls": "none"}, {"max_messages": True},
                    {"sender": "sender@example.test\r\nBcc: hidden@example.test"}, {"smtp_secret_ref": "password"}):
        expect_error(lambda: policy.configuration(invalid))
    expect_error(lambda: policy.document('{"request_id":"one","request_id":"two"}'))
    expect_error(lambda: engine.request_data({"request_id":"x","operation":"search","after_uid":3},"request",{}))


def local_guards(root, config):
    """Exercise file/recipient scopes, MIME privacy, expiry and storage limits without SMTP."""
    attachments = root / "permitted"
    attachments.mkdir()
    (attachments / "valid.txt").write_text("allowed", encoding="utf-8")
    outside = root / "outside.txt"
    outside.write_text("outside scope", encoding="utf-8")
    (attachments / "link.txt").symlink_to(outside)
    ctx = context(root / "guards", {**config,"attachment_root":str(attachments)})
    expect_error(lambda: prepare(ctx,"scope",to=["outsider@example.test"]),"scope")
    expect_error(lambda: prepare(ctx,"escape",attachments=["../outside.txt"]),"file")
    expect_error(lambda: prepare(ctx,"symlink",attachments=["link.txt"]),"file")
    expect_error(lambda: prepare(ctx,"headers",subject="hello\r\nBcc: intruder@example.test"))
    draft = prepare(ctx,"bcc",to=[],bcc=["reader@example.test"])
    mime = BytesParser(policy=mime_policy.default).parsebytes(Path(draft["message_path"]).read_bytes())
    assert "Bcc" not in mime and draft["bcc"] == ["reader@example.test"]
    with patch.object(engine.time,"time",return_value=draft["expires_at"]+1):
        assert approve(ctx,draft)["status"] == "expired"
    duplicate = engine.process(ctx,"request",{"request_id":"bcc","operation":"status"})
    assert duplicate["receipt"]["status"] == "expired"
    expect_error(lambda: prepare(ctx,"bcc",body="a different request"),"conflict")
    quota_ctx = context(root / "quota", {**config,"max_storage_bytes":1048576})
    (root / "quota" / "retained.bin").write_bytes(b"x"*1000000)
    expect_error(lambda: prepare(quota_ctx),"storage")
    assert (root / "quota" / "retained.bin").stat().st_size == 1000000
    record_ctx = context(root / "records", {**config,"max_records":1})
    first = prepare(record_ctx,"first")
    expect_error(lambda: prepare(record_ctx,"second"),"storage")
    assert Path(first["message_path"]).is_file()
    ctx.services["resolve_secret"] = lambda _: "broken secret containing private material"
    error = expect_error(lambda: policy.credentials(ctx,"secret://workspace/test"),"secret")
    assert "private material" not in str(error)


def main():
    unit_policy()
    for mode in ("ssl", "starttls"):
        with mail_fixture(mode) as mail, TemporaryDirectory(prefix="mail-policy-fixture-") as name:
            root = Path(name)
            config = policy.configuration(settings(mail))
            local_guards(root, config)
            ctx = context(root / "read", config)
            result = engine.process(ctx, "request", {"request_id":"search","operation":"search","unseen":True,"since":"2026-01-01","subject":"report"})
            assert result["receipt"]["status"] == "read", result
            found = result["messages"]
            assert len(found["items"]) == 3 and found["uidvalidity"] == 77
            assert found["scan_complete"] and found["next_after_uid"] == 3
            fetched = engine.process(ctx, "request", {"request_id":"read","operation":"read","uid":1,"uidvalidity":77})
            assert fetched["receipt"]["status"] == "read", fetched
            item = fetched["messages"]["items"][0]
            assert item["untrusted_content"] and "untrusted" in item["body"]
            saved = Path(item["attachments"][0]["path"])
            assert saved.parent == root / "read" and saved.read_bytes() == b"fixture-attachment"
            assert saved.stat().st_mode & 0o777 == 0o600
            assert not any(command in {"STORE","CLOSE","EXPUNGE","SELECT"} for command, _ in mail.imap_calls)
            assert all("PEEK" in args for command,args in mail.imap_calls if args.startswith("FETCH"))
            conflict = engine.process(ctx, "request", {"request_id":"stale","operation":"read","uid":1,"uidvalidity":88})
            assert conflict["receipt"]["code"] == "conflict"
            before = len(mail.imap_calls)
            duplicate = engine.process(ctx,"request",{"request_id":"read","operation":"read","uid":1,"uidvalidity":77})
            assert duplicate["receipt"]["duplicate"] and len(mail.imap_calls) == before
            mail.oversized = True
            oversized = engine.process(ctx,"request",{"request_id":"large","operation":"read","uid":1,"uidvalidity":77})
            assert oversized["receipt"]["code"] == "size", oversized
            mail.oversized = False
            for case in ("accepted","disabled","wrong_revision","tampered","rejected_recipient","uncertain","changed_target","cancelled"):
                ctx = context(root / case, dict(config))
                attachment = root / (case + ".txt"); attachment.write_text("original attachment", encoding="utf-8")
                ctx.config["attachment_root"] = str(root)
                draft = prepare(ctx, attachments=[attachment.name])
                attachment.write_text("changed after draft", encoding="utf-8")
                before = len(mail.deliveries)
                if case == "disabled":
                    ctx.config["send_enabled"] = False
                    expect_error(lambda: approve(ctx,draft), "disabled")
                elif case == "wrong_revision":
                    expect_error(lambda: approve(ctx,draft,revision="0"*64), "conflict")
                elif case == "tampered":
                    Path(draft["message_path"]).write_bytes(b"changed immutable MIME")
                    expect_error(lambda: approve(ctx,draft), "conflict")
                elif case == "changed_target":
                    ctx.config["smtp_port"] += 1
                    expect_error(lambda: approve(ctx,draft), "conflict")
                elif case == "rejected_recipient":
                    draft = prepare(ctx,"reject",to=["reader@example.test","reject@example.test"])
                    receipt = approve(ctx,draft)
                    assert receipt["status"] == "failed" and not receipt["uncertain"]
                elif case == "cancelled":
                    ctx.services["cancel_requested"] = lambda: True
                    receipt = approve(ctx,draft)
                    assert receipt["status"] == "failed" and receipt["code"] == "cancelled"
                else:
                    mail.drop_after_data = case == "uncertain"
                    receipt = approve(ctx,draft)
                    assert receipt["status"] == ("uncertain" if mail.drop_after_data else "accepted"), receipt
                    assert len(mail.deliveries) == before + 1
                    delivered = BytesParser(policy=mime_policy.default).parsebytes(mail.deliveries[-1])
                    assert list(delivered.iter_attachments())[0].get_payload(decode=True) == b"original attachment"
                    again = approve(ctx,draft)
                    assert again["duplicate"] and len(mail.deliveries) == before + 1
                    assert "fixture-private-password" not in json.dumps(receipt)
                    mail.drop_after_data = False
                    continue
                assert len(mail.deliveries) == before
            # A persisted in-flight reservation survives process/restart and must not resend.
            ctx = context(root / "reserved", config)
            draft = prepare(ctx)
            with sqlite3.connect(root / "reserved" / "mail.sqlite3") as db:
                row = json.loads(db.execute("SELECT payload FROM jobs").fetchone()[0]); row["phase"] = "sending"
                db.execute("UPDATE jobs SET payload=?", (json.dumps(row),))
            before = len(mail.deliveries)
            assert approve(ctx,draft)["status"] == "uncertain" and len(mail.deliveries) == before
            # TLS trust failure, no plaintext fallback and no credential output.
            ctx = context(root / "bad-trust", {**config,"ca_file":""})
            bad = engine.process(ctx,"request",{"request_id":"tls","operation":"search"})
            assert bad["receipt"]["status"] == "failed"
            print("[ok] Email real protocols, approvals and durable no-retry " + mode, flush=True)
    # Stop during DATA is uncertain, and the supervised process returns promptly.
    with mail_fixture() as mail, TemporaryDirectory(prefix="mail-stop-fixture-") as name:
        mail.hold_after_data = True
        ctx = context(Path(name), policy.configuration(settings(mail)), lambda: bool(mail.deliveries))
        started = time.monotonic()
        result = approve(ctx,prepare(ctx))
        assert result["status"] == "uncertain" and time.monotonic()-started < 3, result
        with sqlite3.connect(Path(name)/"mail.sqlite3") as db:
            stored = json.loads(db.execute("SELECT payload FROM jobs").fetchone()[0])
        assert approve(ctx,stored["draft"])["duplicate"]
        assert len(mail.deliveries) == 1
    print("[ok] cancellation terminates owned transport without replay")


if __name__ == "__main__":
    main()
