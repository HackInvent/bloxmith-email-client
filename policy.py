"""Explicit mail account policy and bounded JSON; received mail is untrusted data."""

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re

DEFAULTS = {
    "imap_host": "", "imap_port": 993, "imap_tls": "ssl", "imap_secret_ref": "",
    "smtp_host": "", "smtp_port": 465, "smtp_tls": "ssl", "smtp_secret_ref": "",
    "sender": "", "allowed_recipients": [], "mailbox": "INBOX", "attachment_root": "",
    "send_enabled": False, "extract_attachments": True, "ca_file": "",
    "timeout_sec": 30, "max_message_bytes": 5242880, "max_body_chars": 100000,
    "max_messages": 20, "max_scan_uids": 1000, "max_attachments": 10,
    "draft_lifetime_sec": 3600, "min_send_interval_sec": 2, "max_records": 1000,
    "max_storage_bytes": 134217728,
}


class MailError(ValueError):
    def __init__(self, code, detail, *, uncertain=False):
        super().__init__(detail)
        self.code, self.uncertain = code, uncertain


def fail(detail, code="validation"):
    raise MailError(code, detail)


def encoded(value, maximum=1048576):
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw) > maximum:
            fail("JSON exceeds its size limit.")
        todo = [(value, 0)]
        while todo:
            item, depth = todo.pop()
            if depth > 20:
                fail("JSON nesting exceeds 20 levels.")
            if isinstance(item, dict):
                todo.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, (list, tuple)):
                todo.extend((v, depth + 1) for v in item)
        return raw
    except (TypeError, UnicodeError, RecursionError, OverflowError):
        fail("Expected bounded finite JSON.")


def document(value, maximum=1048576):
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="replace")) > maximum:
            fail("JSON input exceeds its size limit.")
        def unique(pairs):
            data = {}
            for key, item in pairs:
                if key in data:
                    fail("Duplicate JSON property.")
                data[key] = item
            return data
        try:
            value = json.loads(value, object_pairs_hook=unique,
                parse_constant=lambda _: fail("Finite JSON required."))
        except (ValueError, RecursionError):
            fail("Expected a valid JSON object.")
    if not isinstance(value, Mapping):
        fail("Expected a JSON object.")
    value = dict(value)
    encoded(value, maximum)
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        fail("Identifiers require 1–128 ASCII letters, digits or ._:-.")
    return value


def line(value, maximum, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value) or (not empty and not value.strip()):
        fail("Expected bounded single-line text.")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        fail("Invalid Unicode text.")
    return value.strip()


def address(value):
    value = line(value, 254)
    if not value.isascii() or value.count("@") != 1:
        fail("Use an ASCII email address without a display name.")
    local, domain = value.rsplit("@", 1)
    if (not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local)
            or local.startswith(".") or local.endswith(".") or ".." in local
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", domain)
            or any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in domain.split("."))):
        fail("Invalid email address.")
    return local + "@" + domain.lower()


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        fail(f"Expected an integer between {low} and {high}.")
    return value


def configuration(raw):
    if not isinstance(raw, Mapping) or set(raw) - set(DEFAULTS) - {"execution", "runtime_path", "runtime_path_label"}:
        fail("Unknown setting; account credentials belong in the wallet.")
    config = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    for prefix in ("imap", "smtp"):
        host = line(config[prefix + "_host"], 253, empty=True)
        if host and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host):
            fail("Use an ASCII DNS name or IPv4 host, without scheme, path or port.")
        config[prefix + "_host"] = host.lower()
        integer(config[prefix + "_port"], 1, 65535)
        if config[prefix + "_tls"] not in ("ssl", "starttls"):
            fail("Mail transport requires verified TLS: ssl or starttls.")
        ref = line(config[prefix + "_secret_ref"], 512, empty=True)
        if ref and not ref.startswith("secret://"):
            fail("Use a secret:// wallet reference.")
        config[prefix + "_secret_ref"] = ref
    config["sender"] = address(config["sender"]) if config["sender"] else ""
    recipients = config["allowed_recipients"]
    if not isinstance(recipients, (list, tuple)) or len(recipients) > 100:
        fail("Allowed recipients must be a JSON array of at most 100 exact addresses.")
    config["allowed_recipients"] = [address(value) for value in recipients]
    if len(set(config["allowed_recipients"])) != len(config["allowed_recipients"]):
        fail("Allowed recipient addresses must be distinct.")
    config["mailbox"] = line(config["mailbox"], 128)
    if not config["mailbox"].isascii():
        fail("This version supports ASCII IMAP mailbox names.")
    for key in ("attachment_root", "ca_file"):
        config[key] = line(config[key], 4096, empty=True)
    for key in ("send_enabled", "extract_attachments"):
        if type(config[key]) is not bool:
            fail(key + " must be a boolean.")
    bounds = {"timeout_sec": (1, 300), "max_message_bytes": (1024, 10485760), "max_body_chars": (100, 200000),
        "max_messages": (1, 50), "max_scan_uids": (1, 5000), "max_attachments": (0, 20),
        "draft_lifetime_sec": (30, 86400), "min_send_interval_sec": (1, 3600), "max_records": (1, 10000),
        "max_storage_bytes": (1048576, 1073741824)}
    for key, (low, high) in bounds.items():
        integer(config[key], low, high)
    return config


def target(config):
    return {key: config[key] for key in ("smtp_host", "smtp_port", "smtp_tls", "smtp_secret_ref", "sender", "ca_file")}


def digest(value):
    return hashlib.sha256(encoded(value, 2097152).encode()).hexdigest()


def credentials(context, reference):
    if not reference:
        fail("Configure a wallet reference for this mail account.", "secret")
    try:
        resolver = context.services.get("resolve_secret")
        value = document(resolver(reference), 16384) if callable(resolver) else None
        if not value or set(value) != {"username", "password"}:
            raise ValueError()
        for key in ("username", "password"):
            if not isinstance(value[key], str) or not 1 <= len(value[key]) <= 4096 or any(c in value[key] for c in "\r\n\x00"):
                raise ValueError()
        return value
    except Exception:
        fail("Unlock the wallet and provide a JSON secret with username and password.", "secret")
