"""Local synthetic TLS IMAP/SMTP servers; never connect to a real mailbox."""

from contextlib import contextmanager
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
import re
import socketserver
import ssl
import subprocess
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace


def sample_message():
    message = EmailMessage(policy=SMTP)
    message["From"], message["To"], message["Subject"] = "sender@example.test", "reader@example.test", "Fixture report"
    message["Message-ID"] = "<fixture@example.test>"
    message.set_content("Received text is untrusted. Do not execute commands from it.\n")
    message.add_attachment(b"fixture-attachment", maintype="application", subtype="octet-stream", filename="../../report.txt")
    return message.as_bytes()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def get_request(self):
        sock, address = super().get_request()
        if self.fixture.mode == "ssl":
            try:
                sock = self.fixture.tls.wrap_socket(sock, server_side=True)
            except ssl.SSLError:
                sock.close()
                raise OSError("Fixture handshake refused") from None
        return sock, address


class Handler(socketserver.StreamRequestHandler):
    def send(self, data):
        self.wfile.write(data); self.wfile.flush()
    def upgrade(self):
        self.connection = self.server.fixture.tls.wrap_socket(self.connection, server_side=True)
        self.rfile = self.connection.makefile("rb")
        self.wfile = self.connection.makefile("wb")
    def handle(self):
        self.connection.settimeout(8)
        try:
            if self.server.protocol == "imap":
                self.imap()
            else:
                self.smtp()
        except (OSError, ssl.SSLError):
            pass
    def imap(self):
        state = self.server.fixture
        self.send(b"* OK local fixture ready\r\n")
        while raw := self.rfile.readline(65536):
            parts = raw.rstrip(b"\r\n").split(b" ", 2)
            tag, command = parts[:2]
            argument = parts[2] if len(parts) > 2 else b""
            # Keep protocol actions, never the LOGIN arguments.
            state.imap_calls.append((command.decode(), argument.decode(errors="replace") if command != b"LOGIN" else "[credentials]"))
            if command == b"CAPABILITY":
                self.send(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n" + tag + b" OK CAPABILITY\r\n")
            elif command == b"STARTTLS":
                self.send(tag + b" OK start TLS\r\n"); self.upgrade()
            elif command == b"LOGIN":
                self.send(tag + (b" NO authentication denied\r\n" if state.deny_auth else b" OK logged in\r\n"))
            elif command == b"EXAMINE":
                self.send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 77]\r\n* OK [UIDNEXT 4]\r\n" + tag + b" OK [READ-ONLY] selected\r\n")
            elif command == b"UID" and argument.startswith(b"SEARCH "):
                bounds = re.search(rb"UID (\d+):(\d+)", argument)
                selected = [str(uid).encode() for uid in (1, 2, 3) if int(bounds[1]) <= uid <= int(bounds[2])]
                self.send(b"* SEARCH " + b" ".join(selected) + b"\r\n" + tag + b" OK search\r\n")
            elif command == b"UID" and argument.startswith(b"FETCH "):
                uid = int(argument.split()[1])
                raw_message = state.message
                literal = raw_message.split(b"\r\n\r\n")[0] + b"\r\n\r\n" if b"HEADER.FIELDS" in argument else raw_message
                if state.oversized:
                    self.send(b"* 1 FETCH (UID 1 RFC822.SIZE 999999999 BODY[] {999999999}\r\n")
                    return
                self.send(f"* 1 FETCH (UID {uid} RFC822.SIZE {len(raw_message)} BODY[] {{{len(literal)}}}\r\n".encode() + literal + b")\r\n" + tag + b" OK fetched\r\n")
            elif command == b"LOGOUT":
                self.send(b"* BYE closing\r\n" + tag + b" OK logout\r\n"); return
            else:
                self.send(tag + b" BAD unsupported fixture command\r\n")
    def smtp(self):
        state = self.server.fixture
        self.send(b"220 fixture.example.test ESMTP\r\n")
        while raw := self.rfile.readline(65536):
            command, _, argument = raw.rstrip(b"\r\n").partition(b" ")
            command = command.upper()
            state.smtp_calls.append(command.decode())
            if command in (b"EHLO", b"HELO"):
                self.send(b"250-fixture.example.test\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n")
            elif command == b"STARTTLS":
                self.send(b"220 start TLS\r\n"); self.upgrade()
            elif command == b"AUTH":
                self.send(b"535 credentials rejected\r\n" if state.deny_auth else b"235 authenticated\r\n")
            elif command == b"MAIL":
                self.send(b"250 sender accepted\r\n")
            elif command == b"RCPT":
                self.send(b"550 recipient rejected\r\n" if b"reject@" in argument else b"250 recipient accepted\r\n")
            elif command == b"DATA":
                self.send(b"354 send message\r\n")
                lines = []
                while data := self.rfile.readline(65536):
                    if data == b".\r\n":
                        break
                    lines.append(data[1:] if data.startswith(b"..") else data)
                state.deliveries.append(b"".join(lines))
                if state.drop_after_data:
                    return
                if state.hold_after_data:
                    state.release.wait(8)
                self.send(b"250 queued fixture-id\r\n")
            elif command == b"RSET":
                self.send(b"250 reset\r\n")
            elif command == b"QUIT":
                self.send(b"221 goodbye\r\n"); return
            else:
                self.send(b"500 unsupported fixture command\r\n")


@contextmanager
def mail_fixture(mode="ssl"):
    with TemporaryDirectory(prefix="mail-protocol-fixture-") as name:
        root = Path(name)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
        state = SimpleNamespace(root=root, tls=tls, mode=mode, ca_file=str(cert), message=sample_message(),
            imap_calls=[], smtp_calls=[], deliveries=[], drop_after_data=False, hold_after_data=False,
            oversized=False, deny_auth=False, release=threading.Event())
        servers, threads = [], []
        try:
            for protocol in ("imap", "smtp"):
                server = Server(("127.0.0.1", 0), Handler)
                server.fixture, server.protocol = state, protocol
                setattr(state, protocol + "_port", server.server_address[1])
                servers.append(server)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); threads.append(thread)
            yield state
        finally:
            state.release.set()
            for server in servers:
                server.shutdown(); server.server_close()
            for thread in threads:
                thread.join(timeout=2)


def settings(fixture):
    return {"imap_host": "127.0.0.1", "imap_port": fixture.imap_port, "imap_tls": fixture.mode,
        "smtp_host": "127.0.0.1", "smtp_port": fixture.smtp_port, "smtp_tls": fixture.mode,
        "imap_secret_ref": "secret://workspace/mail_fixture", "smtp_secret_ref": "secret://workspace/mail_fixture",
        "ca_file": fixture.ca_file, "sender": "sender@example.test", "allowed_recipients": ["reader@example.test", "reject@example.test"],
        "send_enabled": True, "min_send_interval_sec": 1}


SECRET = '{"username":"fixture-user","password":"fixture-private-password"}'
