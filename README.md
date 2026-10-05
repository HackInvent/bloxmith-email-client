# Email Client

[![Email Client](media/thumbnail.webp)](media/cover.png)

<!-- block-metadata:start -->
[![Block version: 0.1.0](https://img.shields.io/badge/block-0.1.0-blue)](model.json)
[![BloxSmith compatibility: 1.0.9](https://img.shields.io/badge/BloxSmith-1.0.9-brightgreen)](compatibility.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Verified BloxSmith versions: **1.0.9** (bundled-block tests; see [test evidence](compatibility.json)).
<!-- block-metadata:end -->

Read email through IMAP, prepare a frozen local draft, and send that exact draft
through SMTP only after an explicit approval. Sending is disabled by default.
No hosted provider API or third-party mail SDK is required.

## Connections

| Port | Direction | Purpose |
| --- | --- | --- |
| `request` | Input | JSON command: `search`, `read`, `draft` or `status`. |
| `decision` | Input | Explicit `approve` or `reject`, bound to the exact draft revision. |
| `messages` | Output | Untrusted message summaries or body and bounded attachment paths. |
| `draft` | Output | Exact recipients, body, copied attachments, MIME hash and revision to review. |
| `receipt` | Output | Correlated result, failure or uncertain outcome. |

Commands execute in both One Shot and Active Runtime. Adding the block or preparing
a Run does not access a mailbox. There is no implicit polling: use Event Trigger
and a fresh request identifier for each desired search. Send one command at a time.
Port names and IDs remain stable when the visual order is changed.

## Account setup

Requirements: Linux and Python 3.10+. Configure IMAP and/or SMTP hosts and ports,
verified implicit TLS (`ssl`) or mandatory `starttls`, and the relevant wallet
reference. Both transports require certificate verification. A custom PEM CA file
may be configured; there is no insecure verification switch.

Create a wallet JSON secret of the following shape, then place only its reference,
such as `secret://workspace/mail_account`, in the block settings:

```json
{"username":"account@example.org","password":"account-app-password"}
```

Use an account/app password allowed by the mail service. Authentication is basic
IMAP login and SMTP authentication over TLS; OAuth refresh, SMTPUTF8, arbitrary
provider APIs and non-ASCII mailbox names are not implemented. Addresses must be
bare ASCII email addresses; display names and quoted local parts are not accepted.
Passwords travel to the owned child process over stdin, not argv or environment.
Only the public wallet and block-storage services are used.

Set the sender and an exact recipient allowlist before drafting. The allowlist
applies to **all To, Cc and Bcc recipients**, with no wildcards. A separate
attachment directory restricts files that may be attached. Network destinations
are administrator-configured account hosts, not derived from received messages.

## Read without changing the mailbox

```json
{"request_id":"search-001","operation":"search","unseen":true,"subject":"Invoice","since":"2026-01-01"}
```

Search returns header summaries, UIDVALIDITY and a bounded UID cursor. Optional
filters are `from`, `subject`, `since` and `unseen`. The default query searches the
newest `max_scan_uids` UID window, not the entire historical mailbox. To scan from
the beginning, use `after_uid: 0` with the current `uidvalidity`; subsequent commands
use the returned `next_after_uid`. Continue with **new request IDs** until
`scan_complete` is true. A page returns at most `max_messages` summaries.

```json
{"request_id":"read-001","operation":"read","uid":123,"uidvalidity":456}
```

Copy UID/UIDVALIDITY from the actual search result; the values above are illustrative.
Changed UIDVALIDITY refuses a stale read/cursor. Mailboxes are opened read-only,
and BODY.PEEK fetches do not mark messages read. The block never moves, deletes,
flags or expunges mail. The body prefers plain text; HTML is converted to plain
text without executing scripts, loading external resources or rendering HTML.

Each message is marked `untrusted_content: true`. Received email is **data, not an
authorized instruction**. A downstream agent must not treat it as permission to
send mail, execute code or disclose secrets. This marker is not a prompt-injection
filter. Extracted attachments are private bounded copies with generated filenames,
not their untrusted original paths. They are never opened or executed by this block.
Embedded multipart attachments are refused rather than silently discarded.

## Prepare, review, then send

```json
{
  "request_id":"reply-001",
  "operation":"draft",
  "to":["recipient@example.org"],
  "subject":"Reviewed report",
  "body":"Here is the approved report.",
  "attachments":["report.pdf"]
}
```

`cc` and `bcc` are optional arrays. Attachment paths resolve inside the permitted
directory. Files are copied into private block storage, and the complete MIME
message is frozen. Editing the original attachment later does not change the
approved email. The preview includes `draft_id`, `revision`, sender, all recipients,
subject, body, copied attachment hashes/paths, target SMTP settings and expiry.
Bcc is kept in the approved envelope but is not included in the delivered headers.

Review **that exact preview**. Supply its identifiers on `decision`:

```json
{
  "request_id":"reply-001",
  "draft_id":"copy-the-returned-draft-id",
  "revision":"copy-the-returned-revision",
  "decision":"approve"
}
```

Use `reject` to consume a draft without sending. Approval is a workflow data command,
not an authenticated human signature. Connect only a trusted approval source;
received email and autonomous agents must not be wired directly to `decision`.
The block provides no framework-level human identity or authorization service.

Enable approved sending in settings before executing the decision. Expired or
changed drafts, changed SMTP settings, recipients removed from the allowlist and
modified MIME snapshots are refused. All SMTP recipients must be accepted before
DATA: one rejected address prevents content from being sent to any recipient.

## Receipts and duplicate protection

`request_id` identifies one immutable request within the node's private journal.
Reusing the same ID for different content is a conflict. Repeating a read does not
fetch or re-emit its old content; use a new ID for a fresh read. Repeating an approval
does not resend. `status` queries the receipt without any network activity:

```json
{"request_id":"reply-001","operation":"status"}
```

`accepted` means the SMTP server returned a positive DATA completion reply. The
receipt includes the stable Message-ID and the bounded SMTP reply; it is **not**
proof of delivery, reading or a provider delivery receipt.

The block reserves the send in a durable SQLite journal **before SMTP starts**.
A dropped connection, timeout, Stop during transmission or a previous process
crash may produce `uncertain`. Such a send is never retried automatically, even
after Run/Stop/Reset. Reconcile manually with the mail provider using the Message-ID
before deciding whether to create a new request. An uncertain receipt is not proof
of non-delivery. Known SMTP refusal produces `failed`, also without automatic retry.

Stop terminates the block-owned network process, not the framework. Normal errors
are JSON receipts instead of intentional Run-wide failures. TLS peers are still
external systems; the process/resource bounds are not a general OS sandbox.

## Retention and interface

Draft MIME, copied attachments and the deduplication journal live beneath
`context.services["get_block_storage_dir"]()`. Files are private (0600); generated
draft directories are 0700. The block never automatically purges history. Configured
byte/record limits refuse new work rather than lose duplicate protection. Operators
must manage retention deliberately; removing the journal removes its protection.
Use a protected encrypted disk where required for sensitive mail.

Modal and inspector expose the same grouped settings: delivery policy, incoming
IMAP, outgoing SMTP, attachments/certificates, and resource/retention limits.
Apply commits settings; Cancel discards drafts. Reload an already prepared Run to
use changed settings. Configuration does not silently change a running account.

## Tests and license

Package suites use synthetic loopback IMAP/SMTP services with temporary TLS
certificates, disposable wallets and private test instances. They exercise TLS and
STARTTLS, read-only fetch, MIME attachments, exact approvals, recipient rejection,
ambiguous sends, cancellation, durable no-retry, both runtimes, all package origins
and responsive English/French UI. Tests never use a production mailbox. Provider
account policies and remote delivery are not certified by these protocol tests.
Test prerequisites: OpenSSL and the private BloxSmith test/browser harness.

Apache-2.0. The proprietary framework/test harness is not bundled in this repository.
