"""Email Client: public storage/wallet services and explicit command ports only."""

import json
import sqlite3
from bloxsmith_app.block_api import BlockDefinition, BlockRuntimeOutput, BlockRuntimePreparation, BlockRuntimeResult
from . import engine, policy, ui


# FB1 - Validate account policy, exact recipient scope and source-specific JSON commands.
# FB2 - Read mail through verified TLS, UIDVALIDITY and bounded non-mutating IMAP requests.
# FB3 - Snapshot approved MIME/attachments and persist exact draft/revision decisions per node.
# FB4 - Send only after explicit approval and preserve accepted/failed/uncertain no-retry outcomes.
# FB5 - Cancel owned network processes, bound resources and keep credentials out of logs/outputs.
# FB6 - Preserve both runtime/package contracts and translated responsive draft settings.
class EmailClientBlock(BlockDefinition):
    kind = "email_client"

    def ui_assets(self, surface="modal"):
        return list(self.model.get("ui_assets", {}).get(surface, []))

    def prepare_runtime(self, context):
        policy.configuration(context.config)
        return BlockRuntimePreparation()

    def execute_runtime(self, context):
        outputs, last, request_id = [], "skipped", None
        try:
            if context.input_events:
                names = {int(port.id): port.name for port in context.input_ports}
                events = [(names.get(event.input_port_id), event.value) for event in context.input_events]
            else:
                events = [(name, context.input_value(name, str(number))) for number, name in ((1, "request"), (2, "decision"))
                          if context.has_input_value(name, str(number)) and context.input_value(name, str(number))]
            if len(events) > 2 or any(name not in {"request", "decision"} for name, _ in events):
                policy.fail("Send one request/decision at a time on its named port.")
            for name, value in events:
                request_id = None
                parsed = policy.document(value)
                request_id = policy.identifier(parsed.get("request_id"))
                result = engine.process(context, name, value)
                last = result.get("receipt", {}).get("status", "done")
                for port in context.output_ports:
                    if port.name in result:
                        outputs.append(BlockRuntimeOutput(port_id=int(port.id), port_name=port.name,
                            value=json.dumps(result[port.name], ensure_ascii=True, allow_nan=False), content_type="application/json"))
        except (ValueError, TypeError, RuntimeError, OSError, sqlite3.Error) as exc:
            detail = str(exc) if isinstance(exc, policy.MailError) else "Mail operation is unavailable; check configuration, files and private storage."
            last = exc.code if isinstance(exc, policy.MailError) else "error"
            result = {"status": "error", "code": last, "detail": detail,
                      "uncertain": exc.uncertain if isinstance(exc, policy.MailError) else False}
            if request_id is not None:
                result["request_id"] = request_id
            for port in context.output_ports:
                if port.name == "receipt":
                    outputs.append(BlockRuntimeOutput(port_id=int(port.id), port_name=port.name,
                        value=json.dumps(result, ensure_ascii=True), content_type="application/json"))
        return BlockRuntimeResult(status="success" if outputs else "skipped", outputs=outputs,
            metadata={self.kind: {"status": last}}, logs=["[email-client] " + last] if outputs else [])

    def handle_ui_action(self, *, node, action, values, payload=None):
        if action in {"save_settings", "modal_update_fields", "inspector_update_fields"}:
            patch = (values or {}).get("node_patch") or {}
            if "config" in patch:
                try:
                    policy.configuration({**self.default_config(), **(node.get("config") or {}), **patch["config"]})
                except (ValueError, TypeError) as exc:
                    return {"error": self.translate("block.email_client.error", {"detail": str(exc)}, fallback="Mail configuration: {detail}")}
        return ui.replace_config(super().handle_ui_action(node=node,
            action="modal_update_fields" if action == "save_settings" else action, values=values, payload=payload), node)

    def render_modal(self, *, node, payload=None):
        return ui.modal(self, node, payload)

    def render_inspector_panel(self, *, node, payload=None):
        return ui.inspector(self, node, payload)

    def render_node_card(self, *, node, payload=None):
        config = {**self.default_config(), **(node.get("config") or {})}
        key = "send_ready" if config["send_enabled"] else "draft_only"
        return ui.card(self, node, self.translate("block.email_client." + key,
            fallback="Approval required" if config["send_enabled"] else "Sending disabled"))
