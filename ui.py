"""Package-owned forms, sharing only the framework's public binding helpers."""

from html import escape
import json
from bloxsmith_app.block_api import render_inspector_template, render_node_card_template, render_path_browser_control


def replace_config(result, node):
    """Replace edited JSON settings exactly; generic graph patches otherwise deep-merge objects."""
    patch = result.get("node_patch") if isinstance(result, dict) else None
    if not isinstance(patch, dict) or not isinstance(patch.get("config"), dict):
        return result
    settings = {**(node.get("config") or {}), **patch.pop("config")}
    result.setdefault("graph_operations", []).append({"op": "update_node_config",
        "node_id": str(node.get("id") or ""), "config": settings, "replace": True})
    return result


def fields(block, node, surface):
    """Render trusted field definitions with escaped user values and stable label associations."""
    specs = json.loads((block.directory / "fields.json").read_text(encoding="utf-8"))
    config = {**block.default_config(), **(node.get("config") or {})}
    groups = {name: [] for name in ("main", "incoming", "outgoing", "files", "limits")}
    prefix = escape(f"{block.kind}-{node.get('id', '')}-{surface}", quote=True)
    for spec in specs:
        key, kind = spec["key"], spec.get("type", "text")
        value = config.get(key, "")
        ident = f"{prefix}-{key}"
        attrs = f'data-block-config-field="{key}"'
        if kind in {"json", "integer", "number", "boolean"}:
            attrs += f' data-block-value-type="{kind}"'
        hint_key = f"block.{block.kind}.help_{key}"
        label_key = f"block.{block.kind}.label_{key}"
        label = escape(block.translate(label_key, fallback=spec.get("label", key)))
        hint = escape(block.translate(hint_key, fallback=spec["help"]))
        help_html = f'<p id="{ident}-hint" class="field-hint" data-i18n="{hint_key}">{hint}</p>'
        if kind == "directory":
            control = render_path_browser_control(input_id=ident, label=block.translate(label_key, fallback=spec.get("label", key)), value=str(value),
                       placeholder="", input_attrs=attrs + f' aria-describedby="{ident}-hint"', select_mode="directory")
            rendered = control + help_html
        else:
            common = f'id="{ident}" {attrs} aria-describedby="{ident}-hint"'
            if kind == "select":
                options = "".join(f'<option value="{escape(v, quote=True)}"{" selected" if v == value else ""}>{escape(block.translate("block.email_client.option_" + v, fallback=v))}</option>' for v in spec["options"])
                control = f'<select {common}>{options}</select>'
            elif kind == "json" or kind == "textarea":
                text = json.dumps(value, ensure_ascii=False, indent=2) if kind == "json" and not isinstance(value, str) else str(value)
                control = f'<textarea {common} rows="{spec.get("rows", 4)}" spellcheck="false">{escape(text)}</textarea>'
            elif kind == "boolean":
                control = f'<input {common} type="checkbox"{" checked" if value else ""}>'
            else:
                numeric = kind in {"integer", "number"}
                bounds = f' min="{spec["min"]}" max="{spec["max"]}" step="1"' if numeric else ""
                control = f'<input {common} type="{"number" if numeric else "text"}"{bounds} value="{escape(str(value), quote=True)}">'
            rendered = f'<div class="field-group"><label for="{ident}" data-i18n="{label_key}">{label}</label>{control}{help_html}</div>'
        groups[spec.get("group", "main")].append(rendered)
    main = '<div class="owned-fields">' + "".join(groups["main"]) + "</div>"
    for group in ("incoming", "outgoing", "files", "limits"):
        key = f"block.{block.kind}.group_{group}"
        main += f'<details class="owned-advanced" data-settings-group="{group}"><summary data-i18n="{key}">{escape(block.translate(key, fallback=group.title()))}</summary><div class="owned-fields">{"".join(groups[group])}</div></details>'
    return main


def modal(block, node, payload):
    """Use the generic draft host; refreshing runtime must not replace pending settings."""
    template = (block.directory / "block_modal.html").read_text(encoding="utf-8")
    html = block._render_generic_modal_template(template=template, node=node, payload=payload or {})
    html = html.replace("{{ settings }}", fields(block, node, "modal"))
    return {"html": html, "context": {"node_id": str(node.get("id", "")), "node_kind": block.kind}}


def inspector(block, node, payload):
    """Render fixed settings with the standard Ports tab and sticky Apply control."""
    template = (block.directory / "inspector_panel.html").read_text(encoding="utf-8")
    html = render_inspector_template(template=template, node={**node, "kind": block.kind, "type": block.kind},
                                    payload=payload, replacements={"settings": fields(block, node, "inspector")})
    return {"html": html, "context": {"node_id": str(node.get("id", "")), "full_panel": True}}


def card(block, node, preview):
    """Keep name, purpose and current mode inside the existing card hierarchy."""
    return render_node_card_template(block=block, node=node, node_classes=[block.kind + "-node"],
           replacements={"title": node.get("title") or block.default_title(), "preview": preview,
                         "purpose": block.description()})

