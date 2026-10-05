/** Package-owned Apply: semantic validation and exact JSON replacement via public actions. */
export function bindSettings(root, api) {
  const controller = new AbortController();
  const button = root.querySelector("[data-owned-apply]");
  if (!button) return () => controller.abort();
  let dirty = false, pending = false, generation = 0;
  const status = document.createElement("p");
  status.className = "field-hint owned-form-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  button.parentElement.before(status);
  const sync = () => { button.disabled = !dirty || pending || Boolean(api.isReadOnly?.()); };
  const mark = event => {
    if (!event.target.matches("input,textarea,select")) return;
    generation += 1; dirty = true; status.textContent = ""; sync();
  };
  const value = field => {
    if (field.type === "checkbox") return field.checked;
    const type = field.dataset.blockValueType;
    if (type === "json") {
      try { return JSON.parse(field.value); }
      catch { field.focus(); throw new Error(api.t?.("block.email_client.invalid_json", {}, "Enter valid JSON before applying.") || "Enter valid JSON before applying."); }
    }
    if (type === "integer" || type === "number" || field.type === "number") {
      const parsed = Number(field.value);
      if (!field.value.trim() || !Number.isFinite(parsed) || (type === "integer" && !Number.isInteger(parsed)) || !field.checkValidity()) {
        field.reportValidity(); field.focus();
        throw new Error(api.t?.("block.email_client.invalid_number", {}, "Check the numeric value and its limits.") || "Check the numeric value and its limits.");
      }
      return parsed;
    }
    return field.value;
  };
  const apply = async () => {
    if (!dirty || pending || api.isReadOnly?.()) return;
    const started = generation;
    try {
      const patch = {config: {}}, outputs = new Map();
      for (const field of root.querySelectorAll("[data-block-title-field],[data-block-description-field],[data-block-config-field],[data-block-output-field]")) {
        const current = value(field);
        if (field.dataset.blockConfigField) patch.config[field.dataset.blockConfigField] = current;
        if (field.hasAttribute("data-block-title-field")) patch.title = current;
        if (field.hasAttribute("data-block-description-field")) patch.description = current;
        if (field.dataset.blockOutputField) {
          const id = field.dataset.blockOutputPortId || field.dataset.portId || field.closest("[data-port-id]")?.dataset.portId;
          if (id) {
            const item = outputs.get(id) || {id: Number(id)};
            item[field.dataset.blockOutputField] = current; outputs.set(id, item);
          }
        }
      }
      if (outputs.size) patch.outputs = [...outputs.values()];
      pending = true; sync(); status.textContent = "";
      const result = await api.applyAction("save_settings", {node_patch: patch});
      if (result?.error) throw new Error(result.error);
      if (controller.signal.aborted) return;
      if (started === generation) dirty = false;
      status.textContent = api.t?.("block.email_client.saved", {}, "Settings applied.") || "Settings applied.";
    } catch (error) {
      if (!controller.signal.aborted) status.textContent = String(error.message || error);
    } finally {
      pending = false;
      if (!controller.signal.aborted) sync();
    }
  };
  root.addEventListener("input", mark, {signal: controller.signal});
  root.addEventListener("change", mark, {signal: controller.signal});
  button.addEventListener("click", event => {event.preventDefault(); void apply();}, {signal: controller.signal});
  root.addEventListener("keydown", event => {
    if (event.key === "Enter" && event.target instanceof HTMLInputElement && event.target.type !== "checkbox") {
      event.preventDefault(); void apply();
    }
  }, {signal: controller.signal});
  sync();
  return () => {controller.abort(); status.remove();};
}

