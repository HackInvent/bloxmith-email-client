"""FB6: real release UI, responsive geometry, keyboard, drafts and persistence."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from playwright.sync_api import sync_playwright, expect
from block_test_artifacts import artifact_path
from block_test_packages import install_test_package
from ui_smoke_common import isolated_server, graph_payload, create_project_api, project_editor_url
from blocs.email_client.block import EmailClientBlock


def geometry(modal):
    """Require an opaque panel with reachable actions and an internally scrollable body."""
    measured = modal.evaluate("""el => {
        const r=el.getBoundingClientRect(), body=el.querySelector('.owned-body');
        const actions=[...el.querySelectorAll('[data-close-block-modal], [data-owned-apply]')];
        return {inside:r.left>=-1&&r.right<=innerWidth+1&&r.top>=-1&&r.bottom<=innerHeight+1,
          overflow:el.scrollWidth>el.clientWidth+2||body.scrollWidth>body.clientWidth+2,
          controls:actions.every(a=>{const b=a.getBoundingClientRect();return b.top>=0&&b.bottom<=innerHeight+1}),
          background:getComputedStyle(el).backgroundColor,
          unlabeled:[...el.querySelectorAll('input,select,textarea')].filter(c=>!c.labels?.length&&!c.getAttribute('aria-label')&&!c.getAttribute('aria-labelledby')).length};
    }""")
    assert measured["inside"] and measured["controls"] and not measured["overflow"], measured
    assert not measured["unlabeled"], measured
    assert measured["background"] not in {"transparent", "rgba(0, 0, 0, 0)"}, measured


def main():
    """Exercise current package files in real managed and linked browser hosts."""
    for origin in ("managed", "linked"):
        with isolated_server() as server, sync_playwright() as playwright:
            model = install_test_package(server, "email_client", origin=origin)
            candidate = EmailClientBlock().build_node_payload(node_id="ui-case", position={"x": 160, "y": 160})
            candidate["block_version"] = model["version"]
            project = create_project_api(server, document=graph_payload("Owned form", [candidate], []))["project"]
            url = project_editor_url(server.base_url, project["project_id"], workspace_project_id=project["workspace_project_id"])
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.add_init_script("window.localStorage.setItem('bloxsmith.inspectorPinned','true')")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(url)
                card = page.locator('.canvas-node[data-node-id="ui-case"]')
                expect(card.locator('h3')).to_be_visible()
                card.locator('h3').dblclick()
                modal = page.locator('.owned-modal')
                expect(modal).to_be_visible()
                expect(modal.locator('[data-owned-apply]')).to_be_disabled()
                edited = modal.locator('[data-block-config-field="allowed_recipients"]')
                original = edited.input_value()
                expect(modal.locator('[data-block-config-field="send_enabled"]')).not_to_be_checked()
                edited.fill('["reader@example.test","team@example.test"]')
                expect(modal.locator('[data-owned-apply]')).to_be_enabled()
                modal.locator('[data-close-block-modal]').last.click()
                card.locator('h3').dblclick()
                expect(edited).to_have_value(original)
                edited.fill('["reader@example.test","team@example.test"]')
                with page.expect_response(lambda r: r.url.endswith('/ui-action') and r.request.method == 'POST') as saved:
                    modal.locator('[data-owned-apply]').click()
                assert not saved.value.json().get("error"), saved.value.json()
                if modal.is_visible():
                    modal.locator('[data-close-block-modal]').first.click()
                page.reload()
                card.locator('h3').dblclick()
                assert __import__("json").loads(edited.input_value()) == ["reader@example.test", "team@example.test"]
                for width,height in ((1440,900),(800,700),(390,740),(320,568)):
                    page.set_viewport_size({"width":width,"height":height})
                    page.wait_for_timeout(100)
                    geometry(modal)
                    page.screenshot(path=artifact_path("email_client-"+origin+"-"+str(width)+".png"))
                summary = modal.locator('.owned-advanced').first.locator('summary')
                summary.scroll_into_view_if_needed()
                summary.focus()
                summary.press('Enter')
                expect(modal.locator('.owned-advanced').first).to_have_attribute('open','')
                geometry(modal)
                page.screenshot(path=artifact_path("email_client-"+origin+"-advanced.png"))
                page.set_viewport_size({"width":1440,"height":900})
                for section in modal.locator('[data-settings-group]').all():
                    if section.get_attribute('open') is None:
                        section.locator('summary').click()
                    for control in section.locator('input,select,textarea').all():
                        control.scroll_into_view_if_needed()
                        expect(control).to_be_visible()
                        geometry(modal)
                edited.fill('not json')
                modal.locator('[data-owned-apply]').click()
                expect(modal.locator('.owned-form-status')).to_have_text('Enter valid JSON before applying.')
                edited.fill('["reader@example.test"]')
                modal.locator('[data-close-block-modal]').first.click()
                card.click(position={"x":20,"y":20})
                inspector = page.locator('[data-properties-surface="inspector"][data-node-id="ui-case"]:visible')
                expect(inspector).to_be_visible()
                assert inspector.evaluate('el => el.scrollWidth <= el.clientWidth+2')
                panel_field = inspector.locator('[data-block-config-field="allowed_recipients"]')
                panel_field.fill('["reader@example.test"]')
                with page.expect_response(lambda r: r.url.endswith('/ui-action') and r.request.method == 'POST') as panel_saved:
                    inspector.locator('[data-owned-apply]').click()
                assert not panel_saved.value.json().get('error')
                inspector.locator('[data-inspector-tab="ports"]').click()
                expect(inspector.locator('[data-inspector-panel-tab="ports"]')).to_be_visible()
                inspector.locator('[data-inspector-tab="general"]').click()
                expect(inspector.locator('[data-inspector-panel-tab="general"]')).to_be_visible()
                assert __import__("json").loads(panel_field.input_value()) == ["reader@example.test"]
                page.screenshot(path=artifact_path("email_client-"+origin+"-inspector.png"))
                page.goto(server.base_url+"/")
                page.locator("#homeApplicationSettingsButton").click()
                page.locator("#applicationLanguageSelect").select_option("fr")
                page.wait_for_function("window.CWMessages.getLanguage() === 'fr'")
                page.goto(url)
                card.locator('h3').dblclick()
                expect(modal.locator('.owned-advanced').first.locator('summary')).to_have_text("Réception · IMAP")
                assert not errors, errors
                assert page.evaluate("!window.CWBlockUiBlocks?.email_client")
            finally:
                browser.close()
        print("[ok] email_client " + origin + " UI", flush=True)


if __name__ == "__main__":
    main()
