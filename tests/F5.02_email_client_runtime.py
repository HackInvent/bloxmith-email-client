"""FB1/FB2/FB3/FB4/FB5/FB6: real TLS + wallet, both runtimes and all package origins."""

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(Path(__file__).parent)]
from blocs.email_client.block import EmailClientBlock
from block_test_packages import install_test_package, prepare_release_run, surface_payload
from mail_fixture import SECRET, mail_fixture, settings
from ui_smoke_common import (create_project_api, create_run_api, data_edge, graph_payload, graph_storage_dir,
    http_json, isolated_server, stop_run_api, text_node, wait_for_run_predicate, wait_for_run_terminal)


def main():
    block = EmailClientBlock()
    with mail_fixture() as mail:
        for mode in ("centralized", "zeromq_active"):
            for origin in (None,"managed","linked"):
                with isolated_server() as server:
                    node = block.build_node_payload(node_id="mail", position={"x":400,"y":150}, config_overrides=settings(mail))
                    # Stable port identities and names, not their visual array order.
                    node["inputs"].reverse()
                    if origin:
                        model = install_test_package(server,"email_client",origin=origin)
                        node["block_version"] = model["version"]
                        for surface in ("modal","inspector_panel","node_card"):
                            html = surface_payload(server,model,node,surface)["html"]
                            assert "{{" not in html and "fixture-private-password" not in html
                    http_json(server.base_url,"/api/application/secrets/init",method="POST",payload={"password":"temporary-mail-test"})
                    http_json(server.base_url,"/api/application/secrets",method="POST",payload={"name":"mail_fixture","value":SECRET})
                    document = graph_payload("Explicit mail commands", [text_node("request","Mail request","",70,100),
                        text_node("decision","Exact decision","",70,300),node], [data_edge("request","request",1,"mail",1),
                        data_edge("decision","decision",1,"mail",2)])
                    draft_request = {"request_id":"draft","operation":"draft","to":["reader@example.test"],"subject":"Fixture only","body":"Reviewed text"}
                    if mode == "centralized":
                        document["nodes"][0]["outputs"][0]["text"] = json.dumps(draft_request)
                    project = create_project_api(server,document=document)["project"]
                    before = len(mail.deliveries)
                    if mode == "centralized":
                        def run_command(source,obj):
                            for item in document["nodes"][:2]:
                                item["outputs"][0]["text"] = json.dumps(obj) if item["id"] == source else ""
                            (graph_storage_dir(server,project)/"graph.json").write_text(json.dumps({**document,"graph_id":project["graph_id"]}),encoding="utf-8")
                            http_json(server.base_url,f"/api/projects/{project['graph_id']}/graph/reload",method="POST",payload={})
                            run = create_run_api(server,document,project_id=project["graph_id"],runtime_mode=mode)
                            final = wait_for_run_terminal(server,run["run_id"],timeout_sec=20)
                            assert final["status"] == "success", final.get("logs")
                            assert "fixture-private-password" not in json.dumps(final)
                            return final
                        final = run_command("request",draft_request)
                        draft = json.loads(final["output_values"]["mail:2"]["value"])
                        assert len(mail.deliveries) == before
                        decision = {key:draft[key] for key in ("request_id","draft_id","revision")} | {"decision":"approve"}
                        sent = run_command("decision",decision)
                        receipt = json.loads(sent["output_values"]["mail:3"]["value"])
                        assert receipt["status"] == "accepted" and len(mail.deliveries) == before+1, receipt
                        duplicate = run_command("decision",decision)
                        assert json.loads(duplicate["output_values"]["mail:3"]["value"])["duplicate"]
                        assert len(mail.deliveries) == before+1
                    else:
                        rid = prepare_release_run(server,project["graph_id"],document)["run_id"]
                        http_json(server.base_url,f"/api/runs/{rid}/play",method="POST",payload={})
                        def value(result,port):
                            raw = result.get("output_values",{}).get("mail:"+str(port),{}).get("value")
                            return json.loads(raw) if raw else {}
                        def send(source,obj):
                            http_json(server.base_url,f"/api/runs/{rid}/active/control",method="POST",payload={"action":"publish_output",
                                "node_id":source,"port_id":1,"value":json.dumps(obj),"content_type":"application/json"})
                        def wait(predicate):
                            final = wait_for_run_predicate(server,rid,lambda data: data.get("status")=="failed" or predicate(data),
                                "Mail command did not complete",timeout_sec=20)
                            assert final["status"] != "failed", final.get("logs")
                            assert "fixture-private-password" not in json.dumps(final)
                            return final
                        try:
                            send("request",draft_request)
                            draft = value(wait(lambda data:value(data,2).get("request_id")=="draft"),2)
                            assert len(mail.deliveries) == before
                            decision = {key:draft[key] for key in ("request_id","draft_id","revision")} | {"decision":"approve"}
                            send("decision",{**decision,"revision":"0"*64})
                            wait(lambda data:value(data,3).get("code")=="conflict")
                            assert len(mail.deliveries) == before
                            send("decision",decision)
                            wait(lambda data:value(data,3).get("status")=="accepted")
                            assert len(mail.deliveries) == before+1
                            stop_run_api(server,rid); wait_for_run_terminal(server,rid,timeout_sec=15)
                            rid = prepare_release_run(server,project["graph_id"],document)["run_id"]
                            http_json(server.base_url,f"/api/runs/{rid}/play",method="POST",payload={})
                            send("decision",decision)
                            wait(lambda data:value(data,3).get("duplicate"))
                            assert len(mail.deliveries) == before+1
                            send("request",{"request_id":"search","operation":"search"})
                            result = wait(lambda data:value(data,1).get("request_id")=="search")
                            assert len(value(result,1)["items"]) == 3
                            if origin is None:
                                # Exercise real framework Stop while SMTP has received DATA
                                # but has not acknowledged it. Restart must not resend.
                                send("request",{**draft_request,"request_id":"stop-during-send"})
                                waiting = value(wait(lambda data:value(data,2).get("request_id")=="stop-during-send"),2)
                                interrupted = {key:waiting[key] for key in ("request_id","draft_id","revision")} | {"decision":"approve"}
                                count = len(mail.deliveries)
                                mail.release.clear(); mail.hold_after_data = True
                                try:
                                    # Respect the configured one-second sending cadence;
                                    # the previous accepted send may be less than a second old.
                                    time.sleep(1.05)
                                    send("decision",interrupted)
                                    deadline = time.monotonic()+8
                                    while len(mail.deliveries)==count and time.monotonic()<deadline:
                                        time.sleep(.02)
                                    assert len(mail.deliveries)==count+1, http_json(server.base_url,f"/api/runs/{rid}")
                                    stop_run_api(server,rid)
                                    stopped = wait_for_run_terminal(server,rid,timeout_sec=15)
                                    assert "shutdown_timeout" not in str(stopped.get("logs"))
                                finally:
                                    mail.hold_after_data = False; mail.release.set()
                                rid = prepare_release_run(server,project["graph_id"],document)["run_id"]
                                http_json(server.base_url,f"/api/runs/{rid}/play",method="POST",payload={})
                                send("decision",interrupted)
                                persisted = wait(lambda data:value(data,3).get("request_id")=="stop-during-send")
                                assert value(persisted,3)["status"] == "uncertain", value(persisted,3)
                                assert value(persisted,3)["duplicate"] and len(mail.deliveries)==count+1
                            http_json(server.base_url,"/api/application/secrets/lock",method="POST",payload={})
                            count = len(mail.imap_calls)
                            send("request",{"request_id":"locked","operation":"search"})
                            wait(lambda data:value(data,3).get("code")=="secret")
                            assert len(mail.imap_calls) == count
                        finally:
                            stop_run_api(server,rid)
                            final = wait_for_run_terminal(server,rid,timeout_sec=15)
                            assert "shutdown_timeout" not in str(final.get("logs"))
                print("[ok] Email TLS + wallet + approval persistence " + mode + " " + str(origin), flush=True)


if __name__ == "__main__":
    main()
