import json
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / "playbooks"
    / "block-malicious-ip"
    / "webapp-workflow.json"
)


def test_webapp_playbook_only_forwards_and_notifies() -> None:
    document = json.loads(WORKFLOW.read_text(encoding="utf-8"))
    text = json.dumps(document)
    assert "approvalmail" not in text
    assert "execution" not in text
    assert "SentinelAutoBlock" not in text
    post = document["actions"]["Check_web_app_url"]["else"]["actions"]["Post_incident"]
    assert post["inputs"]["method"] == "POST"
    assert post["inputs"]["uri"].endswith("/api/v1/integrations/sentinel/incidents')}")
    mail = document["actions"]["Check_web_app_url"]["else"]["actions"]["Notification_requested"]["actions"]["Send_review_email"]
    assert mail["inputs"]["path"] == "/v2/Mail"
    assert "Body" in mail["inputs"]["body"]
