import json

from config import bounded_findings_json


def test_bounded_findings_remains_valid_json():
    result = json.loads(bounded_findings_json({"total_findings": 20, "findings": ["x" * 50] * 20}, 200))
    assert result["total_findings"] == 20
    assert result["truncated"] is True
    assert result["returned_findings"] == len(result["findings"])
