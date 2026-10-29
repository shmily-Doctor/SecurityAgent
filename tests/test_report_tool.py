
import json
from pathlib import Path

import pytest

import report_tool


# ==========================================
# 1. 构造模拟扫描结果
# ==========================================

def sample_payload():
    """构造 Bandit、HTTP 和 Nmap 模拟扫描数据。"""

    return {
        "scans": [
            {
                "source": "bandit",
                "result": {
                    "success": True,
                    "findings": [
                        {
                            "file": "security_test_2.py",
                            "line": 22,
                            "test_id": "B301",
                            "severity": "MEDIUM",
                            "description": "不安全的反序列化",
                        },
                        {
                            "file": "security_test_2.py",
                            "line": 15,
                            "test_id": "B324",
                            "severity": "HIGH",
                            "description": "弱哈希算法",
                        },
                    ],
                },
            },
            {
                "source": "http",
                "result": {
                    "success": True,
                    "findings": [
                        {
                            "id": "HTTP-003",
                            "severity": "LOW",
                            "issue": "缺少安全响应头",
                            "recommendation": "评估配置 nosniff",
                        },
                    ],
                },
            },
            {
                "source": "nmap",
                "result": {
                    "success": True,
                    "target": "127.0.0.1",
                    "open_ports": [
                        {
                            "port": 8000,
                            "protocol": "tcp",
                            "state": "open",
                            "service_name": "http-alt",
                        },
                    ],
                },
            },
            {
                "source": "crawler",
                "result": {
                    "success": True,
                    "requests_made": 2,
                    "blocked_links": 1,
                    "limited": False,
                    "pages": [
                        {
                            "url": "http://127.0.0.1:8000/",
                            "depth": 0,
                            "status_code": 200,
                            "state": "ok",
                            "title": "首页",
                            "links": ["http://127.0.0.1:8000/a.html"],
                        },
                        {
                            "url": "http://127.0.0.1:8000/a.html",
                            "depth": 1,
                            "status_code": 200,
                            "state": "ok",
                            "title": "帮助",
                            "links": [],
                        },
                    ],
                },
            },
        ],
    }


# ==========================================
# 2. 调用报告生成业务函数
# ==========================================

def run_report_tool(payload):
    """
    直接调用普通 Python 业务函数。

    不经过 Agents SDK 的工具包装器，
    避免缺少 ToolContext 导致的报错。
    """

    scan_results_json = json.dumps(
        payload,
        ensure_ascii=False,
    )

    result = report_tool.generate_security_report_impl(
        scan_results_json
    )

    return json.loads(result)


# ==========================================
# 3. 八项自动化测试
# ==========================================

def test_collect_findings():
    """测试多工具扫描结果汇总。"""

    findings, network, crawl, status = (
        report_tool.collect_findings(
            sample_payload()["scans"]
        )
    )

    assert len(findings) == 3
    assert len(network) == 1
    assert len(crawl["observations"]) == 2
    assert crawl["requests_made"] == 2
    assert crawl["blocked_links"] == 1
    assert len(status) == 4

    ids = {item["id"] for item in findings}

    assert ids == {
        "B301",
        "B324",
        "HTTP-003",
    }


def test_crawler_not_counted_as_vulnerability():
    """测试抓取结果不会被计算为安全线索。"""

    findings, _, crawl, _ = report_tool.collect_findings(
        sample_payload()["scans"]
    )

    assert len(findings) == 3
    assert crawl["observations"][0]["title"] == "首页"
    assert crawl["observations"][0]["links"] == 1

    markdown = report_tool.build_markdown(
        findings,
        [],
        crawl,
        [],
    )

    assert "本机站点抓取观察" in markdown
    assert "抓取成功不代表站点存在漏洞" in markdown
    assert "| **合计** | **3** |" in markdown


def test_invalid_crawler_pages():
    """测试 pages 不是列表时被拒绝。"""

    with pytest.raises(ValueError):
        report_tool.collect_findings([
            {
                "source": "crawler",
                "result": {"success": True, "pages": "not-a-list"},
            },
        ])


def test_nmap_not_counted_as_vulnerability():
    """测试开放端口不会被计算为漏洞。"""

    findings, network, _, _ = (
        report_tool.collect_findings(
            sample_payload()["scans"]
        )
    )

    assert len(findings) == 3
    assert len(network) == 1
    assert network[0]["port"] == "8000"


def test_severity_counts():
    """测试风险等级统计是否准确。"""

    findings, network, crawl, status = (
        report_tool.collect_findings(
            sample_payload()["scans"]
        )
    )

    markdown = report_tool.build_markdown(
        findings,
        network,
        crawl,
        status,
    )

    assert "| HIGH | 1 |" in markdown
    assert "| MEDIUM | 1 |" in markdown
    assert "| LOW | 1 |" in markdown
    assert "| INFO | 0 |" in markdown

    assert (
        "| **合计** | **3** |"
        in markdown
    )


def test_invalid_source():
    """测试拒绝未知扫描来源。"""

    invalid_scans = [
        {
            "source": "unknown",
            "result": {
                "success": True,
                "findings": [],
            },
        },
    ]

    with pytest.raises(ValueError):
        report_tool.collect_findings(
            invalid_scans
        )


def test_failed_scan():
    """测试失败的扫描不会被标记为成功。"""

    scans = [
        {
            "source": "bandit",
            "result": {
                "success": False,
                "error": "模拟扫描失败",
            },
        },
    ]

    findings, network, crawl, status = (
        report_tool.collect_findings(scans)
    )

    assert findings == []
    assert network == []
    assert crawl["observations"] == []

    assert len(status) == 1
    assert status[0]["status"] == "FAILED"


def test_report_creation(tmp_path, monkeypatch):
    """测试报告生成、内容和风险统计。"""

    monkeypatch.setattr(
        report_tool,
        "REPORT_DIR",
        tmp_path,
    )

    result = run_report_tool(
        sample_payload()
    )

    assert result["success"] is True

    assert result["total_findings"] == 3
    assert result["network_observations"] == 1
    assert result["crawl_observations"] == 2

    assert result["severity_summary"] == {
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 0,
    }

    report_path = (
        tmp_path
        / Path(result["report_file"]).name
    )

    assert report_path.is_file()

    content = report_path.read_text(
        encoding="utf-8"
    )

    assert "SecurityAgent 安全审计报告" in content

    assert "B301" in content
    assert "B324" in content
    assert "HTTP-003" in content
    assert "8000" in content
    assert "本机站点抓取观察" in content
    assert "http://127.0.0.1:8000/a.html" in content


def test_empty_scans(tmp_path, monkeypatch):
    """测试空扫描列表会被拒绝，且不生成文件。"""

    monkeypatch.setattr(
        report_tool,
        "REPORT_DIR",
        tmp_path,
    )

    result = run_report_tool({
        "scans": [],
    })

    assert result["success"] is False

    assert list(tmp_path.iterdir()) == []


def test_no_overwrite(tmp_path, monkeypatch):
    """测试生成新报告不会覆盖已有报告。"""

    monkeypatch.setattr(
        report_tool,
        "REPORT_DIR",
        tmp_path,
    )

    old_report = (
        tmp_path / "existing_report.md"
    )

    old_report.write_text(
        "需要保留的旧报告",
        encoding="utf-8",
    )

    first = run_report_tool(
        sample_payload()
    )

    second = run_report_tool(
        sample_payload()
    )

    assert first["success"] is True
    assert second["success"] is True

    assert (
        first["report_file"]
        != second["report_file"]
    )

    assert old_report.read_text(
        encoding="utf-8"
    ) == "需要保留的旧报告"

    markdown_files = list(
        tmp_path.glob("*.md")
    )

    assert len(markdown_files) == 3

    first_path = (
        tmp_path
        / Path(first["report_file"]).name
    )

    second_path = (
        tmp_path
        / Path(second["report_file"]).name
    )

    assert first_path.is_file()
    assert second_path.is_file()
    assert first_path != second_path
