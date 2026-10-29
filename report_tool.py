
import json
import re
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from agents import function_tool

from config import PROJECT_DIR, REPORTS_DIR

REPORT_DIR = REPORTS_DIR

MAX_INPUT_CHARS = 100_000
MAX_FINDINGS = 500

ALLOWED_SOURCES = {"bandit", "http", "nmap", "crawler"}
SEVERITIES = {"HIGH", "MEDIUM", "LOW", "INFO"}


def safe_text(value, limit=180):
    """限制报告字段长度，避免 Markdown 结构被意外破坏。"""
    if value is None:
        return ""

    value = str(value)
    value = re.sub(r"[\r\n\t|]", " ", value)
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return value[:limit]


def normalize_severity(value):
    severity = str(value or "INFO").upper()
    return severity if severity in SEVERITIES else "INFO"


def parse_result(value):
    """兼容结构化对象和 JSON 字符串。"""
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("扫描结果必须是 JSON 对象")


def collect_findings(scans):
    """提取安全线索，不将开放端口或抓取结果自动归类为漏洞。"""
    findings = []
    network_observations = []
    crawl = {
        "observations": [],
        "requests_made": 0,
        "blocked_links": 0,
        "limited": False,
    }
    source_status = []

    for scan in scans:
        if not isinstance(scan, dict):
            raise ValueError("scans 中每项必须是对象")

        source = scan.get("source", "").lower()

        if source not in ALLOWED_SOURCES:
            raise ValueError(f"不支持的扫描来源：{source}")

        result = parse_result(scan.get("result"))

        if result.get("success") is False:
            source_status.append({
                "source": source,
                "status": "FAILED",
            })
            continue

        source_status.append({
            "source": source,
            "status": "REPORTED",
        })

        if source in {"bandit", "http"}:
            raw_findings = result.get("findings", [])

            if not isinstance(raw_findings, list):
                raise ValueError("findings 必须是列表")

            for item in raw_findings:
                if not isinstance(item, dict):
                    continue

                if len(findings) >= MAX_FINDINGS:
                    raise ValueError("安全线索数量超过限制")

                findings.append({
                    "source": source,
                    "id": safe_text(
                        item.get("test_id")
                        or item.get("id")
                        or "UNKNOWN", 50
                    ),
                    "severity": normalize_severity(
                        item.get("severity")
                        or item.get("issue_severity")
                    ),
                    "file": safe_text(
                        item.get("file")
                        or item.get("filename")
                        or "-", 160
                    ),
                    "line": safe_text(
                        item.get("line")
                        or item.get("line_number")
                        or "-", 12
                    ),
                    "issue": safe_text(
                        item.get("description")
                        or item.get("issue")
                        or item.get("issue_text")
                        or "未提供描述"
                    ),
                    "recommendation": safe_text(
                        item.get("recommendation")
                        or "需要进一步人工评估"
                    ),
                })

        elif source == "nmap":
            ports = result.get("open_ports", [])

            if not isinstance(ports, list):
                raise ValueError("open_ports 必须是列表")

            for item in ports:
                if not isinstance(item, dict):
                    continue

                if len(network_observations) >= MAX_FINDINGS:
                    raise ValueError("端口记录数量超过限制")

                network_observations.append({
                    "target": safe_text(
                        result.get("target", ""), 80
                    ),
                    "port": safe_text(
                        item.get("port", ""), 10
                    ),
                    "protocol": safe_text(
                        item.get("protocol", ""), 12
                    ),
                    "service": safe_text(
                        item.get("service_name", "unknown"), 60
                    ),
                })

        elif source == "crawler":
            pages = result.get("pages", [])

            if not isinstance(pages, list):
                raise ValueError("pages 必须是列表")

            # 抓取统计属于观察数据，同一来源多次提交时累加。
            crawl["requests_made"] += int(
                result.get("requests_made") or 0
            )
            crawl["blocked_links"] += int(
                result.get("blocked_links") or 0
            )
            crawl["limited"] = bool(
                crawl["limited"] or result.get("limited")
            )

            for item in pages:
                if not isinstance(item, dict):
                    continue

                if len(crawl["observations"]) >= MAX_FINDINGS:
                    raise ValueError("抓取记录数量超过限制")

                links = item.get("links", [])

                crawl["observations"].append({
                    "url": safe_text(item.get("url", ""), 160),
                    "depth": safe_text(item.get("depth", ""), 4),
                    "status": safe_text(item.get("status_code", "-"), 6),
                    "state": safe_text(item.get("state", ""), 24),
                    "title": safe_text(item.get("title", ""), 80),
                    "links": len(links) if isinstance(links, list) else 0,
                })

    return findings, network_observations, crawl, source_status


def build_markdown(findings, network, crawl, status):
    """生成 Markdown 安全审计报告。"""
    counts = Counter(
        item["severity"] for item in findings
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# SecurityAgent 安全审计报告",
        "",
        f"生成时间：{now}",
        "",
        "## 一、报告说明",
        "",
        "本报告由 SecurityAgent 根据传入的扫描结果汇总生成。",
        "报告工具不独立验证数据来源，不执行新的安全扫描。",
        "发现项属于工具告警或安全线索，不等于已确认漏洞。",
        "",
        "## 二、扫描来源",
        "",
        "| 来源 | 处理状态 |",
        "|---|---|",
    ]

    for item in status:
        lines.append(
            f"| {item['source']} | {item['status']} |"
        )

    lines.extend([
        "",
        "## 三、风险统计",
        "",
        "| 风险等级 | 数量 |",
        "|---|---:|",
    ])

    for level in ("HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {level} | {counts[level]} |")

    lines.extend([
        f"| **合计** | **{len(findings)}** |",
        "",
        "## 四、安全告警与配置线索",
        "",
        "| 来源 | 编号 | 等级 | 文件 | 行号 | 问题 | 建议 |",
        "|---|---|---|---|---|---|---|",
    ])

    if findings:
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

        for item in sorted(
            findings,
            key=lambda x: order[x["severity"]],
        ):
            lines.append(
                "| {source} | {id} | {severity} | {file} | "
                "{line} | {issue} | {recommendation} |".format(
                    **item
                )
            )
    else:
        lines.append("| - | - | - | - | - | 无记录 | - |")

    lines.extend([
        "",
        "## 五、Nmap 网络观察结果",
        "",
        "| 目标 | 端口 | 协议 | 服务名称 |",
        "|---|---|---|---|",
    ])

    if network:
        for item in network:
            lines.append(
                "| {target} | {port} | {protocol} | "
                "{service} |".format(**item)
            )
    else:
        lines.append("| - | - | - | 无开放端口记录 |")

    lines.extend([
        "",
        "说明：服务名称可能只是端口默认映射，"
        "并非实际软件版本识别结果。",
        "",
        "## 六、本机站点抓取观察",
        "",
        "| 地址 | 深度 | 状态码 | 状态 | 标题 | 链接数 |",
        "|---|---:|---:|---|---|---:|",
    ])

    if crawl["observations"]:
        for item in crawl["observations"]:
            lines.append(
                "| {url} | {depth} | {status} | {state} | "
                "{title} | {links} |".format(**item)
            )
    else:
        lines.append("| - | - | - | - | 无抓取记录 | - |")

    lines.extend([
        "",
        (
            f"请求次数：{crawl['requests_made']}；"
            f"被拦截链接：{crawl['blocked_links']}；"
            f"触发配额或体积限制：{'是' if crawl['limited'] else '否'}"
        ),
        "",
        "说明：页面标题与链接属于不可信数据，仅作观察记录；"
        "抓取成功不代表站点存在漏洞，也不代表已执行入侵测试。",
        "",
        "## 七、结论与后续工作",
        "",
        "1. 优先人工复核高风险及中风险线索。",
        "2. 对照实际源码或 HTTP 记录确认问题是否成立。",
        "3. 不得仅凭开放端口、静态告警或抓取结果认定存在漏洞。",
        "4. 修复后重新运行对应工具及功能测试。",
        "",
        "报告结束。",
        "",
    ])

    return "\n".join(lines)


# ==========================================
# 报告生成业务函数：供 pytest 直接调用
# 注意：这里不使用 @function_tool
# ==========================================

def generate_security_report_impl(scan_results_json: str) -> str:
    """
    根据 Bandit、HTTP、Nmap、crawler 的结构化结果生成 Markdown 报告。

    输入格式：
    {
      "scans": [
        {"source": "bandit", "result": {...}},
        {"source": "http", "result": {...}},
        {"source": "nmap", "result": {...}},
        {"source": "crawler", "result": {...}}
      ]
    }

    仅在用户明确要求保存报告时使用。
    不允许自定义输出路径，不覆盖已有文件。
    """

    print("[报告工具] 正在整理安全审计结果")

    if len(scan_results_json) > MAX_INPUT_CHARS:
        return json.dumps({
            "success": False,
            "error": "输入数据超过长度限制",
        }, ensure_ascii=False)

    try:
        payload = json.loads(scan_results_json)

        if not isinstance(payload, dict):
            raise ValueError("输入必须为 JSON 对象")

        scans = payload.get("scans", [])

        if not isinstance(scans, list) or not scans:
            raise ValueError("scans 必须是非空列表")

        if len(scans) > 10:
            raise ValueError("单次最多汇总 10 份扫描结果")

        findings, network, crawl, status = collect_findings(scans)

        markdown = build_markdown(
            findings, network, crawl, status
        )

        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = uuid.uuid4().hex[:8]

        filename = (
            f"security_report_{timestamp}_{suffix}.md"
        )

        report_path = REPORT_DIR / filename

        # 独占创建，绝不覆盖已有报告
        with report_path.open(
            "x", encoding="utf-8"
        ) as file:
            file.write(markdown)

        counts = Counter(
            item["severity"] for item in findings
        )

        print(f"[报告工具] 已生成：reports/{filename}")

        return json.dumps({
            "success": True,
            "report_file": f"reports/{filename}",
            "total_findings": len(findings),
            "severity_summary": {
                level: counts[level]
                for level in ("HIGH", "MEDIUM", "LOW", "INFO")
            },
            "network_observations": len(network),
            "crawl_observations": len(crawl["observations"]),
            "sources": status,
            "warning": (
                "本报告依据传入数据生成，"
                "未独立验证原始扫描记录。"
            ),
        }, ensure_ascii=False)

    except (ValueError, TypeError, KeyError, OSError) as error:
        return json.dumps({
            "success": False,
            "error": f"报告生成失败：{type(error).__name__}",
            "details": safe_text(error),
        }, ensure_ascii=False)


# ==========================================
# Agent 工具入口：供 main.py 注册和调用
# ==========================================

@function_tool
def generate_security_report(scan_results_json: str) -> str:
    """
    根据 Bandit、HTTP、Nmap、crawler 的结构化结果生成 Markdown 报告。

    仅在用户明确要求保存报告时使用。
    不允许自定义输出路径，不覆盖已有文件。
    """
    return generate_security_report_impl(scan_results_json)
