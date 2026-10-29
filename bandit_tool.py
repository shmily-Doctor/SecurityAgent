
import json
import subprocess
import sys
from pathlib import Path

from agents import function_tool

from config import LAB_DIR, bounded_findings_json

SCAN_DIR = LAB_DIR

# 单文件告警上限：超出后不再逐条返回，避免一次工具结果撑爆上下文
MAX_FINDINGS = 200


@function_tool
def scan_python_security(filename: str) -> str:
    """使用 Bandit 扫描 security_lab 内指定的 Python 文件，并返回源码上下文。"""

    print(f"[Bandit 工具执行] 正在扫描：{filename}")

    if Path(filename).name != filename or not filename.endswith(".py"):
        return "错误：只能扫描实验目录中的 Python 文件。"

    target = (SCAN_DIR / filename).resolve()

    if not target.is_relative_to(SCAN_DIR.resolve()):
        return "错误：目标不在允许的扫描目录内。"

    if not target.is_file():
        return f"错误：文件不存在：{filename}"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )

        if result.returncode not in (0, 1):
            return "Bandit 执行失败：" + result.stderr[:500]

        report = json.loads(result.stdout)

        # 读取真实源码
        source_lines = target.read_text(
            encoding="utf-8"
        ).splitlines()

        # 提取漏洞附近源码
        def get_code_context(line_number, radius=3):
            if not isinstance(line_number, int):
                return []

            start = max(1, line_number - radius)
            end = min(len(source_lines), line_number + radius)

            return [
                {
                    "line": i,
                    "code": source_lines[i - 1]
                }
                for i in range(start, end + 1)
            ]

        # 汇总 Bandit 检测结果
        findings = []
        total_reported = 0

        for item in report.get("results", []):
            total_reported += 1

            if len(findings) >= MAX_FINDINGS:
                continue

            findings.append({
                "line": item.get("line_number"),
                "test_id": item.get("test_id"),
                "severity": item.get("issue_severity"),
                "confidence": item.get("issue_confidence"),
                "description": item.get("issue_text"),
                "code_context": get_code_context(
                    item.get("line_number")
                ),
            })

        # 返回结果给 Agent
        return bounded_findings_json(
            {
                "filename": filename,
                "total_findings": total_reported,
                "returned_findings": len(findings),
                "truncated": total_reported > len(findings),
                "findings": findings,
            },
        )

    except subprocess.TimeoutExpired:
        return "Bandit 扫描超时。"

    except (OSError, ValueError) as error:
        return f"扫描失败：{type(error).__name__}"
