
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from agents import function_tool

from config import LAB_DIR, PROJECT_DIR, bounded_findings_json

# 目前仅允许扫描这个实验目录
SCAN_DIR = LAB_DIR

# 扫描限制
MAX_FILES = 100
MAX_TOTAL_BYTES = 2_000_000

# 不纳入扫描的目录
EXCLUDED_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    ".pytest_cache",
    "node_modules",
}


@function_tool
def scan_python_project() -> str:
    """使用 Bandit 扫描 security_lab 内所有 Python 文件，汇总安全告警。"""

    print("[项目扫描] 正在检查 security_lab ...")

    if not SCAN_DIR.is_dir():
        return json.dumps({
            "success": False,
            "error": "security_lab 目录不存在",
        }, ensure_ascii=False)

    # 枚举 Python 文件
    python_files = []

    for path in SCAN_DIR.rglob("*.py"):

        if any(
            part in EXCLUDED_DIRS
            for part in path.relative_to(SCAN_DIR).parts
        ):
            continue

        # 排除指向目录外的符号链接
        if path.is_symlink():
            continue

        resolved = path.resolve()

        if not resolved.is_relative_to(SCAN_DIR):
            continue

        if not resolved.is_file():
            continue

        python_files.append(resolved)

    python_files.sort()

    if not python_files:
        return json.dumps({
            "success": True,
            "scanned_files": 0,
            "total_findings": 0,
            "findings": [],
            "message": "没有发现 Python 文件",
        }, ensure_ascii=False)

    if len(python_files) > MAX_FILES:
        return json.dumps({
            "success": False,
            "error": f"文件数量超过限制：{MAX_FILES}",
        }, ensure_ascii=False)

    # stat() 放进 try：文件可能在枚举后被删除或替换
    try:
        total_bytes = sum(
            path.stat().st_size
            for path in python_files
        )
    except OSError as error:
        return json.dumps({
            "success": False,
            "error": f"读取文件大小失败：{type(error).__name__}",
        }, ensure_ascii=False)

    if total_bytes > MAX_TOTAL_BYTES:
        return json.dumps({
            "success": False,
            "error": "项目源码超过允许扫描的大小",
        }, ensure_ascii=False)

    try:

        # 只扫描已经筛选和授权的 Python 文件
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                *[str(path) for path in python_files],
            ],
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=90,
            shell=False,
        )


        # 0: 无告警；1: 检测到告警
        if result.returncode not in (0, 1):
            return json.dumps({
                "success": False,
                "error": "Bandit 执行失败",
                "details": result.stderr[-1000:],
            }, ensure_ascii=False)

        report = json.loads(result.stdout)

        severity = Counter()
        findings = []
        by_file = Counter()

        for item in report.get("results", []):
            source_path = Path(
                item.get("filename", "")
            ).resolve()

            if not source_path.is_relative_to(SCAN_DIR):
                continue

            relative_name = str(
                source_path.relative_to(SCAN_DIR)
            )

            level = item.get(
                "issue_severity", "UNDEFINED"
            )

            severity[level] += 1
            by_file[relative_name] += 1

            findings.append({
                "file": relative_name,
                "line": item.get("line_number"),
                "test_id": item.get("test_id"),
                "severity": level,
                "confidence": item.get("issue_confidence"),
                "description": item.get("issue_text"),
            })

        summary = {
            "success": True,
            "scanned_files": len(python_files),
            "total_findings": len(findings),
            "severity_summary": {
                "HIGH": severity["HIGH"],
                "MEDIUM": severity["MEDIUM"],
                "LOW": severity["LOW"],
                "UNDEFINED": severity["UNDEFINED"],
            },
            "findings_by_file": dict(by_file),
            "findings": findings,
            "skipped_files": report.get("errors", []),
        }

        print(
            "[项目扫描] 扫描完成："
            f"{len(python_files)} 个文件，"
            f"{len(findings)} 项告警"
        )

        return bounded_findings_json(summary)

    except subprocess.TimeoutExpired:
        return json.dumps({
            "success": False,
            "error": "扫描超过 90 秒，已终止",
        }, ensure_ascii=False)

    except (OSError, ValueError) as error:
        return json.dumps({
            "success": False,
            "error": f"扫描失败：{type(error).__name__}",
        }, ensure_ascii=False)
