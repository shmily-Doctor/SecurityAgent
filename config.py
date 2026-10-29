"""SecurityAgent 集中配置：路径、模型列表与用量上限。

根目录原本平铺二十多个文件，路径与常量散落在各工具里；
统一放这里，工具模块只导入自己需要的那几项。
"""

from pathlib import Path
import json


# ==========================================
# 1. 路径
# ==========================================

PROJECT_DIR = Path(__file__).resolve().parent

# 唯一允许读写的实验目录
LAB_DIR = (PROJECT_DIR / "security_lab").resolve()

TESTS_DIR = PROJECT_DIR / "tests"
REPORTS_DIR = PROJECT_DIR / "reports"
HTTP_LAB_DIR = PROJECT_DIR / "http_lab"

# 第三方二进制与数据文件（Nmap 发行包）
VENDOR_DIR = PROJECT_DIR / "vendor"
NMAP_DIR = VENDOR_DIR / "nmap"

LOG_PATH = PROJECT_DIR / "security_agent.log"


# ==========================================
# 2. 用量控制（调小可进一步省 token）
# ==========================================

HISTORY_MAX_MESSAGES = 8      # 保留最近 8 条消息（约 4 轮）
HISTORY_MAX_CHARS = 1500      # 历史中每条助手回答最多保留的字符数
MAX_TURNS = 10                # 单次任务内工具调用最大轮数
MAX_OUTPUT_TOKENS = 3000      # 单次回答最大输出

# 单个工具结果返回给模型的最大字符数，超出部分显式标注截断
MAX_TOOL_TEXT = 20_000
# 命令类输出保留的尾部字符数（pytest / nmap 的关键信息都在末尾）
MAX_TOOL_TAIL = 8_000


# ==========================================
# 3. 模型列表（按成本从低到高排列，依次回退）
# ==========================================

MODELS = [
    {
        "name": "百炼 Qwen Plus",
        "provider": "bailian",
        "env": "DASHSCOPE_API_KEY",
        "url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "enabled": True,
    },
    {
        "name": "百炼 Qwen Max",
        "provider": "bailian",
        "env": "DASHSCOPE_API_KEY",
        "url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-max",
        "enabled": False,
    },
    {
        "name": "DeepSeek",
        "provider": "deepseek",
        "env": "DEEPSEEK_API_KEY",
        "url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "enabled": True,
    },
    {
        "name": "OpenAI",
        "provider": "openai",
        "env": "OPENAI_API_KEY",
        "url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
        "enabled": True,
    },
]


# ==========================================
# 4. 通用文本截断工具
# ==========================================

def clamp_text(text, limit=None, note=None):
    """截断过长文本，并留下可核对的行数说明而不是静默丢弃。"""
    if limit is None:
        limit = MAX_TOOL_TEXT

    if text is None:
        return ""

    text = str(text)

    if len(text) <= limit:
        return text

    dropped = len(text) - limit
    marker = note or f"...(已截断 {dropped} 字符)"

    return text[:limit] + "\n" + marker


def bounded_findings_json(report, limit=MAX_TOOL_TEXT):
    """保留有效 JSON，必要时逐条移除告警并标记截断。"""
    report = dict(report)
    findings = list(report.get("findings", []))
    report["findings"] = findings
    report["truncated"] = bool(report.get("truncated", False))
    while True:
        report["returned_findings"] = len(findings)
        encoded = json.dumps(report, ensure_ascii=False)
        if len(encoded) <= limit:
            return encoded
        if findings:
            findings.pop()
            report["truncated"] = True
        else:
            return json.dumps({"success": False, "error": "扫描摘要超过输出限制"}, ensure_ascii=False)


def tail_text(text, limit=None):
    """保留尾部内容，用于 pytest、nmap 这类结论在末尾的输出。"""
    if limit is None:
        limit = MAX_TOOL_TAIL

    if text is None:
        return ""

    text = str(text)

    if len(text) <= limit:
        return text

    dropped = len(text) - limit

    return f"...(前 {dropped} 字符已省略)\n" + text[-limit:]
