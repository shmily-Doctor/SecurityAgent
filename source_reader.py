
from pathlib import Path
from agents import function_tool

from config import LAB_DIR, MAX_TOOL_TEXT

SCAN_DIR = LAB_DIR

MAX_SOURCE_BYTES = 50000

# 返回给模型的源码字符上限；超出时显式标注剩余行数，不静默丢弃
MAX_SOURCE_CHARS = MAX_TOOL_TEXT


@function_tool
def read_python_source(filename: str) -> str:
    """读取 security_lab 内指定 Python 文件的完整源码。"""

    if Path(filename).name != filename:
        return "拒绝：只能读取实验目录内的文件名。"

    if not filename.endswith(".py"):
        return "拒绝：只能读取 Python 源码。"

    target = (SCAN_DIR / filename).resolve()

    if not target.is_relative_to(SCAN_DIR):
        return "拒绝：文件超出授权目录。"

    if not target.is_file():
        return "错误：文件不存在。"

    if target.stat().st_size > MAX_SOURCE_BYTES:
        return "拒绝：文件超过读取大小限制。"

    try:
        code = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "错误：无法读取源文件。"

    numbered = "\n".join(
        f"{i:4d} | {line}"
        for i, line in enumerate(code.splitlines(), 1)
    )

    total_lines = len(code.splitlines())

    # 超长文件按字符上限截断，并说明从第几行开始没有返回，
    # 让模型能明确知道自己看到的是不完整源码。
    complete = len(numbered) <= MAX_SOURCE_CHARS
    if not complete:
        numbered = numbered[:MAX_SOURCE_CHARS]
        shown = numbered.count("\n") + 1
        numbered += (
            f"\n...(已截断：共 {total_lines} 行，"
            f"仅返回前 {shown} 行)"
        )

    print(f"[源码工具] 已读取：{filename}")

    return (
        f"文件：{filename}\n"
        f"{'完整源码' if complete else '源码（不完整）'}：\n{numbered}"
    )
