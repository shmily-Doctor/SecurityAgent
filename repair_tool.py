
import difflib
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from agents import function_tool

from config import LAB_DIR, MAX_TOOL_TEXT


SCAN_DIR = LAB_DIR

MAX_FILE_SIZE = 100_000

# 人工审批口令：只有终端输入该值才落盘
APPROVAL_TOKEN = "APPLY"


class FixRejected(ValueError):
    """入参不合规：文件名、路径、大小未通过校验。"""


def build_fix_plan(filename, new_code):
    """校验入参并生成差异，只读不写。

    返回 {filename, target, old_code, new_code, diff}。
    校验失败抛 FixRejected，读取失败抛 OSError。
    """
    # 仅允许修改实验目录中的单个 Python 文件
    if Path(filename).name != filename:
        raise FixRejected("不允许使用目录路径。")

    if not filename.endswith(".py"):
        raise FixRejected("只能修改 Python 文件。")

    target = (SCAN_DIR / filename).resolve()

    if not target.is_relative_to(SCAN_DIR):
        raise FixRejected("文件不在实验目录中。")

    if not target.is_file():
        raise FixRejected("目标文件不存在。")

    if target.stat().st_size > MAX_FILE_SIZE:
        raise FixRejected("文件过大。")

    if len(new_code.encode("utf-8")) > MAX_FILE_SIZE:
        raise FixRejected("修改后的代码过大。")

    old_code = target.read_text(encoding="utf-8")

    numbered = "\n".join(
        f"{i:4d} | {line}" for i, line in enumerate(old_code.splitlines(), 1)
    )
    if len(numbered) > MAX_TOOL_TEXT:
        raise FixRejected("源码超过读取上限，无法基于完整源码修复。")

    diff = "".join(
        difflib.unified_diff(
            old_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile=f"{filename} (原文件)",
            tofile=f"{filename} (修改方案)"
        )
    )

    return {
        "filename": filename,
        "target": target,
        "old_code": old_code,
        "new_code": new_code,
        "diff": diff,
    }


def apply_code_fix(plan):
    """备份后原子替换目标文件，返回备份路径。

    先写同目录临时文件再 os.replace，写入中途失败时原文件不受影响；
    任何 OSError 都会清理临时文件并向上抛出。
    """
    target = plan["target"]

    backup = target.with_name(
        target.name
        + "."
        + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        + ".bak"
    )

    shutil.copy2(target, backup)

    temp = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")

    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(plan["new_code"])
            handle.flush()
            os.fsync(handle.fileno())

        shutil.copymode(target, temp)

        # 同目录替换：要么旧文件完整，要么新文件完整
        os.replace(temp, target)

    except OSError:
        temp.unlink(missing_ok=True)
        raise

    return backup


def _terminal_approval(diff):
    """终端人工审批；与业务逻辑分离，便于测试注入。"""
    print("\n========== 修复方案 ==========")
    print(diff)
    print("==============================")

    approval = input(
        "\n是否批准修改？输入 APPLY 才会写入文件："
    ).strip()

    return approval == APPROVAL_TOKEN


def propose_code_fix_impl(filename, new_code, approve=_terminal_approval):
    """展示差异并按审批结果写入，供 Agent 与 pytest 共用。"""
    try:
        plan = build_fix_plan(filename, new_code)
    except FixRejected as error:
        return f"拒绝：{error}"
    except (OSError, UnicodeError) as error:
        return f"文件读取失败：{type(error).__name__}"

    if not plan["diff"]:
        return "没有检测到代码变化。"

    if not approve(plan["diff"]):
        return "用户未批准，文件保持不变。"

    try:
        if plan["target"].read_text(encoding="utf-8") != plan["old_code"]:
            return "文件在审批期间发生变化，已取消修改；请重新生成方案。"
        backup = apply_code_fix(plan)
    except (OSError, UnicodeError) as error:
        return (
            f"写入失败，原文件未改变：{type(error).__name__}"
        )

    return (
        f"修改成功：{filename}\n"
        f"备份文件：{backup.name}\n"
        "请重新运行 Bandit 检查。"
    )


@function_tool
def propose_code_fix(
    filename: str,
    new_code: str
) -> str:
    """提出 Python 文件修复方案，展示差异并等待人工确认。"""
    return propose_code_fix_impl(filename, new_code)
