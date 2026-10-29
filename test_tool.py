
import json
import os
import subprocess
import sys

from agents import function_tool

from config import PROJECT_DIR, TESTS_DIR, tail_text

# 只允许执行这一个预设测试文件
TEST_FILE = TESTS_DIR / "test_security_test.py"


@function_tool
def run_security_tests(filename: str) -> str:
    """运行 security_test.py 的预设 pytest 功能测试，并返回真实测试结果。"""

    print(f"[自动测试工具] 正在测试：{filename}")

    # 防止模型传入任意文件路径
    if filename != "security_test.py":
        return json.dumps(
            {
                "success": False,
                "error": "当前只允许测试 security_test.py",
            },
            ensure_ascii=False,
        )

    if not TEST_FILE.is_file():
        return json.dumps(
            {
                "success": False,
                "error": "找不到预设测试文件",
            },
            ensure_ascii=False,
        )

    # 构造测试环境：使用演示密码
    # 不把模型 API Key 传给测试进程
    allowed_env = ("SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP", "LANG")
    test_env = {key: os.environ[key] for key in allowed_env if key in os.environ}
    test_env["APP_PASSWORD"] = "securityagent-test-only"

    # 限制自动加载第三方 pytest 插件
    test_env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                str(TEST_FILE),
            ],
            cwd=str(PROJECT_DIR),
            env=test_env,
            capture_output=True,
            text=True,
            timeout=90,
            shell=False,
        )

        success = result.returncode == 0

        print(
            "[自动测试工具] "
            + ("测试通过" if success else "测试未通过")
        )

        return json.dumps(
            {
                "success": success,
                "filename": filename,
                "return_code": result.returncode,
                "test_output": tail_text(result.stdout),
                "error_output": tail_text(result.stderr, 3000),
            },
            ensure_ascii=False,
        )

    except subprocess.TimeoutExpired:
        return json.dumps(
            {
                "success": False,
                "error": "pytest 执行超过 90 秒",
            },
            ensure_ascii=False,
        )

    except OSError as error:
        return json.dumps(
            {
                "success": False,
                "error": f"执行失败：{type(error).__name__}",
            },
            ensure_ascii=False,
        )
