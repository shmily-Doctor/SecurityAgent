
import subprocess
import sys

import pytest


@pytest.fixture
def target(monkeypatch):
    """为每项测试准备独立的演示环境。"""
    monkeypatch.setenv(
        "APP_PASSWORD",
        "securityagent-test-only"
    )

    from security_lab import security_test

    return security_test


def test_correct_password(target):
    """正确密码应验证成功。"""
    password_hash = target.hash_password("TestPassword123")

    assert target.verify_password(
        "TestPassword123",
        password_hash
    ) is True


def test_wrong_password(target):
    """错误密码必须验证失败。"""
    password_hash = target.hash_password("TestPassword123")

    assert target.verify_password(
        "WrongPassword",
        password_hash
    ) is False


def test_random_salt(target):
    """同一密码生成两次，哈希应当不同。"""
    first = target.hash_password("SamePassword")
    second = target.hash_password("SamePassword")

    assert first != second


def test_invalid_iterations(target):
    """异常大的迭代次数应被拒绝。"""
    password_hash = target.hash_password("TestPassword123")

    parts = password_hash.split("$")
    parts[1] = "999999999"

    invalid_hash = "$".join(parts)

    assert target.verify_password(
        "TestPassword123",
        invalid_hash
    ) is False


def test_valid_command(target, monkeypatch):
    """检查合法命令参数及安全配置，不实际启动子进程。"""

    def fake_run(args, **kwargs):
        assert args == [sys.executable, "--version"]
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 10

        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="Python test",
            stderr=""
        )

    monkeypatch.setattr(
        target.subprocess,
        "run",
        fake_run
    )

    result = target.run_command(
        [sys.executable, "--version"]
    )

    assert result.returncode == 0
    assert result.stdout == "Python test"


@pytest.mark.parametrize(
    "invalid_command",
    [
        "echo hello",
        [],
        ["python", 123],
        None,
    ]
)
def test_reject_invalid_command(target, invalid_command):
    """非法命令参数应触发 TypeError。"""
    with pytest.raises(TypeError):
        target.run_command(invalid_command)
