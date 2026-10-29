
"""项目级递归扫描实验文件。"""

import hashlib


def legacy_password_hash(password: str) -> str:
    """故意使用弱哈希，验证子目录扫描功能。"""
    return hashlib.md5(
        password.encode("utf-8")
    ).hexdigest()
