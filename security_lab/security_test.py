
import subprocess
import hashlib
import hmac
import os

# 示例1：硬编码密码
# 修复：从环境变量读取密码，避免凭据硬编码进源码与版本库
# 注意：延迟到调用时读取，避免 import 阶段因缺少 APP_PASSWORD
# 而抛出 KeyError（否则 pytest 收集和静态分析导入都会失败）。
# 语义仍是「缺失即失败」，只是失败点从 import 移到显式取用处。
def get_password():
    value = os.environ.get("APP_PASSWORD")
    if not value:
        raise RuntimeError("APP_PASSWORD 未设置，拒绝以空口令运行")
    return value

# 示例2：使用不安全的哈希算法
# 修复：改用 PBKDF2-HMAC-SHA256 + 随机盐 + 600000 次迭代
PBKDF2_ITERATIONS = 600000
PBKDF2_MIN_ITERATIONS = 600000
PBKDF2_MAX_ITERATIONS = 2000000


def hash_password(value):
    """使用 PBKDF2-HMAC-SHA256 生成加盐口令哈希。

    返回格式：pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode(),
        salt,
        PBKDF2_ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        salt.hex(),
        derived.hex(),
    )


def verify_password(value, stored):
    """校验明文口令与存储的哈希是否匹配。

    安全考量：
    1. 先校验存储串中的迭代次数是否在 [600000, 2000000] 区间内，
       超出范围直接返回 False，避免小迭代降价攻击与超大迭代导致的 DoS；
    2. 仅在迭代次数合法后才执行哈希计算；
    3. 使用 hmac.compare_digest 常量时间比较，避免计时侧信道。
    """
    try:
        algorithm, iterations, salt_hex, hash_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations)
        # 先检查迭代次数范围，再执行哈希计算
        if not (PBKDF2_MIN_ITERATIONS <= iterations <= PBKDF2_MAX_ITERATIONS):
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            value.encode(),
            salt,
            iterations,
        )
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(derived, expected)


# 示例3：不安全的命令执行配置
# 修复：只接受非空字符串参数列表，显式 shell=False，并设置超时
def run_command(command):
    if not isinstance(command, list) or not command:
        raise TypeError("command must be a non-empty list of arguments")
    if not all(isinstance(arg, str) for arg in command):
        raise TypeError("every command argument must be a string")
    return subprocess.run(
        command,
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
