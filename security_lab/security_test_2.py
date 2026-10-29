
"""SecurityAgent 多文件安全扫描练习。

本文件故意包含不安全代码，仅用于 Bandit 静态分析。
不要将这些函数用于真实业务系统。
"""

import hashlib
import pickle
import tempfile


# 示例1：弱哈希算法
def calculate_hash(data):
    return hashlib.md5(
        data.encode()
    ).hexdigest()


# 示例2：不安全的反序列化
def deserialize_data(data):
    return pickle.loads(data)


# 示例3：不安全的临时文件
def create_temp_filename():
    return tempfile.mktemp()
