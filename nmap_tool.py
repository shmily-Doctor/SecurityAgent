
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET

from agents import function_tool

from config import NMAP_DIR


# ==========================================
# 1. 扫描安全配置
# ==========================================

# 只允许扫描本机回环地址
ALLOWED_TARGET = "127.0.0.1"

# 固定扫描端口，不允许 AI 自行修改
ALLOWED_PORTS = "3000,5000,8000,8080"

# Python 子进程最长执行时间
SCAN_TIMEOUT = 45


# ==========================================
# 2. 定位 Nmap 可执行文件
# ==========================================

def find_nmap():
    """优先使用项目 vendor/nmap，其次回退系统 PATH。"""
    bundled = NMAP_DIR / "nmap.exe"

    if bundled.is_file():
        return str(bundled)

    return shutil.which("nmap")


# ==========================================
# 3. 解析 Nmap XML 扫描结果
# ==========================================

def parse_nmap_xml(xml_text: str) -> dict:
    """
    解析 Nmap XML 输出。

    返回开放端口、全部报告端口及统计信息。
    """

    root = ET.fromstring(xml_text)

    ports = []

    for port in root.findall(".//port"):

        protocol = port.get("protocol", "")
        port_number = int(port.get("portid", "0"))

        state_element = port.find("state")
        service_element = port.find("service")

        state = (
            state_element.get("state", "unknown")
            if state_element is not None
            else "unknown"
        )

        service_name = (
            service_element.get("name", "unknown")
            if service_element is not None
            else "unknown"
        )

        ports.append({
            "port": port_number,
            "protocol": protocol,
            "state": state,
            "service_name": service_name,
        })

    open_ports = [
        item for item in ports
        if item["state"] == "open"
    ]

    return {
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
        "all_reported_ports": ports,
    }


# ==========================================
# 4. SecurityAgent Nmap 工具
# ==========================================

@function_tool
def scan_network_target() -> str:
    """
    使用 Nmap 扫描本机固定 TCP 端口。

    安全限制：
    - 目标固定为 127.0.0.1
    - 端口固定为 3000,5000,8000,8080
    - 不允许自定义命令
    - 不进行漏洞利用
    - 不扫描其他主机
    """

    print("[Nmap] 正在准备本机端口检查")

    # 查找 Nmap 可执行文件：先项目内置，再 PATH
    nmap_path = find_nmap()

    if nmap_path is None:
        return json.dumps({
            "success": False,
            "error": "未找到 Nmap 可执行程序",
            "next_step": (
                "请把 Nmap 发行包放到 vendor/nmap 目录，"
                "或将其安装目录加入 PATH。"
            ),
        }, ensure_ascii=False)

    # 固定命令参数，避免任意命令执行
    command = [
        nmap_path,
        "-sT",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "-p",
        ALLOWED_PORTS,
        "-oX",
        "-",
        ALLOWED_TARGET,
    ]

    print(
        f"[Nmap] 扫描目标：{ALLOWED_TARGET}"
        f"；端口：{ALLOWED_PORTS}"
    )

    try:
        # 执行 Nmap
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            shell=False,
        )

        if result.returncode != 0:
            return json.dumps({
                "success": False,
                "error": "Nmap 执行失败",
                "details": result.stderr[-1000:],
            }, ensure_ascii=False)

        # 解析 XML
        parsed = parse_nmap_xml(result.stdout)

        # 构造报告
        report = {
            "success": True,
            "target": ALLOWED_TARGET,
            "scanned_ports": ALLOWED_PORTS,
            "scan_type": "TCP Connect",
            "service_detection": False,
            "open_port_count": parsed["open_port_count"],
            "open_ports": parsed["open_ports"],
            "all_reported_ports": parsed["all_reported_ports"],
            "note": (
                "仅扫描本机回环地址。"
                "服务名称通常来自端口默认映射，"
                "不代表已经进行版本探测。"
                "开放端口不等于存在漏洞。"
            ),
        }

        print(
            "[Nmap] 扫描完成，发现 "
            f"{parsed['open_port_count']} 个开放端口"
        )

        return json.dumps(
            report,
            ensure_ascii=False,
        )

    except subprocess.TimeoutExpired:
        return json.dumps({
            "success": False,
            "error": "Nmap 扫描超过时间限制",
        }, ensure_ascii=False)

    except ET.ParseError:
        return json.dumps({
            "success": False,
            "error": "Nmap 返回的 XML 格式不正确",
        }, ensure_ascii=False)

    except (OSError, ValueError) as error:
        return json.dumps({
            "success": False,
            "error": (
                "扫描或解析失败："
                f"{type(error).__name__}"
            ),
        }, ensure_ascii=False)
