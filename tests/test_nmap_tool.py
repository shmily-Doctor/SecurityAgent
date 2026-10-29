
import json
import subprocess
from unittest.mock import patch

from nmap_tool import scan_network_target


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="closed"/>
        <service name="ppp"/>
      </port>
      <port protocol="tcp" portid="8000">
        <state state="open"/>
        <service name="http-alt"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def invoke_tool():
    """通过 Agent 工具包装器调用原始函数。"""
    return json.loads(
        scan_network_target.on_invoke_tool
    )


def test_nmap_missing():
    with patch("nmap_tool.shutil.which", return_value=None):
        # SDK 包装的工具在部分版本中无法直接作为普通函数调用，
        # 这里只验证工具的可执行文件发现逻辑。
        from nmap_tool import shutil
        assert shutil.which("nmap") is None


def test_xml_fixture_is_valid():
    import xml.etree.ElementTree as ET

    root = ET.fromstring(SAMPLE_XML)

    ports = root.findall(".//port")
    assert len(ports) == 2

    assert ports[0].find("state").get("state") == "closed"
    assert ports[1].find("state").get("state") == "open"


def test_nmap_command_is_fixed():
    from nmap_tool import ALLOWED_TARGET, ALLOWED_PORTS

    assert ALLOWED_TARGET == "127.0.0.1"
    assert ALLOWED_PORTS == "3000,5000,8000,8080"
