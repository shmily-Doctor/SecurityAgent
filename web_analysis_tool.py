
import json
from urllib.parse import urlsplit, parse_qsl

from agents import function_tool

from config import clamp_text


MAX_SIZE = 20000

SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def split_quoted(text, separator=";"):
    """按分隔符拆分，但保留双引号内部的分隔符。"""
    parts = []
    buffer = []
    quoted = False
    escaped = False

    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\" and quoted:
            buffer.append(char)
            escaped = True
        elif char == '"':
            quoted = not quoted
            buffer.append(char)
        elif char == separator and not quoted:
            parts.append("".join(buffer).strip())
            buffer = []
        else:
            buffer.append(char)

    parts.append("".join(buffer).strip())
    return parts


def parse_message(raw):
    """解析 HTTP/1.x 文本，保留重复 Header。"""
    raw = raw.replace("\r\n", "\n")
    head, separator, _body = raw.partition("\n\n")

    lines = head.splitlines()

    if not lines or not lines[0].strip():
        raise ValueError("HTTP 消息缺少起始行")

    headers = {}

    for line in lines[1:]:
        if line.startswith((" ", "\t")):
            raise ValueError("暂不支持折叠的 HTTP Header")

        if ":" not in line:
            raise ValueError("HTTP Header 格式不正确")

        name, value = line.split(":", 1)
        name = name.strip().lower()

        if not name:
            raise ValueError("HTTP Header 名称不能为空")

        headers.setdefault(name, []).append(value.strip())

    return {
        "start_line": lines[0].strip(),
        "headers": headers,
        "has_body_separator": bool(separator),
    }


def first_header(headers, name):
    values = headers.get(name.lower(), [])
    return values[0] if values else ""


def parse_set_cookie(value):
    """解析一条 Set-Cookie，不返回 Cookie 的值。"""
    parts = split_quoted(value)

    if not parts or "=" not in parts[0]:
        return {
            "valid": False,
            "error": "Set-Cookie 缺少名称或等号",
        }

    name, _cookie_value = parts[0].split("=", 1)
    name = name.strip()

    if not name:
        return {
            "valid": False,
            "error": "Cookie 名称为空",
        }

    attributes = {}

    for part in parts[1:]:
        if not part:
            continue

        key, _, attr_value = part.partition("=")
        attributes[key.strip().lower()] = (
            attr_value.strip().strip('"')
        )

    return {
        "valid": True,
        "name": name,
        "attributes": attributes,
        "has_secure": "secure" in attributes,
        "has_httponly": "httponly" in attributes,
        "samesite": attributes.get("samesite", ""),
        "path": attributes.get("path", ""),
        "has_domain": "domain" in attributes,
    }


def make_finding(code, severity, issue, evidence, advice):
    return {
        "id": code,
        "severity": severity,
        "issue": issue,
        "evidence": evidence,
        "recommendation": advice,
    }


@function_tool
def analyze_http_exchange(
    raw_request: str,
    raw_response: str,
) -> str:
    """离线分析 HTTP/1.x 请求响应、重复头及 Cookie 安全属性。"""

    print("[Web 分析] 正在分析 HTTP 请求与响应")

    if (
        not isinstance(raw_request, str)
        or not isinstance(raw_response, str)
    ):
        return json.dumps({
            "success": False,
            "error": "输入必须是字符串",
        }, ensure_ascii=False)

    if (
        len(raw_request) > MAX_SIZE
        or len(raw_response) > MAX_SIZE
    ):
        return json.dumps({
            "success": False,
            "error": "HTTP 文本超过长度限制",
        }, ensure_ascii=False)

    try:
        request = parse_message(raw_request)
        response = parse_message(raw_response)

        request_line = request["start_line"].split()
        response_line = response["start_line"].split()

        if len(request_line) != 3:
            raise ValueError("请求行格式不正确")

        method, target, version = request_line

        if not version.startswith("HTTP/1."):
            raise ValueError("当前仅支持 HTTP/1.x 文本")

        if len(response_line) < 2:
            raise ValueError("响应状态行格式不正确")

        if not response_line[0].startswith("HTTP/1."):
            raise ValueError("当前仅支持 HTTP/1.x 文本")

        status_code = int(response_line[1])

        if not 100 <= status_code <= 599:
            raise ValueError("HTTP 状态码不正确")

        url = urlsplit(target)

        query_names = [
            name for name, _ in parse_qsl(
                url.query,
                keep_blank_values=True,
            )
        ]

        req_headers = request["headers"]
        resp_headers = response["headers"]

        findings = []
        cookies = []

        # URL 敏感参数
        sensitive_names = {
            "password", "passwd", "token",
            "access_token", "api_key", "secret",
        }

        for name in query_names:
            if name.lower() in sensitive_names:
                findings.append(make_finding(
                    "HTTP-001",
                    "MEDIUM",
                    "URL 包含敏感参数名",
                    f"参数名：{name}",
                    "避免在 URL 查询字符串中传输敏感凭据。",
                ))

        # HTML 安全响应头
        content_type = first_header(
            resp_headers, "content-type"
        ).lower()

        if "text/html" in content_type:
            if "content-security-policy" not in resp_headers:
                findings.append(make_finding(
                    "HTTP-002",
                    "INFO",
                    "HTML 响应未见 CSP",
                    "缺少 Content-Security-Policy",
                    "评估是否需要配置 CSP。",
                ))

            if "x-content-type-options" not in resp_headers:
                findings.append(make_finding(
                    "HTTP-003",
                    "LOW",
                    "未见 X-Content-Type-Options",
                    "缺少 nosniff 防护头",
                    "考虑设置 X-Content-Type-Options: nosniff。",
                ))

        # 多个 Set-Cookie 分别检查
        for value in resp_headers.get("set-cookie", []):
            cookie = parse_set_cookie(value)
            cookies.append(cookie)

            if not cookie["valid"]:
                findings.append(make_finding(
                    "HTTP-004",
                    "LOW",
                    "Set-Cookie 格式异常",
                    "存在无法解析的 Cookie",
                    "检查 Set-Cookie 语法。",
                ))
                continue

            name = cookie["name"]

            for attribute in ("secure", "httponly", "samesite"):
                present = (
                    cookie["has_secure"]
                    if attribute == "secure"
                    else cookie["has_httponly"]
                    if attribute == "httponly"
                    else bool(cookie["samesite"])
                )

                if not present:
                    findings.append(make_finding(
                        "HTTP-004",
                        "LOW",
                        f"Cookie 缺少 {attribute}",
                        f"Cookie 名称：{name}",
                        f"根据用途评估设置 {attribute}。",
                    ))

            samesite = cookie["samesite"].lower()

            if samesite and samesite not in {
                "strict", "lax", "none"
            }:
                findings.append(make_finding(
                    "HTTP-005",
                    "LOW",
                    "SameSite 属性值无效",
                    f"Cookie 名称：{name}",
                    "使用 Strict、Lax 或 None。",
                ))

            if samesite == "none" and not cookie["has_secure"]:
                findings.append(make_finding(
                    "HTTP-006",
                    "MEDIUM",
                    "SameSite=None 缺少 Secure",
                    f"Cookie 名称：{name}",
                    "为 SameSite=None 的 Cookie 设置 Secure。",
                ))

            if name.startswith("__Secure-") and not cookie["has_secure"]:
                findings.append(make_finding(
                    "HTTP-007",
                    "MEDIUM",
                    "__Secure- Cookie 缺少 Secure",
                    f"Cookie 名称：{name}",
                    "使用 Secure 并通过 HTTPS 设置 Cookie。",
                ))

            if name.startswith("__Host-"):
                if (
                    not cookie["has_secure"]
                    or cookie["path"] != "/"
                    or cookie["has_domain"]
                ):
                    findings.append(make_finding(
                        "HTTP-008",
                        "MEDIUM",
                        "__Host- Cookie 属性不符合约束",
                        f"Cookie 名称：{name}",
                        "要求 Secure、Path=/ 且不设置 Domain。",
                    ))

        duplicate_headers = {
            name: len(values)
            for name, values in resp_headers.items()
            if len(values) > 1
        }

        report = {
            "success": True,
            "request": {
                "method": method,
                "path": url.path,
                "query_parameter_names": query_names,
                "header_names": sorted(req_headers),
                "has_cookie": "cookie" in req_headers,
                "has_authorization": (
                    "authorization" in req_headers
                ),
            },
            "response": {
                "status_code": status_code,
                "content_type": content_type,
                "header_names": sorted(resp_headers),
                "duplicate_headers": duplicate_headers,
                "security_headers_present": [
                    label
                    for key, label in SECURITY_HEADERS.items()
                    if key in resp_headers
                ],
                "set_cookie_count": len(cookies),
                "cookies": cookies,
            },
            "total_findings": len(findings),
            "findings": findings,
            "note": (
                "仅进行离线静态分析；未发送网络请求。"
                "Cookie 值及正文不会出现在分析结果中。"
                "安全线索不等于已确认漏洞。"
            ),
        }

        print(
            "[Web 分析] 分析完成，发现 "
            f"{len(findings)} 项安全线索"
        )

        return clamp_text(json.dumps(report, ensure_ascii=False))

    except (ValueError, TypeError) as error:
        return json.dumps({
            "success": False,
            "error": str(error),
        }, ensure_ascii=False)
