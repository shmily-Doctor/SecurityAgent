
from web_analysis_tool import (
    parse_message,
    parse_set_cookie,
    split_quoted,
)


def test_duplicate_headers():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: a=1; Secure\r\n"
        "Set-Cookie: b=2; HttpOnly\r\n"
        "\r\n"
    )

    result = parse_message(raw)

    assert len(result["headers"]["set-cookie"]) == 2


def test_cookie_attributes():
    result = parse_set_cookie(
        "session=demo; Path=/; Secure; HttpOnly; SameSite=Lax"
    )

    assert result["valid"] is True
    assert result["name"] == "session"
    assert result["has_secure"] is True
    assert result["has_httponly"] is True
    assert result["samesite"] == "Lax"


def test_insecure_cookie():
    result = parse_set_cookie(
        "session=demo; Path=/"
    )

    assert result["has_secure"] is False
    assert result["has_httponly"] is False
    assert result["samesite"] == ""


def test_quoted_semicolon():
    result = split_quoted(
        'session="a;b"; Path=/; HttpOnly'
    )

    assert len(result) == 3
    assert result[0] == 'session="a;b"'


def test_cookie_value_is_not_returned():
    result = parse_set_cookie(
        "session=secret-example; Secure"
    )

    assert "secret-example" not in str(result)


def test_host_cookie_attributes():
    result = parse_set_cookie(
        "__Host-session=demo; Secure; Path=/"
    )

    assert result["name"] == "__Host-session"
    assert result["has_secure"] is True
    assert result["path"] == "/"
    assert result["has_domain"] is False
