"""Happy/unhappy: session cookie name vs Secure flag."""
from app.security import session_cookie_name


def test_https_uses_host_prefix():
    assert session_cookie_name(True) == '__Host-session'


def test_http_avoids_host_prefix():
    assert session_cookie_name(False) == 'wol_session'
