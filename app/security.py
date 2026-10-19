"""Shared security validations."""
import ipaddress
from urllib.parse import urlparse


def session_cookie_name(secure: bool) -> str:
    """Cookie name for Flask sessions.

    ``__Host-`` requires Secure; browsers drop it on plain HTTP.
    """
    return '__Host-session' if secure else 'wol_session'


def escape_xml(text):
    if text is None:
        return ''
    return (
        str(text)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&apos;')
    )


def is_private_or_local_host(host):
    if not host:
        return False
    host = host.strip().lower()
    if host in ('localhost',):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def validate_scan_range(network_range):
    """Only private/local networks with prefix /22 or longer."""
    if not network_range or not isinstance(network_range, str):
        return None, 'Invalid network range'
    try:
        net = ipaddress.ip_network(network_range.strip(), strict=False)
    except ValueError:
        return None, 'Invalid network range'
    if net.prefixlen < 22:
        return None, 'Range too large (maximum /22)'
    if not (net.is_private or net.is_link_local):
        return None, 'Only private or link-local networks are allowed'
    return str(net), None


def validate_rtsp_url(url, expected_host=None):
    if not url or not isinstance(url, str):
        return None, 'Invalid URL'
    url = url.strip()
    if len(url) > 2048:
        return None, 'URL too long'
    parsed = urlparse(url)
    if parsed.scheme != 'rtsp':
        return None, 'Only rtsp:// URLs are allowed'
    host = parsed.hostname
    if not host or not is_private_or_local_host(host):
        return None, 'Only private network hosts are allowed'
    if expected_host and host.lower() != expected_host.lower():
        return None, 'URL does not match the device'
    return url, None
