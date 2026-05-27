import hashlib
import base64
import os
import datetime
import re
import requests
from urllib.parse import urlparse, quote
from .security import escape_xml


def _wsse_header(user, password):
    nonce_bytes = os.urandom(16)
    created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    nonce_b64 = base64.b64encode(nonce_bytes).decode()
    digest_raw = nonce_bytes + created.encode('utf-8') + password.encode('utf-8')
    digest = base64.b64encode(hashlib.sha1(digest_raw).digest()).decode()
    return (
        '<Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"'
        ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '<UsernameToken>'
        f'<Username>{escape_xml(user)}</Username>'
        f'<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>'
        f'<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</Nonce>'
        f'<wsu:Created>{created}</wsu:Created>'
        '</UsernameToken></Security>'
    )


def _soap_envelope(body, security=''):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f'<s:Header>{security}</s:Header>'
        f'<s:Body>{body}</s:Body>'
        '</s:Envelope>'
    )


def _post_soap(url, body, user=None, password=None, timeout=2):
    security = _wsse_header(user, password) if (user and password) else ''
    envelope = _soap_envelope(body, security)
    for content_type in ['application/soap+xml; charset=utf-8', 'text/xml; charset=utf-8']:
        try:
            r = requests.post(
                url, data=envelope,
                headers={'Content-Type': content_type, 'SOAPAction': ''},
                timeout=timeout
            )
            if r.status_code < 500:
                return r.text
        except Exception:
            pass
    return None


def _extract_first_profile_token(xml):
    """Extracts the first media profile token from a GetProfiles SOAP response."""
    # Attribute form: token="MainStream"
    m = re.search(r'\btoken\s*=\s*["\']([^"\']+)["\']', xml)
    if m:
        return m.group(1)
    # Element form: <ProfileToken>...</ProfileToken>
    m = re.search(r'<[^>]*[Pp]rofile[Tt]oken[^>]*>([^<]+)</', xml)
    if m:
        return m.group(1)
    return None


def _extract_uri(xml):
    """Extracts the URI value from a GetStreamUri / GetSnapshotUri response."""
    m = re.search(r'<[^>]*[Uu][Rr][Ii][^>]*>\s*([^\s<]+)\s*</', xml)
    return m.group(1).strip() if m else None


def _inject_credentials(rtsp_url, user, password):
    """Inserts user:pass into an RTSP URL if not already present."""
    if not user or not password:
        return rtsp_url
    parsed = urlparse(rtsp_url)
    if parsed.username:
        return rtsp_url  # already has credentials
    cred = f'{quote(user, safe="")}:{quote(password, safe="")}@'
    return rtsp_url.replace(f'{parsed.scheme}://', f'{parsed.scheme}://{cred}', 1)


def _try_onvif(ip, port, user, password):
    """
    Tries to get the main RTSP stream URI from the camera via ONVIF SOAP.
    Returns rtsp_url string or None.
    """
    auth_user = user or 'admin'
    auth_pass = password or ''

    for path in ['/onvif/device_service', '/onvif/media_service', '/onvif/media2']:
        onvif_url = f'http://{ip}:{port}{path}'
        profiles_xml = _post_soap(
            onvif_url,
            '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
            auth_user, auth_pass
        )
        if not profiles_xml:
            continue

        token = _extract_first_profile_token(profiles_xml)
        if not token:
            continue

        stream_xml = _post_soap(
            onvif_url,
            f'<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">'
            f'<StreamSetup>'
            f'<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>'
            f'<Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport>'
            f'</StreamSetup>'
            f'<ProfileToken>{escape_xml(token)}</ProfileToken>'
            f'</GetStreamUri>',
            auth_user, auth_pass
        )
        if not stream_xml:
            continue

        uri = _extract_uri(stream_xml)
        if uri and uri.startswith('rtsp://'):
            return _inject_credentials(uri, user, password)

    return None


def get_rtsp_candidates(ip, open_ports_str=None, user=None, password=None):
    """
    Returns an ordered list of RTSP URL candidates to try, starting with
    the ONVIF-discovered URL and followed by common fallback patterns.
    """
    ports = open_ports_str.split(',') if open_ports_str else []
    # ONVIF discovery ports in preference order
    onvif_http_ports = [p for p in ['8899', '8080', '80', '2020'] if p in ports]
    if not onvif_http_ports:
        onvif_http_ports = ['80', '8080', '8899']

    candidates = []

    # 1. ONVIF SOAP discovery
    for http_port in onvif_http_ports[:3]:
        uri = _try_onvif(ip, http_port, user, password)
        if uri and uri not in candidates:
            candidates.append(uri)
            break  # Use the first working ONVIF result

    # 2. Common fallback patterns
    cred = ''
    if user and password:
        cred = f'{quote(user, safe="")}:{quote(password, safe="")}@'
    elif user:
        cred = f'{quote(user, safe="")}@'

    fallbacks = [
        f'rtsp://{cred}{ip}:554/Streaming/Channels/101',        # Hikvision main
        f'rtsp://{cred}{ip}:554/cam/realmonitor?channel=1&subtype=0',  # Dahua main
        f'rtsp://{cred}{ip}:554/stream1',                        # Generic
        f'rtsp://{cred}{ip}:554/h264Preview_01_main',            # Reolink
        f'rtsp://{cred}{ip}:554/h264',
        f'rtsp://{cred}{ip}:554/live',
        f'rtsp://{cred}{ip}:554/',
        f'rtsp://{cred}{ip}:554/onvif1',
    ]
    for fb in fallbacks:
        if fb not in candidates:
            candidates.append(fb)

    return candidates


def _extract_ptz_profile_token(xml):
    """Extracts the PTZ profile token from a GetProfiles or GetConfigurations SOAP response."""
    # Look for PTZConfiguration token
    m = re.search(r'<PTZConfiguration[^>]*token\s*=\s*["\']([^"\']+)["\']', xml)
    if m:
        return m.group(1)
    # Alternative: look for PTZConfiguration element with token attribute
    m = re.search(r'<[^>]*[Pp][Tt][Zz][Cc]onfiguration[^>]*>([^<]+)</', xml)
    if m:
        return m.group(1).strip()
    # Fallback: return the first profile token
    return _extract_first_profile_token(xml)


def _try_ptz_move(ip, port, user, password, pan, tilt, zoom, profile_token=None):
    """
    Sends a ContinuousMove command via ONVIF PTZ service.
    Returns True if successful, False otherwise.
    """
    auth_user = user or 'admin'
    auth_pass = password or ''

    ptz_paths = ['/onvif/ptz_service', '/onvif/ptz', '/onvif/device_service']

    for path in ptz_paths:
        ptz_url = f'http://{ip}:{port}{path}'

        # If no profile token provided, try to get one
        if not profile_token:
            # Try to get profiles from media service
            media_url = f'http://{ip}:{port}/onvif/media_service'
            profiles_xml = _post_soap(
                media_url,
                '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
                auth_user, auth_pass
            )
            if profiles_xml:
                profile_token = _extract_first_profile_token(profiles_xml)

        if not profile_token:
            continue

        # Build Velocity element
        velocity = '<Velocity>'
        if pan != 0 or tilt != 0:
            velocity += f'<PanTilt xmlns="http://www.onvif.org/ver10/schema" x="{pan}" y="{tilt}"/>'
        if zoom != 0:
            velocity += f'<Zoom xmlns="http://www.onvif.org/ver10/schema" x="{zoom}"/>'
        velocity += '</Velocity>'

        move_body = (
            '<ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl">'
            f'<ProfileToken>{escape_xml(profile_token)}</ProfileToken>'
            f'{velocity}'
            '<Timeout>PT1S</Timeout>'
            '</ContinuousMove>'
        )

        response = _post_soap(ptz_url, move_body, auth_user, auth_pass)
        if response and ('ContinuousMoveResponse' in response or 'OK' in response or response.strip().endswith('>')):
            return True

    return False


def _try_ptz_stop(ip, port, user, password, profile_token=None, pantilt=True, zoom=True):
    """
    Sends a Stop command via ONVIF PTZ service to halt movement.
    Returns True if successful, False otherwise.
    """
    auth_user = user or 'admin'
    auth_pass = password or ''

    ptz_paths = ['/onvif/ptz_service', '/onvif/ptz', '/onvif/device_service']

    for path in ptz_paths:
        ptz_url = f'http://{ip}:{port}{path}'

        # If no profile token provided, try to get one
        if not profile_token:
            media_url = f'http://{ip}:{port}/onvif/media_service'
            profiles_xml = _post_soap(
                media_url,
                '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
                auth_user, auth_pass
            )
            if profiles_xml:
                profile_token = _extract_first_profile_token(profiles_xml)

        if not profile_token:
            continue

        stop_body = (
            '<Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl">'
            f'<ProfileToken>{escape_xml(profile_token)}</ProfileToken>'
            f'<PanTilt>{"true" if pantilt else "false"}</PanTilt>'
            f'<Zoom>{"true" if zoom else "false"}</Zoom>'
            '</Stop>'
        )

        response = _post_soap(ptz_url, stop_body, auth_user, auth_pass)
        if response and ('StopResponse' in response or 'OK' in response or response.strip().endswith('>')):
            return True

    return False


def check_ptz_support(ip, open_ports_str=None, user=None, password=None):
    """
    Checks if the camera supports PTZ by attempting to get PTZ configurations.
    Returns True if PTZ is supported, False otherwise.
    """
    ports = open_ports_str.split(',') if open_ports_str else []
    onvif_http_ports = [p for p in ['8899', '8080', '80', '2020'] if p in ports] or ['80', '8080', '8899']

    auth_user = user or 'admin'
    auth_pass = password or ''

    for port in onvif_http_ports[:2]:
        # Try to get PTZ configurations
        ptz_url = f'http://{ip}:{port}/onvif/ptz_service'
        configs_xml = _post_soap(
            ptz_url,
            '<GetConfigurations xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
            auth_user, auth_pass
        )
        if configs_xml and ('PTZConfiguration' in configs_xml or 'Configuration' in configs_xml):
            return True

        # Alternative: check if PTZ node exists
        nodes_xml = _post_soap(
            ptz_url,
            '<GetNodes xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
            auth_user, auth_pass
        )
        if nodes_xml and 'PTZNode' in nodes_xml:
            return True

    return False


def move_camera(ip, open_ports_str=None, user=None, password=None, direction=None, speed=0.5):
    """
    Moves the camera in the specified direction.
    direction: 'up', 'down', 'left', 'right', 'zoom_in', 'zoom_out', 'stop'
    speed: 0.0 to 1.0
    Returns True if successful.
    """
    ports = open_ports_str.split(',') if open_ports_str else []
    onvif_http_ports = [p for p in ['8899', '8080', '80', '2020'] if p in ports] or ['80', '8080', '8899']

    # Map direction to pan/tilt values
    pan, tilt, zoom = 0, 0, 0
    if direction == 'left':
        pan = -speed
    elif direction == 'right':
        pan = speed
    elif direction == 'up':
        tilt = speed
    elif direction == 'down':
        tilt = -speed
    elif direction == 'zoom_in':
        zoom = speed
    elif direction == 'zoom_out':
        zoom = -speed
    elif direction == 'stop':
        # Stop all movement
        for port in onvif_http_ports[:2]:
            if _try_ptz_stop(ip, port, user, password, pantilt=True, zoom=True):
                return True
        return False

    # Send move command
    for port in onvif_http_ports[:2]:
        if _try_ptz_move(ip, port, user, password, pan, tilt, zoom):
            return True

    return False


def get_snapshot_url(ip, open_ports_str=None, user=None, password=None):
    """
    Tries to get a snapshot URI via ONVIF. Returns URL string or None.
    """
    ports = open_ports_str.split(',') if open_ports_str else []
    onvif_http_ports = [p for p in ['8899', '8080', '80'] if p in ports] or ['80', '8080']
    auth_user = user or 'admin'
    auth_pass = password or ''

    for port in onvif_http_ports[:2]:
        onvif_url = f'http://{ip}:{port}/onvif/device_service'
        profiles_xml = _post_soap(
            onvif_url,
            '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
            auth_user, auth_pass
        )
        if not profiles_xml:
            continue
        token = _extract_first_profile_token(profiles_xml)
        if not token:
            continue
        snap_xml = _post_soap(
            onvif_url,
            f'<GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl">'
            f'<ProfileToken>{escape_xml(token)}</ProfileToken></GetSnapshotUri>',
            auth_user, auth_pass
        )
        if snap_xml:
            uri = _extract_uri(snap_xml)
            if uri:
                return uri
    return None
