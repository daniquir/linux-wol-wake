import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, jsonify, request, Response,
                   session, redirect, url_for, abort)
from werkzeug.security import check_password_hash, generate_password_hash
from .models import db, Device
from .scanner import scan_network, get_local_network
from .wol import wake_device
from .onvif_helper import get_rtsp_candidates, move_camera, check_ptz_support
from .security import session_cookie_name, validate_scan_range, validate_rtsp_url

app = Flask(__name__)

# ── Secret key (persisted across restarts) ──────────────────────────────────
def _load_or_create_secret_key():
    key_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', '.secret_key')
    if os.environ.get('SECRET_KEY'):
        return os.environ['SECRET_KEY'].encode()
    if os.path.exists(key_path):
        return open(key_path, 'rb').read()
    key = secrets.token_bytes(32)
    with open(key_path, 'wb') as f:
        f.write(key)
    return key

app.config['SECRET_KEY'] = _load_or_create_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
# Secure cookies when behind TLS proxy. On plain HTTP (LAN), Secure must be false.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = session_cookie_name(app.config['SESSION_COOKIE_SECURE'])
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# ── Login credentials (env vars APP_USER / APP_PASSWORD) ────────────────────
_APP_USER = os.environ.get('APP_USER', 'admin')
_raw_password = os.environ.get('APP_PASSWORD')

def _validate_password_strength(pwd):
    if len(pwd) < 12:
        return False, 'Password must be at least 12 characters'
    if not re.search(r'[A-Z]', pwd):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', pwd):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'[0-9]', pwd):
        return False, 'Password must contain at least one digit'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-=\[\]\\;\'/+`~]', pwd):
        return False, 'Password must contain at least one special character'
    return True, None

if not _raw_password:
    _raw_password = secrets.token_urlsafe(16)
    print(
        f'\n{"="*60}\n'
        f'  APP_PASSWORD is not set.\n'
        f'  Temporary password: {_raw_password}\n'
        f'  Set APP_PASSWORD in .env to fix it.\n'
        f'  Password must be 12+ chars with upper, lower, digit, and symbol.\n'
        f'{"="*60}\n',
        flush=True
    )
else:
    valid, msg = _validate_password_strength(_raw_password)
    if not valid:
        print(
            f'\n{"="*60}\n'
            f'  WARNING: APP_PASSWORD does not meet security requirements:\n'
            f'  {msg}\n'
            f'  Change the password immediately.\n'
            f'{"="*60}\n',
            flush=True
        )

_APP_PASSWORD_HASH = generate_password_hash(_raw_password)

# ── Brute force protection ───────────────────────────────────────────────────
_login_attempts = {}
_MAX_ATTEMPTS = 5
_BLOCK_DURATION = 300  # 5 minutes

def _is_ip_blocked(ip):
    if ip in _login_attempts:
        attempts, blocked_until = _login_attempts[ip]
        if blocked_until and time.time() < blocked_until:
            return True
        if blocked_until and time.time() >= blocked_until:
            del _login_attempts[ip]
    return False

def _record_failed_login(ip):
    now = time.time()
    if ip not in _login_attempts:
        _login_attempts[ip] = (1, None)
    else:
        attempts, _ = _login_attempts[ip]
        attempts += 1
        if attempts >= _MAX_ATTEMPTS:
            _login_attempts[ip] = (attempts, now + _BLOCK_DURATION)
        else:
            _login_attempts[ip] = (attempts, None)

def _record_successful_login(ip):
    if ip in _login_attempts:
        del _login_attempts[ip]

# ── Security headers ─────────────────────────────────────────────────────────
@app.after_request
def _add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    return response

# ── Auth helpers ─────────────────────────────────────────────────────────────
@app.before_request
def _require_login():
    """Protect all routes except login/logout/static."""
    if request.endpoint in ('login_page', 'logout', 'static'):
        return None
    if not session.get('logged_in'):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not authenticated', 'login': '/login'}), 401
        return redirect(url_for('login_page', next=request.path))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    
    client_ip = request.remote_addr
    if _is_ip_blocked(client_ip):
        abort(429, description='Too many failed attempts. Try again in 5 minutes.')
    
    error = None
    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        pwd  = request.form.get('password', '')
        
        # Validación básica de entrada
        if not user or not pwd or len(user) > 128 or len(pwd) > 256:
            error = 'Invalid username or password'
            _record_failed_login(client_ip)
        elif user == _APP_USER and check_password_hash(_APP_PASSWORD_HASH, pwd):
            _record_successful_login(client_ip)
            session.permanent = True
            session['logged_in'] = True
            session['username'] = user
            next_url = request.args.get('next') or url_for('index')
            # Sanitizar next_url para evitar open redirect
            if not next_url.startswith('/'):
                next_url = url_for('index')
            return redirect(next_url)
        else:
            error = 'Invalid username or password'
            _record_failed_login(client_ip)
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ── SQLite ───────────────────────────────────────────────────────────────────
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'devices.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    # En desarrollo, si cambian las columnas, recreamos la base de datos
    # Comprobamos si la columna 'is_online' existe en la tabla 'device'
    inspector = db.inspect(db.engine)
    if 'device' in inspector.get_table_names():
        columns = [c['name'] for c in inspector.get_columns('device')]
        required_columns = ['is_online', 'alias', 'open_ports', 'is_manual_category', 'wol_reasons', 'is_onvif', 'onvif_user', 'onvif_password']
        if any(col not in columns for col in required_columns):
            db.drop_all()
            db.create_all()
    else:
        db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices', methods=['GET'])
def get_devices():
    devices = Device.query.all()
    return jsonify([d.to_dict() for d in devices])

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    network_range = data.get('range') or get_local_network()
    network_range, err = validate_scan_range(network_range)
    if err:
        return jsonify({'status': 'error', 'message': err}), 400
    found_devices = scan_network(network_range)
    
    # Marcar todos como offline antes del escaneo
    Device.query.update({Device.is_online: False})
    
    # Actualizar o insertar en la base de datos
    for d_info in found_devices:
        device = Device.query.filter_by(mac=d_info['mac']).first()
        if not device:
            # Si la MAC es Unknown, podemos intentar filtrar por IP pero es arriesgado
            if d_info['mac'] == 'Unknown':
                device = Device.query.filter_by(ip=d_info['ip']).first()
            
        if not device:
            device = Device(
                ip=d_info['ip'],
                mac=d_info['mac'],
                hostname=d_info['hostname'],
                vendor=d_info.get('vendor', 'Unknown'),
                category=d_info.get('category', 'Other'),
                is_online=True,
                open_ports=d_info.get('open_ports'),
                wol_enabled=d_info.get('wol_detected', False),
                wol_reasons=d_info.get('wol_reasons'),
                is_onvif=d_info.get('onvif_detected', False)
            )
            db.session.add(device)
        else:
            device.ip = d_info['ip']
            device.hostname = d_info['hostname']
            device.vendor = d_info.get('vendor', 'Unknown')
            # Solo actualizar la categoría si el usuario no la ha fijado manualmente
            if not getattr(device, 'is_manual_category', False):
                if d_info.get('category') and d_info['category'] != 'Other':
                    device.category = d_info['category']
            
            device.is_online = True
            device.open_ports = d_info.get('open_ports')
            device.last_seen = datetime.utcnow()
            # Si se detecta WoL y antes no estaba activado, lo activamos y guardamos razones
            if d_info.get('wol_detected'):
                device.wol_enabled = True
                device.wol_reasons = d_info.get('wol_reasons')
            
            # Actualizar detección ONVIF si es una cámara
            if d_info.get('onvif_detected'):
                device.is_onvif = True
            
            # Si el dispositivo ya existe y tiene WoL activado (por el usuario o detección previa),
            # nos aseguramos de que no se desactive accidentalmente por un escaneo menos preciso.
            # (Aunque en este script solo lo activamos, nunca lo desactivamos en el bucle 'else')
        
    db.session.commit()
    return jsonify({'status': 'ok', 'count': len(found_devices)})

@app.route('/api/toggle-wol/<int:device_id>', methods=['POST'])
def toggle_wol(device_id):
    device = Device.query.get_or_404(device_id)
    device.wol_enabled = not device.wol_enabled
    db.session.commit()
    return jsonify({'status': 'ok', 'wol_enabled': device.wol_enabled})

@app.route('/api/wake/<int:device_id>', methods=['POST'])
def wake(device_id):
    device = Device.query.get_or_404(device_id)
    if device.mac:
        success = wake_device(device.mac)
        return jsonify({'status': 'ok' if success else 'error'})
    return jsonify({'status': 'error', 'message': 'MAC address not found'}), 400

@app.route('/api/add-device', methods=['POST'])
def add_device():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400
    ip = data.get('ip')
    mac = data.get('mac')
    hostname = data.get('hostname', 'Manual Entry')
    alias = data.get('alias')
    category = data.get('category', 'Other')
    
    if not ip or not mac:
        return jsonify({'status': 'error', 'message': 'IP and MAC are required'}), 400
    
    # Normalizar MAC
    mac = mac.upper().replace('-', ':')
    
    device = Device.query.filter_by(mac=mac).first()
    if not device:
        device = Device(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor='Manual',
            alias=alias,
            category=category,
            is_manual_category=(category != 'Other'),
            is_online=False,
            wol_enabled=True,
            is_onvif=(category == 'Camera')
        )
        db.session.add(device)
    else:
        device.ip = ip
        device.hostname = hostname
        if alias: device.alias = alias
        if category: 
            device.category = category
            device.is_manual_category = True
            if category == 'Camera':
                device.is_onvif = True
        device.wol_enabled = True
        
    db.session.commit()
    return jsonify({'status': 'ok', 'device': device.to_dict()})

@app.route('/api/update-device/<int:device_id>', methods=['POST'])
def update_device(device_id):
    device = Device.query.get_or_404(device_id)
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400
    
    if 'alias' in data:
        device.alias = data['alias']
    if 'category' in data:
        device.category = data['category']
        device.is_manual_category = True
    if 'wol_enabled' in data:
        device.wol_enabled = data['wol_enabled']
    
    if 'is_onvif' in data:
        device.is_onvif = data['is_onvif']

    if 'onvif_user' in data:
        device.onvif_user = data['onvif_user']
    if 'onvif_password' in data:
        device.onvif_password = data['onvif_password']
        
    db.session.commit()
    return jsonify({'status': 'ok', 'device': device.to_dict()})

@app.route('/api/network-info', methods=['GET'])
def network_info():
    return jsonify({'range': get_local_network()})


@app.route('/api/camera-probe/<int:device_id>')
def camera_probe(device_id):
    """
    Finds the working RTSP URL for a camera using ffprobe.
    Returns {url, safe_url} on success, or {error, tried, port_open} for diagnostics.
    """
    import socket as _socket

    device = Device.query.get_or_404(device_id)

    # Check ffprobe availability
    ffprobe_ok = False
    try:
        subprocess.run(['ffprobe', '-version'], capture_output=True, check=True, timeout=3)
        ffprobe_ok = True
    except Exception:
        return jsonify({
            'error': 'ffmpeg/ffprobe is not installed. Rebuild the container with "docker compose build".'
        }), 503

    # Quick TCP test on common RTSP ports
    rtsp_ports = [554, 8554]
    port_open = None
    for p in rtsp_ports:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((device.ip, p))
            s.close()
            port_open = p
            break
        except Exception:
            pass

    candidates = get_rtsp_candidates(
        device.ip, device.open_ports, device.onvif_user, device.onvif_password
    )

    tried = []
    for url in candidates[:6]:
        safe = re.sub(r'(rtsp://[^:]+:)[^@]+(@)', r'\1***\2', url)
        try:
            result = subprocess.run(
                [
                    'ffprobe',
                    '-v', 'error',
                    '-rtsp_transport', 'tcp',
                    '-timeout', '2500000',
                    '-i', url,
                    '-show_entries', 'stream=codec_type',
                    '-of', 'json',
                ],
                capture_output=True,
                timeout=5,
            )
            stderr_msg = result.stderr.decode('utf-8', errors='ignore').strip()
            if result.returncode == 0 and b'video' in result.stdout:
                return jsonify({'url': url, 'safe_url': safe})
            tried.append({'url': safe, 'error': stderr_msg[:120] or f'returncode={result.returncode}'})
        except subprocess.TimeoutExpired:
            tried.append({'url': safe, 'error': 'Timeout (5s) — no response'})
        except Exception as e:
            tried.append({'url': safe, 'error': str(e)[:120]})

    port_msg = f'Port {port_open} open' if port_open else 'Ports 554/8554 closed or unreachable'
    return jsonify({
        'error': f'No stream found on {device.ip}. {port_msg}.',
        'port_open': port_open,
        'tried': tried,
    }), 404


@app.route('/api/camera-test-url', methods=['POST'])
def camera_test_url():
    """Tests an arbitrary RTSP URL provided by the user."""
    data = request.get_json(silent=True) or {}
    rtsp_url = data.get('url', '').strip()
    if not rtsp_url:
        return jsonify({'error': 'URL required'}), 400
    rtsp_url, err = validate_rtsp_url(rtsp_url)
    if err:
        return jsonify({'error': err}), 400
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-rtsp_transport', 'tcp',
                '-timeout', '3000000',
                '-i', rtsp_url,
                '-show_entries', 'stream=codec_type,codec_name,width,height',
                '-of', 'json',
            ],
            capture_output=True,
            timeout=6,
        )
        stderr_msg = result.stderr.decode('utf-8', errors='ignore').strip()
        if result.returncode == 0:
            import json as _json
            info = _json.loads(result.stdout.decode('utf-8', errors='ignore') or '{}')
            streams = info.get('streams', [])
            return jsonify({'ok': True, 'streams': streams})
        return jsonify({'ok': False, 'error': stderr_msg[:300] or f'returncode={result.returncode}'})
    except subprocess.TimeoutExpired:
        return jsonify({'ok': False, 'error': 'Timeout — no response in 6s'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/api/camera-stream/<int:device_id>')
def camera_stream(device_id):
    """
    Proxies the RTSP stream as MJPEG multipart.
    Uses image2pipe + manual JPEG frame splitting for maximum browser compatibility.
    Requires ?url=<rtsp_url>.
    """
    device = Device.query.get_or_404(device_id)
    rtsp_url = request.args.get('url', '').strip()
    if not rtsp_url:
        return jsonify({'error': 'url query parameter required. Call /api/camera-probe first.'}), 400
    rtsp_url, err = validate_rtsp_url(rtsp_url, expected_host=device.ip)
    if err:
        return jsonify({'error': err}), 400

    cmd = [
        'ffmpeg',
        '-rtsp_transport', 'tcp',
        '-timeout', '5000000',
        '-i', rtsp_url,
        '-an',
        '-vf', 'fps=5,scale=640:-2,format=yuvj420p',
        '-vcodec', 'mjpeg',
        '-f', 'image2pipe',
        '-q:v', '4',
        '-loglevel', 'quiet',
        'pipe:1',
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    BOUNDARY = b'--jpgboundary\r\nContent-Type: image/jpeg\r\n\r\n'
    JPEG_SOI = b'\xff\xd8'
    JPEG_EOI = b'\xff\xd9'

    def generate():
        buf = b''
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                # Extract and emit all complete JPEG frames from buffer
                while True:
                    start = buf.find(JPEG_SOI)
                    if start == -1:
                        buf = b''
                        break
                    end = buf.find(JPEG_EOI, start + 2)
                    if end == -1:
                        # Incomplete frame — keep buffer from SOI onwards
                        buf = buf[start:]
                        # Safety: drop if buffer grows excessively (corrupt stream)
                        if len(buf) > 2_000_000:
                            buf = b''
                        break
                    frame = buf[start:end + 2]
                    buf = buf[end + 2:]
                    yield BOUNDARY + frame + b'\r\n'
        except GeneratorExit:
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

    return Response(
        generate(),
        mimetype='multipart/x-mixed-replace; boundary=jpgboundary',
        headers={
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'X-Accel-Buffering': 'no',
        },
    )


@app.route('/api/camera-ptz-support/<int:device_id>', methods=['GET'])
def camera_ptz_support(device_id):
    """Check if the camera supports PTZ movement."""
    device = Device.query.get_or_404(device_id)
    if not device.is_onvif:
        return jsonify({'supported': False, 'error': 'Not an ONVIF camera'})

    supported = check_ptz_support(
        device.ip, device.open_ports, device.onvif_user, device.onvif_password
    )
    return jsonify({'supported': supported})


@app.route('/api/camera-ptz/<int:device_id>', methods=['POST'])
def camera_ptz_move(device_id):
    """
    Move the camera using PTZ.
    Expected JSON: {"direction": "up|down|left|right|zoom_in|zoom_out|stop", "speed": 0.5}
    """
    device = Device.query.get_or_404(device_id)
    if not device.is_onvif:
        return jsonify({'error': 'Not an ONVIF camera'}), 400

    data = request.json or {}
    direction = data.get('direction')
    speed = data.get('speed', 0.5)

    valid_directions = ['up', 'down', 'left', 'right', 'zoom_in', 'zoom_out', 'stop']
    if direction not in valid_directions:
        return jsonify({'error': f'Invalid direction. Use: {", ".join(valid_directions)}'}), 400

    # Clamp speed between 0.1 and 1.0
    speed = max(0.1, min(1.0, float(speed)))

    success = move_camera(
        device.ip, device.open_ports, device.onvif_user, device.onvif_password,
        direction=direction, speed=speed
    )

    if success:
        return jsonify({'status': 'ok', 'direction': direction, 'speed': speed})
    else:
        return jsonify({'error': 'PTZ command failed. Camera may not support PTZ or credentials may be incorrect.'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5055)
