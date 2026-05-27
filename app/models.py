from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False)
    mac = db.Column(db.String(17), unique=True, nullable=False)
    hostname = db.Column(db.String(100), nullable=True)
    vendor = db.Column(db.String(100), nullable=True)
    alias = db.Column(db.String(100), nullable=True)
    category = db.Column(db.String(50), nullable=True, default='Unknown')
    is_manual_category = db.Column(db.Boolean, default=False)
    wol_enabled = db.Column(db.Boolean, default=False)
    wol_reasons = db.Column(db.String(500), nullable=True)  # Heuristic WoL detection reasons
    is_online = db.Column(db.Boolean, default=False)
    open_ports = db.Column(db.String(200), nullable=True)  # Comma-separated open ports
    is_onvif = db.Column(db.Boolean, default=False)
    onvif_user = db.Column(db.String(100), nullable=True)
    onvif_password = db.Column(db.String(100), nullable=True)
    last_seen = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'alias': self.alias,
            'category': self.category,
            'is_manual_category': self.is_manual_category,
            'wol_enabled': self.wol_enabled,
            'wol_reasons': self.wol_reasons,
            'is_online': self.is_online,
            'open_ports': self.open_ports,
            'is_onvif': self.is_onvif,
            'onvif_user': self.onvif_user,
            'last_seen': self.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        }
