"""
Modèles de données pour la PKI de l'Université de Yaoundé I
INF4268 — Cryptographie Asymétrique — Master 1 SSI 2025/2026
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import random

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    full_name     = db.Column(db.String(128), default='')
    matricule     = db.Column(db.String(50), default='')
    age           = db.Column(db.Integer, default=0)
    department    = db.Column(db.String(128), default='')
    status_type   = db.Column(db.String(30), default='etudiant')
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20), default='user')
    avatar_color  = db.Column(db.String(20), default='#00d4ff')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime, nullable=True)
    certificates  = db.relationship('Certificate', backref='owner', lazy=True)
    logs          = db.relationship('AuditLog', backref='user_ref', lazy=True)
    requests      = db.relationship('CertificateRequest', 
                                   foreign_keys='CertificateRequest.user_id',
                                   backref='requester', lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def is_admin(self):
        return self.role == 'admin'

    def display_name(self):
        return self.full_name if self.full_name else self.username

    def initials(self):
        n = self.display_name()
        parts = n.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[-1][0]).upper()
        return n[:2].upper()

    def get_status_label(self):
        labels = {
            'etudiant': '🎓 Étudiant',
            'enseignant': '👨‍🏫 Enseignant',
            'personnel': '👔 Personnel'
        }
        return labels.get(self.status_type, '📝 Autre')


class CertificateRequest(db.Model):
    """Demande de certificat (workflow admin)"""
    __tablename__ = 'certificate_requests'
    id            = db.Column(db.Integer, primary_key=True)
    request_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    matricule     = db.Column(db.String(50), nullable=False)
    full_name     = db.Column(db.String(128), nullable=False)
    age           = db.Column(db.Integer, default=0)
    department    = db.Column(db.String(128), nullable=False)
    status_type   = db.Column(db.String(30), nullable=False)
    justification_file = db.Column(db.String(256), default='')
    admin_notes   = db.Column(db.Text, default='')
    status        = db.Column(db.String(20), default='PENDING')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at  = db.Column(db.DateTime, nullable=True)
    processed_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reject_reason = db.Column(db.Text, default='')
    
    processor = db.relationship('User', 
                               foreign_keys=[processed_by],
                               backref='processed_requests')
    
    # CORRECTION : Relation one-to-one avec Certificate
    certificate = db.relationship('Certificate', 
                                  back_populates='request', 
                                  uselist=False,
                                  foreign_keys='Certificate.request_id')

    def get_status_badge(self):
        badges = {
            'PENDING': ('⏳ EN ATTENTE', 'badge-pending'),
            'APPROVED': ('✅ APPROUVÉE', 'badge-approved'),
            'REJECTED': ('❌ REJETÉE', 'badge-rejected')
        }
        return badges.get(self.status, ('❓ INCONNU', 'badge-unknown'))
    
    def get_status_label(self):
        labels = {
            'etudiant': '🎓 Étudiant',
            'enseignant': '👨‍🏫 Enseignant',
            'personnel': '👔 Personnel'
        }
        return labels.get(self.status_type, '📝 Autre')


class AuthorityCA(db.Model):
    """Autorité de Certification - Université de Yaoundé I"""
    __tablename__ = 'authority_ca'
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(128), nullable=False, default='Université de Yaoundé I')
    country        = db.Column(db.String(4),   default='CM')
    city           = db.Column(db.String(64),  default='Yaoundé')
    organisation   = db.Column(db.String(128), default='Université de Yaoundé I')
    department     = db.Column(db.String(128), default='Département d\'Informatique')
    unit           = db.Column(db.String(128), default='INF4268 - Master 1 SSI')
    email          = db.Column(db.String(120), default='contact@uy1.cm')
    cert_pem       = db.Column(db.Text,         nullable=False)
    key_encrypted  = db.Column(db.LargeBinary,  nullable=False)
    fingerprint    = db.Column(db.String(255),  default='')
    serial_counter = db.Column(db.Integer,      default=1000)
    valid_from     = db.Column(db.DateTime,     default=datetime.utcnow)
    valid_until    = db.Column(db.DateTime,     nullable=True)
    algorithm      = db.Column(db.String(64),   default='RSA-2048 / SHA-256')
    created_at     = db.Column(db.DateTime,     default=datetime.utcnow)
    created_by     = db.Column(db.Integer,      db.ForeignKey('users.id'))


class Certificate(db.Model):
    """Certificats émis par l'Université de Yaoundé I"""
    __tablename__ = 'certificates'
    id            = db.Column(db.Integer, primary_key=True)
    serial_hex    = db.Column(db.String(32),  unique=True, nullable=False)
    serial_int    = db.Column(db.Integer,     unique=True, nullable=False)
    common_name   = db.Column(db.String(128), nullable=False)
    email         = db.Column(db.String(120), default='')
    organisation  = db.Column(db.String(128), default='Université de Yaoundé I')
    department    = db.Column(db.String(128), default='')
    status_type   = db.Column(db.String(30), default='etudiant')
    cert_pem      = db.Column(db.Text,         nullable=False)
    status        = db.Column(db.String(20),   default='VALID')
    issued_at     = db.Column(db.DateTime,     default=datetime.utcnow)
    expires_at    = db.Column(db.DateTime,     nullable=True)
    revoked_at    = db.Column(db.DateTime,     nullable=True)
    revoke_reason = db.Column(db.String(64),   nullable=True)
    user_id       = db.Column(db.Integer,      db.ForeignKey('users.id'))
    ca_id         = db.Column(db.Integer,      db.ForeignKey('authority_ca.id'))
    ca            = db.relationship('AuthorityCA', backref='issued_certs')
    request_id    = db.Column(db.Integer,      db.ForeignKey('certificate_requests.id'), nullable=True)
    
    # CORRECTION : Relation one-to-one avec CertificateRequest
    request = db.relationship('CertificateRequest', 
                              back_populates='certificate', 
                              foreign_keys=[request_id])

    def status_badge(self):
        return {
            'VALID':   ('✓ VALIDE',   'badge-valid'),
            'REVOKED': ('✗ RÉVOQUÉ',  'badge-revoked'),
            'EXPIRED': ('⚠ EXPIRÉ',   'badge-expired'),
        }.get(self.status, (self.status, ''))

    def days_until_expiry(self):
        if not self.expires_at:
            return None
        now = datetime.utcnow()
        delta = (self.expires_at - now).days
        return delta


class CRLEntry(db.Model):
    """Liste de Révocation des Certificats"""
    __tablename__ = 'crl_entries'
    id            = db.Column(db.Integer, primary_key=True)
    serial_int    = db.Column(db.Integer, nullable=False)
    serial_hex    = db.Column(db.String(32), default='')
    reason        = db.Column(db.String(64), default='key_compromise')
    reason_label  = db.Column(db.String(128), default='')
    revoked_at    = db.Column(db.DateTime, default=datetime.utcnow)
    cert_cn       = db.Column(db.String(128), default='')
    cert_id       = db.Column(db.Integer, db.ForeignKey('certificates.id'))


class AuditLog(db.Model):
    """Journal d'audit"""
    __tablename__ = 'audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    action     = db.Column(db.String(64))
    icon       = db.Column(db.String(10), default='📋')
    color      = db.Column(db.String(20), default='#00d4ff')
    title      = db.Column(db.String(128), default='')
    details    = db.Column(db.Text, default='')
    username   = db.Column(db.String(64), default='')
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)