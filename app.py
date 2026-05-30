"""
PKI de l'Université de Yaoundé I — INF4268
Master 1 SSI — Année académique 2025/2026
Système complet avec demande de certificat et workflow admin
"""
import os, random, secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import json

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR   = os.path.join(BASE_DIR, 'database')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

from modules.models import db, User, AuthorityCA, Certificate, CRLEntry, AuditLog, CertificateRequest
from modules.pki_engine import PKIEngine, REASONS_LABELS

app = Flask(__name__)
app.config['SECRET_KEY']                     = os.getenv('SECRET_KEY', 'pki-uy1-secret-2025')
app.config['SQLALCHEMY_DATABASE_URI']        = f"sqlite:///{os.path.join(DB_DIR, 'pki.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER']                  = UPLOAD_DIR
app.config['MAX_CONTENT_LENGTH']             = 5 * 1024 * 1024  # 5MB max

db.init_app(app)
login_manager              = LoginManager(app)
login_manager.login_view   = 'login'
login_manager.login_message= 'Veuillez vous connecter pour accéder à la plateforme PKI de l\'Université.'

CA_PASSWORD = os.getenv('CA_PASSWORD', 'UY1@2025Secure!CA').encode()
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

def add_log(action, title, details, icon='📋', color='#00d4ff'):
    try:
        uid   = current_user.id       if current_user.is_authenticated else None
        uname = current_user.username if current_user.is_authenticated else 'Système'
    except Exception:
        uid, uname = None, 'Système'
    log = AuditLog(action=action, title=title, details=details, icon=icon, color=color, username=uname, user_id=uid)
    db.session.add(log)
    db.session.commit()

def get_ca():
    return AuthorityCA.query.first()

def expiring_soon(days=30):
    limit = datetime.utcnow() + timedelta(days=days)
    return Certificate.query.filter(Certificate.status=='VALID', Certificate.expires_at!=None, Certificate.expires_at<=limit).count()

def init_database():
    db.create_all()
    
    # Créer admin si inexistant
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin', 
            email='admin@uy1.cm', 
            full_name='Administrateur PKI Université de Yaoundé I',
            role='admin',
            status_type='personnel',
            department='Département d\'Informatique',
            avatar_color='#c9a84c'
        )
        admin.set_password(os.getenv('ADMIN_PASSWORD', 'AdminUY1@2025'))
        db.session.add(admin)
        db.session.commit()
        
        add_log('SYSTEM', 'Système initialisé', 'Base de données et compte admin créés - Université de Yaoundé I', '🏛', '#a78bfa')

with app.app_context():
    init_database()

@app.context_processor
def inject_globals():
    ca = get_ca()
    notif_count = expiring_soon(30) if ca else 0
    pending_count = CertificateRequest.query.filter_by(status='PENDING').count() if ca and current_user.is_authenticated and current_user.is_admin() else 0
    return dict(
        ca_exists=bool(ca),
        notif_count=notif_count,
        pending_count=pending_count,
        reasons_labels=REASONS_LABELS,
        university_name="Université de Yaoundé I"
    )

# ==================== AUTHENTIFICATION ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('dashboard_admin'))
        return redirect(url_for('dashboard_user'))
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()
            add_log('LOGIN', 'Connexion réussie', f'Utilisateur {user.username} connecté', '👤', '#00e096')
            flash(f'Bienvenue sur la PKI de l\'Université de Yaoundé I, {user.display_name()} !', 'success')
            if user.is_admin():
                return redirect(url_for('dashboard_admin'))
            return redirect(url_for('dashboard_user'))
        flash('Identifiants incorrects.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username  = request.form.get('username','').strip()
        email     = request.form.get('email','').strip()
        password  = request.form.get('password','')
        full_name = request.form.get('full_name','').strip()
        matricule = request.form.get('matricule','').strip()
        age       = request.form.get('age', 0, type=int)
        department = request.form.get('department','').strip()
        status_type = request.form.get('status_type', 'etudiant')
        
        if User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris.", 'danger')
        elif User.query.filter_by(email=email).first():
            flash("Email déjà utilisé.", 'danger')
        elif len(password) < 6:
            flash("Mot de passe trop court (min 6 caractères).", 'danger')
        else:
            colors = ['#00d4ff','#00e096','#a78bfa','#f472b6','#fb923c']
            user = User(
                username=username, 
                email=email, 
                full_name=full_name,
                matricule=matricule,
                age=age,
                department=department,
                status_type=status_type,
                avatar_color=random.choice(colors)
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            add_log('REGISTER', 'Nouveau compte', f'Utilisateur {username} inscrit à la PKI UY1', '✦', '#00d4ff')
            flash('Compte créé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    add_log('LOGOUT', 'Déconnexion', f"{current_user.username} déconnecté", '↩', '#5a6080')
    logout_user()
    flash('Déconnecté avec succès.', 'info')
    return redirect(url_for('index'))

# ==================== DASHBOARDS ====================

@app.route('/dashboard/user')
@login_required
def dashboard_user():
    if current_user.is_admin():
        return redirect(url_for('dashboard_admin'))
    ca = get_ca()
    my_certs = Certificate.query.filter_by(user_id=current_user.id, status='VALID').order_by(Certificate.issued_at.desc()).all()
    pending_request = CertificateRequest.query.filter_by(user_id=current_user.id, status='PENDING').first()
    return render_template('dashboard_user.html', ca=ca, my_certs=my_certs, pending_request=pending_request)

@app.route('/dashboard/admin')
@login_required
def dashboard_admin():
    if not current_user.is_admin():
        return redirect(url_for('dashboard_user'))
    ca = get_ca()
    total_certs = Certificate.query.count()
    valid_certs = Certificate.query.filter_by(status='VALID').count()
    revoked_certs = Certificate.query.filter_by(status='REVOKED').count()
    pending_requests = CertificateRequest.query.filter_by(status='PENDING').count()
    total_users = User.query.count()
    recent_requests = CertificateRequest.query.filter_by(status='PENDING').order_by(CertificateRequest.created_at.desc()).limit(5).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
    return render_template('dashboard_admin.html', ca=ca, total_certs=total_certs, valid_certs=valid_certs, revoked_certs=revoked_certs, pending_requests=pending_requests, total_users=total_users, recent_requests=recent_requests, recent_logs=recent_logs)

# ==================== DEMANDES DE CERTIFICAT ====================

@app.route('/request-certificate', methods=['GET','POST'])
@login_required
def request_certificate():
    if current_user.is_admin():
        flash('Les administrateurs n\'ont pas besoin de demander de certificat.', 'info')
        return redirect(url_for('dashboard_admin'))
    
    existing_pending = CertificateRequest.query.filter_by(user_id=current_user.id, status='PENDING').first()
    if existing_pending:
        flash('Vous avez déjà une demande en attente de traitement. Veuillez patienter.', 'warning')
        return redirect(url_for('dashboard_user'))
    
    if request.method == 'POST':
        matricule = request.form.get('matricule', '').strip()
        full_name = request.form.get('full_name', '').strip()
        age = request.form.get('age', 0, type=int)
        department = request.form.get('department', '').strip()
        status_type = request.form.get('status_type', 'etudiant')
        
        # ====== Gestion améliorée du fichier justificatif ======
        filename = ''
        file_error = None
        
        if 'justification_file' in request.files:
            file = request.files['justification_file']
            if file and file.filename:  # Un fichier a été sélectionné
                
                # Vérifier l'extension
                if not allowed_file(file.filename):
                    file_error = f"Format de fichier non autorisé. Utilisez: {', '.join(ALLOWED_EXTENSIONS)}"
                else:
                    # Vérifier la taille (lire le fichier pour connaître sa taille réelle)
                    file.seek(0, 2)  # Aller à la fin
                    file_size = file.tell()
                    file.seek(0)      # Revenir au début
                    
                    if file_size > app.config['MAX_CONTENT_LENGTH']:
                        file_error = f"Le fichier est trop volumineux. Maximum {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)} Mo"
                    else:
                        # Tout est OK, sauvegarder
                        filename = secure_filename(f"{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        print(f"[DEBUG] Fichier sauvegardé: {filename} ({file_size} bytes)")  # Pour déboguer
            else:
                # Aucun fichier sélectionné, c'est optionnel donc pas d'erreur
                pass
        
        # Si une erreur de fichier s'est produite, on retourne au formulaire
        if file_error:
            flash(file_error, 'danger')
            return render_template('request_certificate.html')
        
        # Générer un numéro de demande unique
        request_number = f"DEM-{datetime.now().strftime('%Y%m%d')}-{secrets.randbelow(10000):04d}"
        
        cert_request = CertificateRequest(
            request_number=request_number,
            user_id=current_user.id,
            matricule=matricule if matricule else current_user.matricule,
            full_name=full_name if full_name else current_user.full_name,
            age=age if age else current_user.age,
            department=department if department else current_user.department,
            status_type=status_type,
            justification_file=filename,
            status='PENDING'
        )
        db.session.add(cert_request)
        db.session.commit()
        
        # Message de confirmation avec ou sans fichier
        if filename:
            flash(f'Votre demande a été envoyée avec le justificatif "{filename}". Vous serez notifié une fois traitée.', 'success')
        else:
            flash('Votre demande a été envoyée (sans pièce jointe). Vous serez notifié une fois traitée.', 'success')
        
        add_log('REQUEST_CERT', 'Demande de certificat', f"{current_user.username} a demandé un certificat ({request_number})", '📝', '#00d4ff')
        return redirect(url_for('dashboard_user'))
    
    return render_template('request_certificate.html')

@app.route('/debug/uploads')
@login_required
def debug_uploads():
    if not current_user.is_admin():
        return "Accès refusé", 403
    
    files = os.listdir(UPLOAD_DIR)
    return jsonify({
        'upload_dir': UPLOAD_DIR,
        'files': files,
        'count': len(files)
    })

@app.route('/admin/pending-requests')
@login_required
def pending_requests():
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration de l\'Université.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    requests = CertificateRequest.query.order_by(CertificateRequest.created_at.desc()).all()
    return render_template('pending_requests.html', requests=requests)

@app.route('/admin/approve-request/<int:req_id>', methods=['POST'])
@login_required
def approve_request(req_id):
    if not current_user.is_admin():
        flash('Accès refusé.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    cert_request = db.session.get(CertificateRequest, req_id)
    if not cert_request or cert_request.status != 'PENDING':
        flash('Demande introuvable ou déjà traitée.', 'danger')
        return redirect(url_for('pending_requests'))
    
    ca = get_ca()
    if not ca:
        flash('Aucune Autorité de Certification configurée.', 'danger')
        return redirect(url_for('admin_ca'))
    
    # Mettre à jour les infos de l'utilisateur
    user = cert_request.requester
    user.matricule = cert_request.matricule
    user.full_name = cert_request.full_name
    user.age = cert_request.age
    user.department = cert_request.department
    user.status_type = cert_request.status_type
    db.session.commit()
    
    # Émettre le certificat
    ca.serial_counter += 1
    serial = ca.serial_counter
    
    cert_pem, expires_at, serial_hex = PKIEngine.issue_certificate(
        ca_cert_pem=ca.cert_pem,
        ca_key_enc=ca.key_encrypted,
        ca_password=CA_PASSWORD,
        serial_number=serial,
        common_name=f"{user.full_name} ({user.username})",
        email=user.email,
        organisation="Université de Yaoundé I",
        department=user.department,
        status_type=user.status_type,
        validity_days=365
    )
    
    cert_obj = Certificate(
        serial_hex=serial_hex,
        serial_int=serial,
        common_name=user.full_name,
        email=user.email,
        organisation="Université de Yaoundé I",
        department=user.department,
        status_type=user.status_type,
        cert_pem=cert_pem,
        status='VALID',
        expires_at=expires_at,
        user_id=user.id,
        ca_id=ca.id,
        request_id=cert_request.id
    )
    db.session.add(cert_obj)
    
    # Mettre à jour la demande
    cert_request.status = 'APPROVED'
    cert_request.processed_at = datetime.utcnow()
    cert_request.processed_by = current_user.id
    cert_request.admin_notes = request.form.get('admin_notes', '')
    db.session.commit()
    
    add_log('APPROVE_REQUEST', 'Demande approuvée', f"Certificat émis pour {user.full_name} ({serial_hex})", '✅', '#00e096')
    flash(f'Certificat émis avec succès pour {user.full_name} !', 'success')
    return redirect(url_for('pending_requests'))

@app.route('/admin/reject-request/<int:req_id>', methods=['POST'])
@login_required
def reject_request(req_id):
    if not current_user.is_admin():
        flash('Accès refusé.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    cert_request = db.session.get(CertificateRequest, req_id)
    if not cert_request or cert_request.status != 'PENDING':
        flash('Demande introuvable ou déjà traitée.', 'danger')
        return redirect(url_for('pending_requests'))
    
    reject_reason = request.form.get('reject_reason', 'Non spécifiée')
    cert_request.status = 'REJECTED'
    cert_request.processed_at = datetime.utcnow()
    cert_request.processed_by = current_user.id
    cert_request.reject_reason = reject_reason
    db.session.commit()
    
    add_log('REJECT_REQUEST', 'Demande rejetée', f"Demande de {cert_request.requester.full_name} rejetée : {reject_reason[:50]}", '❌', '#ff3b5c')
    flash('Demande rejetée.', 'warning')
    return redirect(url_for('pending_requests'))

# ==================== GESTION DES CERTIFICATS ====================

@app.route('/certificates')
@login_required
def certificates():
    ca = get_ca()
    if current_user.is_admin():
        certs = Certificate.query.order_by(Certificate.issued_at.desc()).all()
    else:
        certs = Certificate.query.filter_by(user_id=current_user.id).order_by(Certificate.issued_at.desc()).all()
    return render_template('certificates.html', certs=certs, ca=ca)

@app.route('/certificates/revoke/<int:cert_id>', methods=['POST'])
@login_required
def revoke_certificate(cert_id):
    if not current_user.is_admin():
        flash('Seule l\'administration de l\'Université peut révoquer des certificats.', 'danger')
        return redirect(url_for('certificates'))
    
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        flash('Certificat introuvable.', 'danger')
        return redirect(url_for('certificates'))
    
    if cert.status == 'REVOKED':
        flash('Ce certificat est déjà révoqué.', 'warning')
        return redirect(url_for('certificates'))
    
    reason       = request.form.get('reason','key_compromise')
    reason_label = REASONS_LABELS.get(reason, reason)
    now          = datetime.now(timezone.utc)
    cert.status        = 'REVOKED'
    cert.revoked_at    = now
    cert.revoke_reason = reason
    crl_entry = CRLEntry(serial_int=cert.serial_int, serial_hex=cert.serial_hex, reason=reason, reason_label=reason_label, revoked_at=now, cert_cn=cert.common_name, cert_id=cert.id)
    db.session.add(crl_entry)
    db.session.commit()
    add_log('REVOKE_CERT', 'Certificat révoqué', f'{cert.common_name} · {reason_label}', '🗑', '#ff3b5c')
    flash(f'Certificat de {cert.common_name} révoqué ({reason_label}).', 'warning')
    return redirect(url_for('certificates'))

@app.route('/certificates/<int:cert_id>/download')
@login_required
def download_cert(cert_id):
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        flash('Certificat introuvable.', 'danger')
        return redirect(url_for('certificates'))
    if not current_user.is_admin() and cert.user_id != current_user.id:
        flash('Accès refusé.', 'danger')
        return redirect(url_for('certificates'))
    
    from io import BytesIO
    buf = BytesIO(cert.cert_pem.encode())
    safe_cn = cert.common_name.replace(' ', '_').replace('/', '_')
    add_log('DOWNLOAD_CERT', 'Certificat téléchargé', f'Certificat de {cert.common_name} téléchargé', '⬇', '#00d4ff')
    return send_file(buf, as_attachment=True, download_name=f'certificat_{safe_cn}.pem', mimetype='application/x-pem-file')

# ==================== VÉRIFICATION ====================

# ==================== VÉRIFICATION ====================

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    if not current_user.is_admin():
        flash('La vérification de certificats est réservée à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))

    result = None
    mode = None  # 'search' ou 'pem'

    if request.method == 'POST':
        ca = get_ca()
        if not ca:
            flash('Aucune AC configurée.', 'danger')
            return render_template('verify.html', result=None, mode=None)

        revoked_serials = [e.serial_int for e in CRLEntry.query.all()]
        revoked_reasons = {e.serial_int: e.reason_label for e in CRLEntry.query.all()}

        # ── MODE 1 : Recherche par numéro de série / nom ──
        if request.form.get('mode') == 'search':
            mode = 'search'
            q = request.form.get('serial_input', '').strip()

            if not q:
                flash('Veuillez entrer un numéro de série, un nom ou un email.', 'warning')
                return render_template('verify.html', result=None, mode=None)

            cert_obj = None
            try:
                cert_obj = Certificate.query.filter_by(serial_int=int(q)).first()
            except ValueError:
                pass
            if not cert_obj:
                cert_obj = Certificate.query.filter(Certificate.serial_hex.ilike(f'%{q}%')).first()
            if not cert_obj:
                cert_obj = Certificate.query.filter(Certificate.common_name.ilike(f'%{q}%')).first()
            if not cert_obj:
                cert_obj = Certificate.query.filter(Certificate.email.ilike(f'%{q}%')).first()

            if not cert_obj:
                flash(f'Aucun certificat trouvé pour « {q} ».', 'danger')
                return render_template('verify.html', result=None, mode=None)

            result = PKIEngine.verify_certificate(
                cert_pem=cert_obj.cert_pem,
                ca_cert_pem=ca.cert_pem,
                revoked_serials=revoked_serials
            )
            result['cert_obj'] = cert_obj
            result['search_query'] = q

            # Ajouter la raison de révocation si révoqué
            if not result['valid'] and cert_obj.serial_int in revoked_reasons:
                result['revoke_reason_label'] = revoked_reasons[cert_obj.serial_int]

            add_log(
                'VERIFY_CERT',
                'Vérification certificat (recherche)',
                f'{cert_obj.common_name} → {"✓ VALIDE" if result["valid"] else "✗ INVALIDE"}',
                '🔍', '#00d4ff'
            )

        # ── MODE 2 : Vérification par PEM brut collé ──
        elif request.form.get('mode') == 'pem':
            mode = 'pem'
            pem_input = request.form.get('pem_input', '').strip()

            if not pem_input:
                flash('Veuillez coller le contenu PEM du certificat.', 'warning')
                return render_template('verify.html', result=None, mode=None)

            result = PKIEngine.verify_certificate_from_pem(
                cert_pem_input=pem_input,
                ca_cert_pem=ca.cert_pem,
                revoked_serials=revoked_serials
            )
            result['pem_input'] = pem_input

            # Chercher si ce certificat existe en base (par numéro de série)
            if 'serial' in result and result.get('serial'):
                cert_obj = Certificate.query.filter_by(serial_int=result['serial']).first()
                if cert_obj:
                    result['cert_obj'] = cert_obj
                    if cert_obj.serial_int in revoked_reasons:
                        result['revoke_reason_label'] = revoked_reasons[cert_obj.serial_int]

            add_log(
                'VERIFY_CERT',
                'Vérification certificat (PEM externe)',
                f'CN={result.get("subject", "Inconnu")} → {"✓ VALIDE" if result.get("valid") else "✗ INVALIDE"}',
                '🔍', '#a78bfa'
            )

    return render_template('verify.html', result=result, mode=mode)

# ==================== CRL ====================

@app.route('/crl')
@login_required
def view_crl():
    if not current_user.is_admin():
        flash('La liste de révocation est accessible uniquement à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    crl_entries = CRLEntry.query.order_by(CRLEntry.revoked_at.desc()).all()
    ca = get_ca()
    return render_template('crl.html', crl_entries=crl_entries, ca=ca)

# ==================== ADMIN CA ====================

@app.route('/admin/ca')
@login_required
def admin_ca():
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration de l\'Université.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    ca = get_ca()
    bench = PKIEngine.benchmark_keygen(2048, runs=3)
    return render_template('admin_ca.html', ca=ca, bench=bench)

@app.route('/admin/create-ca', methods=['POST'])
@login_required
def create_ca():
    if not current_user.is_admin():
        flash('Accès refusé.', 'danger')
        return redirect(url_for('admin_ca'))
    
    if get_ca():
        flash('L\'Autorité de Certification de l\'Université existe déjà.', 'warning')
        return redirect(url_for('admin_ca'))
    
    name        = request.form.get('ca_name', 'Université de Yaoundé I').strip()
    country     = request.form.get('ca_country', 'CM').strip()[:2].upper()
    city        = request.form.get('ca_city', 'Yaoundé').strip()
    org         = request.form.get('ca_org', 'Université de Yaoundé I').strip()
    department  = request.form.get('ca_dept', 'Département d\'Informatique').strip()
    unit        = request.form.get('ca_unit', 'INF4268 - Master 1 SSI').strip()
    email       = request.form.get('ca_email', 'contact@uy1.cm').strip()
    
    cert_pem, key_enc, valid_until, fp = PKIEngine.generate_root_ca(
        common_name=name,
        country=country,
        city=city,
        organisation=org,
        department=department,
        unit=unit,
        email=email,
        password=CA_PASSWORD,
        key_size=2048,
        validity_years=10
    )
    
    ca = AuthorityCA(
        name=name,
        country=country,
        city=city,
        organisation=org,
        department=department,
        unit=unit,
        email=email,
        cert_pem=cert_pem,
        key_encrypted=key_enc,
        fingerprint=fp,
        valid_until=valid_until,
        created_by=current_user.id
    )
    db.session.add(ca)
    db.session.commit()
    
    add_log('CREATE_CA', 'AC créée : Université de Yaoundé I', 
            f'RSA-2048/SHA-256 · Valide jusqu\'au {valid_until.strftime("%d/%m/%Y")}', '🏛', '#c9a84c')
    flash('L\'Autorité de Certification de l\'Université de Yaoundé I a été créée avec succès !', 'success')
    return redirect(url_for('admin_ca'))

# ==================== AUTRES PAGES ADMIN ====================

@app.route('/audit')
@login_required
def audit():
    if not current_user.is_admin():
        flash('Le journal d\'audit est réservé à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('audit.html', logs=logs)

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', all_users=all_users)

@app.route('/admin/promote/<int:uid>', methods=['POST'])
@login_required
def promote_user(uid):
    if not current_user.is_admin():
        flash('Accès refusé.', 'danger')
        return redirect(url_for('admin'))
    
    user = db.session.get(User, uid)
    if not user:
        flash('Utilisateur introuvable.', 'danger')
        return redirect(url_for('users'))
    
    if user.id == current_user.id:
        flash('Impossible de modifier votre propre rôle.', 'warning')
        return redirect(url_for('users'))
    
    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    add_log('PROMOTE', f'Rôle modifié : {user.username}', f'Nouveau rôle : {user.role.upper()}', '⚙', '#a78bfa')
    flash(f'Rôle de {user.username} → {user.role.upper()}.', 'success')
    return redirect(url_for('users'))

@app.route('/profile')
@login_required
def profile():
    my_certs = Certificate.query.filter_by(user_id=current_user.id).order_by(Certificate.issued_at.desc()).all()
    my_requests = CertificateRequest.query.filter_by(user_id=current_user.id).order_by(CertificateRequest.created_at.desc()).all()
    my_logs  = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.created_at.desc()).limit(20).all()
    return render_template('profile.html', my_certs=my_certs, my_requests=my_requests, my_logs=my_logs)

# ==================== APIS ====================

@app.route('/api/ca-cert.pem')
def download_ca_cert():
    ca = get_ca()
    if not ca:
        return 'Aucune autorité de certification configurée', 404
    from io import BytesIO
    add_log('DOWNLOAD_CA', 'CA Cert téléchargé', "Certificat de l'Université téléchargé", '⬇', '#00d4ff')
    buf = BytesIO(ca.cert_pem.encode())
    return send_file(buf, as_attachment=True, download_name='universite_yaounde_I_ca.pem', mimetype='application/x-pem-file')

# Dans app.py, modifiez la route /api/crl.pem :

@app.route('/api/crl.pem')
def download_crl():
    ca = get_ca()
    if not ca:
        return 'No CA configured', 404
    
    entries = CRLEntry.query.all()
    revoked_list = [(e.serial_int, e.reason, e.revoked_at) for e in entries]
    
    try:
        crl_pem = PKIEngine.generate_crl(
            ca_cert_pem=ca.cert_pem,
            ca_key_enc=ca.key_encrypted,
            ca_password=CA_PASSWORD,
            revoked_list=revoked_list
        )
    except Exception as e:
        print(f"Erreur génération CRL: {e}")
        flash("Erreur lors de la génération de la CRL", "danger")
        return redirect(url_for('view_crl'))
    
    from io import BytesIO
    add_log('DOWNLOAD_CRL', 'CRL téléchargée', f'CRL téléchargée ({len(entries)} entrées)', '📋', '#c9a84c')
    
    buf = BytesIO(crl_pem.encode())
    return send_file(
        buf, 
        as_attachment=True, 
        download_name='crl_uy1.pem', 
        mimetype='application/x-pem-file'  # ou 'application/x-x509-crl'
    )

@app.route('/certificates/<int:cert_id>/view')
@login_required
def view_certificate(cert_id):
    """Page de visualisation magnifique du certificat numérique officiel"""
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        flash('Certificat introuvable.', 'danger')
        return redirect(url_for('certificates'))
    if not current_user.is_admin() and cert.user_id != current_user.id:
        flash('Accès refusé.', 'danger')
        return redirect(url_for('certificates'))

    ca = get_ca()
    add_log('VIEW_CERT', 'Certificat consulté',
            f'Certificat de {cert.common_name} visualisé (#{cert.serial_hex})',
            '👁', '#c9a84c')
    return render_template('certificate_view.html', cert=cert, ca=ca)

@app.route('/certificates/<int:cert_id>/print')
@login_required
def print_certificate(cert_id):
    """Page d'impression/PDF propre — sans sidebar ni navigation"""
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        flash('Certificat introuvable.', 'danger')
        return redirect(url_for('certificates'))
    if not current_user.is_admin() and cert.user_id != current_user.id:
        flash('Accès refusé.', 'danger')
        return redirect(url_for('certificates'))

    ca = get_ca()
    add_log('PRINT_CERT', 'Certificat imprimé/PDF',
            f'Certificat de {cert.common_name} exporté en PDF (#{cert.serial_hex})',
            '🖨', '#c9a84c')
    return render_template('certificate_print.html', cert=cert, ca=ca)

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify({
        'total': Certificate.query.count(),
        'valid': Certificate.query.filter_by(status='VALID').count(),
        'revoked': Certificate.query.filter_by(status='REVOKED').count(),
        'expiring': expiring_soon(30),
        'crl_size': CRLEntry.query.count(),
        'pending_requests': CertificateRequest.query.filter_by(status='PENDING').count()
    })

# ── CRL en PDF (page d'impression officielle) ──
@app.route('/crl/print')
@login_required
def print_crl():
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))

    from datetime import timezone, timedelta
    ca = get_ca()
    if not ca:
        flash('Aucune AC configurée.', 'danger')
        return redirect(url_for('view_crl'))

    crl_entries = CRLEntry.query.order_by(CRLEntry.revoked_at.desc()).all()
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=7)

    add_log('PRINT_CRL', 'CRL exportée en PDF',
            f'CRL exportée ({len(crl_entries)} entrées)',
            '📋', '#c9a84c')
    return render_template('crl_print.html',
                           crl_entries=crl_entries,
                           ca=ca,
                           now=now,
                           next_update=next_update)


# ── Certificat CA en PDF (page d'impression officielle) ──
@app.route('/admin/ca/print')
@login_required
def print_ca():
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))

    ca = get_ca()
    if not ca:
        flash('Aucune AC configurée.', 'danger')
        return redirect(url_for('admin_ca'))

    add_log('PRINT_CA', 'Certificat CA exporté en PDF',
            'Document officiel de l\'Autorité de Certification exporté',
            '🏛', '#c9a84c')
    return render_template('ca_print.html', ca=ca)


# ── CRL en texte brut lisible (format humain, pas PEM binaire) ──
@app.route('/api/crl.txt')
@login_required
def download_crl_txt():
    """CRL en format texte lisible par un humain"""
    if not current_user.is_admin():
        return 'Accès refusé', 403

    from datetime import timezone, timedelta
    ca = get_ca()
    if not ca:
        return 'Aucune AC configurée', 404

    entries = CRLEntry.query.order_by(CRLEntry.revoked_at.desc()).all()
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=7)

    lines = []
    lines.append('=' * 70)
    lines.append('  LISTE DE RÉVOCATION DES CERTIFICATS (CRL)')
    lines.append('  Université de Yaoundé I — INF4268 — M1 SSI')
    lines.append('=' * 70)
    lines.append(f'  Émetteur       : {ca.name}')
    lines.append(f'  Organisation   : {ca.organisation}')
    lines.append(f'  Pays           : {ca.country}')
    lines.append(f'  Email          : {ca.email}')
    lines.append(f'  Algorithme     : {ca.algorithm}')
    lines.append(f'  Empreinte CA   : {ca.fingerprint[:32]}...')
    lines.append(f'  thisUpdate     : {now.strftime("%d/%m/%Y %H:%M UTC")}')
    lines.append(f'  nextUpdate     : {next_update.strftime("%d/%m/%Y %H:%M UTC")}')
    lines.append(f'  Conformité     : RFC 5280 / X.509 v2')
    lines.append('=' * 70)
    lines.append(f'  Nombre de certificats révoqués : {len(entries)}')
    lines.append('=' * 70)

    if entries:
        lines.append('')
        lines.append('  CERTIFICATS RÉVOQUÉS :')
        lines.append('')
        for i, e in enumerate(entries, 1):
            lines.append(f'  [{i:03d}] Série (HEX)    : {e.serial_hex}')
            lines.append(f'        Titulaire       : {e.cert_cn or "—"}')
            lines.append(f'        Date révocation : {e.revoked_at.strftime("%d/%m/%Y %H:%M UTC")}')
            lines.append(f'        Motif (RFC5280) : {e.reason_label or e.reason}')
            lines.append('')
    else:
        lines.append('')
        lines.append('  Aucun certificat révoqué — Liste vide.')
        lines.append('')

    lines.append('=' * 70)
    lines.append('  Ce document est généré automatiquement par la PKI UY1.')
    lines.append('  Pour la CRL au format PEM (usage technique/OpenSSL),')
    lines.append('  téléchargez le fichier crl_uy1.pem depuis l\'interface admin.')
    lines.append('=' * 70)

    content = '\n'.join(lines)

    from io import BytesIO
    buf = BytesIO(content.encode('utf-8'))
    add_log('DOWNLOAD_CRL_TXT', 'CRL texte téléchargée',
            f'CRL lisible téléchargée ({len(entries)} entrées)',
            '📋', '#c9a84c')
    return send_file(buf, as_attachment=True,
                     download_name='crl_uy1_lisible.txt',
                     mimetype='text/plain; charset=utf-8')


# ── Certificat CA en PDF pour les utilisateurs (lecture seule) ──
@app.route('/user/ca/print')
@login_required
def user_print_ca():
    """Version publique du certificat CA pour les utilisateurs"""
    ca = get_ca()
    if not ca:
        flash('Aucune AC configurée.', 'danger')
        return redirect(url_for('dashboard_user'))

    add_log('PRINT_CA_USER', 'Certificat CA consulté (utilisateur)',
            f'Utilisateur {current_user.username} a consulté le certificat CA',
            '🏛', '#c9a84c')
    return render_template('ca_print.html', ca=ca)


# ── CRL en PDF pour les utilisateurs (lecture seule) ──
@app.route('/user/crl/print')
@login_required
def user_print_crl():
    """Version publique de la CRL pour les utilisateurs"""
    from datetime import timezone, timedelta
    
    ca = get_ca()
    if not ca:
        flash('Aucune AC configurée.', 'danger')
        return redirect(url_for('dashboard_user'))

    crl_entries = CRLEntry.query.order_by(CRLEntry.revoked_at.desc()).all()
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=7)

    add_log('PRINT_CRL_USER', 'CRL consultée (utilisateur)',
            f'Utilisateur {current_user.username} a consulté la CRL ({len(crl_entries)} entrées)',
            '📋', '#c9a84c')
    return render_template('crl_print.html',
                           crl_entries=crl_entries,
                           ca=ca,
                           now=now,
                           next_update=next_update)

@app.route('/demo/signature')
@login_required
def demo_signature():
    """Démonstration de signature numérique"""
    return render_template('demo_signature.html')

@app.route('/demo/verify-signature', methods=['POST'])
@login_required
def verify_signature_demo():
    """API de vérification de signature pour la démo"""
    data = request.json
    document = data.get('document', '')
    certificate_id = data.get('certificate_id')
    
    # Récupérer le certificat
    cert = Certificate.query.get(certificate_id)
    if not cert:
        return jsonify({'valid': False, 'error': 'Certificat non trouvé'})
    
    # Vérifier si révoqué
    revoked = CRLEntry.query.filter_by(serial_int=cert.serial_int).first()
    
    # Vérifier la signature (simulée)
    # Dans un cas réel, on vérifierait la signature cryptographique
    
    return jsonify({
        'valid': not bool(revoked),
        'revoked': bool(revoked),
        'certificate': {
            'owner': cert.common_name,
            'serial': cert.serial_hex,
            'expires': cert.expires_at.strftime('%d/%m/%Y')
        },
        'reason': revoked.reason_label if revoked else None
    })

@app.route('/certificates/<int:cert_id>/download-key')
@login_required
def download_private_key(cert_id):
    """⚠️ ATTENTION: Uniquement pour démo !"""
    if not current_user.is_admin():
        flash('Accès refusé.', 'danger')
        return redirect(url_for('certificates'))
    
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        flash('Certificat introuvable.', 'danger')
        return redirect(url_for('certificates'))
    
    # ⚠️ Ceci est dangereux - ne faites jamais cela en production !
    # Pour la démo, on génère une clé factice
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = fake_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    from io import BytesIO
    buf = BytesIO(key_pem)
    return send_file(buf, as_attachment=True, download_name=f'private_key_{cert.id}.pem', mimetype='application/x-pem-file')

# ── TÉLÉCHARGEMENT DE LA PIÈCE JOINTE D'UNE DEMANDE ──
@app.route('/admin/request/<int:req_id>/download-file')
@login_required
def download_request_file(req_id):
    """Télécharger le fichier justificatif d'une demande"""
    if not current_user.is_admin():
        flash('Accès réservé à l\'administration.', 'danger')
        return redirect(url_for('dashboard_user'))
    
    cert_request = db.session.get(CertificateRequest, req_id)
    if not cert_request:
        flash('Demande introuvable.', 'danger')
        return redirect(url_for('pending_requests'))
    
    if not cert_request.justification_file:
        flash('Aucune pièce jointe pour cette demande.', 'warning')
        return redirect(url_for('pending_requests'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], cert_request.justification_file)
    
    if not os.path.exists(filepath):
        flash(f'Le fichier {cert_request.justification_file} est introuvable sur le serveur.', 'danger')
        return redirect(url_for('pending_requests'))
    
    # Déterminer le type MIME
    ext = cert_request.justification_file.rsplit('.', 1)[1].lower()
    mime_types = {
        'pdf': 'application/pdf',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png'
    }
    mime_type = mime_types.get(ext, 'application/octet-stream')
    
    add_log('DOWNLOAD_REQUEST_FILE', 'Pièce jointe téléchargée',
            f'Fichier {cert_request.justification_file} téléchargé pour la demande {cert_request.request_number}',
            '📎', '#c9a84c')
    
    return send_file(filepath, as_attachment=True, download_name=cert_request.justification_file, mimetype=mime_type)

@app.route('/debug/pending-files')
@login_required
def debug_pending_files():
    """Debug: voir les demandes et leurs fichiers"""
    if not current_user.is_admin():
        return "Accès refusé", 403
    
    requests = CertificateRequest.query.all()
    result = []
    for req in requests:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], req.justification_file) if req.justification_file else None
        result.append({
            'id': req.id,
            'request_number': req.request_number,
            'justification_file': req.justification_file,
            'status': req.status,
            'file_exists': os.path.exists(filepath) if filepath else False,
            'filepath': str(filepath) if filepath else None
        })
    
    return jsonify(result)

if __name__ == '__main__':
    print("="*70)
    print("  🏛️  PKI - UNIVERSITÉ DE YAOUNDÉ I  🏛️")
    print("  INF4268 — Cryptographie Asymétrique — Master 1 SSI 2025/2026")
    print("="*70)
    print("  🌐 Application disponible sur : http://localhost:5000")
    print("  👑 Compte Administrateur : admin / AdminUY1@2025")
    print("="*70)
    app.run(debug=True, port=5000)

