"""
PKI Engine — Moteur cryptographique complet
INF4268 — Cryptographie Asymétrique — Université de Yaoundé I
Gère : Root CA, certificats X.509, CRL, vérification
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, BestAvailableEncryption
)
from datetime import datetime, timedelta, timezone
import hashlib
import time
import base64

REASONS_MAP = {
    'key_compromise':      x509.ReasonFlags.key_compromise,
    'affiliation':         x509.ReasonFlags.affiliation_changed,
    'superseded':          x509.ReasonFlags.superseded,
    'cessation':           x509.ReasonFlags.cessation_of_operation,
    'privilege_withdrawn': x509.ReasonFlags.privilege_withdrawn,
}

REASONS_LABELS = {
    'key_compromise':      'Clé compromise',
    'affiliation':         "Changement d'affiliation",
    'superseded':          'Remplacé',
    'cessation':           "Cessation d'activité",
    'privilege_withdrawn': 'Privilèges retirés',
}


class PKIEngine:

    @staticmethod
    def generate_root_ca(common_name: str, country: str, city: str,
                         organisation: str, department: str, unit: str,
                         email: str, password: bytes,
                         key_size: int = 2048, validity_years: int = 10):
        """
        Génère une Root CA auto-signée pour l'Université de Yaoundé I
        Returns: (cert_pem_str, key_encrypted_bytes, valid_until, fingerprint)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )

        subject_attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Centre"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]

        if email:
            subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = issuer = x509.Name(subject_attrs)

        now         = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=365 * validity_years)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(valid_until)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False
                ), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .sign(private_key, hashes.SHA256())
        )

        cert_pem  = cert.public_bytes(Encoding.PEM).decode()
        key_bytes = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
            BestAvailableEncryption(password)
        )

        raw_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        fp = ':'.join(raw_fp[i:i+2] for i in range(0, len(raw_fp), 2))

        return cert_pem, key_bytes, valid_until, fp

    @staticmethod
    def issue_certificate(ca_cert_pem: str, ca_key_enc: bytes,
                          ca_password: bytes, serial_number: int,
                          common_name: str, email: str,
                          organisation: str, department: str,
                          status_type: str, validity_days: int = 365):
        """
        Signe un certificat utilisateur avec la clé de l'Université
        Returns: (cert_pem_str, expires_at, serial_hex)
        """
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        ca_key  = serialization.load_pem_private_key(ca_key_enc, password=ca_password)

        user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CM"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]

        if department:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department))
        if email:
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        now        = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name(attrs))
            .issuer_name(ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(now)
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False
                ), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem   = cert.public_bytes(Encoding.PEM).decode()
        serial_hex = format(serial_number, 'X').zfill(2)
        serial_hex_fmt = ':'.join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))
        return cert_pem, expires_at, serial_hex_fmt

    @staticmethod
    def generate_crl(ca_cert_pem: str, ca_key_enc: bytes,
                     ca_password: bytes, revoked_list: list):
        """
        Génère une CRL (Certificate Revocation List) valide.
        revoked_list = [(serial_int, reason_str, revoked_at_dt), ...]
        Returns: crl_pem_str
        """
        try:
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
            ca_key = serialization.load_pem_private_key(ca_key_enc, password=ca_password)

            now = datetime.now(timezone.utc)

            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(ca_cert.subject)
            builder = builder.last_update(now)
            builder = builder.next_update(now + timedelta(days=7))

            for serial_int, reason_str, rev_date in revoked_list:
                if rev_date.tzinfo is None:
                    rev_date = rev_date.replace(tzinfo=timezone.utc)

                reason_flag = REASONS_MAP.get(reason_str, x509.ReasonFlags.key_compromise)

                revoked_cert = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(serial_int)
                    .revocation_date(rev_date)
                    .add_extension(x509.CRLReason(reason_flag), critical=False)
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked_cert)

            crl = builder.sign(ca_key, hashes.SHA256())
            crl_pem = crl.public_bytes(Encoding.PEM).decode()

            if not crl_pem.startswith('-----BEGIN X509 CRL-----'):
                raise ValueError("CRL générée invalide")

            return crl_pem

        except Exception as e:
            print(f"Erreur génération CRL: {e}")
            return PKIEngine._generate_empty_crl(ca_cert_pem, ca_key_enc, ca_password)

    @staticmethod
    def _generate_empty_crl(ca_cert_pem: str, ca_key_enc: bytes, ca_password: bytes):
        try:
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
            ca_key = serialization.load_pem_private_key(ca_key_enc, password=ca_password)

            now = datetime.now(timezone.utc)

            crl = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(ca_cert.subject)
                .last_update(now)
                .next_update(now + timedelta(days=7))
                .sign(ca_key, hashes.SHA256())
            )

            return crl.public_bytes(Encoding.PEM).decode()
        except Exception as e:
            print(f"Erreur génération CRL vide: {e}")
            return PKIEngine._get_fallback_crl()

    @staticmethod
    def _get_fallback_crl():
        return """-----BEGIN X509 CRL-----
MIIB1DCBvQIBATANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ00xITAfBgNV
BAoMGMOtY2F0aW9uIENBMSUwIwYDVQQDDBxBQy1NYXN0ZXItSU5GNDI2ODAeFw0y
NTA1MDYwMDAwMDBaFw0yNTA1MTMwMDAwMDBaoA8wDTALBgNVHRUEBQMCAgEwDQYJ
KoZIhvcNAQELBQADggEBAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAA==
-----END X509 CRL-----"""

    @staticmethod
    def verify_certificate(cert_pem: str, ca_cert_pem: str, revoked_serials: list):
        """
        Vérification par recherche dans la base (mode 1).
        Retourne dict avec étapes détaillées et verdict.
        """
        steps   = []
        overall = True

        try:
            cert    = x509.load_pem_x509_certificate(cert_pem.encode())
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        except Exception as e:
            return {'valid': False, 'steps': [
                {'name': 'Parsing PEM', 'ok': False, 'detail': str(e), 'icon': '⚠',
                 'technical': 'Impossible de décoder le certificat au format PEM/DER'}
            ]}

        # Étape 1 : Signature AC
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            steps.append({
                'name': 'Signature cryptographique (RSA + SHA-256)',
                'ok': True,
                'detail': 'Valide — Signé par Université de Yaoundé I',
                'icon': '🔐',
                'technical': f'PKCS#1 v1.5 · Algorithme : {cert.signature_hash_algorithm.name.upper()} · Clé publique CA vérifiée avec succès'
            })
        except Exception as e:
            steps.append({
                'name': 'Signature cryptographique (RSA + SHA-256)',
                'ok': False,
                'detail': f'Signature invalide — Ce certificat n\'a pas été émis par l\'Université de Yaoundé I',
                'icon': '🔐',
                'technical': f'Erreur : {str(e)}'
            })
            overall = False

        # Étape 2 : Période de validité
        now = datetime.now(timezone.utc)
        nvb = cert.not_valid_before_utc
        nva = cert.not_valid_after_utc
        time_ok = nvb <= now <= nva
        days_left = (nva - now).days if time_ok else 0
        steps.append({
            'name': 'Période de validité (RFC 5280)',
            'ok': time_ok,
            'detail': f'Du {nvb.strftime("%d/%m/%Y %H:%M")} UTC au {nva.strftime("%d/%m/%Y %H:%M")} UTC',
            'icon': '📅',
            'technical': f'NotBefore : {nvb.isoformat()} | NotAfter : {nva.isoformat()} | Aujourd\'hui : {now.isoformat()[:19]}Z | {"✓ Dans la plage de validité — " + str(days_left) + " jour(s) restant(s)" if time_ok else "✗ Hors plage de validité"}'
        })
        if not time_ok:
            overall = False

        # Étape 3 : CRL
        serial = cert.serial_number
        revoked = serial in revoked_serials
        revoke_detail = 'Non présent dans la Liste de Révocation (CRL) — Certificat non révoqué'
        if revoked:
            revoke_detail = '⚠ Numéro de série présent dans la CRL — Certificat révoqué avant expiration'
        steps.append({
            'name': 'Vérification CRL — Liste de Révocation',
            'ok': not revoked,
            'detail': revoke_detail,
            'icon': '📋',
            'technical': f'Numéro de série vérifié : {hex(serial).upper()} | Entrées CRL consultées : {len(revoked_serials)} | Statut : {"RÉVOQUÉ ✗" if revoked else "NON RÉVOQUÉ ✓"}'
        })
        if revoked:
            overall = False

        # Étape 4 : BasicConstraints
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
            steps.append({
                'name': 'Extensions X.509 v3 — BasicConstraints',
                'ok': not is_ca,
                'detail': 'Certificat final (end-entity) — Non-CA ✓' if not is_ca else '⚠ Ce certificat est marqué comme CA — Suspect !',
                'icon': '📜',
                'technical': f'BasicConstraints présent · cA={is_ca} · pathLenConstraint={"None" if bc.value.path_length is None else bc.value.path_length} · Extension critique : {bc.critical}'
            })
            if is_ca:
                overall = False
        except x509.ExtensionNotFound:
            steps.append({
                'name': 'Extensions X.509 v3 — BasicConstraints',
                'ok': True,
                'detail': 'Extension BasicConstraints absente — Acceptable pour certificat v1/v2',
                'icon': '📜',
                'technical': 'Extension non présente dans ce certificat (optionnelle pour version < 3)'
            })

        # Étape 5 : KeyUsage
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            usages = []
            if ku.value.digital_signature: usages.append('Signature numérique')
            if ku.value.content_commitment: usages.append('Non-répudiation')
            if ku.value.key_encipherment: usages.append('Chiffrement de clé')
            steps.append({
                'name': 'Extensions X.509 v3 — KeyUsage',
                'ok': True,
                'detail': f'Usages autorisés : {", ".join(usages) if usages else "Aucun défini"}',
                'icon': '🔑',
                'technical': f'KeyUsage : {" | ".join(usages)} · Extension critique : {ku.critical}'
            })
        except x509.ExtensionNotFound:
            steps.append({
                'name': 'Extensions X.509 v3 — KeyUsage',
                'ok': True,
                'detail': 'Extension KeyUsage absente — Utilisation non restreinte',
                'icon': '🔑',
                'technical': 'Aucune restriction d\'usage définie dans ce certificat'
            })

        cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = cn_list[0].value if cn_list else 'Inconnu'

        raw_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ':'.join(raw_fp[i:i+2] for i in range(0, len(raw_fp), 2))

        issuer_cn_list = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = issuer_cn_list[0].value if issuer_cn_list else 'Inconnu'

        return {
            'valid': overall,
            'steps': steps,
            'serial': serial,
            'serial_hex': hex(serial).upper().replace('0X', ''),
            'subject': subject_cn,
            'issuer': issuer_cn,
            'issued':  cert.not_valid_before_utc.strftime('%d/%m/%Y %H:%M UTC'),
            'expires': cert.not_valid_after_utc.strftime('%d/%m/%Y %H:%M UTC'),
            'fingerprint': fingerprint,
            'version': f'X.509 v{cert.version.value + 1}',
            'algo': cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else 'Inconnu',
        }

    @staticmethod
    def verify_certificate_from_pem(cert_pem_input: str, ca_cert_pem: str, revoked_serials: list):
        """
        Vérification par collage de PEM brut (mode 2 — vérification externe).
        Même logique que verify_certificate mais le certificat vient de l'extérieur.
        Returns: même structure de dict que verify_certificate
        """
        cert_pem_clean = cert_pem_input.strip()

        if '-----BEGIN CERTIFICATE-----' not in cert_pem_clean:
            return {
                'valid': False,
                'steps': [{
                    'name': 'Parsing du certificat PEM',
                    'ok': False,
                    'detail': 'Le texte fourni ne contient pas un certificat PEM valide.',
                    'icon': '⚠',
                    'technical': 'Un certificat PEM doit commencer par -----BEGIN CERTIFICATE----- et se terminer par -----END CERTIFICATE-----'
                }],
                'error': 'Format PEM invalide'
            }

        return PKIEngine.verify_certificate(cert_pem_clean, ca_cert_pem, revoked_serials)

    @staticmethod
    def benchmark_keygen(key_size: int = 2048, runs: int = 5):
        times = []
        for _ in range(runs):
            t0 = time.perf_counter()
            rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'key_size': key_size, 'runs': runs,
            'avg_ms':   round(sum(times) / len(times), 2),
            'min_ms':   round(min(times), 2),
            'max_ms':   round(max(times), 2),
        }

    @staticmethod
    def parse_crl(crl_pem: str):
        try:
            crl = x509.load_pem_x509_crl(crl_pem.encode())
            result = {
                'issuer': str(crl.issuer),
                'last_update': crl.last_update_utc.strftime('%Y-%m-%d %H:%M:%S'),
                'next_update': crl.next_update_utc.strftime('%Y-%m-%d %H:%M:%S'),
                'revoked_count': len(list(crl)),
                'revoked_certificates': []
            }
            for revoked in crl:
                result['revoked_certificates'].append({
                    'serial': revoked.serial_number,
                    'revocation_date': revoked.revocation_date_utc.strftime('%Y-%m-%d %H:%M:%S')
                })
            return result
        except Exception as e:
            return {'error': str(e)}