"""
Script d'initialisation de la base de données PKI.
Lance ce script UNE SEULE FOIS après le clonage.
"""
from app import app, db
from modules.models import User, Certificate, CRLEntry
from werkzeug.security import generate_password_hash
import os

def init_database():
    with app.app_context():
        # Créer le dossier database s'il n'existe pas
        os.makedirs('database', exist_ok=True)
        os.makedirs('uploads', exist_ok=True)

        # Créer toutes les tables
        db.create_all()
        print("✅ Tables créées.")

        # Vérifier si un admin existe déjà
        existing_admin = User.query.filter_by(role='admin').first()
        if not existing_admin:
            admin = User(
                username='admin',
                email='admin@pki.uy1',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Compte admin créé : admin@pki.uy1 / admin123")
        else:
            print("ℹ️  Compte admin déjà existant.")

        print("\n🎉 Base de données initialisée avec succès !")
        print("   Lance maintenant : python3 app.py")

if __name__ == '__main__':
    init_database()
