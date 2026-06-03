# Mini-PKI avec révocation par arbre de Merkle

**Cours** : INF4268 — Cryptographie Asymétrique  
**Université** : Université de Yaoundé I  
**Encadreur** : Dr. Ekodeck Stéphane  

## Description
Infrastructure à clés publiques (PKI) minimaliste avec :
- Autorité de certification (CA) auto-signée RSA-2048 / SHA-256
- Émission et gestion de certificats X.509 v3
- Liste de révocation hybride : CRL (RFC 5280) + Arbre de Merkle
- Preuves d'inclusion et de non-inclusion en O(log n)
- Interface web Flask multi-rôles (admin / utilisateur)

## Installation
Voir INSTALL.md

## Stack technique
- Python 3.x / Flask
- SQLAlchemy / SQLite
- Cryptography (pyca)
- Bootstrap / JetBrains Mono
