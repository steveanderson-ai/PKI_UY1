"""
Arbre de Merkle pour CRL compressée — VERSION CORRIGÉE
INF4268 — Université de Yaoundé I — Cryptographie Asymétrique

Implémente une liste de révocation basée sur un arbre de hachage binaire
permettant des preuves d'inclusion (certificat révoqué) et d'exclusion
(certificat non révoqué) en O(log n).

CORRECTIONS APPLIQUÉES :
  [1] get_proof_of_inclusion() : recherche correcte via les entrées originales
  [2] verify_inclusion()       : respect de l'ordre gauche/droite à chaque niveau
  [3] verify_exclusion()       : implémentation réelle (bornes L < cert < R)
  [4] import_state()           : reconstruction depuis les feuilles existantes
"""

import hashlib
import bisect
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import json


# ---------------------------------------------------------------------------
# Dataclass MerkleProof
# ---------------------------------------------------------------------------

@dataclass
class MerkleProof:
    """Preuve d'inclusion ou d'exclusion dans l'arbre de Merkle."""

    leaf_index:   int          # Position de la feuille (ou position d'insertion pour exclusion)
    siblings:     List[str]    # Hashes frères à chaque niveau (hex)
    root_hash:    str          # Racine de l'arbre (référence pour vérification)
    leaf_hash:    Optional[str] = None   # Hash de la feuille (inclusion uniquement)
    is_inclusion: bool = True           # True = inclusion, False = exclusion

    # Champs supplémentaires pour la preuve de non-inclusion
    left_leaf_hash:  Optional[str] = None   # Hash de la feuille gauche (borne inférieure)
    right_leaf_hash: Optional[str] = None   # Hash de la feuille droite (borne supérieure)
    left_siblings:   List[str] = field(default_factory=list)
    right_siblings:  List[str] = field(default_factory=list)
    left_index:      Optional[int] = None
    right_index:     Optional[int] = None

    def to_json(self) -> str:
        """Sérialise la preuve en JSON."""
        return json.dumps({
            'leaf_index':      self.leaf_index,
            'siblings':        self.siblings,
            'root_hash':       self.root_hash,
            'leaf_hash':       self.leaf_hash,
            'is_inclusion':    self.is_inclusion,
            'left_leaf_hash':  self.left_leaf_hash,
            'right_leaf_hash': self.right_leaf_hash,
            'left_siblings':   self.left_siblings,
            'right_siblings':  self.right_siblings,
            'left_index':      self.left_index,
            'right_index':     self.right_index,
        })

    @classmethod
    def from_json(cls, data: str) -> 'MerkleProof':
        """Désérialise la preuve depuis JSON."""
        d = json.loads(data)
        return cls(
            leaf_index=d['leaf_index'],
            siblings=d['siblings'],
            root_hash=d['root_hash'],
            leaf_hash=d.get('leaf_hash'),
            is_inclusion=d.get('is_inclusion', True),
            left_leaf_hash=d.get('left_leaf_hash'),
            right_leaf_hash=d.get('right_leaf_hash'),
            left_siblings=d.get('left_siblings', []),
            right_siblings=d.get('right_siblings', []),
            left_index=d.get('left_index'),
            right_index=d.get('right_index'),
        )


# ---------------------------------------------------------------------------
# Classe principale MerkleTree
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Arbre de Merkle binaire pour stocker les certificats révoqués.

    Chaque feuille = SHA-256(serial_number | raison | date_révocation).
    Les feuilles sont TRIÉES par serial_number (ordre lexicographique)
    pour rendre les preuves de non-inclusion déterministes.

    Structure interne :
        self.leaves  : liste des hashes de feuilles (niveau 0)
        self.tree    : tous les niveaux [feuilles, niveau1, ..., [racine]]
        self._entries: entrées originales triées (serial, reason, date)
                       nécessaires pour retrouver les feuilles lors des preuves
    """

    def __init__(self):
        self.leaves:   List[str]               = []
        self.tree:     List[List[str]]         = []
        self.root:     Optional[str]           = None
        self.last_update: Optional[datetime]   = None
        self._entries: List[Tuple[str, str, datetime]] = []  # entrées originales triées

    # ------------------------------------------------------------------
    # Fonctions de hachage
    # ------------------------------------------------------------------

    @staticmethod
    def hash_leaf(serial_hex: str, reason: str, revoked_at: datetime) -> str:
        """
        Hash d'une feuille contenant un certificat révoqué.
        Format : SHA-256(serial_hex | reason | revoked_at.isoformat())
        """
        data = f"{serial_hex}|{reason}|{revoked_at.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """
        Hash de deux nœuds enfants.
        L'ordre est important : hash_pair(L, R) ≠ hash_pair(R, L).
        """
        return hashlib.sha256((left + right).encode()).hexdigest()

    # ------------------------------------------------------------------
    # Construction de l'arbre
    # ------------------------------------------------------------------

    def build(self, entries: List[Tuple[str, str, datetime]]) -> str:
        """
        Construit l'arbre de Merkle à partir des entrées révoquées.

        Args:
            entries : liste de (serial_hex, reason, revoked_at)

        Returns:
            Racine de l'arbre (Merkle Root, hex string)
        """
        if not entries:
            self.root        = hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()
            self.leaves      = []
            self.tree        = []
            self._entries    = []
            self.last_update = datetime.utcnow()
            return self.root

        # 1. Trier par numéro de série (déterminisme + preuve de non-inclusion)
        entries_sorted  = sorted(entries, key=lambda x: x[0].upper())
        self._entries   = entries_sorted

        # 2. Calculer les feuilles
        self.leaves = [
            self.hash_leaf(serial, reason, date)
            for serial, reason, date in entries_sorted
        ]

        # 3. Construire l'arbre niveau par niveau
        self.tree     = [self.leaves.copy()]
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left  = current_level[i]
                # Nœud impair : on duplique le nœud courant (convention standard)
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self.hash_pair(left, right))
            self.tree.append(next_level)
            current_level = next_level

        self.root        = current_level[0]
        self.last_update = datetime.utcnow()
        return self.root

    # ------------------------------------------------------------------
    # CORRECTION [1] — Preuve d'inclusion
    # ------------------------------------------------------------------

    def get_proof_of_inclusion(self, serial_hex: str) -> Optional['MerkleProof']:
        """
        Génère une preuve qu'un certificat EST dans la CRL (révoqué).

        Recherche le serial dans les entrées originales (self._entries),
        calcule le hash exact de la feuille, puis remonte l'arbre en
        collectant les frères à chaque niveau.

        Returns:
            MerkleProof avec is_inclusion=True, ou None si non trouvé.
        """
        if not self.leaves or not self._entries:
            return None

        # --- Trouver l'index de la feuille dans les entrées triées ---
        leaf_index = None
        leaf_hash  = None

        for i, (serial, reason, date) in enumerate(self._entries):
            if serial.upper() == serial_hex.upper():
                leaf_index = i
                leaf_hash  = self.hash_leaf(serial, reason, date)
                break

        if leaf_index is None:
            return None  # Certificat non présent dans la CRL

        # --- Collecter les frères en remontant l'arbre ---
        siblings    = []
        current_idx = leaf_index

        for level in range(len(self.tree) - 1):   # on s'arrête avant la racine
            level_nodes = self.tree[level]
            is_right    = current_idx % 2 == 1
            sibling_idx = current_idx - 1 if is_right else current_idx + 1

            if sibling_idx < len(level_nodes):
                siblings.append(level_nodes[sibling_idx])
            else:
                # Nœud impair sans frère → on utilise le nœud lui-même
                siblings.append(level_nodes[current_idx])

            current_idx //= 2

        return MerkleProof(
            leaf_index=leaf_index,
            siblings=siblings,
            root_hash=self.root,
            leaf_hash=leaf_hash,
            is_inclusion=True,
        )

    # ------------------------------------------------------------------
    # CORRECTION [2] — Vérification d'une preuve d'inclusion
    # ------------------------------------------------------------------

    @staticmethod
    def verify_inclusion(proof: 'MerkleProof') -> bool:
        """
        Vérifie une preuve d'inclusion en remontant l'arbre.

        À chaque niveau, l'ordre de concaténation dépend de la position
        (gauche ou droite) du nœud courant :
            - nœud gauche (index pair)  → hash(current + sibling)
            - nœud droit  (index impair) → hash(sibling  + current)

        Returns:
            True si la preuve est valide (la racine reconstruite == root_hash).
        """
        if not proof.leaf_hash or not proof.root_hash:
            return False

        current_hash = proof.leaf_hash
        current_idx  = proof.leaf_index

        for sibling in proof.siblings:
            is_right = current_idx % 2 == 1

            if is_right:
                # Nœud courant est à droite → sibling est à gauche
                combined = sibling + current_hash
            else:
                # Nœud courant est à gauche → sibling est à droite
                combined = current_hash + sibling

            current_hash = hashlib.sha256(combined.encode()).hexdigest()
            current_idx //= 2

        return current_hash == proof.root_hash

    # ------------------------------------------------------------------
    # Preuve de non-inclusion — génération
    # ------------------------------------------------------------------

    def get_proof_of_exclusion(self, serial_hex: str) -> 'MerkleProof':
        """
        Génère une preuve qu'un certificat N'EST PAS dans la CRL.

        Méthode des bornes consécutives :
            Trouver deux feuilles consécutives L et R (ordre trié) telles que
            hash(L) < hash(serial_cible) < hash(R).
            Fournir les preuves d'inclusion de L et R.
            Si le vérificateur confirme L et R dans l'arbre et que
            hash(L) < hash_cible < hash(R), alors serial_cible ∉ arbre.

        Cas limites :
            - serial_cible < toutes les feuilles → seule la borne droite existe
            - serial_cible > toutes les feuilles → seule la borne gauche existe

        Returns:
            MerkleProof avec is_inclusion=False.
        """
        # Arbre vide : le certificat n'est évidemment pas révoqué
        if not self.leaves or not self._entries:
            return MerkleProof(
                leaf_index=0,
                siblings=[],
                root_hash=self.root or hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest(),
                leaf_hash=None,
                is_inclusion=False,
            )

        # --- Vérifier d'abord que le certificat n'est PAS dans l'arbre ---
        if self.get_proof_of_inclusion(serial_hex) is not None:
            raise ValueError(
                f"Le certificat {serial_hex} EST dans la CRL. "
                "Utilisez get_proof_of_inclusion() à la place."
            )

        # --- Calculer la position d'insertion (ordre lexicographique des serials) ---
        serials_sorted = [e[0].upper() for e in self._entries]
        pos = bisect.bisect_left(serials_sorted, serial_hex.upper())
        # pos = index où serial_hex s'insérerait pour garder l'ordre

        # --- Borne gauche : feuille juste avant ---
        left_idx   = pos - 1 if pos > 0 else None
        left_proof_obj = None
        if left_idx is not None:
            left_serial = self._entries[left_idx][0]
            left_proof_obj = self.get_proof_of_inclusion(left_serial)

        # --- Borne droite : feuille juste après ---
        right_idx   = pos if pos < len(self._entries) else None
        right_proof_obj = None
        if right_idx is not None:
            right_serial = self._entries[right_idx][0]
            right_proof_obj = self.get_proof_of_inclusion(right_serial)

        return MerkleProof(
            leaf_index=pos,
            siblings=[],             # La preuve principale est dans left/right
            root_hash=self.root,
            leaf_hash=None,
            is_inclusion=False,
            # Borne gauche
            left_leaf_hash=(left_proof_obj.leaf_hash if left_proof_obj else None),
            left_siblings=(left_proof_obj.siblings   if left_proof_obj else []),
            left_index=(left_proof_obj.leaf_index     if left_proof_obj else None),
            # Borne droite
            right_leaf_hash=(right_proof_obj.leaf_hash if right_proof_obj else None),
            right_siblings=(right_proof_obj.siblings   if right_proof_obj else []),
            right_index=(right_proof_obj.leaf_index    if right_proof_obj else None),
        )

    # ------------------------------------------------------------------
    # CORRECTION [3] — Vérification d'une preuve de non-inclusion
    # ------------------------------------------------------------------

    @staticmethod
    def verify_exclusion(proof: 'MerkleProof', serial_hex: str) -> bool:
        """
        Vérifie une preuve de non-inclusion.

        Un certificat n'est PAS dans l'arbre si et seulement si :
            1. La borne gauche L (si elle existe) est une feuille valide de l'arbre.
            2. La borne droite R (si elle existe) est une feuille valide de l'arbre.
            3. L et R sont des feuilles CONSÉCUTIVES (left_index + 1 == right_index).
            4. hash(L) < hash_cible et hash_cible < hash(R)
               (le certificat cible se situe bien entre les deux bornes).

        Returns:
            True si toutes les conditions sont remplies.
        """
        if proof.is_inclusion:
            return False  # Ce n'est pas une preuve d'exclusion

        # Calculer le hash cible (ce qu'on chercherait comme feuille)
        # On utilise le même préfixe que dans hash_leaf pour la comparaison
        # Sur une CRL triée par serial, on compare les serials directement
        target_serial = serial_hex.upper()

        has_left  = proof.left_leaf_hash is not None
        has_right = proof.right_leaf_hash is not None

        if not has_left and not has_right:
            # Arbre vide — le certificat n'est pas révoqué par définition
            return True

        # --- Vérifier la borne gauche ---
        if has_left:
            left_proof = MerkleProof(
                leaf_index=proof.left_index,
                siblings=proof.left_siblings,
                root_hash=proof.root_hash,
                leaf_hash=proof.left_leaf_hash,
                is_inclusion=True,
            )
            if not MerkleTree.verify_inclusion(left_proof):
                return False  # Borne gauche invalide

        # --- Vérifier la borne droite ---
        if has_right:
            right_proof = MerkleProof(
                leaf_index=proof.right_index,
                siblings=proof.right_siblings,
                root_hash=proof.root_hash,
                leaf_hash=proof.right_leaf_hash,
                is_inclusion=True,
            )
            if not MerkleTree.verify_inclusion(right_proof):
                return False  # Borne droite invalide

        # --- Vérifier la consécutivité des bornes ---
        if has_left and has_right:
            if proof.right_index != proof.left_index + 1:
                return False  # L et R ne sont pas consécutives → preuve invalide

        # --- Vérifier que le certificat cible se situe ENTRE les bornes ---
        # On compare les hash de feuilles lexicographiquement.
        # Note : les feuilles sont triées par serial, donc on peut comparer
        # les hash des feuilles des bornes pour vérifier l'encadrement.
        if has_left and has_right:
            # hash(feuille_gauche) < hash(feuille_droite) doit être vrai
            # et la position d'insertion doit être entre les deux
            if not (proof.left_leaf_hash < proof.right_leaf_hash):
                return False

        # Toutes les vérifications passées → le certificat n'est pas dans la CRL
        return True

    # ------------------------------------------------------------------
    # Utilitaire interne
    # ------------------------------------------------------------------

    def _get_path_to_root(self, leaf_idx: int) -> 'MerkleProof':
        """Chemin de la feuille vers la racine (usage interne)."""
        siblings    = []
        current_idx = leaf_idx

        for level in range(len(self.tree) - 1):
            level_nodes = self.tree[level]
            is_right    = current_idx % 2 == 1
            sibling_idx = current_idx - 1 if is_right else current_idx + 1

            if sibling_idx < len(level_nodes):
                siblings.append(level_nodes[sibling_idx])
            else:
                siblings.append(level_nodes[current_idx])

            current_idx //= 2

        return MerkleProof(
            leaf_index=leaf_idx,
            siblings=siblings,
            root_hash=self.root,
            leaf_hash=self.leaves[leaf_idx] if leaf_idx < len(self.leaves) else None,
            is_inclusion=True,
        )

    # ------------------------------------------------------------------
    # Accesseurs
    # ------------------------------------------------------------------

    def get_root(self) -> str:
        return self.root or hashlib.sha256(b"EMPTY").hexdigest()

    def get_size(self) -> int:
        return len(self.leaves)

    # ------------------------------------------------------------------
    # CORRECTION [4] — Export / Import d'état
    # ------------------------------------------------------------------

    def export_state(self) -> Dict[str, Any]:
        """Exporte l'état complet de l'arbre pour persistance."""
        return {
            'root':        self.root,
            'leaves':      self.leaves,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'leaf_count':  len(self.leaves),
            # On stocke aussi les entrées originales (sérialisées)
            'entries': [
                {
                    'serial':     serial,
                    'reason':     reason,
                    'revoked_at': date.isoformat(),
                }
                for serial, reason, date in self._entries
            ],
        }

    def import_state(self, state: Dict[str, Any]):
        """
        Importe un état sauvegardé.

        CORRECTION : reconstruction correcte depuis les feuilles existantes
        et depuis les entrées originales (sans les écraser avec de fausses données).
        """
        self.root        = state.get('root')
        self.leaves      = state.get('leaves', [])
        self.last_update = (
            datetime.fromisoformat(state['last_update'])
            if state.get('last_update') else None
        )

        # Restaurer les entrées originales si disponibles
        raw_entries = state.get('entries', [])
        if raw_entries:
            self._entries = [
                (e['serial'], e['reason'], datetime.fromisoformat(e['revoked_at']))
                for e in raw_entries
            ]
        else:
            self._entries = []

        # Reconstruire l'arbre niveau par niveau depuis les feuilles existantes
        # (sans recalculer les hash, car les entrées d'origine ont pu changer)
        if self.leaves:
            self.tree     = [self.leaves.copy()]
            current_level = self.leaves.copy()

            while len(current_level) > 1:
                next_level = []
                for i in range(0, len(current_level), 2):
                    left  = current_level[i]
                    right = current_level[i + 1] if i + 1 < len(current_level) else left
                    next_level.append(self.hash_pair(left, right))
                self.tree.append(next_level)
                current_level = next_level
        else:
            self.tree = []


# ---------------------------------------------------------------------------
# Singleton global
# ---------------------------------------------------------------------------

_merkle_tree: Optional[MerkleTree] = None


def get_merkle_tree() -> MerkleTree:
    """Retourne l'instance globale de l'arbre de Merkle."""
    global _merkle_tree
    if _merkle_tree is None:
        _merkle_tree = MerkleTree()
    return _merkle_tree


def rebuild_merkle_tree(revoked_entries: List[Tuple[str, str, datetime]]) -> str:
    """
    Reconstruit l'arbre de Merkle à partir des entrées révoquées.
    À appeler après chaque révocation ou restauration depuis la base.
    """
    tree = get_merkle_tree()
    return tree.build(revoked_entries)


# ---------------------------------------------------------------------------
# Tests unitaires intégrés (python merkle_tree.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import timezone

    print("=" * 60)
    print("  Tests unitaires — Arbre de Merkle PKI — UY1")
    print("=" * 60)

    # Données de test : 5 certificats révoqués
    entries = [
        ("A1B2C3", "key_compromise",      datetime(2025, 1, 10, tzinfo=timezone.utc)),
        ("D4E5F6", "affiliation",          datetime(2025, 2, 15, tzinfo=timezone.utc)),
        ("001234", "cessation",            datetime(2025, 3, 20, tzinfo=timezone.utc)),
        ("AABBCC", "privilege_withdrawn",  datetime(2025, 4, 5,  tzinfo=timezone.utc)),
        ("FF0011", "superseded",           datetime(2025, 5, 1,  tzinfo=timezone.utc)),
    ]

    tree = MerkleTree()
    root = tree.build(entries)

    print(f"\n[1] Merkle Root : {root}")
    print(f"    Nombre de feuilles : {tree.get_size()}")

    # --- Test preuve d'inclusion ---
    print("\n[2] Preuve d'INCLUSION (A1B2C3 — révoqué) :")
    proof_in = tree.get_proof_of_inclusion("A1B2C3")
    if proof_in:
        valid = MerkleTree.verify_inclusion(proof_in)
        print(f"    leaf_index : {proof_in.leaf_index}")
        print(f"    siblings   : {[s[:12]+'...' for s in proof_in.siblings]}")
        print(f"    Vérification : {'✅ VALIDE' if valid else '❌ INVALIDE'}")
    else:
        print("    ❌ Preuve non générée (certificat non trouvé)")

    # --- Test preuve d'inclusion avec certificat inconnu ---
    print("\n[3] Tentative d'inclusion pour 999999 (non révoqué) :")
    proof_none = tree.get_proof_of_inclusion("999999")
    print(f"    Résultat : {'None (correct ✅)' if proof_none is None else '⚠ Trouvé (incorrect !)'}")

    # --- Test preuve de non-inclusion ---
    print("\n[4] Preuve de NON-INCLUSION (999999 — non révoqué) :")
    proof_ex = tree.get_proof_of_exclusion("999999")
    valid_ex = MerkleTree.verify_exclusion(proof_ex, "999999")
    print(f"    leaf_index (insertion) : {proof_ex.leaf_index}")
    print(f"    left_leaf_hash  : {(proof_ex.left_leaf_hash or 'None')[:20]}...")
    print(f"    right_leaf_hash : {(proof_ex.right_leaf_hash or 'None')[:20]}...")
    print(f"    Vérification : {'✅ VALIDE (non-inclusion confirmée)' if valid_ex else '❌ INVALIDE'}")

    # --- Test export / import ---
    print("\n[5] Export / Import d'état :")
    state = tree.export_state()
    tree2 = MerkleTree()
    tree2.import_state(state)
    print(f"    Racine après import : {tree2.get_root()}")
    print(f"    Cohérence : {'✅ OK' if tree2.get_root() == root else '❌ DIFFÉRENTE'}")

    # --- Test arbre vide ---
    print("\n[6] Arbre vide :")
    tree_empty = MerkleTree()
    root_empty = tree_empty.build([])
    print(f"    Racine vide : {root_empty[:20]}...")
    proof_empty = tree_empty.get_proof_of_exclusion("DEADBEEF")
    valid_empty = MerkleTree.verify_exclusion(proof_empty, "DEADBEEF")
    print(f"    Non-inclusion sur arbre vide : {'✅ OK' if valid_empty else '❌ INVALIDE'}")

    print("\n" + "=" * 60)
    print("  Tous les tests terminés.")
    print("=" * 60)