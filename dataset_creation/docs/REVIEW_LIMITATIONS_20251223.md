# Revue Approfondie - Limitations et Améliorations

**Date**: 2025-12-23
**Niveau d'analyse**: Ultrathink

---

## Résumé Exécutif

L'intégration VulnCheck KEV/NVD a produit **18,864 relations `exploits`** mais révèle des limitations structurelles significatives:

| Métrique | Valeur | Évaluation |
|----------|--------|------------|
| Techniques avec CVE | 16/835 | **CRITIQUE** (1.9%) |
| CVEs sans mapping ATT&CK | 7,351/22,391 | **PRÉOCCUPANT** (32.8%) |
| CWEs non mappés | 20+ CWEs majeurs | **À CORRIGER** |
| Scoring dual implémenté | Non | **EN ATTENTE** |

---

## 1. Analyse de Couverture

### 1.1 Techniques MITRE ATT&CK

**Statistiques**:
- Total techniques MITRE: **835**
- Techniques avec données CVE: **16** (1.9%)
- Techniques sans CVE: **819** (98.1%)

**Techniques couvertes**:
```
T1005  - Data from Local System
T1059  - Command and Scripting Interpreter
T1078  - Valid Accounts
T1083  - File and Directory Discovery
T1090  - Proxy
T1105  - Ingress Tool Transfer
T1189  - Drive-by Compromise
T1190  - Exploit Public-Facing Application
T1203  - Exploitation for Client Execution
T1486  - Data Encrypted for Impact
T1489  - Service Stop
T1490  - Inhibit System Recovery
T1491  - Defacement
T1548  - Abuse Elevation Control Mechanism
T1557  - Adversary-in-the-Middle
T1574  - Hijack Execution Flow
```

**Analyse**: La couverture est limitée aux techniques directement liées à des classes de vulnérabilités (CWE). C'est attendu car:
1. Les CVE décrivent des **failles**, pas des **comportements** d'attaque
2. Beaucoup de techniques ATT&CK sont **post-exploitation** (pas liées à CVE)
3. Le mapping CWE→ATT&CK est intrinsèquement limité

### 1.2 CVEs sans Mapping

**Statistiques**:
- CVEs totales traitées: **22,391**
- CVEs avec mapping: **15,040** (67.2%)
- CVEs sans mapping: **7,351** (32.8%)

**Top 20 CWEs non mappés**:

| CWE | Nom | CVEs | Mapping ATT&CK Proposé |
|-----|-----|------|------------------------|
| CWE-798 | Hard-coded Credentials | 510 | **T1078** (Valid Accounts) |
| CWE-1321 | Prototype Pollution | 158 | T1059 (Code Execution) |
| CWE-611 | XXE | 145 | **T1005** (Data Collection) |
| CWE-74 | Injection | 145 | T1059 (Execution) |
| CWE-121 | Stack Buffer Overflow | 141 | **T1203** (Exploitation) |
| CWE-307 | Brute Force | 133 | **T1110** (Brute Force) |
| CWE-276 | Incorrect Default Perms | 108 | T1548 (Abuse Elevation) |
| CWE-288 | Auth Bypass via Alt Path | 106 | **T1078** (Valid Accounts) |
| CWE-639 | Authorization Bypass IDOR | 102 | T1548 |
| CWE-352 | CSRF | 93 | T1185 (Browser Session Hijacking) |
| CWE-522 | Insufficiently Protected Creds | 86 | T1078 |
| CWE-347 | Improper Crypto Signature | 79 | T1557 |
| CWE-290 | Auth Bypass Spoofing | 71 | T1078 |
| CWE-732 | Incorrect Permission | 71 | T1548 |
| CWE-521 | Weak Password | 71 | T1078, T1110 |
| CWE-319 | Cleartext Transmission | 60 | T1557 |
| CWE-266 | Incorrect Privilege | 56 | T1548 |
| CWE-98 | Improper Control of Filename | 56 | T1574 |
| CWE-613 | Insufficient Session Expiration | 55 | T1185 |
| CWE-384 | Session Fixation | 53 | T1185 |

**Impact**: +2,000 CVEs supplémentaires si ces CWEs sont mappés.

---

## 2. Analyse de Confiance

### 2.1 Distribution Actuelle

| Type de Relation | Total | Low (<0.5) | Medium (0.5-0.8) | High (>=0.8) |
|------------------|-------|------------|------------------|--------------|
| enables | 16,882 | 0% | 61.7% | 38.3% |
| blocks | 1,445 | 0% | 59.7% | 40.3% |
| pivot_to | 3,299 | 0% | 61.4% | 38.6% |
| prerequisites | 500 | 0% | 4.6% | 95.4% |
| **exploits** | **18,864** | **0%** | **78.5%** | **21.5%** |

### 2.2 Problème: Concentration dans la Bande 0.6-0.7

Pour les relations `exploits`:
- 78.5% sont dans la bande 0.6-0.7
- 13.4% dans la bande 0.8-0.9
- 8.1% dans la bande 0.9-1.0

**Cause**: Le calcul de confiance actuel est trop simpliste:
```python
confidence = 0.5  # Base
if is_exploited: confidence += 0.3  # Toutes les KEV
if cvss >= 9.0: confidence += 0.15
if is_ransomware: confidence += 0.05
```

Résultat: Presque toutes les KEV (exploitées) = 0.5 + 0.3 = 0.8 minimum, mais les CVEs NVD sans KEV = 0.5-0.65.

### 2.3 Scoring Dual Non Implémenté

| Composant | Statut | Impact |
|-----------|--------|--------|
| P_théorique | ❌ Non implémenté | Pas de validation logique |
| P_empirique | ❌ Non implémenté | Pas de corroboration CTI |
| Classification CONFIRMED/PLAUSIBLE | ❌ Non implémenté | Pas de catégorisation |

---

## 3. Gaps Fonctionnels

### 3.1 Dimensions Opérationnelles Manquantes

| Dimension | Statut | Impact |
|-----------|--------|--------|
| Profils Faux Positifs | ❌ Absent | LLM ne sait pas guider le tuning |
| Contexte Métier | ❌ Absent | Pas de priorisation sectorielle |
| Incertitude Calibrée | ❌ Absent | Réponses sans nuance de confiance |

### 3.2 Enrichissement CTI Partiel

| Source | Intégrée dans exploits | Intégrée dans graphe causal |
|--------|------------------------|------------------------------|
| VulnCheck KEV | ✅ | ✅ (via exploits) |
| NVD | ✅ | ✅ (via exploits) |
| MITRE ATT&CK | ✅ | ✅ |
| **CTI Reports (MD)** | ✅ **EN COURS** | ✅ **EN COURS** |
| LOLBAS | ❌ | ✅ (via enables) |
| NIST Mappings | ❌ | ❌ |
| AlienVault OTX | ❌ | ❌ |
| LOLDrivers | ❌ | ✅ (partiel) |

#### 3.2.1 Extraction CTI Reports (Nouveau)

**Script**: `extract_cti_reports.py`
**Source**: 454 rapports CTI markdown (2020-2025)
**Méthode**: Extraction hybride LLM (vLLM Nemotron) + regex avec traçabilité

**Résultats validation (10 rapports 2024)**:
| Métrique | Valeur |
|----------|--------|
| Rapports traités | 10/10 (100%) |
| Techniques uniques | 86 |
| Acteurs identifiés | 4 (APT29, FIN7, CARR, CyberAv3ngers) |
| Traçabilité | ✅ Context ±150 chars par technique |

**Capacités d'extraction**:
- Techniques MITRE ATT&CK (T1XXX.XXX)
- Threat actors (APT, FIN, UNC groups)
- Malware families (Cobalt Strike, LockBit, etc.)
- CVE IDs
- Contexte source pour chaque extraction

**Statut**: Prêt pour extraction complète (454 rapports)

### 3.3 Tests Unitaires

- Couverture actuelle: **0%**
- Objectif: **80%**
- Risque: Régression silencieuse lors des modifications

---

## 4. Recommandations d'Amélioration

### 4.1 PRIORITÉ CRITIQUE - Étendre le Mapping CWE→ATT&CK

**Action immédiate**: Ajouter les 10 CWEs les plus fréquents non mappés.

```python
# Ajouts proposés pour filter_kev_nvd.py
CWE_TO_ATTACK_EXTENDED = {
    # Existants...

    # Nouveaux mappings prioritaires
    'CWE-798': ['T1078'],              # Hard-coded Credentials
    'CWE-1321': ['T1059'],             # Prototype Pollution
    'CWE-611': ['T1005', 'T1190'],     # XXE
    'CWE-121': ['T1203'],              # Stack Buffer Overflow
    'CWE-307': ['T1110'],              # Brute Force
    'CWE-288': ['T1078'],              # Auth Bypass
    'CWE-352': ['T1185'],              # CSRF
    'CWE-522': ['T1078'],              # Insufficiently Protected Credentials
    'CWE-319': ['T1557'],              # Cleartext Transmission
    'CWE-384': ['T1185'],              # Session Fixation
}
```

**Impact estimé**: +2,000 CVEs mappées, couverture passant de 67% à ~77%.

### 4.2 PRIORITÉ HAUTE - Implémenter Scoring Dual

1. **P_théorique** (Issue #5):
   - Kill chain ordering
   - Prerequisite logic
   - Subtechnique hierarchy

2. **P_empirique** (Issue #6):
   - Actor co-occurrence
   - Campaign documentation
   - Multi-source corroboration

### 4.3 PRIORITÉ MOYENNE - Enrichissement Multi-Sources

Intégrer dans le calcul de confiance:
- LOLBAS: Binaires légitimes utilisés par acteurs
- NIST: Standards de contrôle
- OTX: Intelligence de menaces récente

### 4.4 PRIORITÉ BASSE - Dimensions Opérationnelles

Après scoring dual:
- Profils FP (Issue #10)
- Contexte métier (Issue #11)
- Incertitude calibrée (Issue #12)

---

## 5. Limitations Structurelles (Non-Corrigeables)

### 5.1 Nature des Données CVE vs ATT&CK

| Concept | CVE | ATT&CK |
|---------|-----|--------|
| Focus | Faille technique | Comportement d'attaque |
| Granularité | Vulnérabilité unique | Technique/Tactique |
| Temporalité | Point dans le temps | Pattern récurrent |

**Implication**: Un mapping CVE→ATT&CK sera toujours partiel car beaucoup de techniques ATT&CK ne correspondent pas à des vulnérabilités (ex: T1566 Phishing, T1071 Application Layer Protocol).

### 5.2 Techniques Sans CVE Correspondante

Environ 600+ techniques MITRE ne peuvent PAS avoir de CVE:
- Techniques de reconnaissance (T1595, T1596...)
- Techniques de persistence système (T1136, T1098...)
- Techniques de mouvement latéral (T1021, T1550...)
- Techniques d'exfiltration (T1041, T1048...)

**Solution**: Ces techniques doivent être enrichies par d'autres sources (LOLBAS, OTX, rapports d'acteurs).

---

## 6. Métriques de Succès Révisées

| Métrique | Objectif Initial | Objectif Révisé | Actuel |
|----------|------------------|-----------------|--------|
| Techniques avec CVE | 50% | **5%** | 1.9% |
| CVEs mappées | 90% | **80%** | 67.2% |
| Relations CONFIRMED | 40% | 40% | À mesurer |
| Techniques multi-sources | 50% | 50% | ~10% (via CTI) |
| Tests couverture | 80% | 80% | 0% |
| **CTI Reports extraits** | - | **100%** | **2.2%** (10/454) |

---

## 7. Plan d'Action Proposé

### Sprint 1 (Immédiat)

1. ✅ **Créer extract_cti_reports.py** - Extraction LLM hybride
2. ✅ **Valider qualité** - 10 rapports test, 86 techniques extraites
3. ⏳ **Lancer extraction complète** - 454 rapports CTI (Issue #8)
4. **Étendre CWE_TO_ATTACK** avec 10+ nouveaux CWEs (Issue #16)
5. **Relancer filter_kev_nvd.py** et build_causal_graph.py

### Sprint 2

6. **Implémenter P_théorique** (Issue #5)
7. **Tests unitaires** pour scoring (Issue #14)
8. **Intégrer CTI extraits** dans graphe causal

### Sprint 3

9. **Implémenter P_empirique** (Issue #6)
10. **Classification matrix** (Issue #7)
11. **Intégration LOLBAS/OTX** dans scoring

---

## 8. Annexe: Statistiques Complètes du Graphe

```
=== CAUSAL GRAPH METADATA ===
generated_at: 2025-12-23T15:58:05
total_techniques: 835
total_enables: 16,882
total_blocks: 1,445
total_pivot_to: 3,299
total_prerequisites: 627
total_exploits: 18,864
techniques_with_cves: 16
ransomware_techniques: 16
sources: MITRE ATT&CK, VulnCheck KEV, NVD

=== TOTAL RELATIONS ===
41,117 relations inférées
```

---

**Auteur**: Claude Code
**Révision**: Session 2025-12-23 (ultrathink analysis)
