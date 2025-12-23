# CyberLLMInstruct - Status Report
**Date**: 2025-12-23
**Session**: CTI Enrichment, Confidence Scoring & Quality Metrics

---

## Executive Summary

Session majeure de développement sur le pipeline d'enrichissement CTI et le graphe causal. **8 issues GitHub fermées** avec implémentation complète des fonctionnalités de scoring, tests unitaires, et métriques de qualité.

---

## Pipeline Status

| Étape | Statut | Script | Données |
|-------|--------|--------|---------|
| 1. Collection | ✅ DONE | `1_data_collector.py` | 200K+ entrées brutes |
| 2. Filtrage | ✅ DONE | `2_data_filter.py` | 50K+ entrées filtrées |
| 3. Extraction CTI | ✅ DONE | `extract_cti_reports.py` | 454 reports, 3,927 chains |
| 4. Enrichissement CTI | ✅ DONE | `enrich_with_cti.py` | 835 techniques enrichies |
| 5. Scoring Confiance | ✅ DONE | `build_causal_graph.py` | P_théorique + P_empirique |
| 6. Métriques Qualité | ✅ DONE | `quality_metrics.py` | Rapport auto-généré |
| 7. Génération QnA | ⏳ PENDING | `3_data_structurer.py` | - |
| 8. Assemblage Final | ⏳ PENDING | `8_final_assembler.py` | - |

---

## Issues Fermées (8 au total)

### Session Précédente
| # | Titre | Statut |
|---|-------|--------|
| #17 | CTI Extraction from Reports | ✅ |
| #8 | Cross-Reference CTI Sources | ✅ |
| #5 | Theoretical Scoring (P_théorique) | ✅ |
| #6 | Empirical Scoring (P_empirique) | ✅ |
| #7 | Combined Confidence Classification | ✅ |
| #15 | VulnCheck KEV/NVD Integration | ✅ |

### Session Actuelle
| # | Titre | Action | Détails |
|---|-------|--------|---------|
| #16 | Extend CWE→ATT&CK mapping | ✅ Fermée | +42 CWEs, +1,932 CVEs mappées |
| #14 | Unit tests causal graph | ✅ Fermée | 48 tests, 100% pass |
| #13 | Dataset quality metrics | ✅ Fermée | Script `quality_metrics.py` |
| #4 | Dataset reconstruction bug | 📝 Commenté | En attente réponse utilisateur |

---

## Fichiers Créés/Modifiés

### Nouveaux Scripts

```
dataset_creation/
├── extract_cti_reports.py     # Extraction CTI avec vLLM Nemotron
├── enrich_with_cti.py         # Cross-référence sources multiples
├── quality_metrics.py         # Analyse qualité dataset
├── filter_kev_nvd.py          # Filtrage CVE + mapping CWE→ATT&CK
└── tests/
    └── test_causal_graph.py   # 48 tests unitaires
```

### Données Générées

```
filtered_data/
├── cti_extracted_20251223_183110.json        # 454 reports extraits
├── cti_causal_relations_20251223_183110.json # 3,927 attack chains
├── techniques_enriched_cti_20251223_194337.json    # 835 techniques
├── techniques_enriched_summary_20251223_194337.json
├── cve_attack_mapping_20251223_195235.json   # 22,391 CVEs mappées
├── cve_attack_summary_20251223_195236.json   # Stats CVE→ATT&CK
├── kev_filtered_20251223_195235.json         # 4,435 KEV entries
├── nvd_critical_filtered_20251223_195235.json# 18,997 NVD critiques
└── quality_report_20251223_202300.json       # Rapport qualité
```

---

## Détails Techniques par Issue

### #16 - Extension CWE→ATT&CK Mapping

**Fichier**: `filter_kev_nvd.py`

**Avant**: 26 CWEs mappés
**Après**: 68 CWEs mappés (+42)

**Nouvelles catégories ajoutées**:

| Catégorie | CWEs | Techniques ATT&CK |
|-----------|------|-------------------|
| Credentials | CWE-798, 522, 521, 259, 256, 312 | T1078, T1552 |
| Session | CWE-352, 384, 613, 1021 | T1185 |
| Memory | CWE-121, 123, 124, 126, 127, 191, 415, 476, 704, 824 | T1203 |
| Injection | CWE-74, 611, 917, 1236, 1321 | T1059, T1005, T1190 |
| Auth | CWE-288, 289, 290, 307 | T1078, T1110 |
| Crypto | CWE-319, 326, 328, 330, 757, 311 | T1557, T1040, T1552 |
| DoS | CWE-400, 770, 674, 835 | T1499 |
| Phishing | CWE-601 | T1566 |

**Résultats**:

| Métrique | Avant | Après | Delta |
|----------|-------|-------|-------|
| CVEs mappées | 15,040 | 16,972 | +1,932 |
| Couverture | 67.2% | 75.8% | +8.6% |
| Techniques | 16 | 22 | +6 |

---

### #14 - Tests Unitaires Causal Graph

**Fichier**: `tests/test_causal_graph.py`

**Classes de test**:

| Classe | Tests | Fonction testée |
|--------|-------|-----------------|
| `TestTheoreticalScore` | 13 | `calculate_theoretical_score()` |
| `TestEmpiricalScore` | 18 | `calculate_empirical_score()` |
| `TestCombinedConfidence` | 9 | `calculate_combined_confidence()` |
| `TestEdgeCases` | 4 | Valeurs limites |
| `TestIntegration` | 2 | Pipeline complet |

**Couverture des composants**:

```
P_théorique:
├── Kill Chain Order (0.0-0.30)
├── I/O Relations (0.0-0.30)
├── Hierarchy (0.0-0.25)
└── Prerequisites (0.0-0.15)

P_empirique:
├── Actor Co-occurrence (0.0-0.40)
├── Campaign Documentation (0.0-0.30)
├── Source Corroboration (0.0-0.20)
└── Recency (0.0-0.10)
```

**Exécution**: `pytest tests/test_causal_graph.py -v`
**Résultat**: 48 passed in 0.04s

---

### #13 - Dataset Quality Metrics

**Fichier**: `quality_metrics.py`

**Métriques implémentées**:

#### 1. Distribution de Confiance
```python
HIGH (>=0.7):    3 (0.4%)
MEDIUM (0.4-0.7): 45 (5.4%)
LOW (0.2-0.4):   102 (12.2%)
UNLIKELY (<0.2): 685 (82.0%)
```

#### 2. Couverture CTI
```python
Total techniques: 835
2+ sources: 20.8%
3+ sources: 4.0%
Sources: {lolbas: 8, otx: 65, nist: 488, cti_chains: 242, loldrivers: 5, hijacklibs: 2}
```

#### 3. Score Global
- Confiance: 40 points max
- Couverture: 40 points max
- Diversité sources: 20 points max
- **Score actuel**: 26.9/100

#### 4. Alertes Automatiques
- ⚠️ WARNING: Seuils non-critiques
- ❌ CRITICAL: Seuils critiques (exit code 1)

---

## Architecture du Système de Scoring

### Formule P_théorique (Issue #5)

```
P_théorique = min(0.95, KC + IO + H + P)

où:
  KC = Kill Chain Score (0-0.30)
       - Adjacent phases: 0.30
       - Close phases (diff ≤3): 0.20
       - Distant phases: 0.10
       - Same phase: 0.05
       - Reverse: 0.00

  IO = I/O Relation Score (0-0.30)
       - Credentials match: 0.30
       - Access match: 0.25
       - Shared data sources: min(0.20, N×0.05)

  H = Hierarchy Score (0-0.25)
       - Parent→Subtechnique: 0.25

  P = Prerequisites Score (0-0.15)
       - Documented in MITRE: 0.15
```

### Formule P_empirique (Issue #6)

```
P_empirique = min(0.95, AC + CD + SC + R)

où:
  AC = Actor Co-occurrence (0-0.40)
       - >=10 actors: 0.40
       - 5-9 actors: 0.30
       - 2-4 actors: 0.20
       - 1 actor: 0.10

  CD = Campaign Documentation (0-0.30)
       - >=10 reports: 0.30
       - 5-9 reports: 0.20
       - 1-4 reports: N×0.05

  SC = Source Corroboration (0-0.20)
       - >=4 sources: 0.20
       - 2-3 sources: 0.10
       - 1 source: 0.05

  R = Recency (0-0.10)
       - This year: 0.10
       - Last year: 0.08
       - Within 2 years: 0.05
       - Within 5 years: 0.02
```

### Formule Combinée (Issue #7)

```
P_combined = (0.4 × P_théorique) + (0.6 × P_empirique)

Classification:
  HIGH:   P_combined >= 0.70
  MEDIUM: 0.40 <= P_combined < 0.70
  LOW:    P_combined < 0.40
```

---

## Top 10 Techniques Corroborées

| Rang | ID | Nom | Score | Sources |
|------|-----|-----|-------|---------|
| 1 | T1027 | Obfuscated Files or Information | 0.75 | LOLBAS, OTX, NIST, CTI_chains |
| 2 | T1059 | Command and Scripting Interpreter | 0.70 | LOLBAS, OTX, NIST, CTI_chains |
| 3 | T1105 | Ingress Tool Transfer | 0.70 | LOLBAS, OTX, NIST, CTI_chains |
| 4 | T1566.002 | Spearphishing Link | 0.60 | OTX, NIST, CTI_chains |
| 5 | T1071 | Application Layer Protocol | 0.60 | OTX, NIST, CTI_chains |
| 6 | T1190 | Exploit Public-Facing Application | 0.60 | OTX, NIST, CTI_chains |
| 7 | T1055 | Process Injection | 0.60 | OTX, NIST, CTI_chains |
| 8 | T1059.001 | PowerShell | 0.60 | OTX, NIST, CTI_chains |
| 9 | T1003 | OS Credential Dumping | 0.57 | LOLBAS, NIST, CTI_chains |
| 10 | T1562 | Impair Defenses | 0.55 | LOLDrivers, NIST, CTI_chains |

---

## Issues Restantes (5)

| # | Titre | Priorité | Dépendances |
|---|-------|----------|-------------|
| 12 | Calibrated uncertainty responses | 🟡 MEDIUM | #5,6,7 ✅ |
| 9 | Contradiction detection | 🟢 LOW | Enrichissement ✅ |
| 10 | False positive profiles | 🟢 LOW | Recherche externe |
| 11 | Business context weighting | 🟢 LOW | Aucune |
| 4 | Dataset reconstruction | ⏳ | Attente utilisateur |

---

## Commandes Utiles

```bash
# Exécuter les tests
pytest dataset_creation/tests/test_causal_graph.py -v

# Analyser la qualité du dataset
python quality_metrics.py

# Générer le mapping CVE→ATT&CK
python filter_kev_nvd.py

# Enrichir les techniques avec CTI
python enrich_with_cti.py
```

---

## Bug Fixes Appliqués

1. **enrich_with_cti.py**: Fixed `TypeError` in `load_hijacklibs()`
   - Cause: `'NoneType' object is not subscriptable`
   - Fix: `locations = entry.get('ExpectedLocations') or []`

2. **enrich_with_cti.py**: Fixed `TypeError` in `load_nist_mappings()`
   - Cause: `capability_description` peut être None
   - Fix: `desc = mapping.get('capability_description') or ''`

3. **test_causal_graph.py**: Fixed floating point comparison
   - Cause: `0.15000000000000002 != 0.15`
   - Fix: `abs(result - 0.15) < 0.001`

---

## Prochaines Étapes Recommandées

1. **Améliorer couverture CTI** - Ajouter plus de sources pour dépasser 50% 3+ sources
2. **Implémenter #12** - Incertitude calibrée pour génération de réponses
3. **Exécuter pipeline complet** - Générer dataset final avec toutes les améliorations
