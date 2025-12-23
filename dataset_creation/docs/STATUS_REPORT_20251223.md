# Rapport de Statut - CyberLLMInstruct Dataset Creation
**Date**: 2025-12-23

---

## Résumé exécutif

Le projet CyberLLMInstruct vise à créer un dataset d'entraînement LLM pour la cybersécurité opérationnelle. Cette session a fait des avancées majeures sur l'architecture du graphe causal et le modèle de scoring de confiance.

**État global**: Architecture définie, implémentation partielle, documentation complète.

---

## 1. État actuel du pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 1: Data Collection                              [DONE]   │
│ • 8 sources CTI collectées                                     │
│ • Scripts: collect_*.py                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 2: Data Filtering                               [DONE]   │
│ • Critères de qualité appliqués                                │
│ • Script: data_filter.py                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 3: QnA Generation                           [PARTIAL]    │
│ • Génération basique fonctionnelle                             │
│ • Script: data_structurer.py                                   │
│ • TODO: Intégrer dimensions opérationnelles                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 4: Causal Graph                             [PARTIAL]    │
│ • 4 types de relations inférées                                │
│ • Script: build_causal_graph.py                                │
│ • TODO: Scoring dual, enrichissement CTI                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 5: Final Dataset                            [PENDING]    │
│ • Agrégation de toutes les paires                              │
│ • Validation qualité                                           │
│ • Export formats (JSON, Parquet)                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Données collectées

### Sources CTI primaires

| Source | Fichier filtré | Entrées | Techniques |
|--------|---------------|---------|------------|
| MITRE ATT&CK | `mitre_attack_*_filtered.json` | 24,653 | 835 |
| LOLBAS | `lolbas_*_filtered.json` | 227 | 55 |
| NIST Mappings | `nist_attack_mapping_filtered.json` | 5,331 | 470 |
| AlienVault OTX | `alienvault_otx_*_filtered.json` | 1,151 | 66 |
| LOLDrivers | `loldrivers_*_filtered.json` | 495 | 6 |
| HijackLibs | `hijacklibs_*_filtered.json` | 566 | 1 |
| OSINT Framework | `osint_framework_*_filtered.json` | 1,149 | N/A |
| Awesome Lists | `awesome_*_filtered.json` | Variable | N/A |

### Répertoire des données

```
/data/github/CyberLLMInstruct/dataset_creation/
├── filtered_data/           # Données filtrées (Stage 2 output)
├── structured_data/         # Paires QnA générées (Stage 3 output)
│   └── samples/             # Échantillons pour validation
├── causal_graph/            # Graphe causal (Stage 4 output)
│   ├── mitre_causal_graph.json
│   └── enriched_techniques_sample.json
└── docs/                    # Documentation (nouveau)
```

---

## 3. Graphe causal - État actuel

### Relations inférées (run du 2025-12-23)

| Type | Quantité | Méthode | Confiance |
|------|----------|---------|-----------|
| `enables` | 16,882 | Actor co-occurrence | 0.3 - 0.9 |
| `blocks` | 1,445 | Mitigation analysis | 0.2 - 0.9 |
| `pivot_to` | 3,299 | Same phase + shared actors | 0.3 - 0.8 |
| `prerequisite` | 627 | Subtechnique + phase order | 0.6 - 0.95 |
| **TOTAL** | **22,253** | | |

### Implémentation actuelle

**Fichier**: `build_causal_graph.py` (597 lignes)

**Classes**:
- `CausalRelation`: Dataclass pour une relation
- `EnrichedTechnique`: Technique avec contexte causal
- `MITRECausalGraphBuilder`: Builder principal

**Méthodes d'inférence**:
1. `infer_enables_from_actor_usage()` - Pattern matching sur séquences acteurs
2. `infer_blocks_from_mitigations()` - Analyse sémantique des mitigations
3. `infer_pivot_alternatives()` - Alternatives tactiques
4. `infer_prerequisites_from_subtechniques()` - Dépendances hiérarchiques

### Limitations identifiées

1. **Scoring simplifié**: Heuristique unique, pas encore dual
2. **Pas d'enrichissement CTI**: Sources non croisées
3. **Pas de timestamps**: Récence non calculable
4. **Pas de profils FP**: Taux de faux positifs absents

---

## 4. Décisions architecturales

### ADR-001: Modèle de scoring dual

**Décision**: Séparer le scoring en deux dimensions orthogonales.

**Contexte**: Un score unique mélange la faisabilité théorique et l'observation empirique, rendant l'interprétation ambiguë.

**Solution**:
- **P_théorique**: Probabilité basée sur la logique (kill chain, I/O, hiérarchie)
- **P_empirique**: Probabilité basée sur les observations CTI

**Matrice de classification**:
```
                 P_empirique
              LOW        HIGH
         ┌──────────┬──────────┐
P_théo   │IMPROBABLE│CORRÉLATION│
  LOW    └──────────┴──────────┘
         ┌──────────┬──────────┐
P_théo   │PLAUSIBLE │ CONFIRMÉ │
  HIGH   └──────────┴──────────┘
```

**Statut**: Documenté, implémentation pending (Issue #1, #2, #3)

---

### ADR-002: Triangulation sans invention

**Décision**: Toutes les données doivent être traçables à des sources existantes.

**Contexte**: Le risque d'hallucination LLM est exacerbé si les données d'entraînement contiennent des informations inventées.

**Règles**:
1. Jamais de données générées sans source
2. Corroboration multi-sources augmente la confiance
3. Les contradictions sont loggées, pas résolues automatiquement
4. Chaque relation inclut ses evidences

**Statut**: Principe appliqué, enrichissement CTI pending (Issue #4, #5)

---

### ADR-003: Dimensions opérationnelles

**Décision**: Enrichir le dataset avec métadonnées opérationnelles.

**Contexte**: Un assistant cybersécurité doit raisonner comme un analyste SOC, pas réciter des faits.

**Dimensions**:
1. **Gestion de l'incertitude**: Formulations calibrées selon la confiance
2. **Contexte métier**: Pondération par secteur, criticité, régulation
3. **Faux positifs**: Profils, tuning, discrimination

**Statut**: Documenté, implémentation pending (Issue #6, #7, #8)

---

## 5. Documentation créée

| Document | Description | Chemin |
|----------|-------------|--------|
| Architecture graphe causal | Vue d'ensemble et types de relations | `docs/CAUSAL_GRAPH_ARCHITECTURE.md` |
| Modèle de scoring | P_théorique, P_empirique, matrice | `docs/CONFIDENCE_SCORING_MODEL.md` |
| Corroboration multi-sources | Stratégie CTI, triangulation | `docs/MULTI_SOURCE_CORROBORATION.md` |
| Dimensions opérationnelles | Incertitude, contexte, FP | `docs/OPERATIONAL_DIMENSIONS.md` |
| Issues GitHub | Backlog de développement | `docs/GITHUB_ISSUES.md` |
| Ce rapport | Statut complet | `docs/STATUS_REPORT_20251223.md` |

---

## 6. Backlog prioritisé

### Sprint 1: Fondations (priorité haute)
- [ ] **Issue #4**: Enrichissement CTI multi-sources
- [ ] **Issue #1**: Scoring P_théorique
- [ ] **Issue #10**: Tests unitaires

### Sprint 2: Scoring complet
- [ ] **Issue #2**: Scoring P_empirique
- [ ] **Issue #3**: Classification matrice
- [ ] **Issue #5**: Détection contradictions

### Sprint 3: Opérationnel
- [ ] **Issue #6**: Profils faux positifs
- [ ] **Issue #8**: Incertitude calibrée
- [ ] **Issue #7**: Contexte métier

### Sprint 4: Qualité
- [ ] **Issue #9**: Métriques qualité

---

## 7. Métriques de succès

### Objectifs quantitatifs

| Métrique | Objectif | Actuel |
|----------|----------|--------|
| Relations CONFIRMED | ≥ 40% | À mesurer |
| Techniques avec ≥3 sources | ≥ 50% | ~5% |
| Réponses avec incertitude calibrée | ≥ 90% | 0% |
| Couverture tests | ≥ 80% | 0% |

### Objectifs qualitatifs

- [ ] Aucune donnée inventée
- [ ] Traçabilité complète source → relation → réponse
- [ ] Réponses adaptées au contexte métier
- [ ] Guidance de tuning pour techniques à haut FP

---

## 8. Risques identifiés

| Risque | Impact | Mitigation |
|--------|--------|------------|
| Couverture CTI insuffisante | Scoring empirique peu fiable | Ajouter sources (MISP, VT) |
| Timestamps manquants | Récence non calculable | Parser dates des rapports |
| Complexité scoring | Implémentation longue | Itérer par version |
| Qualité des profils FP | Estimations incorrectes | Valider avec SOC réels |

---

## 9. Prochaines étapes

1. **Immédiat**: Créer les issues GitHub depuis `GITHUB_ISSUES.md`
2. **Sprint 1**: Implémenter enrichissement CTI + P_théorique
3. **Validation**: Revue humaine d'un échantillon de 100 relations
4. **Itération**: Ajuster les seuils selon les résultats

---

## Annexe: Arborescence du projet

```
/data/github/CyberLLMInstruct/
├── dataset_creation/
│   ├── collect_*.py           # Stage 1: Collection
│   ├── data_filter.py         # Stage 2: Filtrage
│   ├── data_structurer.py     # Stage 3: QnA generation
│   ├── build_causal_graph.py  # Stage 4: Graphe causal
│   ├── vllm_client.py         # Client LLM partagé
│   ├── filtered_data/         # Données filtrées
│   ├── structured_data/       # Paires QnA
│   ├── causal_graph/          # Graphe causal output
│   └── docs/                  # Documentation (nouveau)
│       ├── CAUSAL_GRAPH_ARCHITECTURE.md
│       ├── CONFIDENCE_SCORING_MODEL.md
│       ├── MULTI_SOURCE_CORROBORATION.md
│       ├── OPERATIONAL_DIMENSIONS.md
│       ├── GITHUB_ISSUES.md
│       └── STATUS_REPORT_20251223.md
└── README.md
```

---

**Auteur**: Claude Code (session 2025-12-23)
**Révisé par**: [En attente de revue humaine]
