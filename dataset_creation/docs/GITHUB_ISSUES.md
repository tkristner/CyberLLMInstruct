# GitHub Issues - Backlog de Développement

Ce document contient les issues à créer sur GitHub pour la traçabilité du projet.

---

## Epic: Scoring de Confiance Dual

### Issue #1: Implémenter le scoring P_théorique

**Titre**: `feat(causal-graph): Implement theoretical confidence scoring (P_théorique)`

**Labels**: `enhancement`, `priority-high`, `causal-graph`

**Description**:
```markdown
## Contexte
Le scoring actuel utilise une heuristique simple. Nous devons implémenter un scoring théorique basé sur des critères vérifiables.

## Critères de scoring (voir docs/CONFIDENCE_SCORING_MODEL.md)
- [ ] Ordre du Kill Chain (0.0 - 0.3)
- [ ] Relation I/O entre techniques (0.0 - 0.3)
- [ ] Hiérarchie MITRE parent/subtechnique (0.0 - 0.25)
- [ ] Prérequis documentés (0.0 - 0.15)

## Implémentation
- Fichier: `build_causal_graph.py`
- Nouvelle fonction: `calculate_theoretical_score(t1_ext, t2_ext) -> Tuple[float, List[str]]`
- Retourne: (score, evidence_list) pour traçabilité

## Acceptance Criteria
- [ ] Score calculé pour toutes les relations `enables`
- [ ] Evidence list documente chaque composant du score
- [ ] Tests unitaires avec cas limites
- [ ] Score plafonné à 0.95

## Références
- Documentation: docs/CONFIDENCE_SCORING_MODEL.md
- Architecture: docs/CAUSAL_GRAPH_ARCHITECTURE.md
```

---

### Issue #2: Implémenter le scoring P_empirique

**Titre**: `feat(causal-graph): Implement empirical confidence scoring (P_empirique)`

**Labels**: `enhancement`, `priority-high`, `causal-graph`

**Description**:
```markdown
## Contexte
Le scoring empirique mesure ce qui est réellement observé dans les données CTI, pas ce qui est théoriquement possible.

## Critères de scoring (voir docs/CONFIDENCE_SCORING_MODEL.md)
- [ ] Co-occurrence acteurs (0.0 - 0.4)
- [ ] Documentation dans campagnes (0.0 - 0.3)
- [ ] Corroboration multi-sources (0.0 - 0.2)
- [ ] Récence des observations (0.0 - 0.1)

## Dépendances
- Nécessite enrichissement CTI (#4)
- Nécessite timestamps dans les données

## Implémentation
- Fichier: `build_causal_graph.py`
- Nouvelle fonction: `calculate_empirical_score(t1_ext, t2_ext, cti_data) -> Tuple[float, List[str]]`
- Intégration avec sources OTX, LOLBAS, NIST

## Acceptance Criteria
- [ ] Score calculé pour relations avec données CTI disponibles
- [ ] Evidence list avec sources citées
- [ ] Tests avec données mockées
- [ ] Gestion des données manquantes (score 0 si pas de CTI)

## Références
- Documentation: docs/CONFIDENCE_SCORING_MODEL.md
- Sources: docs/MULTI_SOURCE_CORROBORATION.md
```

---

### Issue #3: Matrice de classification CONFIRMED/PLAUSIBLE/CORRELATION/UNLIKELY

**Titre**: `feat(causal-graph): Implement confidence classification matrix`

**Labels**: `enhancement`, `priority-medium`, `causal-graph`

**Description**:
```markdown
## Contexte
Combiner P_théorique et P_empirique pour classifier chaque relation.

## Matrice de classification
| P_théorique | P_empirique | Catégorie |
|-------------|-------------|-----------|
| ≥ 0.5 | ≥ 0.5 | CONFIRMED |
| ≥ 0.5 | < 0.5 | PLAUSIBLE |
| < 0.5 | ≥ 0.5 | CORRELATION |
| < 0.5 | < 0.5 | UNLIKELY |

## Implémentation
- Dataclass: `DualConfidenceScore`
- Fonction: `classify_confidence(p_theo, p_emp) -> str`
- Ajout dans `CausalRelation` dataclass

## Acceptance Criteria
- [ ] Chaque relation a une catégorie
- [ ] Statistiques de distribution disponibles
- [ ] Export JSON inclut les deux scores + catégorie
- [ ] Tests pour chaque cas de la matrice

## Dépendances
- Issue #1 (P_théorique)
- Issue #2 (P_empirique)
```

---

## Epic: Enrichissement Multi-Sources

### Issue #4: Enrichir les techniques avec sources CTI

**Titre**: `feat(enrichment): Cross-reference techniques with CTI sources`

**Labels**: `enhancement`, `priority-high`, `data-enrichment`

**Description**:
```markdown
## Contexte
Chaque technique doit être enrichie avec les données de toutes nos sources CTI.

## Sources à intégrer
- [ ] LOLBAS (227 binaires, 55 techniques)
- [ ] NIST Mappings (5,331 mappings, 470 techniques)
- [ ] AlienVault OTX (1,151 pulses, 66 techniques)
- [ ] LOLDrivers (495 drivers, 6 techniques)
- [ ] HijackLibs (566 DLLs, 1 technique)

## Mapping requis
Pour chaque technique MITRE:
1. Lookup par ID externe (T1234)
2. Lookup par nom (fuzzy match si nécessaire)
3. Agrégation des données trouvées
4. Calcul du score de corroboration

## Output
```python
@dataclass
class EnrichedTechniqueWithCTI:
    technique_id: str
    technique_name: str
    sources_count: int
    corroboration_score: float
    source_details: Dict[str, SourceEvidence]
    contradictions: List[Contradiction]
```

## Acceptance Criteria
- [ ] 100% des techniques mappées
- [ ] Statistiques de couverture par source
- [ ] Log des techniques non-trouvées par source
- [ ] Export JSON avec détails de sources

## Références
- Documentation: docs/MULTI_SOURCE_CORROBORATION.md
```

---

### Issue #5: Détecter et logger les contradictions inter-sources

**Titre**: `feat(enrichment): Detect and log contradictions between sources`

**Labels**: `enhancement`, `priority-medium`, `data-quality`

**Description**:
```markdown
## Contexte
Les sources CTI peuvent se contredire. Il faut détecter et documenter ces cas.

## Types de contradictions
1. **Effectiveness**: Source A dit "prevent", Source B dit "detect only"
2. **Severity**: CVSS différent entre sources
3. **Attribution**: Acteurs différents attribués

## Comportement
- NE PAS résoudre automatiquement
- Logger pour revue humaine
- Inclure dans les métadonnées

## Implémentation
```python
@dataclass
class Contradiction:
    field: str
    source_a: Dict[str, Any]
    source_b: Dict[str, Any]
    resolution: str  # "pending_review", "a_preferred", "b_preferred"
    notes: str
```

## Acceptance Criteria
- [ ] Détection automatique des contradictions
- [ ] Export dans fichier séparé pour revue
- [ ] Statistiques de contradictions par type
- [ ] Documentation des critères de détection
```

---

## Epic: Dimensions Opérationnelles

### Issue #6: Ajouter profils de faux positifs aux techniques

**Titre**: `feat(operational): Add false positive profiles to techniques`

**Labels**: `enhancement`, `priority-high`, `operational`

**Description**:
```markdown
## Contexte
Pour générer des réponses réalistes, le LLM doit connaître les taux de FP et contextes de tuning.

## Structure
```python
@dataclass
class FalsePositiveProfile:
    fp_rate_estimate: float  # Estimé de publications/expérience
    legitimate_uses: List[str]
    high_fp_contexts: List[str]
    discrimination_indicators: List[str]
    tuning_recommendations: List[str]
```

## Sources pour les estimations
- Publications académiques sur détection
- Documentation SIEM vendors (Splunk, Elastic)
- Sigma rules avec metadata
- Expérience SOC documentée

## Techniques prioritaires
Les 50 techniques les plus détectées (par nombre de règles Sigma):
- T1059.001 (PowerShell)
- T1053.005 (Scheduled Task)
- T1003.001 (LSASS)
- etc.

## Acceptance Criteria
- [ ] Profil FP pour top 50 techniques
- [ ] Sources documentées pour chaque estimation
- [ ] Intégration dans EnrichedTechnique
- [ ] Export pour génération QnA
```

---

### Issue #7: Implémenter la pondération contextuelle métier

**Titre**: `feat(operational): Implement business context priority weighting`

**Labels**: `enhancement`, `priority-medium`, `operational`

**Description**:
```markdown
## Contexte
La priorité d'une alerte dépend du contexte métier (secteur, criticité, régulation).

## Facteurs de pondération
```python
@dataclass
class BusinessContext:
    sector: str  # finance, healthcare, energy, retail...
    asset_criticality: str  # critical, important, standard
    regulatory_framework: List[str]  # PCI-DSS, HIPAA, NIS2...
    security_maturity: str  # high, medium, low
```

## Multiplicateurs
- Secteur finance: x1.3
- Secteur énergie: x1.4
- Asset critique: x1.5
- Régulation stricte: x1.2
- Maturité faible: x1.3

## Implémentation
- Fonction: `adjust_priority_for_context(base_priority, context)`
- Intégration dans génération de réponses
- Templates de réponses adaptés au contexte

## Acceptance Criteria
- [ ] Fonction de calcul avec tests
- [ ] Au moins 5 exemples de réponses contextualisées
- [ ] Documentation des multiplicateurs et sources
```

---

### Issue #8: Génération de réponses avec incertitude calibrée

**Titre**: `feat(qa-generation): Generate responses with calibrated uncertainty`

**Labels**: `enhancement`, `priority-high`, `qa-generation`

**Description**:
```markdown
## Contexte
Le LLM doit apprendre à moduler sa confiance dans ses réponses.

## Formulations par niveau
| Confiance | Formulations |
|-----------|--------------|
| >0.8 | "confirmé par", "clairement établi" |
| 0.5-0.8 | "probable", "suggère", "selon les données" |
| <0.5 | "possible corrélation", "à confirmer", "données limitées" |

## Implémentation dans data_structurer.py
- Nouveau paramètre: `confidence_level` dans génération
- Templates de réponses adaptés
- Métadonnées d'incertitude dans output

## Acceptance Criteria
- [ ] 3 niveaux de formulation implémentés
- [ ] 90% des réponses avec incertitude calibrée
- [ ] Tests de cohérence formulation/score
- [ ] Exemples documentés par niveau
```

---

## Epic: Infrastructure & Qualité

### Issue #9: Métriques de qualité du dataset

**Titre**: `feat(quality): Implement dataset quality metrics`

**Labels**: `enhancement`, `priority-medium`, `quality`

**Description**:
```markdown
## Métriques à implémenter

### Distribution de confiance
- % CONFIRMED ≥ 40%
- % PLAUSIBLE ≤ 35%
- % CORRELATION ≤ 15%
- % UNLIKELY ≤ 10%

### Couverture CTI
- % techniques avec ≥3 sources: objectif 50%
- % techniques avec ≥2 sources: objectif 80%

### Qualité opérationnelle
- % réponses avec incertitude calibrée: ≥90%
- % réponses avec contexte métier: ≥70%
- % réponses avec guidance FP: ≥80%

## Output
- Script: `quality_metrics.py`
- Rapport JSON avec toutes les métriques
- Alertes si seuils non atteints
```

---

### Issue #10: Tests unitaires pour le graphe causal

**Titre**: `test(causal-graph): Add comprehensive unit tests`

**Labels**: `testing`, `priority-high`

**Description**:
```markdown
## Couverture requise

### build_causal_graph.py
- [ ] `infer_enables_from_actor_usage()`
- [ ] `infer_blocks_from_mitigations()`
- [ ] `infer_pivot_alternatives()`
- [ ] `infer_prerequisites_from_subtechniques()`
- [ ] `calculate_theoretical_score()` (#1)
- [ ] `calculate_empirical_score()` (#2)
- [ ] `classify_confidence()` (#3)

### Cas de test
- Données valides
- Données manquantes (None, empty)
- Cas limites (score = 0, score = 1)
- Contradictions (#5)

## Framework
- pytest
- Fixtures avec données MITRE mockées
- Couverture minimum: 80%
```

---

## Ordre de priorité recommandé

### Sprint 1: Fondations
1. Issue #4 - Enrichissement CTI (bloquant pour #2)
2. Issue #1 - P_théorique
3. Issue #10 - Tests unitaires

### Sprint 2: Scoring complet
4. Issue #2 - P_empirique
5. Issue #3 - Classification
6. Issue #5 - Contradictions

### Sprint 3: Opérationnel
7. Issue #6 - Profils FP
8. Issue #8 - Incertitude calibrée
9. Issue #7 - Contexte métier

### Sprint 4: Qualité
10. Issue #9 - Métriques qualité

---

## Notes pour création sur GitHub

```bash
# Créer les issues via gh CLI
gh issue create --title "feat(causal-graph): Implement theoretical confidence scoring" \
  --body "$(cat issue_1_body.md)" \
  --label "enhancement,priority-high,causal-graph"

# Ou utiliser l'interface web GitHub
# Repository: https://github.com/[user]/CyberLLMInstruct
```
