# Modèle de Scoring de Confiance

## Philosophie

Le scoring de confiance doit être **ancré dans la réalité** et non basé sur des heuristiques arbitraires. Chaque score doit être traçable jusqu'à des evidences vérifiables.

---

## Modèle Dual: P_théorique vs P_empirique

### Concept

Nous distinguons deux dimensions orthogonales de la confiance:

```
                    P_empirique (observé en CTI)
                           │
              HIGH         │          HIGH
         ┌─────────────────┼─────────────────┐
         │   PLAUSIBLE     │    CONFIRMÉ     │
         │   "Logique mais │   "Observé et   │
         │    pas encore   │    logique"     │
         │    observé"     │                 │
    LOW  ├─────────────────┼─────────────────┤ P_théorique
         │   IMPROBABLE    │   CORRÉLATION   │   (logique)
         │   "Ni logique   │   "Observé mais │
         │    ni observé"  │    pas logique" │
         │                 │                 │     HIGH
         └─────────────────┴─────────────────┘
                          LOW
```

### P_théorique (Score de faisabilité logique)

Évalue si la relation est **logiquement réalisable** selon:

1. **Ordre du Kill Chain** (0.0 - 0.3)
   - Phase N → Phase N+1: +0.3
   - Phase N → Phase N+2: +0.2
   - Phase N → Phase N+3: +0.1
   - Phases non-séquentielles: +0.0

2. **Relation I/O** (0.0 - 0.3)
   - T1 produit ce que T2 consomme: +0.3
   - T1 et T2 partagent des ressources: +0.15
   - Aucune relation évidente: +0.0

3. **Hiérarchie MITRE** (0.0 - 0.25)
   - Parent → Subtechnique: +0.25
   - Même tactique: +0.1
   - Tactiques différentes: +0.0

4. **Prérequis documentés** (0.0 - 0.15)
   - Relation explicite dans MITRE: +0.15
   - Implicite par description: +0.07

**Score maximum théorique: 1.0** (plafonné à 0.95)

### P_empirique (Score d'observation CTI)

Évalue si la relation est **effectivement observée** selon:

1. **Co-occurrence acteurs** (0.0 - 0.4)
   - ≥10 acteurs: +0.4
   - 5-9 acteurs: +0.3
   - 2-4 acteurs: +0.2
   - 1 acteur: +0.1
   - 0 acteur: +0.0

2. **Documentation campagnes** (0.0 - 0.3)
   - Séquence explicite dans procédure: +0.3
   - Mentionné dans campagne: +0.15
   - Non documenté: +0.0

3. **Sources CTI multiples** (0.0 - 0.2)
   - ≥3 sources (MITRE + OTX + autre): +0.2
   - 2 sources: +0.15
   - 1 source: +0.05

4. **Récence** (0.0 - 0.1)
   - Observé dans les 12 derniers mois: +0.1
   - Observé dans les 24 derniers mois: +0.05
   - Plus ancien: +0.0

**Score maximum empirique: 1.0** (plafonné à 0.95)

---

## Matrice de classification

| P_théorique | P_empirique | Catégorie | Interprétation |
|-------------|-------------|-----------|----------------|
| ≥ 0.5 | ≥ 0.5 | **CONFIRMÉ** | Relation établie, haute confiance |
| ≥ 0.5 | < 0.5 | **PLAUSIBLE** | Logique mais peu observé - attention |
| < 0.5 | ≥ 0.5 | **CORRÉLATION** | Observé sans logique claire - investigation |
| < 0.5 | < 0.5 | **IMPROBABLE** | Faible évidence - à ignorer ou vérifier |

---

## Implémentation proposée

```python
@dataclass
class DualConfidenceScore:
    """Score de confiance dual avec traçabilité."""
    p_theoretical: float  # 0.0 - 1.0
    p_empirical: float    # 0.0 - 1.0
    category: str         # CONFIRMED, PLAUSIBLE, CORRELATION, UNLIKELY
    theoretical_evidence: List[str]  # Justifications théoriques
    empirical_evidence: List[str]    # Observations CTI
    sources: List[str]               # Sources de données utilisées
    last_updated: str                # ISO timestamp

def calculate_theoretical_score(t1_ext: Dict, t2_ext: Dict) -> Tuple[float, List[str]]:
    """
    Calcule P_théorique basé sur:
    - Séquence kill chain
    - Relations I/O
    - Hiérarchie MITRE
    - Prérequis documentés

    Returns: (score, evidence_list)
    """
    score = 0.0
    evidence = []

    # 1. Kill chain sequence
    phase_diff = t2_ext['phase_order'] - t1_ext['phase_order']
    if 1 <= phase_diff <= 3:
        phase_score = 0.3 - (phase_diff - 1) * 0.1
        score += phase_score
        evidence.append(f"Kill chain: {t1_ext['phase']} → {t2_ext['phase']} (+{phase_score:.2f})")

    # 2. I/O relationship (simplified - needs NLP analysis)
    # TODO: Implement semantic analysis of technique descriptions

    # 3. Hierarchy
    if t2_ext.get('parent_id') == t1_ext['id']:
        score += 0.25
        evidence.append("Hierarchy: parent → subtechnique (+0.25)")
    elif t1_ext['tactic'] == t2_ext['tactic']:
        score += 0.1
        evidence.append(f"Same tactic: {t1_ext['tactic']} (+0.10)")

    # 4. Documented prerequisites
    if t1_ext['id'] in t2_ext.get('documented_prereqs', []):
        score += 0.15
        evidence.append("Documented prerequisite in MITRE (+0.15)")

    return min(0.95, score), evidence

def calculate_empirical_score(t1_ext: Dict, t2_ext: Dict, cti_data: Dict) -> Tuple[float, List[str]]:
    """
    Calcule P_empirique basé sur:
    - Co-occurrence acteurs
    - Documentation campagnes
    - Corroboration multi-sources
    - Récence

    Returns: (score, evidence_list)
    """
    score = 0.0
    evidence = []

    # 1. Actor co-occurrence
    shared_actors = set(t1_ext['actors']) & set(t2_ext['actors'])
    if len(shared_actors) >= 10:
        score += 0.4
        evidence.append(f"{len(shared_actors)} shared actors (+0.40)")
    elif len(shared_actors) >= 5:
        score += 0.3
        evidence.append(f"{len(shared_actors)} shared actors (+0.30)")
    elif len(shared_actors) >= 2:
        score += 0.2
        evidence.append(f"{len(shared_actors)} shared actors (+0.20)")
    elif len(shared_actors) == 1:
        score += 0.1
        evidence.append(f"1 shared actor (+0.10)")

    # 2. Campaign documentation
    sequence_key = f"{t1_ext['id']}→{t2_ext['id']}"
    if sequence_key in cti_data.get('documented_sequences', {}):
        doc = cti_data['documented_sequences'][sequence_key]
        if doc.get('explicit'):
            score += 0.3
            evidence.append(f"Explicit sequence in {doc['source']} (+0.30)")
        else:
            score += 0.15
            evidence.append(f"Implicit sequence in {doc['source']} (+0.15)")

    # 3. Multi-source corroboration
    sources = set()
    if t1_ext.get('mitre_citations'): sources.add('MITRE')
    if t1_ext.get('otx_pulses'): sources.add('OTX')
    if t1_ext.get('lolbas_refs'): sources.add('LOLBAS')
    if t1_ext.get('nist_mappings'): sources.add('NIST')

    if len(sources) >= 3:
        score += 0.2
        evidence.append(f"Corroborated by {len(sources)} sources: {', '.join(sources)} (+0.20)")
    elif len(sources) == 2:
        score += 0.15
        evidence.append(f"Corroborated by 2 sources: {', '.join(sources)} (+0.15)")

    # 4. Recency (requires timestamp data)
    # TODO: Implement when timestamp data available

    return min(0.95, score), evidence

def classify_confidence(p_theo: float, p_emp: float) -> str:
    """Classify based on dual scores."""
    if p_theo >= 0.5 and p_emp >= 0.5:
        return "CONFIRMED"
    elif p_theo >= 0.5:
        return "PLAUSIBLE"
    elif p_emp >= 0.5:
        return "CORRELATION"
    else:
        return "UNLIKELY"
```

---

## Sources de données pour le scoring

### Pour P_théorique

| Source | Contribution | Disponibilité |
|--------|--------------|---------------|
| MITRE Kill Chain | Ordre des phases | Disponible |
| MITRE Descriptions | Relations I/O | Nécessite NLP |
| MITRE Hierarchy | Parent/subtechnique | Disponible |
| MITRE Relationships | Prérequis explicites | Disponible |

### Pour P_empirique

| Source | Contribution | Disponibilité |
|--------|--------------|---------------|
| MITRE Actors | Co-occurrence | Disponible |
| MITRE Procedures | Séquences documentées | Partiellement |
| AlienVault OTX | Pulses CTI | Disponible (66 techniques) |
| LOLBAS | Binaires abusés | Disponible (55 techniques) |
| NIST Mappings | Contrôles liés | Disponible (470 techniques) |
| LOLDrivers | Drivers vulnérables | Disponible (6 techniques) |
| HijackLibs | DLL hijacking | Disponible (1 technique) |

---

## Progression de grade: B → A

Pour améliorer le grade d'une relation de PLAUSIBLE (B) vers CONFIRMÉ (A):

1. **Enrichissement CTI**
   - Ajouter des sources CTI (OTX, MISP, etc.)
   - Corrélation avec rapports de campagnes

2. **Corroboration multi-sources**
   - Vérifier la relation dans ≥3 sources
   - Documenter chaque confirmation

3. **Validation temporelle**
   - Confirmer l'observation récente (<12 mois)
   - Vérifier la persistance du pattern

4. **Documentation explicite**
   - Référencer les procédures MITRE
   - Lier aux CVE/CWE quand applicable

---

## Métriques de qualité

```
Objectifs de distribution:
├── CONFIRMÉ:    ≥ 40% des relations
├── PLAUSIBLE:   ≤ 35% des relations
├── CORRÉLATION: ≤ 15% des relations
└── IMPROBABLE:  ≤ 10% des relations
```

Ces seuils garantissent un dataset majoritairement de haute qualité.

---

## Références

- Document parent: `CAUSAL_GRAPH_ARCHITECTURE.md`
- Implémentation: `build_causal_graph.py` (à enrichir)
- Issues liées: `#XX - Implement dual confidence scoring`
