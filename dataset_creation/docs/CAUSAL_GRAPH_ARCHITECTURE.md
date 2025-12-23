# Architecture du Graphe Causal MITRE ATT&CK

## Vue d'ensemble

Le graphe causal enrichit les données MITRE ATT&CK avec des relations inférées pour créer un dataset d'entraînement LLM capable de raisonner sur les chaînes d'attaque et les stratégies de défense.

```
┌─────────────────────────────────────────────────────────────────┐
│                     NIVEAU 1: DONNÉES BRUTES                    │
│  Sources: MITRE ATT&CK, LOLBAS, NIST, OTX, LOLDrivers, etc.    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              NIVEAU 2: RELATIONS INFÉRÉES (Actuel)              │
│  • enables: T1 → T2 (séquence kill chain)                      │
│  • blocks: Mitigation → Technique                               │
│  • pivot_to: T1 ↔ T2 (alternatives)                            │
│  • prerequisite: T1 → T2 (dépendance)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              NIVEAU 3: SCORING DUAL (À implémenter)             │
│  • P_théorique: Probabilité logique (kill chain)               │
│  • P_empirique: Probabilité observée (CTI)                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│           NIVEAU 4: ENRICHISSEMENT OPÉRATIONNEL                 │
│  • Gestion de l'incertitude                                    │
│  • Contexte métier                                              │
│  • Nuances de faux positifs                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Principes fondamentaux

### 1. Aucune invention de données

**Principe cardinal**: Le système ne DOIT JAMAIS inventer de données. Toutes les relations sont:
- Extraites directement des sources CTI
- Inférées par croisement de données existantes
- Validées par corroboration multi-sources

### 2. Traçabilité complète

Chaque relation doit inclure:
- Source(s) de données
- Méthode d'inférence utilisée
- Niveau de confiance avec justification
- Evidence vérifiable

### 3. Scoring basé sur l'evidence

La confiance N'EST PAS arbitraire. Elle est calculée à partir de:
- Nombre d'acteurs démontrant un pattern
- Citations dans les procédures MITRE
- Présence de détections documentées
- Corroboration inter-sources

---

## Types de relations inférées

### 1. `enables` - Séquence d'activation

**Définition**: T1 → T2 signifie que l'exécution de T1 crée les conditions pour T2.

**Méthode d'inférence** (`infer_enables_from_actor_usage`):
1. Mapper chaque acteur/malware aux techniques utilisées
2. Identifier les séquences de phases (ex: initial-access → execution)
3. Compter les acteurs montrant le même pattern
4. Confidence = f(nombre d'acteurs, proximité des phases)

**Critères**:
- Phases séquentielles (écart ≤ 3 phases)
- Minimum 2 acteurs démontrant le pattern
- Confidence: 0.3 + (count × 0.1), max 0.9

**Exemple**:
```json
{
  "source_name": "Spearphishing Attachment",
  "target_name": "User Execution",
  "relation_type": "enables",
  "confidence": 0.7,
  "evidence": ["7 actors demonstrate this sequence"],
  "actors": ["APT29", "Lazarus", "FIN7", "APT28", "Turla"]
}
```

### 2. `blocks` - Mitigation bloquante

**Définition**: M → T signifie que la mitigation M réduit/bloque la technique T.

**Méthode d'inférence** (`infer_blocks_from_mitigations`):
1. Analyser les relations `mitigates` de MITRE
2. Extraire les mécanismes de blocage du texte (prevent, block, disable...)
3. Identifier les contrôles spécifiques (AppLocker, WDAC, GPO...)
4. Confidence basée sur le verbe d'action:
   - prevent/block: 0.9
   - disable: 0.8
   - restrict: 0.7
   - limit: 0.6
   - control: 0.5
   - monitor/detect: 0.2-0.3 (non-bloquant)

**Exemple**:
```json
{
  "source_name": "Application Isolation and Sandboxing",
  "target_name": "Exploitation for Client Execution",
  "relation_type": "blocks",
  "confidence": 0.9,
  "evidence": ["Controls: AppLocker, UAC", "Mechanisms: prevent, restrict"]
}
```

### 3. `pivot_to` - Alternatives tactiques

**Définition**: T1 ↔ T2 signifie que T2 est une alternative à T1 pour le même objectif.

**Méthode d'inférence** (`infer_pivot_alternatives`):
1. Grouper les techniques par phase
2. Identifier les techniques utilisées par les mêmes acteurs
3. Vérifier que les mitigations diffèrent (possibilité de pivot)
4. Confidence = f(acteurs partagés, différence de mitigations)

**Critères**:
- Même phase kill chain
- ≥ 2 acteurs utilisant les deux techniques
- Mitigations différentes (au moins partiellement)

**Exemple**:
```json
{
  "source_name": "PowerShell",
  "target_name": "Windows Command Shell",
  "relation_type": "pivot_to",
  "confidence": 0.8,
  "evidence": [
    "Same phase: execution",
    "Shared by 15 actors",
    "T1 unique mitigations: 3",
    "T2 unique mitigations: 2"
  ]
}
```

### 4. `prerequisite` - Dépendance logique

**Définition**: T1 → T2 signifie que T1 est nécessaire avant T2.

**Méthode d'inférence** (`infer_prerequisites_from_subtechniques`):
1. Parent → Subtechnique (confiance 0.95)
2. Dépendances tactiques documentées:
   - execution requiert initial-access
   - persistence requiert initial-access + execution
   - lateral-movement requiert credential-access + discovery
   - exfiltration requiert collection
   - impact requiert initial-access + execution

**Exemple**:
```json
{
  "source_name": "Credential Dumping",
  "target_name": "Credential Dumping: LSASS Memory",
  "relation_type": "prerequisite",
  "confidence": 0.95,
  "evidence": ["Parent technique enables subtechnique execution"]
}
```

---

## Statistiques actuelles

```
Relations inférées (run du 2025-12-23):
├── enables:      16,882 relations
├── blocks:        1,445 relations
├── pivot_to:      3,299 relations
└── prerequisite:    627 relations
    TOTAL:        22,253 relations causales
```

---

## Fichiers générés

| Fichier | Description | Taille |
|---------|-------------|--------|
| `causal_graph/mitre_causal_graph.json` | Graphe complet | ~10 MB |
| `causal_graph/enriched_techniques_sample.json` | 50 techniques enrichies | ~500 KB |

---

## Limitations actuelles

1. **Confiance simplifiée**: Score unique, pas encore dual (théorique + empirique)
2. **Sources limitées**: Principalement MITRE, enrichissement CTI partiel
3. **Pas de contexte métier**: Pas de pondération sectorielle
4. **Pas d'incertitude explicite**: Intervalles de confiance non calculés

Ces limitations seront adressées dans les prochaines itérations (voir issues GitHub).

---

## Références

- MITRE ATT&CK: https://attack.mitre.org/
- Kill Chain Phases: 14 phases tactiques (recon → impact)
- Fichier source: `build_causal_graph.py`
