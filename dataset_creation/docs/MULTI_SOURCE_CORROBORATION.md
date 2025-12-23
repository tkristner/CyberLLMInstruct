# Corroboration Multi-Sources CTI

## Principe fondamental

> **Aucune donnée inventée** - La qualité prime sur la quantité.

Toutes les relations et enrichissements doivent être traçables à des sources CTI vérifiables. La triangulation entre sources augmente la confiance.

---

## Sources CTI disponibles

### Sources primaires (intégrées)

| Source | Type | Entrées | Techniques couvertes | Contribution |
|--------|------|---------|---------------------|--------------|
| **MITRE ATT&CK** | Référentiel | 24,653 | 835 | Base de toutes les relations |
| **LOLBAS** | Binaires légitimes | 227 | 55 | Windows living-off-the-land |
| **NIST Mappings** | Contrôles sécurité | 5,331 | 470 | Mitigations techniques |
| **AlienVault OTX** | Threat Intel | 1,151 | 66 | Observations terrain |
| **LOLDrivers** | Drivers vulnérables | 495 | 6 | Attaques kernel |
| **HijackLibs** | DLL hijacking | 566 | 1 (T1574) | Persistence/escalation |

### Sources additionnelles (à intégrer)

| Source | Type | Priorité | Valeur ajoutée |
|--------|------|----------|----------------|
| MISP Feeds | IOC partagés | P1 | Corroboration temps réel |
| VirusTotal | Hashes/comportements | P1 | Validation samples |
| Shodan | Exposition réseau | P2 | Surface d'attaque |
| CERT-FR Bulletins | Alertes nationales | P2 | Contexte français/européen |
| CTI Reports (vendors) | Rapports d'analyse | P3 | Séquences d'attaque documentées |

---

## Stratégie de corroboration

### Niveau 1: Enrichissement technique

```
MITRE Technique
     │
     ├── + LOLBAS → Binaires Windows abusables
     │     └── Si technique = T1218, T1059, etc.
     │
     ├── + NIST → Contrôles de mitigation
     │     └── Mapping NIST SP 800-53 → ATT&CK
     │
     ├── + OTX → Observations terrain
     │     └── Pulses mentionnant la technique
     │
     ├── + LOLDrivers → Vecteurs kernel
     │     └── Si technique implique drivers
     │
     └── + HijackLibs → Chemins DLL
           └── Pour T1574 et subtechniques
```

### Niveau 2: Corroboration croisée

Une relation gagne en confiance quand elle est observée dans **plusieurs sources indépendantes**:

```python
def calculate_corroboration_score(technique_id: str, sources: Dict) -> float:
    """
    Score de corroboration basé sur le nombre de sources.

    Sources indépendantes:
    - MITRE (documentation officielle)
    - LOLBAS (communauté red team)
    - NIST (gouvernement US)
    - OTX (communauté CTI)
    - LOLDrivers (recherche sécurité)
    - HijackLibs (recherche spécialisée)
    """
    source_count = 0

    if sources.get('mitre_refs'):
        source_count += 1
    if sources.get('lolbas_refs'):
        source_count += 1
    if sources.get('nist_controls'):
        source_count += 1
    if sources.get('otx_pulses'):
        source_count += 1
    if sources.get('loldrivers_refs'):
        source_count += 1
    if sources.get('hijacklibs_refs'):
        source_count += 1

    # Score: 0.0 si 0-1 source, augmente avec plus de sources
    if source_count <= 1:
        return 0.0
    elif source_count == 2:
        return 0.3
    elif source_count == 3:
        return 0.5
    elif source_count >= 4:
        return 0.7

    return 0.0
```

### Niveau 3: Triangulation temporelle

Pour les relations `enables`, vérifier la **cohérence temporelle**:

```
Si T1 observé à t1 et T2 observé à t2:
  - t2 > t1 → cohérent avec enables
  - t2 < t1 → incohérent (rejeter ou marquer comme corrélation)
  - |t2 - t1| < 24h → séquence probable
  - |t2 - t1| > 30j → séquence improbable
```

---

## Flux de traitement

```
┌─────────────────────────────────────────────────────────────┐
│                     PHASE 1: COLLECTE                        │
│  filtered_data/                                              │
│  ├── mitre_attack_*_filtered.json                           │
│  ├── lolbas_*_filtered.json                                 │
│  ├── nist_attack_mapping_filtered.json                      │
│  ├── alienvault_otx_*_filtered.json                         │
│  ├── loldrivers_*_filtered.json                             │
│  └── hijacklibs_*_filtered.json                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 2: INDEXATION                       │
│  build_causal_graph.py                                      │
│  - Index par technique_id                                    │
│  - Index par acteur                                          │
│  - Index par phase kill chain                               │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 3: CROISEMENT                        │
│  Pour chaque technique:                                      │
│  1. Chercher dans LOLBAS (même nom/ID)                      │
│  2. Chercher dans NIST (mapping ATT&CK)                     │
│  3. Chercher dans OTX (technique tags)                      │
│  4. Chercher dans LOLDrivers (ATT&CK refs)                  │
│  5. Chercher dans HijackLibs (technique)                    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 4: SCORING                           │
│  - Compter les sources confirmantes                         │
│  - Vérifier la cohérence des informations                   │
│  - Identifier les contradictions                            │
│  - Calculer score de corroboration                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 5: OUTPUT                            │
│  EnrichedTechnique avec:                                    │
│  - sources_count: int                                       │
│  - corroboration_score: float                               │
│  - source_details: Dict[source_name, evidence]              │
│  - contradictions: List[str] (si présentes)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Exemple de technique enrichie

```json
{
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "corroboration": {
    "score": 0.7,
    "sources_count": 4,
    "sources": {
      "mitre": {
        "present": true,
        "actors_count": 87,
        "procedures_count": 156,
        "evidence": "Extensively documented in MITRE"
      },
      "lolbas": {
        "present": true,
        "binary": "powershell.exe",
        "commands": ["powershell.exe -ep bypass -file ..."],
        "evidence": "LOLBAS entry with execution examples"
      },
      "nist": {
        "present": true,
        "controls": ["SC-18", "CM-7", "SI-4"],
        "evidence": "Mapped to 3 NIST controls"
      },
      "otx": {
        "present": true,
        "pulses_count": 23,
        "evidence": "Referenced in 23 OTX pulses"
      },
      "loldrivers": {
        "present": false,
        "evidence": null
      },
      "hijacklibs": {
        "present": false,
        "evidence": null
      }
    },
    "contradictions": []
  }
}
```

---

## Gestion des contradictions

Quand les sources se contredisent:

1. **Logger la contradiction**
2. **Ne pas résoudre automatiquement** - signaler pour revue humaine
3. **Pondérer par autorité**: MITRE > NIST > OTX > autres
4. **Marquer l'incertitude** dans les métadonnées

```json
{
  "contradictions": [
    {
      "field": "mitigation_effectiveness",
      "source_a": {"name": "MITRE", "value": "high"},
      "source_b": {"name": "OTX", "value": "low"},
      "resolution": "pending_review",
      "notes": "OTX reports bypass; MITRE theoretical"
    }
  ]
}
```

---

## Couverture actuelle

### Techniques par nombre de sources

```
Distribution (835 techniques totales):
├── 4+ sources:   ~5%  (42 techniques)   ← Haute confiance
├── 3 sources:   ~15%  (125 techniques)  ← Bonne confiance
├── 2 sources:   ~35%  (292 techniques)  ← Confiance modérée
└── 1 source:    ~45%  (376 techniques)  ← À enrichir
```

### Objectif

Atteindre **≥50% des techniques avec ≥3 sources** via:
1. Intégration de nouvelles sources CTI
2. Mapping plus précis des IDs entre sources
3. Extraction NLP des références implicites

---

## Références

- Document parent: `CAUSAL_GRAPH_ARCHITECTURE.md`
- Scoring: `CONFIDENCE_SCORING_MODEL.md`
- Implémentation: `build_causal_graph.py` (fonction d'enrichissement à ajouter)
