# Analyse des Sources CTI Potentielles

**Date**: 2025-12-23
**Répertoire analysé**: `raw_data/tmp_to_analyze/`

---

## Résumé exécutif

| Source | Entrées | Pertinence Graphe Causal | Recommandation |
|--------|---------|-------------------------|----------------|
| **VulnCheck KEV** | 4,435 | **HAUTE** | Intégrer en priorité |
| NVD 2.0 (2020-2025) | 179,034 | MOYENNE | Intégrer pour enrichissement |
| NVD 2.0 (paginated) | 323,672 | BASSE | Doublon avec ci-dessus |
| NVD 1.1 (legacy) | ~280,000 | BASSE | Format obsolète |
| MITRE CVE List v5 | 307,368 | BASSE | Redondant avec NVD |

---

## 1. VulnCheck KEV (CISA Known Exploited Vulnerabilities)

### Description
Base de données des vulnérabilités **activement exploitées** maintenue par CISA, enrichie par VulnCheck avec des métadonnées supplémentaires.

### Structure
```json
{
  "vendorProject": "Microsoft",
  "product": "Windows",
  "shortDescription": "...",
  "vulnerabilityName": "...",
  "cve": ["CVE-2019-1315"],
  "cwes": ["CWE-59"],
  "vulncheck_xdb": [{"exploit_type": "local", ...}],
  "knownRansomwareCampaignUse": "Known",
  "cisa_date_added": "2022-02-10T00:00:00Z"
}
```

### Statistiques
| Métrique | Valeur |
|----------|--------|
| Entrées totales | 4,435 |
| Avec exploits documentés | 1,198 (27%) |
| **Liées à ransomware** | **552 (12%)** |
| Avec CWE | 1,317 (30%) |
| Mappables ATT&CK (via CWE) | 763 (17%) |

### Valeur pour le graphe causal

**HAUTE PERTINENCE**

1. **Exploitation confirmée**: Contrairement aux CVE théoriques, ces vulnérabilités sont **activement exploitées** dans la nature.

2. **Lien ransomware**: 552 CVEs liées à des campagnes ransomware connues, permettant de créer des relations:
   - `CVE-2019-1315 enables ransomware_deployment`
   - `T1068 (Exploitation for Privilege Escalation) enables ransomware_execution`

3. **CWE → ATT&CK mapping**:
   ```
   CWE-78 (OS Command Injection) → T1059 (97 CVEs)
   CWE-787 (Buffer Overflow) → T1203 (96 CVEs)
   CWE-416 (Use After Free) → T1203 (86 CVEs)
   CWE-22 (Path Traversal) → T1083 (68 CVEs)
   CWE-502 (Deserialization) → T1059 (58 CVEs)
   CWE-94 (Code Injection) → T1059 (53 CVEs)
   ```

4. **Produits les plus ciblés par ransomware**:
   - Microsoft Windows: 74 CVEs
   - Adobe Flash Player: 18 CVEs
   - Microsoft Exchange: 17 CVEs
   - Internet Explorer: 11 CVEs

### Intégration proposée

```python
# Nouvelles relations à inférer
def infer_from_kev(kev_data):
    relations = []

    for entry in kev_data:
        cve = entry['cve'][0]
        cwes = entry.get('cwes', [])

        # 1. CVE -> Technique (via CWE mapping)
        for cwe in cwes:
            if cwe in CWE_TO_ATTACK:
                technique = CWE_TO_ATTACK[cwe]
                relations.append({
                    'type': 'exploits',
                    'source': cve,
                    'target': technique,
                    'evidence': f'CWE mapping: {cwe}',
                    'confidence': 0.8  # Exploitation confirmée
                })

        # 2. Ransomware correlation
        if entry.get('knownRansomwareCampaignUse') == 'Known':
            relations.append({
                'type': 'enables',
                'source': cve,
                'target': 'T1486',  # Data Encrypted for Impact
                'evidence': 'Known ransomware campaign',
                'confidence': 0.9
            })

    return relations
```

---

## 2. NVD 2.0 (Years 2020-2025)

### Description
National Vulnerability Database, format 2.0, années récentes.

### Structure
```json
{
  "cve": {
    "id": "CVE-2024-XXXXX",
    "descriptions": [...],
    "metrics": {"cvssMetricV31": [...]},
    "weaknesses": [{"description": [{"value": "CWE-XXX"}]}],
    "references": [...]
  }
}
```

### Statistiques
| Métrique | Valeur |
|----------|--------|
| CVEs totaux | 179,034 |
| Avec refs ATT&CK | 1 (négligeable) |
| CVSS ≥ 9.0 (Critical) | 5,173 (2024 seul) |
| Avec CWE | ~97% |

### Valeur pour le graphe causal

**MOYENNE PERTINENCE**

1. **Volume**: Grande quantité de CVEs pour enrichissement
2. **CWE**: Bon mapping CWE → ATT&CK possible
3. **CVSS**: Permet de filtrer les vulnérabilités critiques
4. **Limitations**:
   - Pas de confirmation d'exploitation
   - Pas de lien avec acteurs/campagnes
   - Redondant avec KEV pour les CVEs importantes

### Intégration proposée

Utiliser comme **source secondaire** pour:
1. Enrichir les CVEs de KEV avec CVSS scores
2. Ajouter des CWE manquants
3. Élargir le mapping CWE → ATT&CK

---

## 3. NVD 2.0 (Paginated)

### Description
Même source que #2, mais paginée différemment (164 fichiers).

### Statistiques
- Fichiers: 164
- CVEs totaux: ~323,672

### Recommandation

**NE PAS INTÉGRER** - Doublon de la source #2. Préférer le format par année qui est plus facile à mettre à jour.

---

## 4. NVD 1.1 (Legacy)

### Description
Format legacy de NVD, années 1999-2025.

### Statistiques
- Fichiers: 27
- ~10 GB de données historiques

### Recommandation

**NE PAS INTÉGRER** - Format obsolète, remplacé par NVD 2.0. Les CVEs historiques ont moins de valeur pour un graphe causal opérationnel.

---

## 5. MITRE CVE List v5

### Description
Liste CVE maintenue par MITRE (autorité CVE).

### Statistiques
| Métrique | Valeur |
|----------|--------|
| Entrées totales | 323,653 |
| Publiées | 307,368 |
| Rejetées | 16,285 |

### Recommandation

**NE PAS INTÉGRER** - Redondant avec NVD qui contient les mêmes CVEs avec plus de métadonnées (CVSS, etc.).

---

## Recommandations d'intégration

### Priorité 1: VulnCheck KEV

**Justification**:
- Vulnérabilités **activement exploitées** (pas théoriques)
- Lien **ransomware** explicite (552 CVEs)
- **Exploits** référencés (1,198 CVEs)
- Volume gérable (4,435 entrées)

**Valeur ajoutée au graphe**:
1. Relations `CVE exploits Technique` (via CWE)
2. Relations `CVE enables ransomware` (552 relations haute confiance)
3. Enrichissement P_empirique avec dates d'exploitation

**Script à créer**: `collect_vulncheck_kev.py`

### Priorité 2: NVD 2.0 (subset)

**Justification**:
- Enrichissement CVSS pour scoring de criticité
- CWE additionnels pour mapping ATT&CK
- Uniquement les CVEs critiques (CVSS ≥ 9.0)

**Approche recommandée**:
1. Filtrer CVSS ≥ 9.0 (~5,000 CVEs/an)
2. Croiser avec KEV pour éviter doublons
3. Ajouter uniquement les CVEs non-présentes dans KEV

**Script à créer**: `enrich_from_nvd.py`

### Ne pas intégrer

- NVD 2.0 paginated (doublon)
- NVD 1.1 (obsolète)
- MITRE CVE List (redondant)

---

## Impact sur le graphe causal

### Nouvelles relations possibles

| Type | Source | Quantité estimée |
|------|--------|------------------|
| `exploits` | KEV → ATT&CK | ~763 relations |
| `enables` | CVE → Ransomware | ~552 relations |
| `mitigated_by` | Patch → CVE | ~4,435 relations |

### Amélioration du scoring empirique

Avec KEV intégré:
- **Timestamps d'exploitation**: Dates CISA pour calculer la récence
- **Confirmation terrain**: P_empirique boost pour techniques liées à KEV
- **Contexte ransomware**: Pondération spéciale pour CVEs ransomware

### Mapping CWE → ATT&CK à enrichir

```python
CWE_TO_ATTACK_EXTENDED = {
    # Injection
    'CWE-78': ['T1059'],      # OS Command Injection
    'CWE-89': ['T1190'],      # SQL Injection
    'CWE-94': ['T1059'],      # Code Injection
    'CWE-79': ['T1189'],      # XSS

    # Memory Corruption
    'CWE-787': ['T1203'],     # Buffer Overflow
    'CWE-416': ['T1203'],     # Use After Free
    'CWE-119': ['T1203'],     # Buffer Errors

    # Auth/Access
    'CWE-287': ['T1078'],     # Auth Bypass
    'CWE-306': ['T1190'],     # Missing Auth
    'CWE-284': ['T1548'],     # Access Control

    # File Operations
    'CWE-22': ['T1083'],      # Path Traversal
    'CWE-434': ['T1105'],     # File Upload
    'CWE-59': ['T1574'],      # Symlink

    # Deserialization
    'CWE-502': ['T1059'],     # Deserialization

    # Input Validation
    'CWE-20': ['T1190'],      # Input Validation
}
```

---

## Prochaines étapes

1. **Créer issue GitHub** pour intégration KEV
2. **Développer** `collect_vulncheck_kev.py`
3. **Enrichir** `build_causal_graph.py` avec méthode `infer_from_kev()`
4. **Ajouter** mapping CWE → ATT&CK étendu
5. **Valider** sur échantillon avant intégration complète

---

## Annexe: Mapping CWE → ATT&CK detaillé

Source: MITRE ATT&CK et analyse manuelle

| CWE | Nom | Techniques ATT&CK |
|-----|-----|------------------|
| CWE-78 | OS Command Injection | T1059 (Execution) |
| CWE-787 | Out-of-bounds Write | T1203 (Exploitation for Client Execution) |
| CWE-416 | Use After Free | T1203 |
| CWE-119 | Buffer Overflow | T1203 |
| CWE-22 | Path Traversal | T1083 (File Discovery), T1005 (Collection) |
| CWE-502 | Deserialization | T1059, T1190 (Exploit Public App) |
| CWE-94 | Code Injection | T1059 |
| CWE-287 | Auth Bypass | T1078 (Valid Accounts), T1556 (Modify Auth) |
| CWE-306 | Missing Auth | T1190 |
| CWE-79 | XSS | T1189 (Drive-by Compromise) |
| CWE-89 | SQL Injection | T1190, T1059 |
| CWE-434 | Unrestricted File Upload | T1105 (Ingress Tool Transfer) |
| CWE-59 | Symlink Following | T1574 (Hijack Execution Flow) |
| CWE-20 | Input Validation | T1190 |
| CWE-284 | Access Control | T1548 (Abuse Elevation Control) |
