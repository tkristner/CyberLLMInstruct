# Dimensions Opérationnelles pour un Assistant Réaliste

## Objectif

Former un LLM qui ne se contente pas de réciter des faits, mais qui **raisonne comme un analyste SOC expérimenté**:
- Exprime l'incertitude de manière calibrée
- Adapte ses recommandations au contexte métier
- Comprend les nuances des faux positifs

---

## Dimension 1: Gestion de l'Incertitude

### Problème

Un assistant qui répond avec une confiance absolue est dangereux:
- Risque de sur-réaction sur des alertes mineures
- Risque de sous-estimation de menaces réelles
- Perte de crédibilité quand les erreurs surviennent

### Solution: Expression calibrée

Le LLM doit apprendre à moduler ses réponses selon le niveau de confiance:

| Niveau | Formulations | Usage |
|--------|--------------|-------|
| **Haute confiance (>0.8)** | "Cette relation est confirmée par...", "Les données montrent clairement..." | Relations CONFIRMÉ avec sources multiples |
| **Confiance modérée (0.5-0.8)** | "Selon les observations disponibles...", "Il est probable que...", "Les indicateurs suggèrent..." | Relations PLAUSIBLE |
| **Faible confiance (<0.5)** | "Les données sont limitées mais...", "Une corrélation possible existe...", "À confirmer par investigation..." | Relations CORRÉLATION ou UNLIKELY |

### Exemple d'entraînement

```json
{
  "instruction": "Un SIEM détecte rundll32.exe chargeant scrobj.dll depuis un chemin inhabituel. Quel est le risque?",
  "context": {
    "technique": "T1218.010",
    "confidence_score": 0.85,
    "sources": ["MITRE", "LOLBAS", "Sigma"],
    "actors_observed": 12
  },
  "response": "Cette combinaison présente un risque élevé de technique LOLBAS (Living Off the Land). La confiance est haute (85%) car:\n\n1. **12 groupes APT documentés** utilisent cette technique (APT29, Lazarus, etc.)\n2. **Corroboré par 3 sources**: MITRE ATT&CK T1218.010, LOLBAS Project, et règles Sigma\n3. **Mécanisme bien compris**: scrobj.dll peut télécharger et exécuter du code distant via GenerateTypeLib\n\n**Recommandations immédiates**:\n- Isoler le poste concerné\n- Collecter le contenu d'INetCache\n- Analyser la ligne de commande complète\n\n**Contexte d'incertitude**: Bien que la technique soit confirmée, l'intention malveillante dépend de l'analyse du payload téléchargé.",
  "metadata": {
    "uncertainty_expressed": true,
    "confidence_level": "high",
    "sources_cited": 3
  }
}
```

---

## Dimension 2: Priorisation Contextuelle

### Problème

Une même alerte a des implications différentes selon:
- Le secteur d'activité (finance vs healthcare vs industrie)
- La criticité des assets impactés
- La posture de sécurité existante
- Les contraintes réglementaires

### Solution: Pondération métier

Intégrer des facteurs contextuels dans le scoring:

```python
@dataclass
class BusinessContext:
    sector: str  # "finance", "healthcare", "energy", "retail", etc.
    asset_criticality: str  # "critical", "important", "standard"
    regulatory_framework: List[str]  # ["PCI-DSS", "HIPAA", "NIS2", etc.]
    security_maturity: str  # "high", "medium", "low"

def adjust_priority_for_context(base_priority: float, context: BusinessContext) -> float:
    """Ajuste la priorité selon le contexte métier."""
    multiplier = 1.0

    # Secteurs à haute valeur cible
    high_value_sectors = {"finance": 1.3, "healthcare": 1.2, "energy": 1.4, "defense": 1.5}
    multiplier *= high_value_sectors.get(context.sector, 1.0)

    # Assets critiques
    if context.asset_criticality == "critical":
        multiplier *= 1.5
    elif context.asset_criticality == "important":
        multiplier *= 1.2

    # Régulations strictes
    strict_regulations = {"PCI-DSS", "HIPAA", "NIS2", "DORA"}
    if set(context.regulatory_framework) & strict_regulations:
        multiplier *= 1.2

    # Maturité inversée (moins mature = plus de risque)
    maturity_factor = {"high": 0.8, "medium": 1.0, "low": 1.3}
    multiplier *= maturity_factor.get(context.security_maturity, 1.0)

    return min(1.0, base_priority * multiplier)
```

### Exemple d'entraînement

```json
{
  "instruction": "Comment prioriser une alerte T1003 (Credential Dumping) sur un serveur de fichiers d'une banque?",
  "context": {
    "technique": "T1003",
    "sector": "finance",
    "asset_type": "file_server",
    "regulatory": ["PCI-DSS", "DORA"],
    "connected_to_payment_systems": true
  },
  "response": "**Priorité: CRITIQUE** (ajustée pour le contexte bancaire)\n\n**Facteurs d'élévation**:\n1. **Secteur finance** (+30%): Cible privilégiée des APT financiers (Carbanak, FIN7)\n2. **Proximité paiements** (+50%): Le serveur a accès aux systèmes de paiement\n3. **Régulation PCI-DSS**: Le dump de credentials peut exposer des données cartes\n4. **DORA imminent**: Obligation de notification en 4h\n\n**Actions immédiates** (SLA: 15 minutes):\n1. Bloquer le compte source au niveau AD\n2. Isoler le serveur du réseau de paiement\n3. Capturer la mémoire du processus LSASS\n4. Notifier le RSSI et l'équipe conformité\n\n**Contexte technique**:\nSur un serveur de fichiers standard, cette alerte serait \"HIGH\". Le contexte bancaire et la connexion aux systèmes de paiement l'élèvent à \"CRITICAL\".\n\n**Faux positif possible?**: Vérifier si c'est un scan de vulnérabilité autorisé ou un outil d'administration (ex: scan Tenable). Dans ce cas, valider avec le calendrier de scans.",
  "metadata": {
    "context_adjusted": true,
    "base_priority": "high",
    "adjusted_priority": "critical",
    "adjustment_factors": ["sector", "payment_proximity", "regulation"]
  }
}
```

---

## Dimension 3: Nuances de Faux Positifs

### Problème

Un assistant naïf traite toutes les alertes comme si elles étaient vraies. En réalité:
- Certaines techniques ont des usages légitimes (PowerShell admin)
- Certains contextes génèrent des FP systématiques
- La fatigue d'alerte est un vrai risque opérationnel

### Solution: Métadonnées de faux positifs

Enrichir chaque technique avec:

```python
@dataclass
class FalsePositiveProfile:
    fp_rate_estimate: float  # 0.0 - 1.0 (estimé)
    legitimate_uses: List[str]  # Usages légitimes connus
    high_fp_contexts: List[str]  # Contextes à fort taux de FP
    discrimination_indicators: List[str]  # Comment distinguer FP vs vrai positif
    tuning_recommendations: List[str]  # Recommandations de tuning

# Exemple pour T1059.001 (PowerShell)
powershell_fp = FalsePositiveProfile(
    fp_rate_estimate=0.7,  # 70% de FP en environnement non-tuné
    legitimate_uses=[
        "Scripts d'administration système",
        "Outils de déploiement (SCCM, Intune)",
        "Monitoring et inventaire",
        "CI/CD pipelines"
    ],
    high_fp_contexts=[
        "Postes d'administrateurs",
        "Serveurs de management",
        "Environnements DevOps"
    ],
    discrimination_indicators=[
        "Chemin d'exécution inhabituel (hors System32)",
        "Encodage Base64 de la commande",
        "Paramètre -ep bypass ou -nop",
        "Connexion réseau sortante immédiate",
        "Exécution depuis process parent suspect (Word, Excel)"
    ],
    tuning_recommendations=[
        "Whitelister les scripts signés par IT",
        "Exclure les comptes de service documentés",
        "Créer des exceptions pour les outils de déploiement",
        "Monitorer uniquement les paramètres à risque"
    ]
)
```

### Exemple d'entraînement

```json
{
  "instruction": "Notre SIEM génère 500 alertes PowerShell par jour. Comment réduire les faux positifs sans perdre de vrais positifs?",
  "context": {
    "technique": "T1059.001",
    "daily_alerts": 500,
    "environment": "enterprise_windows",
    "fp_profile": {
      "estimated_rate": 0.7,
      "legitimate_uses": ["admin_scripts", "sccm", "monitoring"]
    }
  },
  "response": "**Diagnostic**: Avec ~70% de taux de FP estimé pour PowerShell, vous avez probablement ~350 FP et ~150 vrais positifs quotidiens. Voici une stratégie de réduction progressive:\n\n**Phase 1: Exclusions à faible risque** (réduction ~40%)\n1. Exclure les exécutions depuis `C:\\Windows\\System32\\` par SYSTEM\n2. Whitelister les scripts signés par votre certificat IT\n3. Exclure les comptes de service SCCM/Intune documentés\n\n**Phase 2: Tuning des paramètres** (réduction ~20%)\n4. Focuser sur les indicateurs de compromission:\n   - `-EncodedCommand` ou `-ep bypass`\n   - Parent process = winword.exe, excel.exe, outlook.exe\n   - Téléchargement via `Net.WebClient` ou `Invoke-WebRequest`\n   - Appels vers des IP externes\n\n**Phase 3: Enrichissement contextuel** (réduction ~10%)\n5. Corrélation avec l'inventaire des admins autorisés\n6. Détection d'anomalie horaire (exécution à 3h du matin)\n7. Baseline par machine et utilisateur\n\n**Risques à monitorer**:\n- Ne pas exclure les chemins temporaires (`%TEMP%`, `%APPDATA%`)\n- Maintenir la détection des paramètres d'évasion\n- Logger les exclusions pour audit\n\n**Métriques de succès**:\n- Objectif: <50 alertes/jour à investiguer\n- Taux de vrai positif dans le résidu: >30%\n- Temps moyen d'investigation: <5 min/alerte",
  "metadata": {
    "fp_awareness": true,
    "tuning_strategy": "progressive",
    "risk_acknowledgment": true
  }
}
```

---

## Architecture de dataset enrichi

Pour chaque paire instruction/réponse, inclure ces métadonnées:

```json
{
  "instruction": "...",
  "context": {
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "kill_chain_phase": "execution"
  },
  "response": "...",

  "operational_metadata": {
    "confidence": {
      "p_theoretical": 0.75,
      "p_empirical": 0.82,
      "category": "CONFIRMED",
      "sources": ["MITRE", "LOLBAS", "OTX"]
    },
    "uncertainty": {
      "expressed_in_response": true,
      "calibration_level": "high",
      "caveats_mentioned": ["context-dependent", "requires validation"]
    },
    "business_context": {
      "sector_relevance": ["all"],
      "priority_modifiers": ["asset_criticality", "regulatory"]
    },
    "false_positive": {
      "awareness_expressed": true,
      "fp_rate_mentioned": 0.7,
      "discrimination_guidance": true,
      "tuning_provided": true
    }
  }
}
```

---

## Objectifs de qualité

### Pour chaque paire générée

| Dimension | Objectif | Métrique |
|-----------|----------|----------|
| **Incertitude** | Expression calibrée | % réponses avec formulations adaptées au niveau de confiance |
| **Contexte** | Adaptabilité | % réponses mentionnant des facteurs contextuels |
| **Faux positifs** | Conscience opérationnelle | % réponses pour techniques à haut FP incluant guidance de tuning |

### Distribution cible

```
Réponses avec incertitude calibrée:  ≥ 90%
Réponses avec contexte métier:       ≥ 70%
Réponses avec guidance FP:           ≥ 80% (pour techniques à FP > 0.3)
```

---

## Références

- Document parent: `CAUSAL_GRAPH_ARCHITECTURE.md`
- Scoring: `CONFIDENCE_SCORING_MODEL.md`
- Sources: `MULTI_SOURCE_CORROBORATION.md`
- Implémentation: `data_structurer.py` (génération QnA à enrichir)
