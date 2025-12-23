#!/usr/bin/env python3
"""
NIVEAU 2: Construction du graphe causal MITRE ATT&CK
Infère les relations causales à partir des données MITRE existantes.

Relations inférées:
- enables: T1 → T2 si un acteur utilise T1 puis T2 dans des phases séquentielles
- blocks: M → T si la mitigation M bloque la technique T (ou ses subtechniques)
- pivot_to: T1 → T2 si T2 est une alternative à T1 dans la même phase
- prerequisite: T1 → T2 si T1 est nécessaire pour T2 (inféré du kill chain)
- exploits: CVE → T si la CVE permet d'exploiter la technique T (via CWE mapping)

Sources de données:
- MITRE ATT&CK (techniques, acteurs, mitigations)
- VulnCheck KEV (CVEs exploitées, ransomware)
- NVD (CVEs critiques avec CVSS)
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from datetime import datetime
import glob


# Kill chain phases in tactical order (MITRE Enterprise)
PHASE_ORDER = [
    'reconnaissance',        # 0 - Gather victim info
    'resource-development',  # 1 - Build capabilities
    'initial-access',        # 2 - Entry point
    'execution',             # 3 - Run malicious code
    'persistence',           # 4 - Maintain foothold
    'privilege-escalation',  # 5 - Gain higher perms
    'defense-evasion',       # 6 - Avoid detection
    'credential-access',     # 7 - Steal credentials
    'discovery',             # 8 - Learn environment
    'lateral-movement',      # 9 - Move through network
    'collection',            # 10 - Gather target data
    'command-and-control',   # 11 - Communicate with implants
    'exfiltration',          # 12 - Steal data out
    'impact'                 # 13 - Disrupt/destroy
]

PHASE_TO_ORDER = {p: i for i, p in enumerate(PHASE_ORDER)}


@dataclass
class CausalRelation:
    """Représente une relation causale inférée."""
    source_id: str
    source_name: str
    target_id: str
    target_name: str
    relation_type: str  # enables, blocks, pivot_to, prerequisite, exploits
    confidence: float   # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)  # Acteurs qui démontrent cette relation
    cves: List[str] = field(default_factory=list)  # CVEs liées (pour relations exploits)
    is_ransomware: bool = False  # Indicateur ransomware


@dataclass
class EnrichedTechnique:
    """Technique enrichie avec contexte causal."""
    id: str
    name: str
    description: str
    phases: List[str]
    phase_orders: List[int]
    subtechniques: List[Dict]
    used_by: List[Dict]  # Acteurs/malwares qui utilisent
    mitigated_by: List[Dict]  # Mitigations
    enables: List[Dict]  # Techniques activées
    enabled_by: List[Dict]  # Techniques prérequises
    blocked_by: List[Dict]  # Mitigations qui bloquent
    alternatives: List[Dict]  # Techniques alternatives (pivot_to)
    exploited_by_cves: List[Dict] = field(default_factory=list)  # CVEs qui exploitent cette technique
    ransomware_linked: bool = False  # Lié à des campagnes ransomware


class MITRECausalGraphBuilder:
    """Construit le graphe causal à partir des données MITRE et CTI."""

    def __init__(self, mitre_data: List[Dict], kev_data: List[Dict] = None):
        self.raw_data = mitre_data
        self.kev_data = kev_data or []
        self.by_id: Dict[str, Dict] = {}
        self.by_type: Dict[str, List[Dict]] = defaultdict(list)
        self.relationships: Dict[str, List[Dict]] = defaultdict(list)

        # Indexes construits
        self.techniques: Dict[str, Dict] = {}
        self.techniques_by_external_id: Dict[str, Dict] = {}  # T1059 -> technique
        self.mitigations: Dict[str, Dict] = {}
        self.actors: Dict[str, Dict] = {}  # intrusion-set
        self.malware: Dict[str, Dict] = {}
        self.tools: Dict[str, Dict] = {}

        # Relations inférées
        self.enables: List[CausalRelation] = []
        self.blocks: List[CausalRelation] = []
        self.pivot_to: List[CausalRelation] = []
        self.prerequisites: List[CausalRelation] = []
        self.exploits: List[CausalRelation] = []  # CVE -> Technique

        # CVE indexes
        self.cves_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.ransomware_techniques: Set[str] = set()

        self._build_indexes()
        if self.kev_data:
            self._build_kev_indexes()

    def _build_indexes(self):
        """Construit les index par type et ID."""
        for entry in self.raw_data:
            entry_id = entry.get('id', '')
            entry_type = entry.get('type', '')
            external_id = self._get_external_id(entry)

            self.by_id[entry_id] = entry
            self.by_type[entry_type].append(entry)

            # Index par catégorie
            if entry_type == 'attack-pattern':
                self.techniques[entry_id] = entry
                if external_id:
                    self.techniques_by_external_id[external_id] = entry
            elif entry_type == 'course-of-action':
                self.mitigations[entry_id] = entry
            elif entry_type == 'intrusion-set':
                self.actors[entry_id] = entry
            elif entry_type == 'malware':
                self.malware[entry_id] = entry
            elif entry_type == 'tool':
                self.tools[entry_id] = entry
            elif entry_type == 'relationship':
                rel_type = entry.get('relationship_type', '')
                self.relationships[rel_type].append(entry)

        print(f"Indexed: {len(self.techniques)} techniques, {len(self.mitigations)} mitigations")
        print(f"         {len(self.actors)} actors, {len(self.malware)} malware, {len(self.tools)} tools")
        print(f"         {len(self.techniques_by_external_id)} techniques by external ID")
        print(f"Relations: {sum(len(v) for v in self.relationships.values())} total")

    def _build_kev_indexes(self):
        """Construit les index à partir des données KEV/NVD filtrées."""
        print(f"\n=== Building KEV/CVE indexes from {len(self.kev_data)} entries ===")

        mapped_count = 0
        ransomware_count = 0

        for cve_entry in self.kev_data:
            cve_id = cve_entry.get('cve_id', '')
            techniques = cve_entry.get('attack_techniques', [])
            is_ransomware = cve_entry.get('is_ransomware', False)

            for tech_id in techniques:
                # Trouver la technique MITRE correspondante
                technique = self.techniques_by_external_id.get(tech_id)
                if technique:
                    internal_id = technique.get('id', '')
                    self.cves_by_technique[internal_id].append({
                        'cve_id': cve_id,
                        'description': cve_entry.get('description', '')[:200],
                        'cvss_score': cve_entry.get('cvss_score'),
                        'is_exploited': cve_entry.get('is_exploited', False),
                        'is_ransomware': is_ransomware,
                        'cwes': cve_entry.get('cwes', []),
                        'source': cve_entry.get('source', 'unknown')
                    })
                    mapped_count += 1

                    if is_ransomware:
                        self.ransomware_techniques.add(internal_id)
                        ransomware_count += 1

        print(f"Mapped {mapped_count} CVE->Technique links")
        print(f"Ransomware-linked techniques: {len(self.ransomware_techniques)}")
        print(f"Techniques with CVE data: {len(self.cves_by_technique)}")

    def infer_exploits_from_cves(self) -> List[CausalRelation]:
        """
        MÉTHODE 5: Inférer 'exploits' depuis les données CVE/KEV.

        Crée des relations CVE -> Technique basées sur le mapping CWE->ATT&CK.
        Confiance plus élevée pour:
        - CVEs dans KEV (exploitation confirmée)
        - CVEs avec CVSS élevé
        - CVEs liées à ransomware
        """
        print("\n=== Inferring 'exploits' from CVE data ===")

        for tech_id, cves in self.cves_by_technique.items():
            technique = self.techniques.get(tech_id, {})
            tech_name = technique.get('name', 'Unknown')
            external_id = self._get_external_id(technique)

            for cve_data in cves:
                # Calculer la confiance
                confidence = 0.5  # Base

                # Boost si exploitation confirmée (KEV)
                if cve_data.get('is_exploited'):
                    confidence += 0.3

                # Boost si CVSS élevé
                cvss = cve_data.get('cvss_score')
                if cvss:
                    if cvss >= 9.0:
                        confidence += 0.15
                    elif cvss >= 7.0:
                        confidence += 0.1

                # Boost si ransomware
                is_ransomware = cve_data.get('is_ransomware', False)
                if is_ransomware:
                    confidence += 0.05

                confidence = min(0.95, confidence)

                # Evidence
                evidence = []
                if cve_data.get('is_exploited'):
                    evidence.append("CISA KEV: Confirmed exploitation in the wild")
                if cvss:
                    evidence.append(f"CVSS: {cvss}")
                if cve_data.get('cwes'):
                    evidence.append(f"CWEs: {', '.join(cve_data['cwes'][:3])}")
                if is_ransomware:
                    evidence.append("Known ransomware campaign")

                rel = CausalRelation(
                    source_id=cve_data['cve_id'],
                    source_name=cve_data['cve_id'],
                    target_id=tech_id,
                    target_name=f"{external_id}: {tech_name}",
                    relation_type='exploits',
                    confidence=confidence,
                    evidence=evidence,
                    cves=[cve_data['cve_id']],
                    is_ransomware=is_ransomware
                )
                self.exploits.append(rel)

        print(f"Inferred {len(self.exploits)} 'exploits' relations")
        print(f"  - High confidence (>=0.8): {sum(1 for r in self.exploits if r.confidence >= 0.8)}")
        print(f"  - Ransomware-linked: {sum(1 for r in self.exploits if r.is_ransomware)}")
        return self.exploits

    def _get_technique_phases(self, technique: Dict) -> List[Tuple[str, int]]:
        """Retourne les phases d'une technique avec leur ordre."""
        phases = []
        for phase in technique.get('kill_chain_phases', []):
            phase_name = phase.get('phase_name', '')
            if phase_name in PHASE_TO_ORDER:
                phases.append((phase_name, PHASE_TO_ORDER[phase_name]))
        return sorted(phases, key=lambda x: x[1])

    def _get_external_id(self, entry: Dict) -> str:
        """Extrait l'ID externe (ex: T1003) d'une entrée MITRE."""
        for ref in entry.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', '')
        return ''

    def infer_enables_from_actor_usage(self) -> List[CausalRelation]:
        """
        MÉTHODE 1: Inférer 'enables' depuis les patterns d'usage des acteurs.

        Si un acteur A utilise T1 (phase P) et T2 (phase P+n), alors T1 enables T2.
        La confiance augmente avec le nombre d'acteurs qui montrent ce pattern.
        """
        print("\n=== Inferring 'enables' from actor usage patterns ===")

        # Map actor/malware -> techniques used (with phases)
        entity_techniques: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)

        for rel in self.relationships.get('uses', []):
            source_id = rel.get('source_ref', '')
            target_id = rel.get('target_ref', '')

            source = self.by_id.get(source_id, {})
            target = self.by_id.get(target_id, {})

            # Only actor/malware -> technique relationships
            if source.get('type') in ('intrusion-set', 'malware', 'campaign') and \
               target.get('type') == 'attack-pattern':

                phases = self._get_technique_phases(target)
                for phase_name, phase_order in phases:
                    entity_techniques[source_id].append((
                        target_id,
                        target.get('name', ''),
                        phase_order
                    ))

        # Find enables patterns
        enables_count: Dict[Tuple[str, str], Dict] = defaultdict(lambda: {
            'count': 0,
            'actors': [],
            'source_name': '',
            'target_name': ''
        })

        for entity_id, techniques in entity_techniques.items():
            entity = self.by_id.get(entity_id, {})
            entity_name = entity.get('name', entity_id)

            # Sort by phase order
            techniques_sorted = sorted(techniques, key=lambda x: x[2])

            # For each pair (earlier phase -> later phase)
            for i, (t1_id, t1_name, p1) in enumerate(techniques_sorted):
                for t2_id, t2_name, p2 in techniques_sorted[i+1:]:
                    # Only if phases are sequential or close (within 3 phases)
                    if 0 < p2 - p1 <= 3:
                        key = (t1_id, t2_id)
                        enables_count[key]['count'] += 1
                        enables_count[key]['actors'].append(entity_name)
                        enables_count[key]['source_name'] = t1_name
                        enables_count[key]['target_name'] = t2_name

        # Build relations with confidence
        for (source_id, target_id), data in enables_count.items():
            if data['count'] >= 2:  # At least 2 actors show this pattern
                confidence = min(0.9, 0.3 + (data['count'] * 0.1))

                rel = CausalRelation(
                    source_id=source_id,
                    source_name=data['source_name'],
                    target_id=target_id,
                    target_name=data['target_name'],
                    relation_type='enables',
                    confidence=confidence,
                    evidence=[f"{data['count']} actors demonstrate this sequence"],
                    actors=data['actors'][:5]  # Top 5 actors
                )
                self.enables.append(rel)

        print(f"Inferred {len(self.enables)} 'enables' relations")
        return self.enables

    def infer_blocks_from_mitigations(self) -> List[CausalRelation]:
        """
        MÉTHODE 2: Inférer 'blocks' depuis les relations mitigates.

        Analyse les descriptions de mitigation pour comprendre COMMENT
        la mitigation bloque la technique (mécanisme de blocage).
        """
        print("\n=== Inferring 'blocks' from mitigation descriptions ===")

        # Keywords indicating blocking mechanisms
        block_keywords = {
            'prevent': 0.9,
            'block': 0.9,
            'disable': 0.8,
            'restrict': 0.7,
            'limit': 0.6,
            'control': 0.5,
            'monitor': 0.3,  # Monitoring is not blocking
            'detect': 0.2,   # Detection is not blocking
        }

        for rel in self.relationships.get('mitigates', []):
            source_id = rel.get('source_ref', '')  # Mitigation
            target_id = rel.get('target_ref', '')  # Technique
            description = rel.get('description', '')

            source = self.by_id.get(source_id, {})
            target = self.by_id.get(target_id, {})

            if not source or not target:
                continue

            # Analyze description for blocking mechanism
            desc_lower = description.lower()
            max_confidence = 0.5  # Base confidence for mitigates relation
            mechanisms = []

            for keyword, conf in block_keywords.items():
                if keyword in desc_lower:
                    max_confidence = max(max_confidence, conf)
                    mechanisms.append(keyword)

            # Extract specific mechanisms from description
            evidence = []
            if description:
                # Look for specific controls mentioned
                controls = re.findall(r'(AppLocker|WDAC|GPO|UAC|firewall|EDR|audit)', description, re.I)
                if controls:
                    evidence.append(f"Controls: {', '.join(set(controls))}")
                evidence.append(f"Mechanisms: {', '.join(mechanisms)}" if mechanisms else "General mitigation")

            rel_obj = CausalRelation(
                source_id=source_id,
                source_name=source.get('name', ''),
                target_id=target_id,
                target_name=target.get('name', ''),
                relation_type='blocks',
                confidence=max_confidence,
                evidence=evidence
            )
            self.blocks.append(rel_obj)

        print(f"Inferred {len(self.blocks)} 'blocks' relations")
        return self.blocks

    def infer_pivot_alternatives(self) -> List[CausalRelation]:
        """
        MÉTHODE 3: Inférer 'pivot_to' - techniques alternatives dans la même phase.

        Si T1 et T2 sont dans la même phase ET utilisées par les mêmes acteurs,
        ET ont des mitigations différentes, alors T1 pivot_to T2.
        """
        print("\n=== Inferring 'pivot_to' alternatives ===")

        # Group techniques by phase
        techniques_by_phase: Dict[str, List[Dict]] = defaultdict(list)
        for tech_id, tech in self.techniques.items():
            phases = self._get_technique_phases(tech)
            for phase_name, _ in phases:
                techniques_by_phase[phase_name].append(tech)

        # Map technique -> actors who use it
        tech_to_actors: Dict[str, Set[str]] = defaultdict(set)
        for rel in self.relationships.get('uses', []):
            source = self.by_id.get(rel.get('source_ref', ''), {})
            target_id = rel.get('target_ref', '')

            if source.get('type') in ('intrusion-set', 'malware') and \
               target_id in self.techniques:
                tech_to_actors[target_id].add(source.get('name', ''))

        # Map technique -> mitigations
        tech_to_mitigations: Dict[str, Set[str]] = defaultdict(set)
        for rel in self.relationships.get('mitigates', []):
            source_id = rel.get('source_ref', '')  # Mitigation
            target_id = rel.get('target_ref', '')  # Technique
            source = self.by_id.get(source_id, {})

            if target_id in self.techniques:
                tech_to_mitigations[target_id].add(source.get('name', ''))

        # Find alternatives: same phase, shared actors, different mitigations
        for phase, techniques in techniques_by_phase.items():
            for i, t1 in enumerate(techniques):
                t1_id = t1.get('id', '')
                t1_actors = tech_to_actors.get(t1_id, set())
                t1_mits = tech_to_mitigations.get(t1_id, set())

                for t2 in techniques[i+1:]:
                    t2_id = t2.get('id', '')
                    t2_actors = tech_to_actors.get(t2_id, set())
                    t2_mits = tech_to_mitigations.get(t2_id, set())

                    # Check for shared actors
                    shared_actors = t1_actors & t2_actors

                    # Check for different mitigations (allows pivot)
                    unique_to_t1 = t1_mits - t2_mits
                    unique_to_t2 = t2_mits - t1_mits

                    # If shared actors AND different mitigations
                    if len(shared_actors) >= 2 and (unique_to_t1 or unique_to_t2):
                        confidence = min(0.8, 0.3 + len(shared_actors) * 0.1)

                        evidence = [
                            f"Same phase: {phase}",
                            f"Shared by {len(shared_actors)} actors",
                            f"T1 unique mitigations: {len(unique_to_t1)}",
                            f"T2 unique mitigations: {len(unique_to_t2)}"
                        ]

                        rel = CausalRelation(
                            source_id=t1_id,
                            source_name=t1.get('name', ''),
                            target_id=t2_id,
                            target_name=t2.get('name', ''),
                            relation_type='pivot_to',
                            confidence=confidence,
                            evidence=evidence,
                            actors=list(shared_actors)[:5]
                        )
                        self.pivot_to.append(rel)

        print(f"Inferred {len(self.pivot_to)} 'pivot_to' relations")
        return self.pivot_to

    def infer_prerequisites_from_subtechniques(self) -> List[CausalRelation]:
        """
        MÉTHODE 4: Inférer 'prerequisite' depuis les subtechniques et séquences.

        Une parent technique est prérequis pour ses subtechniques.
        Certaines phases sont prérequis pour d'autres (ex: initial-access -> execution).
        """
        print("\n=== Inferring 'prerequisite' relations ===")

        # Subtechnique implies parent is prerequisite
        for rel in self.relationships.get('subtechnique-of', []):
            source_id = rel.get('source_ref', '')  # Subtechnique
            target_id = rel.get('target_ref', '')  # Parent

            source = self.by_id.get(source_id, {})
            target = self.by_id.get(target_id, {})

            if source and target:
                rel_obj = CausalRelation(
                    source_id=target_id,  # Parent is prerequisite
                    source_name=target.get('name', ''),
                    target_id=source_id,  # For subtechnique
                    target_name=source.get('name', ''),
                    relation_type='prerequisite',
                    confidence=0.95,
                    evidence=["Parent technique enables subtechnique execution"]
                )
                self.prerequisites.append(rel_obj)

        # Phase-based prerequisites (strong tactical dependencies)
        phase_prereqs = {
            'execution': ['initial-access'],
            'persistence': ['initial-access', 'execution'],
            'privilege-escalation': ['initial-access', 'execution'],
            'lateral-movement': ['credential-access', 'discovery'],
            'exfiltration': ['collection'],
            'impact': ['initial-access', 'execution']
        }

        # Map techniques to phases
        phase_to_techniques: Dict[str, List[Dict]] = defaultdict(list)
        for tech_id, tech in self.techniques.items():
            phases = self._get_technique_phases(tech)
            for phase_name, _ in phases:
                phase_to_techniques[phase_name].append(tech)

        # Build phase-level prerequisites (sample - not exhaustive)
        for target_phase, prereq_phases in phase_prereqs.items():
            target_techs = phase_to_techniques.get(target_phase, [])[:5]  # Sample
            for prereq_phase in prereq_phases:
                prereq_techs = phase_to_techniques.get(prereq_phase, [])[:3]  # Sample

                for prereq_tech in prereq_techs:
                    for target_tech in target_techs:
                        rel_obj = CausalRelation(
                            source_id=prereq_tech.get('id', ''),
                            source_name=prereq_tech.get('name', ''),
                            target_id=target_tech.get('id', ''),
                            target_name=target_tech.get('name', ''),
                            relation_type='prerequisite',
                            confidence=0.6,
                            evidence=[f"Tactical order: {prereq_phase} → {target_phase}"]
                        )
                        self.prerequisites.append(rel_obj)

        print(f"Inferred {len(self.prerequisites)} 'prerequisite' relations")
        return self.prerequisites

    def build_enriched_techniques(self) -> List[EnrichedTechnique]:
        """Construit les techniques enrichies avec tout le contexte causal."""
        print("\n=== Building enriched techniques ===")

        enriched = []

        # Pre-index relations
        enables_by_source = defaultdict(list)
        enabled_by_target = defaultdict(list)
        blocks_by_target = defaultdict(list)
        alternatives_by_source = defaultdict(list)

        for rel in self.enables:
            enables_by_source[rel.source_id].append(rel)
            enabled_by_target[rel.target_id].append(rel)

        for rel in self.blocks:
            blocks_by_target[rel.target_id].append(rel)

        for rel in self.pivot_to:
            alternatives_by_source[rel.source_id].append(rel)
            alternatives_by_source[rel.target_id].append(CausalRelation(
                source_id=rel.target_id,
                source_name=rel.target_name,
                target_id=rel.source_id,
                target_name=rel.source_name,
                relation_type='pivot_to',
                confidence=rel.confidence,
                evidence=rel.evidence,
                actors=rel.actors
            ))

        # Build used_by index
        tech_used_by = defaultdict(list)
        for rel in self.relationships.get('uses', []):
            source = self.by_id.get(rel.get('source_ref', ''), {})
            target_id = rel.get('target_ref', '')

            if source.get('type') in ('intrusion-set', 'malware', 'tool'):
                tech_used_by[target_id].append({
                    'id': source.get('id', ''),
                    'name': source.get('name', ''),
                    'type': source.get('type', ''),
                    'description': rel.get('description', '')[:500]
                })

        # Build subtechniques index
        parent_subtechniques = defaultdict(list)
        for rel in self.relationships.get('subtechnique-of', []):
            source_id = rel.get('source_ref', '')
            target_id = rel.get('target_ref', '')
            source = self.by_id.get(source_id, {})

            if source:
                parent_subtechniques[target_id].append({
                    'id': source_id,
                    'name': source.get('name', ''),
                    'external_id': self._get_external_id(source)
                })

        for tech_id, tech in self.techniques.items():
            phases = self._get_technique_phases(tech)

            enriched_tech = EnrichedTechnique(
                id=tech_id,
                name=tech.get('name', ''),
                description=tech.get('description', '')[:1000],
                phases=[p[0] for p in phases],
                phase_orders=[p[1] for p in phases],
                subtechniques=parent_subtechniques.get(tech_id, []),
                used_by=tech_used_by.get(tech_id, [])[:10],
                mitigated_by=[],  # Will be filled from blocks
                enables=[asdict(r) for r in enables_by_source.get(tech_id, [])[:5]],
                enabled_by=[asdict(r) for r in enabled_by_target.get(tech_id, [])[:5]],
                blocked_by=[asdict(r) for r in blocks_by_target.get(tech_id, [])[:5]],
                alternatives=[asdict(r) for r in alternatives_by_source.get(tech_id, [])[:5]]
            )
            enriched.append(enriched_tech)

        print(f"Built {len(enriched)} enriched techniques")
        return enriched

    def export_causal_graph(self, output_path: str):
        """Exporte le graphe causal complet en JSON."""
        graph = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_techniques': len(self.techniques),
                'total_enables': len(self.enables),
                'total_blocks': len(self.blocks),
                'total_pivot_to': len(self.pivot_to),
                'total_prerequisites': len(self.prerequisites),
                'total_exploits': len(self.exploits),
                'techniques_with_cves': len(self.cves_by_technique),
                'ransomware_techniques': len(self.ransomware_techniques),
                'phases': PHASE_ORDER,
                'sources': ['MITRE ATT&CK', 'VulnCheck KEV', 'NVD']
            },
            'relations': {
                'enables': [asdict(r) for r in self.enables],
                'blocks': [asdict(r) for r in self.blocks],
                'pivot_to': [asdict(r) for r in self.pivot_to],
                'prerequisites': [asdict(r) for r in self.prerequisites[:500]],
                'exploits': [asdict(r) for r in self.exploits]
            }
        }

        with open(output_path, 'w') as f:
            json.dump(graph, f, indent=2)

        print(f"\nExported causal graph to {output_path}")
        return graph


def find_latest_file(pattern: str, directory: str = "filtered_data") -> Optional[Path]:
    """Trouve le fichier le plus récent correspondant au pattern."""
    files = list(Path(directory).glob(pattern))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def main():
    """Main entry point."""
    # Load MITRE data - exclude ICS variant, use main Enterprise ATT&CK
    mitre_files = list(Path("filtered_data").glob("mitre_attack_2*_filtered_*.json"))
    # Filter out ICS files
    mitre_files = [f for f in mitre_files if 'ics' not in f.name.lower()]
    mitre_path = max(mitre_files, key=lambda p: p.stat().st_mtime) if mitre_files else None

    if not mitre_path:
        mitre_path = Path('filtered_data/mitre_attack_20251221_164817_filtered_20251221_220238.json')

    print(f"Loading MITRE data from {mitre_path}...")
    with open(mitre_path, 'r') as f:
        mitre_data = json.load(f)

    # Load KEV/CVE data if available
    kev_path = find_latest_file("cve_attack_mapping_*.json")
    kev_data = []
    if kev_path and kev_path.exists():
        print(f"Loading KEV/CVE data from {kev_path}...")
        with open(kev_path, 'r') as f:
            kev_data = json.load(f)
        print(f"Loaded {len(kev_data)} CVE entries")
    else:
        print("No KEV/CVE data found, running without CVE enrichment")

    # Build causal graph
    builder = MITRECausalGraphBuilder(mitre_data, kev_data)

    # Run all inference methods
    builder.infer_enables_from_actor_usage()
    builder.infer_blocks_from_mitigations()
    builder.infer_pivot_alternatives()
    builder.infer_prerequisites_from_subtechniques()

    # Run CVE-based inference if data available
    if kev_data:
        builder.infer_exploits_from_cves()

    # Build enriched techniques
    enriched = builder.build_enriched_techniques()

    # Export
    output_dir = Path('causal_graph')
    output_dir.mkdir(exist_ok=True)

    # Export causal relations
    builder.export_causal_graph(str(output_dir / 'mitre_causal_graph.json'))

    # Export enriched techniques (sample)
    sample_enriched = enriched[:50]  # First 50 for review
    with open(output_dir / 'enriched_techniques_sample.json', 'w') as f:
        json.dump([asdict(t) for t in sample_enriched], f, indent=2)

    print(f"\nExported sample of {len(sample_enriched)} enriched techniques")

    # Show examples
    print("\n" + "="*60)
    print("EXEMPLES DE RELATIONS INFÉRÉES")
    print("="*60)

    print("\n--- ENABLES (top 5 by confidence) ---")
    for rel in sorted(builder.enables, key=lambda x: -x.confidence)[:5]:
        print(f"  {rel.source_name} → {rel.target_name}")
        print(f"    Confidence: {rel.confidence:.2f}, Actors: {rel.actors[:3]}")

    print("\n--- BLOCKS (top 5 by confidence) ---")
    for rel in sorted(builder.blocks, key=lambda x: -x.confidence)[:5]:
        print(f"  {rel.source_name} BLOCKS {rel.target_name}")
        print(f"    Confidence: {rel.confidence:.2f}, Evidence: {rel.evidence[:2]}")

    print("\n--- PIVOT_TO (top 5) ---")
    for rel in sorted(builder.pivot_to, key=lambda x: -x.confidence)[:5]:
        print(f"  {rel.source_name} ↔ {rel.target_name}")
        print(f"    Confidence: {rel.confidence:.2f}, Shared actors: {len(rel.actors)}")

    if builder.exploits:
        print("\n--- EXPLOITS (top 5 by confidence) ---")
        for rel in sorted(builder.exploits, key=lambda x: -x.confidence)[:5]:
            ransomware_tag = " [RANSOMWARE]" if rel.is_ransomware else ""
            print(f"  {rel.source_name} EXPLOITS {rel.target_name}{ransomware_tag}")
            print(f"    Confidence: {rel.confidence:.2f}, Evidence: {rel.evidence[:2]}")


if __name__ == '__main__':
    main()
