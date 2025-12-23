#!/usr/bin/env python3
"""
Issue #8: Cross-reference techniques with CTI sources

Enrichit chaque technique MITRE avec les données de toutes les sources CTI:
- LOLBAS (Living Off The Land Binaries)
- LOLDrivers (Vulnerable drivers)
- HijackLibs (DLL hijacking)
- AlienVault OTX (Threat intelligence pulses)
- NIST Mappings (Security controls)
- CTI Reports (Attack chains extraites)

Output: techniques enrichies avec score de corroboration multi-sources
"""

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class SourceEvidence:
    """Evidence from a single CTI source."""
    source_name: str
    source_type: str  # lolbas, loldrivers, otx, nist, cti_report
    entries_count: int
    sample_entries: List[Dict] = field(default_factory=list)
    confidence_boost: float = 0.0


@dataclass
class CTIChainEvidence:
    """Evidence from extracted CTI attack chains."""
    chain_count: int  # How many chains involve this technique
    as_source: int    # Times this technique enables another
    as_target: int    # Times this technique is enabled by another
    actors: List[str] = field(default_factory=list)
    connected_techniques: List[str] = field(default_factory=list)
    avg_confidence: float = 0.0


@dataclass
class EnrichedTechniqueWithCTI:
    """Technique enriched with all CTI sources."""
    technique_id: str           # MITRE internal ID
    external_id: str            # T1234.001
    technique_name: str
    sources_count: int          # Number of sources that reference this technique
    corroboration_score: float  # 0.0 - 1.0
    source_details: Dict[str, SourceEvidence] = field(default_factory=dict)
    cti_chains: Optional[CTIChainEvidence] = None
    is_lolbin: bool = False
    is_driver_abuse: bool = False
    has_dll_hijack: bool = False
    nist_controls: List[str] = field(default_factory=list)


class CTIEnricher:
    """Cross-references MITRE techniques with all CTI sources."""

    def __init__(self, filtered_data_dir: str = "filtered_data"):
        self.data_dir = Path(filtered_data_dir)

        # Source data
        self.lolbas: List[Dict] = []
        self.loldrivers: List[Dict] = []
        self.hijacklibs: List[Dict] = []
        self.otx_pulses: List[Dict] = []
        self.nist_mappings: List[Dict] = []
        self.cti_chains: List[Dict] = []

        # MITRE technique index
        self.techniques_by_external_id: Dict[str, Dict] = {}
        self.techniques_by_name: Dict[str, Dict] = {}

        # Enrichment indexes
        self.lolbas_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.drivers_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.hijack_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.otx_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.nist_by_technique: Dict[str, List[Dict]] = defaultdict(list)
        self.chains_by_technique: Dict[str, List[Dict]] = defaultdict(list)

        # Stats
        self.stats = defaultdict(int)

    def _find_latest_file(self, pattern: str) -> Optional[Path]:
        """Find most recent file matching pattern."""
        files = list(self.data_dir.glob(pattern))
        if not files:
            return None
        return max(files, key=lambda p: p.stat().st_mtime)

    def load_mitre_techniques(self) -> int:
        """Load MITRE ATT&CK techniques for reference."""
        mitre_file = self._find_latest_file("mitre_attack_2*_filtered_*.json")
        if not mitre_file:
            logger.error("MITRE ATT&CK data not found")
            return 0

        logger.info(f"Loading MITRE data from {mitre_file}")
        with open(mitre_file) as f:
            data = json.load(f)

        for entry in data:
            if entry.get('type') == 'attack-pattern':
                # Get external ID (T1234)
                external_id = None
                for ref in entry.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        external_id = ref.get('external_id', '')
                        break

                if external_id:
                    self.techniques_by_external_id[external_id] = entry
                    name = entry.get('name', '').lower()
                    self.techniques_by_name[name] = entry

        logger.info(f"Loaded {len(self.techniques_by_external_id)} MITRE techniques")
        return len(self.techniques_by_external_id)

    def load_lolbas(self) -> int:
        """Load LOLBAS data and index by technique."""
        lolbas_file = self._find_latest_file("lolbas_*_filtered_*.json")
        if not lolbas_file:
            logger.warning("LOLBAS data not found")
            return 0

        with open(lolbas_file) as f:
            self.lolbas = json.load(f)

        # LOLBAS maps to specific techniques
        lolbas_technique_map = {
            'Execute': ['T1059', 'T1218'],      # Command execution, signed binary proxy
            'Download': ['T1105'],              # Ingress tool transfer
            'AWL Bypass': ['T1218'],            # Signed binary proxy execution
            'Reconnaissance': ['T1016', 'T1082'], # System info discovery
            'Copy': ['T1105'],                  # File transfer
            'Compile': ['T1027.004'],           # Compile after delivery
            'Encode': ['T1027'],                # Obfuscated files
            'Credentials': ['T1003'],           # Credential dumping
            'Dump': ['T1003'],
            'UACBypass': ['T1548.002'],         # Bypass UAC
        }

        for entry in self.lolbas:
            # Get technique categories from commands
            categories = set()
            for cmd in entry.get('Commands', []):
                cat = cmd.get('Category', '')
                if cat:
                    categories.add(cat)

            # Map to techniques
            mapped_techniques = set()
            for cat in categories:
                if cat in lolbas_technique_map:
                    mapped_techniques.update(lolbas_technique_map[cat])

            # Add to index
            for tech_id in mapped_techniques:
                self.lolbas_by_technique[tech_id].append({
                    'name': entry.get('Name', ''),
                    'description': entry.get('Description', '')[:200],
                    'categories': list(categories),
                    'url': entry.get('url', '')
                })

        self.stats['lolbas_total'] = len(self.lolbas)
        self.stats['lolbas_techniques'] = len(self.lolbas_by_technique)
        logger.info(f"Loaded {len(self.lolbas)} LOLBAS entries -> {len(self.lolbas_by_technique)} techniques")
        return len(self.lolbas)

    def load_loldrivers(self) -> int:
        """Load LOLDrivers data and index by technique."""
        drivers_file = self._find_latest_file("loldrivers_*_filtered_*.json")
        if not drivers_file:
            logger.warning("LOLDrivers data not found")
            return 0

        with open(drivers_file) as f:
            self.loldrivers = json.load(f)

        for entry in self.loldrivers:
            mitre_id = entry.get('MitreID', '')
            if mitre_id:
                self.drivers_by_technique[mitre_id].append({
                    'id': entry.get('Id', ''),
                    'category': entry.get('Category', ''),
                    'verified': entry.get('Verified', False),
                    'tags': entry.get('Tags', [])[:5]
                })

        self.stats['loldrivers_total'] = len(self.loldrivers)
        self.stats['loldrivers_techniques'] = len(self.drivers_by_technique)
        logger.info(f"Loaded {len(self.loldrivers)} LOLDrivers -> {len(self.drivers_by_technique)} techniques")
        return len(self.loldrivers)

    def load_hijacklibs(self) -> int:
        """Load HijackLibs data."""
        hijack_file = self._find_latest_file("hijacklibs_*_filtered_*.json")
        if not hijack_file:
            logger.warning("HijackLibs data not found")
            return 0

        with open(hijack_file) as f:
            self.hijacklibs = json.load(f)

        # All HijackLibs map to T1574.001 (DLL Search Order Hijacking)
        tech_id = 'T1574.001'
        for entry in self.hijacklibs:
            locations = entry.get('ExpectedLocations') or []
            self.hijack_by_technique[tech_id].append({
                'name': entry.get('Name', ''),
                'vendor': entry.get('Vendor', ''),
                'cve': entry.get('CVE', ''),
                'locations': locations[:3] if locations else []
            })

        # Also add parent technique
        self.hijack_by_technique['T1574'] = self.hijack_by_technique[tech_id]

        self.stats['hijacklibs_total'] = len(self.hijacklibs)
        self.stats['hijacklibs_techniques'] = len(self.hijack_by_technique)
        logger.info(f"Loaded {len(self.hijacklibs)} HijackLibs -> T1574.001")
        return len(self.hijacklibs)

    def load_otx(self) -> int:
        """Load AlienVault OTX pulses and index by technique."""
        otx_file = self._find_latest_file("alienvault_otx_*_filtered_*.json")
        if not otx_file:
            logger.warning("OTX data not found")
            return 0

        with open(otx_file) as f:
            self.otx_pulses = json.load(f)

        for pulse in self.otx_pulses:
            attack_ids = pulse.get('attack_ids', [])
            if not attack_ids:
                # Try to extract from tags
                for tag in pulse.get('tags', []):
                    if tag.startswith('T1') and len(tag) >= 5:
                        attack_ids.append(tag)

            for tech_id in attack_ids:
                # Normalize ID
                tech_id = tech_id.upper().strip()
                if re.match(r'T\d{4}', tech_id):
                    self.otx_by_technique[tech_id].append({
                        'pulse_id': pulse.get('id', ''),
                        'name': pulse.get('name', '')[:100],
                        'adversary': pulse.get('adversary', ''),
                        'created': pulse.get('created', ''),
                        'tags': pulse.get('tags', [])[:5]
                    })

        self.stats['otx_total'] = len(self.otx_pulses)
        self.stats['otx_techniques'] = len(self.otx_by_technique)
        logger.info(f"Loaded {len(self.otx_pulses)} OTX pulses -> {len(self.otx_by_technique)} techniques")
        return len(self.otx_pulses)

    def load_nist_mappings(self) -> int:
        """Load NIST control to ATT&CK mappings."""
        nist_file = self._find_latest_file("nist_attack_mapping_*.json")
        if not nist_file:
            logger.warning("NIST mappings not found")
            return 0

        with open(nist_file) as f:
            self.nist_mappings = json.load(f)

        for mapping in self.nist_mappings:
            tech_id = mapping.get('attack_object_id', '')
            if tech_id:
                desc = mapping.get('capability_description') or ''
                self.nist_by_technique[tech_id].append({
                    'control_id': mapping.get('capability_id', ''),
                    'control_group': mapping.get('capability_group', ''),
                    'mapping_type': mapping.get('mapping_type', ''),
                    'description': desc[:200] if desc else ''
                })

        self.stats['nist_total'] = len(self.nist_mappings)
        self.stats['nist_techniques'] = len(self.nist_by_technique)
        logger.info(f"Loaded {len(self.nist_mappings)} NIST mappings -> {len(self.nist_by_technique)} techniques")
        return len(self.nist_mappings)

    def load_cti_chains(self) -> int:
        """Load extracted CTI attack chains."""
        chains_file = self._find_latest_file("cti_causal_relations_*.json")
        if not chains_file:
            logger.warning("CTI chains not found")
            return 0

        with open(chains_file) as f:
            self.cti_chains = json.load(f)

        for chain in self.cti_chains:
            source_id = chain.get('source_id', '')
            target_id = chain.get('target_id', '')

            if source_id:
                self.chains_by_technique[source_id].append({
                    'role': 'source',
                    'connected_to': target_id,
                    'actors': chain.get('actors', []),
                    'confidence': chain.get('confidence', 0),
                    'report': chain.get('source_report', '')
                })

            if target_id:
                self.chains_by_technique[target_id].append({
                    'role': 'target',
                    'connected_to': source_id,
                    'actors': chain.get('actors', []),
                    'confidence': chain.get('confidence', 0),
                    'report': chain.get('source_report', '')
                })

        self.stats['cti_chains_total'] = len(self.cti_chains)
        self.stats['cti_chains_techniques'] = len(self.chains_by_technique)
        logger.info(f"Loaded {len(self.cti_chains)} CTI chains -> {len(self.chains_by_technique)} techniques")
        return len(self.cti_chains)

    def load_all_sources(self):
        """Load all CTI sources."""
        logger.info("=== Loading all CTI sources ===")
        self.load_mitre_techniques()
        self.load_lolbas()
        self.load_loldrivers()
        self.load_hijacklibs()
        self.load_otx()
        self.load_nist_mappings()
        self.load_cti_chains()
        logger.info("=== All sources loaded ===\n")

    def calculate_corroboration_score(self, tech_id: str) -> Tuple[float, Dict[str, SourceEvidence]]:
        """
        Calculate corroboration score based on multiple sources.

        Score components:
        - LOLBAS presence: +0.15
        - LOLDrivers presence: +0.10
        - HijackLibs presence: +0.10
        - OTX pulses: +0.05 per pulse (max 0.20)
        - NIST controls: +0.02 per control (max 0.15)
        - CTI chains: +0.03 per chain (max 0.30)

        Max theoretical score: 1.0
        """
        score = 0.0
        sources = {}

        # LOLBAS
        lolbas_entries = self.lolbas_by_technique.get(tech_id, [])
        if lolbas_entries:
            score += 0.15
            sources['lolbas'] = SourceEvidence(
                source_name='LOLBAS',
                source_type='lolbas',
                entries_count=len(lolbas_entries),
                sample_entries=lolbas_entries[:3],
                confidence_boost=0.15
            )

        # LOLDrivers
        driver_entries = self.drivers_by_technique.get(tech_id, [])
        if driver_entries:
            score += 0.10
            sources['loldrivers'] = SourceEvidence(
                source_name='LOLDrivers',
                source_type='loldrivers',
                entries_count=len(driver_entries),
                sample_entries=driver_entries[:3],
                confidence_boost=0.10
            )

        # HijackLibs
        hijack_entries = self.hijack_by_technique.get(tech_id, [])
        if hijack_entries:
            score += 0.10
            sources['hijacklibs'] = SourceEvidence(
                source_name='HijackLibs',
                source_type='hijacklibs',
                entries_count=len(hijack_entries),
                sample_entries=hijack_entries[:3],
                confidence_boost=0.10
            )

        # OTX
        otx_entries = self.otx_by_technique.get(tech_id, [])
        if otx_entries:
            otx_boost = min(0.20, len(otx_entries) * 0.05)
            score += otx_boost
            sources['otx'] = SourceEvidence(
                source_name='AlienVault OTX',
                source_type='otx',
                entries_count=len(otx_entries),
                sample_entries=otx_entries[:3],
                confidence_boost=otx_boost
            )

        # NIST
        nist_entries = self.nist_by_technique.get(tech_id, [])
        if nist_entries:
            nist_boost = min(0.15, len(nist_entries) * 0.02)
            score += nist_boost
            sources['nist'] = SourceEvidence(
                source_name='NIST Mappings',
                source_type='nist',
                entries_count=len(nist_entries),
                sample_entries=nist_entries[:3],
                confidence_boost=nist_boost
            )

        # CTI Chains
        chain_entries = self.chains_by_technique.get(tech_id, [])
        if chain_entries:
            chain_boost = min(0.30, len(chain_entries) * 0.03)
            score += chain_boost
            sources['cti_chains'] = SourceEvidence(
                source_name='CTI Reports',
                source_type='cti_chains',
                entries_count=len(chain_entries),
                sample_entries=chain_entries[:5],
                confidence_boost=chain_boost
            )

        return min(1.0, score), sources

    def get_cti_chain_evidence(self, tech_id: str) -> Optional[CTIChainEvidence]:
        """Get detailed CTI chain evidence for a technique."""
        chain_entries = self.chains_by_technique.get(tech_id, [])
        if not chain_entries:
            return None

        as_source = sum(1 for c in chain_entries if c['role'] == 'source')
        as_target = sum(1 for c in chain_entries if c['role'] == 'target')

        actors = set()
        connected = set()
        confidences = []

        for c in chain_entries:
            actors.update(c.get('actors', []))
            connected.add(c.get('connected_to', ''))
            if c.get('confidence'):
                confidences.append(c['confidence'])

        return CTIChainEvidence(
            chain_count=len(chain_entries),
            as_source=as_source,
            as_target=as_target,
            actors=list(actors)[:10],
            connected_techniques=list(connected)[:20],
            avg_confidence=sum(confidences) / len(confidences) if confidences else 0.0
        )

    def enrich_all_techniques(self) -> List[EnrichedTechniqueWithCTI]:
        """Enrich all MITRE techniques with CTI data."""
        logger.info("=== Enriching techniques with CTI ===")

        enriched = []
        techniques_with_cti = 0

        for external_id, tech in self.techniques_by_external_id.items():
            score, sources = self.calculate_corroboration_score(external_id)
            chain_evidence = self.get_cti_chain_evidence(external_id)

            # Get NIST controls
            nist_controls = [
                e.get('control_id', '')
                for e in self.nist_by_technique.get(external_id, [])
            ][:10]

            enriched_tech = EnrichedTechniqueWithCTI(
                technique_id=tech.get('id', ''),
                external_id=external_id,
                technique_name=tech.get('name', ''),
                sources_count=len(sources),
                corroboration_score=score,
                source_details={k: asdict(v) for k, v in sources.items()},
                cti_chains=asdict(chain_evidence) if chain_evidence else None,
                is_lolbin=external_id in self.lolbas_by_technique,
                is_driver_abuse=external_id in self.drivers_by_technique,
                has_dll_hijack=external_id in self.hijack_by_technique,
                nist_controls=nist_controls
            )
            enriched.append(enriched_tech)

            if score > 0:
                techniques_with_cti += 1

        # Sort by corroboration score
        enriched.sort(key=lambda x: -x.corroboration_score)

        logger.info(f"Enriched {len(enriched)} techniques")
        logger.info(f"Techniques with CTI data: {techniques_with_cti} ({100*techniques_with_cti/len(enriched):.1f}%)")

        return enriched

    def export_results(self, enriched: List[EnrichedTechniqueWithCTI], output_dir: str = "filtered_data"):
        """Export enriched techniques."""
        output_path = Path(output_dir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Full export
        full_output = output_path / f"techniques_enriched_cti_{timestamp}.json"
        with open(full_output, 'w') as f:
            json.dump([asdict(t) for t in enriched], f, indent=2)
        logger.info(f"Exported full results to {full_output}")

        # Summary statistics
        summary = {
            'timestamp': timestamp,
            'total_techniques': len(enriched),
            'techniques_with_cti': sum(1 for t in enriched if t.corroboration_score > 0),
            'avg_corroboration_score': sum(t.corroboration_score for t in enriched) / len(enriched),
            'source_coverage': {
                'lolbas': sum(1 for t in enriched if t.is_lolbin),
                'loldrivers': sum(1 for t in enriched if t.is_driver_abuse),
                'hijacklibs': sum(1 for t in enriched if t.has_dll_hijack),
                'otx': sum(1 for t in enriched if 'otx' in t.source_details),
                'nist': sum(1 for t in enriched if t.nist_controls),
                'cti_chains': sum(1 for t in enriched if t.cti_chains)
            },
            'stats': dict(self.stats),
            'top_10_corroborated': [
                {
                    'id': t.external_id,
                    'name': t.technique_name,
                    'score': t.corroboration_score,
                    'sources': list(t.source_details.keys())
                }
                for t in enriched[:10]
            ]
        }

        summary_output = output_path / f"techniques_enriched_summary_{timestamp}.json"
        with open(summary_output, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Exported summary to {summary_output}")

        return full_output, summary_output


def main():
    """Main entry point."""
    enricher = CTIEnricher()
    enricher.load_all_sources()

    enriched = enricher.enrich_all_techniques()
    full_path, summary_path = enricher.export_results(enriched)

    # Print summary
    print("\n" + "="*60)
    print("CTI ENRICHMENT SUMMARY")
    print("="*60)

    with open(summary_path) as f:
        summary = json.load(f)

    print(f"\nTotal techniques: {summary['total_techniques']}")
    print(f"Techniques with CTI: {summary['techniques_with_cti']}")
    print(f"Average corroboration score: {summary['avg_corroboration_score']:.3f}")

    print("\nSource coverage:")
    for source, count in summary['source_coverage'].items():
        print(f"  {source}: {count} techniques")

    print("\nTop 10 most corroborated techniques:")
    for t in summary['top_10_corroborated']:
        print(f"  {t['id']}: {t['name']}")
        print(f"    Score: {t['score']:.2f}, Sources: {', '.join(t['sources'])}")


if __name__ == '__main__':
    main()
