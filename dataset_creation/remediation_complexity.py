#!/usr/bin/env python3
"""
Remediation Complexity Module

Issue #11: Implement business context priority weighting based on
remediation complexity derived from CIS Implementation Groups and NIST mappings.

Sources used:
- CIS Controls v8.1: Implementation Groups (IG1=basic, IG2=intermediate, IG3=advanced)
- NIST 800-53 → ATT&CK mappings: Links techniques to security controls
- MITRE ATT&CK mitigations: Direct mitigation relationships

Complexity Levels:
- IG1 (Basic): Small orgs, minimal effort, foundational controls
- IG2 (Intermediate): Medium orgs, moderate effort, standard controls
- IG3 (Advanced): Large orgs, significant effort, advanced controls

Usage:
    from remediation_complexity import RemediationAnalyzer

    analyzer = RemediationAnalyzer()
    complexity = analyzer.get_technique_complexity("T1059.001")
    print(complexity.level, complexity.score, complexity.controls)
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ComplexityLevel(Enum):
    """Remediation complexity levels based on CIS Implementation Groups."""
    BASIC = "basic"           # IG1 - Small orgs, quick wins
    INTERMEDIATE = "intermediate"  # IG2 - Medium effort
    ADVANCED = "advanced"     # IG3 - Significant investment
    UNKNOWN = "unknown"       # No mapping available


@dataclass
class ControlMapping:
    """A security control mapped to a technique."""
    control_id: str
    control_name: str
    framework: str  # 'CIS', 'NIST', 'MITRE'
    implementation_group: Optional[int] = None  # 1, 2, or 3 for CIS
    family: Optional[str] = None


@dataclass
class RemediationComplexity:
    """Remediation complexity assessment for a technique."""
    technique_id: str
    technique_name: Optional[str] = None
    level: ComplexityLevel = ComplexityLevel.UNKNOWN
    score: float = 0.5  # 0.0 (easy) to 1.0 (hard)
    min_implementation_group: Optional[int] = None
    controls: List[ControlMapping] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    effort_description: str = ""

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'complexity_level': self.level.value,
            'complexity_score': self.score,
            'min_implementation_group': self.min_implementation_group,
            'controls_count': len(self.controls),
            'mitigations_count': len(self.mitigations),
            'effort_description': self.effort_description,
        }


class RemediationAnalyzer:
    """Analyze remediation complexity for ATT&CK techniques."""

    def __init__(self, data_dir: str = "filtered_data"):
        self.data_dir = Path(data_dir)

        # Data caches
        self.cis_controls: Dict[str, Dict] = {}  # sub_control_id -> {ig, title, ...}
        self.nist_to_attack: Dict[str, List[str]] = {}  # technique_id -> [nist_control_ids]
        self.attack_to_nist: Dict[str, List[str]] = {}  # technique_id -> [nist_control_ids]
        self.mitre_mitigations: Dict[str, List[str]] = {}  # technique_id -> [mitigation_names]
        self.nist_controls: Dict[str, Dict] = {}  # control_id -> {title, family, ...}

        # CIS Control family to NIST family approximate mapping
        self.cis_to_nist_family = {
            'cisc-001': ['cm'],  # Asset Inventory -> Configuration Management
            'cisc-002': ['cm', 'si'],  # Software Inventory -> CM, System Integrity
            'cisc-003': ['si', 'sc'],  # Data Protection -> SI, System Communications
            'cisc-004': ['cm', 'ac'],  # Secure Configuration -> CM, Access Control
            'cisc-005': ['ac', 'ia'],  # Account Management -> AC, Identification/Auth
            'cisc-006': ['ac', 'ia'],  # Access Control -> AC, IA
            'cisc-007': ['si', 'sc'],  # Continuous Vuln Management -> SI, SC
            'cisc-008': ['au'],  # Audit Log Management -> Audit
            'cisc-009': ['sc', 'ac'],  # Email/Browser Protections -> SC, AC
            'cisc-010': ['si', 'sc'],  # Malware Defenses -> SI, SC
            'cisc-011': ['cm', 'si'],  # Data Recovery -> CM, SI
            'cisc-012': ['sc', 'ac'],  # Network Infrastructure -> SC, AC
            'cisc-013': ['sc', 'si'],  # Network Monitoring -> SC, SI
            'cisc-014': ['at'],  # Security Awareness -> Awareness Training
            'cisc-015': ['ac', 'sc'],  # Service Provider Management -> AC, SC
            'cisc-016': ['cm', 'sa'],  # Application Software Security -> CM, SA
            'cisc-017': ['ir'],  # Incident Response -> IR
            'cisc-018': ['ca', 'ra'],  # Penetration Testing -> CA, Risk Assessment
        }

        self._load_data()

    def _find_file(self, pattern: str) -> Optional[Path]:
        """Find file matching pattern, searching recursively."""
        files = list(self.data_dir.glob(f"**/{pattern}"))
        if not files:
            files = list(self.data_dir.glob(pattern))
        return max(files, key=lambda p: p.stat().st_mtime) if files else None

    def _load_data(self):
        """Load all required data sources."""
        self._load_cis_controls()
        self._load_nist_attack_mapping()
        self._load_mitre_mitigations()
        self._load_nist_controls()

        logger.info(f"Loaded {len(self.cis_controls)} CIS sub-controls")
        logger.info(f"Loaded {len(self.attack_to_nist)} technique→NIST mappings")
        logger.info(f"Loaded {len(self.mitre_mitigations)} technique→mitigation mappings")

    def _load_cis_controls(self):
        """Load CIS Controls with Implementation Groups."""
        cis_file = self._find_file("cis-controls*_filtered_*.json")
        if not cis_file:
            logger.warning("CIS Controls file not found")
            return

        with open(cis_file) as f:
            data = json.load(f)

        controls = data if isinstance(data, list) else data.get('controls', [])

        for ctrl in controls:
            ctrl_id = ctrl.get('id', '')
            for sub in ctrl.get('controls', []):
                sub_id = sub.get('id', '')

                # Extract Implementation Groups
                igs = []
                for prop in sub.get('props', []):
                    if prop.get('name') == 'implementation-group':
                        igs.append(int(prop.get('value', 0)))

                min_ig = min(igs) if igs else None

                self.cis_controls[sub_id] = {
                    'id': sub_id,
                    'title': sub.get('title', ''),
                    'parent_id': ctrl_id,
                    'parent_title': ctrl.get('title', ''),
                    'implementation_groups': igs,
                    'min_ig': min_ig,
                }

    def _normalize_nist_id(self, nist_id: str) -> str:
        """Normalize NIST control ID (AC-02 -> ac-2)."""
        if not nist_id:
            return ""
        # Convert to lowercase and remove leading zeros
        parts = nist_id.lower().split('-')
        if len(parts) == 2:
            family = parts[0]
            try:
                number = str(int(parts[1]))  # Removes leading zeros
                return f"{family}-{number}"
            except ValueError:
                return nist_id.lower()
        return nist_id.lower()

    def _load_nist_attack_mapping(self):
        """Load NIST 800-53 to ATT&CK mappings."""
        mapping_file = self._find_file("nist_attack_mapping*_filtered_*.json")
        if not mapping_file:
            logger.warning("NIST→ATT&CK mapping file not found")
            return

        with open(mapping_file) as f:
            data = json.load(f)

        mappings = data if isinstance(data, list) else data.get('mapping_objects', [])

        for m in mappings:
            if m.get('mapping_type') != 'mitigates':
                continue

            technique_id = m.get('attack_object_id', '')
            nist_id = self._normalize_nist_id(m.get('capability_id', ''))

            if technique_id and nist_id:
                if technique_id not in self.attack_to_nist:
                    self.attack_to_nist[technique_id] = []
                self.attack_to_nist[technique_id].append(nist_id)

                if nist_id not in self.nist_to_attack:
                    self.nist_to_attack[nist_id] = []
                self.nist_to_attack[nist_id].append(technique_id)

    def _load_mitre_mitigations(self):
        """Load MITRE ATT&CK mitigations."""
        attack_file = self._find_file("mitre_attack_*_filtered_*.json")
        if not attack_file:
            logger.warning("MITRE ATT&CK file not found")
            return

        with open(attack_file) as f:
            data = json.load(f)

        objects = data.get('objects', data) if isinstance(data, dict) else data

        # Build ID to name mapping for mitigations
        mitigation_names = {}
        for obj in objects:
            if isinstance(obj, dict) and obj.get('type') == 'course-of-action':
                mitigation_names[obj.get('id', '')] = obj.get('name', '')

        # Build technique to mitigation mapping
        technique_ids = {}
        for obj in objects:
            if isinstance(obj, dict) and obj.get('type') == 'attack-pattern':
                # Get external ID (T1234)
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_ids[obj.get('id', '')] = ref.get('external_id', '')

        # Process relationships
        for obj in objects:
            if isinstance(obj, dict) and obj.get('type') == 'relationship':
                if obj.get('relationship_type') == 'mitigates':
                    source_ref = obj.get('source_ref', '')
                    target_ref = obj.get('target_ref', '')

                    # Get technique external ID
                    tech_ext_id = technique_ids.get(target_ref, '')
                    mitigation_name = mitigation_names.get(source_ref, '')

                    if tech_ext_id and mitigation_name:
                        if tech_ext_id not in self.mitre_mitigations:
                            self.mitre_mitigations[tech_ext_id] = []
                        self.mitre_mitigations[tech_ext_id].append(mitigation_name)

    def _load_nist_controls(self):
        """Load NIST 800-53 control details."""
        nist_file = self._find_file("nist_standards_*_filtered_*.json")
        if not nist_file:
            logger.warning("NIST standards file not found")
            return

        with open(nist_file) as f:
            data = json.load(f)

        controls = data if isinstance(data, list) else data.get('controls', [])

        for ctrl in controls:
            ctrl_id = ctrl.get('id', '')
            self.nist_controls[ctrl_id] = {
                'id': ctrl_id,
                'title': ctrl.get('title', ''),
                'family': ctrl.get('family_id', ''),
                'family_title': ctrl.get('family_title', ''),
            }

    def _get_cis_ig_for_nist_family(self, nist_family: str) -> List[int]:
        """Get CIS Implementation Groups that map to a NIST control family."""
        igs = []

        for cis_id, nist_families in self.cis_to_nist_family.items():
            if nist_family.lower() in nist_families:
                # Find all sub-controls for this CIS control
                for sub_id, sub_data in self.cis_controls.items():
                    if sub_data.get('parent_id', '').startswith(cis_id):
                        if sub_data.get('min_ig'):
                            igs.append(sub_data['min_ig'])

        return igs

    def _get_control_complexity_weight(self, nist_family: str) -> float:
        """
        Get complexity weight based on NIST control family.

        Higher weight = more complex/harder to implement.
        Based on typical implementation effort:
        - AT (Awareness Training): Easy
        - CM (Configuration Mgmt): Medium
        - SC (System Communications): Hard
        """
        family_weights = {
            # Easy to implement (0.2-0.4)
            'at': 0.2,  # Awareness Training
            'ps': 0.3,  # Personnel Security
            'pl': 0.3,  # Planning
            'mp': 0.3,  # Media Protection

            # Medium effort (0.4-0.6)
            'ac': 0.5,  # Access Control
            'au': 0.5,  # Audit
            'ia': 0.5,  # Identification/Authentication
            'ma': 0.5,  # Maintenance
            'pe': 0.5,  # Physical Protection
            'cm': 0.5,  # Configuration Management
            'ir': 0.5,  # Incident Response

            # High effort (0.6-0.8)
            'ca': 0.6,  # Assessment
            'cp': 0.6,  # Contingency Planning
            'ra': 0.6,  # Risk Assessment
            'sa': 0.7,  # System Acquisition
            'sc': 0.7,  # System Communications
            'si': 0.7,  # System Integrity
            'sr': 0.8,  # Supply Chain
        }
        return family_weights.get(nist_family.lower(), 0.5)

    def get_technique_complexity(self, technique_id: str) -> RemediationComplexity:
        """
        Calculate remediation complexity for a technique.

        Complexity is based on:
        1. Minimum CIS Implementation Group required
        2. NIST control family weights
        3. Number of controls needed
        """
        result = RemediationComplexity(technique_id=technique_id)

        # Get NIST controls for this technique
        nist_control_ids = self.attack_to_nist.get(technique_id, [])
        # Deduplicate
        nist_control_ids = list(set(nist_control_ids))

        # Get MITRE mitigations
        mitigations = self.mitre_mitigations.get(technique_id, [])
        result.mitigations = mitigations

        # Collect all relevant IGs and family weights
        all_igs = []
        family_weights = []
        families_seen = set()

        for nist_id in nist_control_ids:
            ctrl_info = self.nist_controls.get(nist_id, {})
            family = ctrl_info.get('family', '')

            # Extract family from control ID if not in nist_controls
            if not family and '-' in nist_id:
                family = nist_id.split('-')[0]

            # Add control to result
            result.controls.append(ControlMapping(
                control_id=nist_id,
                control_name=ctrl_info.get('title', nist_id),
                framework='NIST',
                family=family,
            ))

            # Get CIS IGs for this NIST family
            if family and family not in families_seen:
                families_seen.add(family)
                igs = self._get_cis_ig_for_nist_family(family)
                all_igs.extend(igs)
                family_weights.append(self._get_control_complexity_weight(family))

        # Add MITRE mitigations
        for mit in mitigations:
            result.controls.append(ControlMapping(
                control_id=f"MITRE-{mit[:20]}",
                control_name=mit,
                framework='MITRE',
            ))

        # Calculate complexity score
        if all_igs:
            min_ig = min(all_igs)
            max_ig = max(all_igs)
            result.min_implementation_group = min_ig

            # Count IGs to find the predominant level
            ig_counts = {1: all_igs.count(1), 2: all_igs.count(2), 3: all_igs.count(3)}
            total_igs = sum(ig_counts.values())

            # Calculate weighted IG score based on distribution
            # More IG1 controls = easier remediation
            ig1_ratio = ig_counts[1] / total_igs if total_igs else 0
            ig2_ratio = ig_counts[2] / total_igs if total_igs else 0
            ig3_ratio = ig_counts[3] / total_igs if total_igs else 0

            # Weighted score: IG1=0.2, IG2=0.5, IG3=0.9
            ig_score = (ig1_ratio * 0.20) + (ig2_ratio * 0.50) + (ig3_ratio * 0.90)

            # Adjust with family weights
            if family_weights:
                avg_family_weight = sum(family_weights) / len(family_weights)
                # Blend: 60% IG distribution, 40% family complexity
                result.score = (ig_score * 0.6) + (avg_family_weight * 0.4)
            else:
                result.score = ig_score

            # Determine level based on score thresholds
            # Adjust based on IG1 ratio - more IG1 = easier
            if ig1_ratio >= 0.5 or result.score < 0.38:
                result.level = ComplexityLevel.BASIC
                result.effort_description = f"Basic (IG1: {ig1_ratio:.0%}) - Quick wins, foundational controls"
            elif ig1_ratio >= 0.35 or result.score < 0.52:
                result.level = ComplexityLevel.INTERMEDIATE
                result.effort_description = f"Intermediate (IG1-2 mix) - Standard security resources"
            else:
                result.level = ComplexityLevel.ADVANCED
                result.effort_description = f"Advanced (IG2-3: {ig2_ratio+ig3_ratio:.0%}) - Mature security program needed"

        elif nist_control_ids or mitigations:
            # Have controls but no direct IG mapping - use family weights
            if family_weights:
                avg_weight = sum(family_weights) / len(family_weights)
                result.score = avg_weight

                if avg_weight < 0.35:
                    result.level = ComplexityLevel.BASIC
                elif avg_weight < 0.55:
                    result.level = ComplexityLevel.INTERMEDIATE
                else:
                    result.level = ComplexityLevel.ADVANCED
            else:
                # Estimate based on control count only
                control_count = len(nist_control_ids) + len(mitigations)
                if control_count <= 3:
                    result.level = ComplexityLevel.BASIC
                    result.score = 0.30
                elif control_count <= 8:
                    result.level = ComplexityLevel.INTERMEDIATE
                    result.score = 0.50
                else:
                    result.level = ComplexityLevel.ADVANCED
                    result.score = 0.70

            result.effort_description = f"Based on {len(families_seen)} control families, {len(mitigations)} mitigations"

        else:
            result.level = ComplexityLevel.UNKNOWN
            result.score = 0.5
            result.effort_description = "No control mappings available"

        return result

    def get_all_technique_complexities(self) -> Dict[str, RemediationComplexity]:
        """Get complexity for all known techniques."""
        all_techniques = set()
        all_techniques.update(self.attack_to_nist.keys())
        all_techniques.update(self.mitre_mitigations.keys())

        results = {}
        for tech_id in all_techniques:
            results[tech_id] = self.get_technique_complexity(tech_id)

        return results

    def get_complexity_summary(self) -> Dict:
        """Get summary statistics of complexity distribution."""
        complexities = self.get_all_technique_complexities()

        level_counts = {level.value: 0 for level in ComplexityLevel}
        scores = []

        for comp in complexities.values():
            level_counts[comp.level.value] += 1
            scores.append(comp.score)

        return {
            'total_techniques': len(complexities),
            'by_level': level_counts,
            'avg_score': sum(scores) / len(scores) if scores else 0,
            'techniques_with_controls': len([c for c in complexities.values() if c.controls]),
        }

    def export_complexities(self, output_path: str = "filtered_data/remediation_complexity.json"):
        """Export all technique complexities to JSON."""
        complexities = self.get_all_technique_complexities()

        output = {
            'summary': self.get_complexity_summary(),
            'techniques': {
                tech_id: comp.to_dict()
                for tech_id, comp in sorted(complexities.items())
            }
        }

        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)

        logger.info(f"Exported {len(complexities)} technique complexities to {output_path}")
        return output_path


def main():
    """Main entry point."""
    analyzer = RemediationAnalyzer()

    # Print summary
    summary = analyzer.get_complexity_summary()
    print("\n" + "=" * 60)
    print("REMEDIATION COMPLEXITY ANALYSIS")
    print("=" * 60)
    print(f"Total techniques analyzed: {summary['total_techniques']}")
    print(f"Techniques with controls: {summary['techniques_with_controls']}")
    print(f"Average complexity score: {summary['avg_score']:.2f}")
    print("\nBy complexity level:")
    for level, count in summary['by_level'].items():
        pct = 100 * count / summary['total_techniques'] if summary['total_techniques'] else 0
        print(f"  {level.upper()}: {count} ({pct:.1f}%)")

    # Show examples
    print("\n" + "-" * 60)
    print("SAMPLE TECHNIQUE COMPLEXITIES")
    print("-" * 60)

    examples = ['T1059.001', 'T1566.001', 'T1078', 'T1105', 'T1486']
    for tech_id in examples:
        comp = analyzer.get_technique_complexity(tech_id)
        print(f"\n{tech_id}:")
        print(f"  Level: {comp.level.value.upper()}")
        print(f"  Score: {comp.score:.2f}")
        print(f"  Min IG: {comp.min_implementation_group or 'N/A'}")
        print(f"  Controls: {len(comp.controls)}")
        print(f"  Mitigations: {len(comp.mitigations)}")
        print(f"  Effort: {comp.effort_description}")

    # Export
    analyzer.export_complexities()
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
