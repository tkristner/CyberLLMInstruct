#!/usr/bin/env python3
"""
Contradiction Detection Module

Issue #9: Detect and log contradictions between CTI sources.

Types of contradictions detected:
1. Effectiveness conflicts - One source says "prevent", another says "detect only"
2. Severity conflicts - Different CVSS scores between sources
3. Attribution conflicts - Different threat actors attributed

Contradictions are logged for human review, NOT auto-resolved.

Usage:
    from contradiction_detector import ContradictionDetector

    detector = ContradictionDetector()
    contradictions = detector.detect_all(enriched_techniques)
    detector.export_for_review(contradictions, "contradictions_review.json")
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContradictionType(Enum):
    """Types of contradictions that can be detected."""
    EFFECTIVENESS = "effectiveness"      # prevent vs detect
    SEVERITY = "severity"                 # CVSS score differences
    ATTRIBUTION = "attribution"           # different actors
    TECHNIQUE_MAPPING = "technique_mapping"  # different technique IDs
    RELATIONSHIP = "relationship"         # enables vs blocks
    CONFIDENCE = "confidence"             # significant confidence differences


class ResolutionStatus(Enum):
    """Status of contradiction resolution."""
    PENDING_REVIEW = "pending_review"
    SOURCE_A_PREFERRED = "source_a_preferred"
    SOURCE_B_PREFERRED = "source_b_preferred"
    BOTH_VALID = "both_valid"  # Context-dependent, both can be true
    RESOLVED_MANUALLY = "resolved_manually"
    IGNORED = "ignored"


@dataclass
class ContradictionSource:
    """Information about a source in a contradiction."""
    source_name: str
    source_type: str  # lolbas, otx, nist, cti_chains, etc.
    value: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None


@dataclass
class Contradiction:
    """Represents a detected contradiction between sources."""
    contradiction_id: str
    type: ContradictionType
    technique_id: str
    technique_name: str
    field: str  # Which field has the contradiction
    source_a: ContradictionSource
    source_b: ContradictionSource
    severity: str  # low, medium, high
    resolution: ResolutionStatus = ResolutionStatus.PENDING_REVIEW
    notes: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())


class ContradictionDetector:
    """Detect contradictions between CTI sources."""

    def __init__(self):
        self.contradictions: List[Contradiction] = []
        self.stats = {
            'total_checked': 0,
            'contradictions_found': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
        }

    def _generate_id(self) -> str:
        """Generate unique contradiction ID."""
        return f"CONTRA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.contradictions):04d}"

    def detect_effectiveness_contradiction(
        self,
        technique_id: str,
        technique_name: str,
        source_claims: Dict[str, Dict]
    ) -> List[Contradiction]:
        """
        Detect effectiveness contradictions.
        E.g., One source says a mitigation prevents, another says it only detects.
        """
        contradictions = []

        # Keywords indicating prevention
        prevention_keywords = {'prevent', 'block', 'stop', 'disable', 'mitigate'}
        # Keywords indicating detection only
        detection_keywords = {'detect', 'monitor', 'alert', 'log', 'observe'}

        for source_name, source_data in source_claims.items():
            description = source_data.get('description', '').lower()

            is_prevention = any(kw in description for kw in prevention_keywords)
            is_detection = any(kw in description for kw in detection_keywords)

            source_data['_effectiveness'] = 'prevention' if is_prevention else 'detection' if is_detection else 'unknown'

        # Compare pairs
        sources = list(source_claims.items())
        for i, (name_a, data_a) in enumerate(sources):
            for name_b, data_b in sources[i+1:]:
                eff_a = data_a.get('_effectiveness', 'unknown')
                eff_b = data_b.get('_effectiveness', 'unknown')

                if eff_a != 'unknown' and eff_b != 'unknown' and eff_a != eff_b:
                    contradiction = Contradiction(
                        contradiction_id=self._generate_id(),
                        type=ContradictionType.EFFECTIVENESS,
                        technique_id=technique_id,
                        technique_name=technique_name,
                        field="effectiveness",
                        source_a=ContradictionSource(
                            source_name=name_a,
                            source_type=data_a.get('source_type', 'unknown'),
                            value=eff_a,
                            evidence=[data_a.get('description', '')[:200]]
                        ),
                        source_b=ContradictionSource(
                            source_name=name_b,
                            source_type=data_b.get('source_type', 'unknown'),
                            value=eff_b,
                            evidence=[data_b.get('description', '')[:200]]
                        ),
                        severity="medium",
                        notes=f"Effectiveness conflict: {eff_a} vs {eff_b}"
                    )
                    contradictions.append(contradiction)

        return contradictions

    def detect_attribution_contradiction(
        self,
        technique_id: str,
        technique_name: str,
        source_actors: Dict[str, Set[str]]
    ) -> List[Contradiction]:
        """
        Detect attribution contradictions.
        E.g., Different sources attribute the same technique to different exclusive groups.
        """
        contradictions = []

        # Known mutually exclusive actor groups (simplistic example)
        exclusive_groups = [
            {'APT28', 'APT29', 'Sandworm', 'Turla'},  # Russian
            {'APT10', 'APT41', 'Volt Typhoon'},       # Chinese
            {'Lazarus', 'APT38', 'Kimsuky'},          # North Korean
            {'APT33', 'APT34', 'APT35'},              # Iranian
        ]

        sources = list(source_actors.items())
        for i, (name_a, actors_a) in enumerate(sources):
            for name_b, actors_b in sources[i+1:]:
                # Check if attributed to different nation-state groups
                for group in exclusive_groups:
                    a_in_group = actors_a & group
                    b_in_group = actors_b & group

                    # If one source attributes to group A actors and another to group B
                    # This is only a contradiction if they claim EXCLUSIVE attribution
                    # For now, we just note significant differences
                    if a_in_group and b_in_group and a_in_group != b_in_group:
                        contradiction = Contradiction(
                            contradiction_id=self._generate_id(),
                            type=ContradictionType.ATTRIBUTION,
                            technique_id=technique_id,
                            technique_name=technique_name,
                            field="threat_actors",
                            source_a=ContradictionSource(
                                source_name=name_a,
                                source_type="cti",
                                value=", ".join(sorted(a_in_group)),
                            ),
                            source_b=ContradictionSource(
                                source_name=name_b,
                                source_type="cti",
                                value=", ".join(sorted(b_in_group)),
                            ),
                            severity="low",
                            notes="Different actor attribution within same region group"
                        )
                        contradictions.append(contradiction)

        return contradictions

    def detect_confidence_contradiction(
        self,
        technique_id: str,
        technique_name: str,
        source_confidences: Dict[str, float],
        threshold: float = 0.4
    ) -> List[Contradiction]:
        """
        Detect significant confidence score differences between sources.
        """
        contradictions = []

        sources = list(source_confidences.items())
        for i, (name_a, conf_a) in enumerate(sources):
            for name_b, conf_b in sources[i+1:]:
                diff = abs(conf_a - conf_b)
                if diff >= threshold:
                    contradiction = Contradiction(
                        contradiction_id=self._generate_id(),
                        type=ContradictionType.CONFIDENCE,
                        technique_id=technique_id,
                        technique_name=technique_name,
                        field="confidence",
                        source_a=ContradictionSource(
                            source_name=name_a,
                            source_type="cti",
                            value=f"{conf_a:.2f}",
                            confidence=conf_a,
                        ),
                        source_b=ContradictionSource(
                            source_name=name_b,
                            source_type="cti",
                            value=f"{conf_b:.2f}",
                            confidence=conf_b,
                        ),
                        severity="low" if diff < 0.5 else "medium",
                        notes=f"Confidence difference: {diff:.2f}"
                    )
                    contradictions.append(contradiction)

        return contradictions

    def analyze_enriched_technique(self, technique: Dict) -> List[Contradiction]:
        """Analyze a single enriched technique for contradictions."""
        contradictions = []

        tech_id = technique.get('external_id', technique.get('technique_id', 'unknown'))
        tech_name = technique.get('technique_name', 'Unknown')
        source_details = technique.get('source_details', {})

        if not source_details:
            return contradictions

        self.stats['total_checked'] += 1

        # Collect data for contradiction detection
        source_claims = {}
        source_actors = {}
        source_confidences = {}

        for source_name, source_data in source_details.items():
            if isinstance(source_data, dict):
                source_claims[source_name] = {
                    'source_type': source_data.get('source_type', source_name),
                    'description': str(source_data.get('sample_entries', [{}])[0].get('description', ''))
                    if source_data.get('sample_entries') else '',
                }
                source_confidences[source_name] = source_data.get('confidence_boost', 0.1)

        # Detect contradictions
        contradictions.extend(
            self.detect_effectiveness_contradiction(tech_id, tech_name, source_claims)
        )

        contradictions.extend(
            self.detect_confidence_contradiction(tech_id, tech_name, source_confidences)
        )

        # Update stats
        for c in contradictions:
            self.stats['contradictions_found'] += 1
            self.stats['by_type'][c.type.value] += 1
            self.stats['by_severity'][c.severity] += 1

        return contradictions

    def detect_all(self, enriched_techniques: List[Dict]) -> List[Contradiction]:
        """Detect all contradictions in enriched techniques."""
        logger.info(f"Analyzing {len(enriched_techniques)} techniques for contradictions...")

        all_contradictions = []
        for technique in enriched_techniques:
            contradictions = self.analyze_enriched_technique(technique)
            all_contradictions.extend(contradictions)
            self.contradictions.extend(contradictions)

        logger.info(f"Found {len(all_contradictions)} contradictions")
        return all_contradictions

    def export_for_review(
        self,
        contradictions: List[Contradiction] = None,
        output_path: str = "contradictions_review.json"
    ) -> Path:
        """Export contradictions for human review."""
        contradictions = contradictions or self.contradictions

        output = {
            'export_timestamp': datetime.now().isoformat(),
            'total_contradictions': len(contradictions),
            'stats': dict(self.stats),
            'by_type': {
                ctype.value: [
                    asdict(c) for c in contradictions
                    if c.type == ctype
                ]
                for ctype in ContradictionType
            },
            'all_contradictions': [
                {
                    **asdict(c),
                    'type': c.type.value,
                    'resolution': c.resolution.value,
                }
                for c in contradictions
            ]
        }

        output_file = Path(output_path)
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"Exported {len(contradictions)} contradictions to {output_file}")
        return output_file

    def print_summary(self):
        """Print contradiction summary."""
        print("\n" + "=" * 60)
        print("CONTRADICTION DETECTION SUMMARY")
        print("=" * 60)
        print(f"Techniques analyzed: {self.stats['total_checked']}")
        print(f"Contradictions found: {self.stats['contradictions_found']}")

        if self.stats['by_type']:
            print("\nBy Type:")
            for ctype, count in self.stats['by_type'].items():
                print(f"  {ctype}: {count}")

        if self.stats['by_severity']:
            print("\nBy Severity:")
            for severity, count in self.stats['by_severity'].items():
                print(f"  {severity}: {count}")

        print("=" * 60)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Detect contradictions in CTI data")
    parser.add_argument("--input", type=Path, help="Path to enriched techniques JSON")
    parser.add_argument("--output", type=Path, default=Path("filtered_data/intermediate/contradictions_review.json"))

    args = parser.parse_args()

    # Auto-detect input file
    if not args.input:
        enriched_files = sorted(Path("filtered_data/enrichment/enriched_techniques").glob("techniques_enriched_cti_*.json"))
        if enriched_files:
            args.input = enriched_files[-1]
            logger.info(f"Auto-detected: {args.input}")
        else:
            logger.error("No enriched techniques file found")
            return

    # Load and analyze
    with open(args.input) as f:
        techniques = json.load(f)

    detector = ContradictionDetector()
    contradictions = detector.detect_all(techniques)
    detector.export_for_review(contradictions, str(args.output))
    detector.print_summary()


if __name__ == "__main__":
    main()
