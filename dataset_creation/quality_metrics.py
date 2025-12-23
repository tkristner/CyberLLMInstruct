#!/usr/bin/env python3
"""
Dataset Quality Metrics

Issue #13: Implement dataset quality metrics for validation before final assembly.

Metrics categories:
1. Confidence Distribution - % of relations by confidence level
2. CTI Coverage - % of techniques with multi-source corroboration
3. Operational Quality - readiness for production use

Usage:
    python quality_metrics.py --enriched-file techniques_enriched_cti_*.json
    python quality_metrics.py --causal-graph causal_graph_*.json
"""

import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from collections import Counter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class QualityThresholds:
    """Quality thresholds for validation."""
    # Confidence distribution thresholds
    min_high_confidence: float = 0.40      # >=40% HIGH confidence
    max_medium_confidence: float = 0.35    # <=35% MEDIUM
    max_low_confidence: float = 0.15       # <=15% LOW
    max_unlikely: float = 0.10             # <=10% very low (<0.2)

    # CTI coverage thresholds
    min_3_source_coverage: float = 0.50    # 50% with >=3 sources
    min_2_source_coverage: float = 0.80    # 80% with >=2 sources

    # Operational quality thresholds
    min_calibrated_uncertainty: float = 0.90  # 90% with uncertainty language
    min_business_context: float = 0.70        # 70% with business context
    min_fp_guidance: float = 0.80             # 80% with FP guidance


@dataclass
class ConfidenceDistribution:
    """Distribution of confidence levels."""
    high: int = 0        # >= 0.7
    medium: int = 0      # 0.4 - 0.69
    low: int = 0         # 0.2 - 0.39
    unlikely: int = 0    # < 0.2
    total: int = 0

    @property
    def high_pct(self) -> float:
        return self.high / self.total if self.total > 0 else 0.0

    @property
    def medium_pct(self) -> float:
        return self.medium / self.total if self.total > 0 else 0.0

    @property
    def low_pct(self) -> float:
        return self.low / self.total if self.total > 0 else 0.0

    @property
    def unlikely_pct(self) -> float:
        return self.unlikely / self.total if self.total > 0 else 0.0


@dataclass
class CTICoverage:
    """CTI source coverage metrics."""
    techniques_total: int = 0
    techniques_with_1_source: int = 0
    techniques_with_2_sources: int = 0
    techniques_with_3_sources: int = 0
    techniques_with_4_plus_sources: int = 0
    source_distribution: Dict[str, int] = field(default_factory=dict)

    @property
    def pct_2_plus_sources(self) -> float:
        two_plus = self.techniques_with_2_sources + self.techniques_with_3_sources + self.techniques_with_4_plus_sources
        return two_plus / self.techniques_total if self.techniques_total > 0 else 0.0

    @property
    def pct_3_plus_sources(self) -> float:
        three_plus = self.techniques_with_3_sources + self.techniques_with_4_plus_sources
        return three_plus / self.techniques_total if self.techniques_total > 0 else 0.0


@dataclass
class QualityAlert:
    """Quality threshold violation alert."""
    metric: str
    threshold: float
    actual: float
    severity: str  # WARNING, CRITICAL
    message: str


@dataclass
class QualityReport:
    """Complete quality metrics report."""
    timestamp: str
    confidence_distribution: Dict
    cti_coverage: Dict
    relation_stats: Dict
    alerts: List[Dict]
    overall_score: float
    passes_thresholds: bool


class DatasetQualityAnalyzer:
    """Analyze dataset quality metrics."""

    def __init__(self, thresholds: QualityThresholds = None):
        self.thresholds = thresholds or QualityThresholds()
        self.alerts: List[QualityAlert] = []

    def analyze_enriched_techniques(self, file_path: Path) -> Tuple[CTICoverage, ConfidenceDistribution]:
        """Analyze enriched techniques file for CTI coverage and confidence."""
        logger.info(f"Analyzing enriched techniques: {file_path}")

        with open(file_path) as f:
            techniques = json.load(f)

        coverage = CTICoverage()
        confidence = ConfidenceDistribution()

        coverage.techniques_total = len(techniques)
        source_counts = Counter()

        for tech in techniques:
            # Count sources per technique
            sources = []
            # Use source_details (actual field name) or cti_data (legacy)
            source_details = tech.get('source_details', tech.get('cti_data', {}))

            if source_details.get('lolbas'):
                sources.append('lolbas')
            if source_details.get('loldrivers'):
                sources.append('loldrivers')
            if source_details.get('hijacklibs'):
                sources.append('hijacklibs')
            if source_details.get('otx'):
                sources.append('otx')
            if source_details.get('nist'):
                sources.append('nist')
            if source_details.get('cti_chains'):
                sources.append('cti_chains')

            # Also use sources_count if available
            num_sources = tech.get('sources_count', len(sources))
            for src in sources:
                source_counts[src] += 1

            if num_sources == 0:
                pass  # No sources
            elif num_sources == 1:
                coverage.techniques_with_1_source += 1
            elif num_sources == 2:
                coverage.techniques_with_2_sources += 1
            elif num_sources == 3:
                coverage.techniques_with_3_sources += 1
            else:
                coverage.techniques_with_4_plus_sources += 1

            # Analyze corroboration score for confidence
            score = tech.get('corroboration_score', 0.0)
            confidence.total += 1

            if score >= 0.7:
                confidence.high += 1
            elif score >= 0.4:
                confidence.medium += 1
            elif score >= 0.2:
                confidence.low += 1
            else:
                confidence.unlikely += 1

        coverage.source_distribution = dict(source_counts)

        return coverage, confidence

    def analyze_causal_graph(self, file_path: Path) -> Dict:
        """Analyze causal graph relations."""
        logger.info(f"Analyzing causal graph: {file_path}")

        with open(file_path) as f:
            graph = json.load(f)

        stats = {
            'enables': 0,
            'blocks': 0,
            'pivot_to': 0,
            'exploits': 0,
            'prerequisites': 0,
            'total_relations': 0,
            'high_confidence_relations': 0,
            'medium_confidence_relations': 0,
            'low_confidence_relations': 0,
        }

        # Count relations by type
        for rel_type in ['enables', 'blocks', 'pivot_to', 'exploits', 'prerequisites']:
            relations = graph.get(rel_type, [])
            stats[rel_type] = len(relations)
            stats['total_relations'] += len(relations)

            for rel in relations:
                conf = rel.get('confidence', 0.0)
                if conf >= 0.7:
                    stats['high_confidence_relations'] += 1
                elif conf >= 0.4:
                    stats['medium_confidence_relations'] += 1
                else:
                    stats['low_confidence_relations'] += 1

        return stats

    def check_thresholds(self, coverage: CTICoverage, confidence: ConfidenceDistribution) -> List[QualityAlert]:
        """Check if metrics meet quality thresholds."""
        alerts = []

        # Confidence distribution checks
        if confidence.high_pct < self.thresholds.min_high_confidence:
            alerts.append(QualityAlert(
                metric="high_confidence_pct",
                threshold=self.thresholds.min_high_confidence,
                actual=confidence.high_pct,
                severity="WARNING",
                message=f"HIGH confidence relations below threshold: {confidence.high_pct:.1%} < {self.thresholds.min_high_confidence:.0%}"
            ))

        if confidence.medium_pct > self.thresholds.max_medium_confidence:
            alerts.append(QualityAlert(
                metric="medium_confidence_pct",
                threshold=self.thresholds.max_medium_confidence,
                actual=confidence.medium_pct,
                severity="WARNING",
                message=f"MEDIUM confidence relations above threshold: {confidence.medium_pct:.1%} > {self.thresholds.max_medium_confidence:.0%}"
            ))

        if confidence.unlikely_pct > self.thresholds.max_unlikely:
            alerts.append(QualityAlert(
                metric="unlikely_pct",
                threshold=self.thresholds.max_unlikely,
                actual=confidence.unlikely_pct,
                severity="CRITICAL",
                message=f"UNLIKELY relations above threshold: {confidence.unlikely_pct:.1%} > {self.thresholds.max_unlikely:.0%}"
            ))

        # CTI coverage checks
        if coverage.pct_3_plus_sources < self.thresholds.min_3_source_coverage:
            alerts.append(QualityAlert(
                metric="3_source_coverage",
                threshold=self.thresholds.min_3_source_coverage,
                actual=coverage.pct_3_plus_sources,
                severity="WARNING",
                message=f"3+ source coverage below threshold: {coverage.pct_3_plus_sources:.1%} < {self.thresholds.min_3_source_coverage:.0%}"
            ))

        if coverage.pct_2_plus_sources < self.thresholds.min_2_source_coverage:
            alerts.append(QualityAlert(
                metric="2_source_coverage",
                threshold=self.thresholds.min_2_source_coverage,
                actual=coverage.pct_2_plus_sources,
                severity="CRITICAL",
                message=f"2+ source coverage below threshold: {coverage.pct_2_plus_sources:.1%} < {self.thresholds.min_2_source_coverage:.0%}"
            ))

        return alerts

    def calculate_overall_score(self, coverage: CTICoverage, confidence: ConfidenceDistribution) -> float:
        """Calculate overall quality score (0-100)."""
        score = 0.0

        # Confidence distribution (40 points max)
        # More HIGH = better, less UNLIKELY = better
        conf_score = (confidence.high_pct * 30) + ((1 - confidence.unlikely_pct) * 10)
        score += min(40, conf_score)

        # CTI coverage (40 points max)
        cov_score = (coverage.pct_3_plus_sources * 20) + (coverage.pct_2_plus_sources * 20)
        score += min(40, cov_score)

        # Source diversity (20 points max)
        num_sources = len(coverage.source_distribution)
        diversity_score = min(20, num_sources * 4)  # 5+ sources = max
        score += diversity_score

        return min(100, score)

    def generate_report(
        self,
        enriched_file: Optional[Path] = None,
        causal_graph_file: Optional[Path] = None,
        output_dir: Path = Path("filtered_data")
    ) -> QualityReport:
        """Generate complete quality report."""

        coverage = CTICoverage()
        confidence = ConfidenceDistribution()
        relation_stats = {}

        # Analyze enriched techniques if provided
        if enriched_file and enriched_file.exists():
            coverage, confidence = self.analyze_enriched_techniques(enriched_file)

        # Analyze causal graph if provided
        if causal_graph_file and causal_graph_file.exists():
            relation_stats = self.analyze_causal_graph(causal_graph_file)

        # Check thresholds
        alerts = self.check_thresholds(coverage, confidence)

        # Calculate overall score
        overall_score = self.calculate_overall_score(coverage, confidence)

        # Determine if passes
        critical_alerts = [a for a in alerts if a.severity == "CRITICAL"]
        passes = len(critical_alerts) == 0 and overall_score >= 60

        report = QualityReport(
            timestamp=datetime.now().isoformat(),
            confidence_distribution={
                'high': confidence.high,
                'high_pct': round(confidence.high_pct, 4),
                'medium': confidence.medium,
                'medium_pct': round(confidence.medium_pct, 4),
                'low': confidence.low,
                'low_pct': round(confidence.low_pct, 4),
                'unlikely': confidence.unlikely,
                'unlikely_pct': round(confidence.unlikely_pct, 4),
                'total': confidence.total,
            },
            cti_coverage={
                'techniques_total': coverage.techniques_total,
                'with_1_source': coverage.techniques_with_1_source,
                'with_2_sources': coverage.techniques_with_2_sources,
                'with_3_sources': coverage.techniques_with_3_sources,
                'with_4_plus_sources': coverage.techniques_with_4_plus_sources,
                'pct_2_plus_sources': round(coverage.pct_2_plus_sources, 4),
                'pct_3_plus_sources': round(coverage.pct_3_plus_sources, 4),
                'source_distribution': coverage.source_distribution,
            },
            relation_stats=relation_stats,
            alerts=[asdict(a) for a in alerts],
            overall_score=round(overall_score, 2),
            passes_thresholds=passes,
        )

        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f"quality_report_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(asdict(report), f, indent=2)

        logger.info(f"Quality report saved to {output_file}")

        # Print summary
        self._print_summary(report, alerts)

        return report

    def _print_summary(self, report: QualityReport, alerts: List[QualityAlert]):
        """Print quality summary to console."""
        print("\n" + "=" * 60)
        print("DATASET QUALITY REPORT")
        print("=" * 60)

        print(f"\nOverall Score: {report.overall_score:.1f}/100")
        print(f"Passes Thresholds: {'YES' if report.passes_thresholds else 'NO'}")

        print("\n--- Confidence Distribution ---")
        cd = report.confidence_distribution
        print(f"  HIGH (>=0.7):    {cd['high']:5d} ({cd['high_pct']:.1%})")
        print(f"  MEDIUM (0.4-0.7): {cd['medium']:5d} ({cd['medium_pct']:.1%})")
        print(f"  LOW (0.2-0.4):   {cd['low']:5d} ({cd['low_pct']:.1%})")
        print(f"  UNLIKELY (<0.2): {cd['unlikely']:5d} ({cd['unlikely_pct']:.1%})")

        print("\n--- CTI Coverage ---")
        cov = report.cti_coverage
        print(f"  Total techniques: {cov['techniques_total']}")
        print(f"  2+ sources: {cov['pct_2_plus_sources']:.1%}")
        print(f"  3+ sources: {cov['pct_3_plus_sources']:.1%}")
        print(f"  Source distribution: {cov['source_distribution']}")

        if report.relation_stats:
            print("\n--- Relation Statistics ---")
            rs = report.relation_stats
            print(f"  Total relations: {rs.get('total_relations', 0)}")
            print(f"  - enables: {rs.get('enables', 0)}")
            print(f"  - blocks: {rs.get('blocks', 0)}")
            print(f"  - pivot_to: {rs.get('pivot_to', 0)}")
            print(f"  - exploits: {rs.get('exploits', 0)}")
            print(f"  - prerequisites: {rs.get('prerequisites', 0)}")

        if alerts:
            print("\n--- ALERTS ---")
            for alert in alerts:
                icon = "⚠️ " if alert.severity == "WARNING" else "❌"
                print(f"  {icon} [{alert.severity}] {alert.message}")
        else:
            print("\n--- ALERTS ---")
            print("  ✅ No quality alerts")

        print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Analyze dataset quality metrics")
    parser.add_argument("--enriched-file", type=Path, help="Path to enriched techniques JSON")
    parser.add_argument("--causal-graph", type=Path, help="Path to causal graph JSON")
    parser.add_argument("--output-dir", type=Path, default=Path("filtered_data"), help="Output directory")
    parser.add_argument("--strict", action="store_true", help="Use strict thresholds")

    args = parser.parse_args()

    # Auto-detect files if not provided
    if not args.enriched_file:
        enriched_files = sorted(Path("filtered_data").glob("techniques_enriched_cti_*.json"))
        if enriched_files:
            args.enriched_file = enriched_files[-1]
            logger.info(f"Auto-detected enriched file: {args.enriched_file}")

    if not args.causal_graph:
        graph_files = sorted(Path("filtered_data").glob("causal_graph_*.json"))
        if graph_files:
            args.causal_graph = graph_files[-1]
            logger.info(f"Auto-detected causal graph: {args.causal_graph}")

    # Create analyzer
    thresholds = QualityThresholds()
    if args.strict:
        thresholds.min_high_confidence = 0.50
        thresholds.min_3_source_coverage = 0.60

    analyzer = DatasetQualityAnalyzer(thresholds)

    # Generate report
    report = analyzer.generate_report(
        enriched_file=args.enriched_file,
        causal_graph_file=args.causal_graph,
        output_dir=args.output_dir
    )

    # Exit with error code if critical alerts
    if not report.passes_thresholds:
        exit(1)


if __name__ == "__main__":
    main()
