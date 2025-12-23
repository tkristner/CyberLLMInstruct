#!/usr/bin/env python3
"""
Calibrated Uncertainty Module

Issue #12: Generate responses with calibrated uncertainty language.

This module provides:
1. Uncertainty templates based on confidence scores
2. Response formatting with appropriate hedging language
3. Integration helpers for data_structurer.py

Usage:
    from calibrated_uncertainty import UncertaintyCalibrator

    calibrator = UncertaintyCalibrator()
    response = calibrator.format_response(
        content="T1059 enables T1105",
        confidence=0.85,
        evidence=["Observed in 5 campaigns", "3 CTI sources"]
    )
"""

import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence level classification."""
    HIGH = "high"           # >= 0.7
    MEDIUM = "medium"       # 0.4 - 0.69
    LOW = "low"             # 0.2 - 0.39
    SPECULATIVE = "speculative"  # < 0.2


@dataclass
class UncertaintyTemplate:
    """Template for uncertainty-calibrated language."""
    level: ConfidenceLevel
    prefixes: List[str]
    qualifiers: List[str]
    evidence_intros: List[str]
    caveats: List[str]


# Template definitions for each confidence level
UNCERTAINTY_TEMPLATES = {
    ConfidenceLevel.HIGH: UncertaintyTemplate(
        level=ConfidenceLevel.HIGH,
        prefixes=[
            "Based on strong evidence,",
            "Multiple sources confirm that",
            "It is well-established that",
            "Analysis clearly shows that",
            "CTI data consistently indicates that",
        ],
        qualifiers=[
            "is confirmed to",
            "definitively",
            "is known to",
            "reliably",
            "consistently",
        ],
        evidence_intros=[
            "This is supported by",
            "Evidence includes",
            "This is corroborated by",
            "Multiple sources confirm this:",
        ],
        caveats=[
            "",  # No caveat needed for high confidence
        ]
    ),

    ConfidenceLevel.MEDIUM: UncertaintyTemplate(
        level=ConfidenceLevel.MEDIUM,
        prefixes=[
            "According to available data,",
            "Evidence suggests that",
            "Based on current intelligence,",
            "Analysis indicates that",
            "CTI sources suggest that",
        ],
        qualifiers=[
            "likely",
            "probably",
            "appears to",
            "is expected to",
            "typically",
        ],
        evidence_intros=[
            "This is based on",
            "Supporting evidence includes",
            "This assessment relies on",
            "Available data shows",
        ],
        caveats=[
            "However, additional confirmation may be needed.",
            "This assessment may be refined as more data becomes available.",
            "Confidence in this assessment is moderate.",
        ]
    ),

    ConfidenceLevel.LOW: UncertaintyTemplate(
        level=ConfidenceLevel.LOW,
        prefixes=[
            "Limited evidence suggests that",
            "Preliminary analysis indicates that",
            "Initial observations suggest that",
            "Based on sparse data,",
            "Early indicators point to",
        ],
        qualifiers=[
            "may",
            "could potentially",
            "might",
            "possibly",
            "in some cases",
        ],
        evidence_intros=[
            "Limited evidence includes",
            "This is tentatively based on",
            "Sparse data suggests",
            "Initial indicators include",
        ],
        caveats=[
            "This assessment has low confidence and requires further validation.",
            "Additional data collection is recommended before acting on this.",
            "This should be treated as a hypothesis requiring confirmation.",
            "Confidence is low due to limited corroborating evidence.",
        ]
    ),

    ConfidenceLevel.SPECULATIVE: UncertaintyTemplate(
        level=ConfidenceLevel.SPECULATIVE,
        prefixes=[
            "Speculatively,",
            "It is theoretically possible that",
            "Unconfirmed reports suggest that",
            "In the absence of strong evidence,",
            "Hypothetically,",
        ],
        qualifiers=[
            "theoretically could",
            "might hypothetically",
            "is speculated to",
            "could conceivably",
            "is unconfirmed but might",
        ],
        evidence_intros=[
            "This speculation is based on",
            "Unverified indicators include",
            "Theoretical reasoning suggests",
            "Hypothetical connections include",
        ],
        caveats=[
            "WARNING: This is speculative and should not be used for operational decisions.",
            "CAUTION: No reliable evidence supports this assessment.",
            "This is a hypothesis only and lacks empirical support.",
            "Treat this as unconfirmed intelligence requiring significant validation.",
        ]
    ),
}


@dataclass
class CalibratedResponse:
    """Response with calibrated uncertainty."""
    content: str
    confidence: float
    confidence_level: ConfidenceLevel
    formatted_response: str
    evidence_section: Optional[str] = None
    caveat: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class UncertaintyCalibrator:
    """Calibrate response language based on confidence scores."""

    def __init__(self, seed: int = None):
        """Initialize calibrator with optional random seed for reproducibility."""
        if seed is not None:
            random.seed(seed)
        self.templates = UNCERTAINTY_TEMPLATES

    def get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Map confidence score to level."""
        if confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.4:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.2:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.SPECULATIVE

    def get_template(self, level: ConfidenceLevel) -> UncertaintyTemplate:
        """Get template for confidence level."""
        return self.templates[level]

    def format_response(
        self,
        content: str,
        confidence: float,
        evidence: List[str] = None,
        include_evidence: bool = True,
        include_caveat: bool = True,
        include_score: bool = False,
    ) -> CalibratedResponse:
        """
        Format response with calibrated uncertainty language.

        Args:
            content: The core content/claim to format
            confidence: Confidence score (0-1)
            evidence: List of evidence strings
            include_evidence: Whether to include evidence section
            include_caveat: Whether to include confidence caveat
            include_score: Whether to include numeric score

        Returns:
            CalibratedResponse with formatted text and metadata
        """
        level = self.get_confidence_level(confidence)
        template = self.get_template(level)

        # Select random elements from template
        prefix = random.choice(template.prefixes)
        qualifier = random.choice(template.qualifiers)

        # Build formatted response
        parts = []

        # Main statement with prefix
        parts.append(f"{prefix} {content}")

        # Evidence section
        evidence_section = None
        if include_evidence and evidence:
            evidence_intro = random.choice(template.evidence_intros)
            evidence_list = "\n".join(f"  - {e}" for e in evidence[:5])  # Max 5 items
            evidence_section = f"\n\n{evidence_intro}\n{evidence_list}"
            parts.append(evidence_section)

        # Caveat
        caveat = None
        if include_caveat and level != ConfidenceLevel.HIGH:
            caveat = random.choice([c for c in template.caveats if c])
            if caveat:
                parts.append(f"\n\n{caveat}")

        # Optional confidence score
        if include_score:
            score_text = f"\n\n[Confidence: {confidence:.0%} - {level.value.upper()}]"
            parts.append(score_text)

        formatted = "".join(parts)

        return CalibratedResponse(
            content=content,
            confidence=confidence,
            confidence_level=level,
            formatted_response=formatted,
            evidence_section=evidence_section,
            caveat=caveat,
            metadata={
                'prefix_used': prefix,
                'qualifier_used': qualifier,
                'evidence_count': len(evidence) if evidence else 0,
            }
        )

    def format_relation(
        self,
        source_technique: str,
        target_technique: str,
        relation_type: str,
        confidence: float,
        evidence: List[str] = None,
        actors: List[str] = None,
    ) -> CalibratedResponse:
        """
        Format a causal relation with calibrated uncertainty.

        Args:
            source_technique: Source technique name/ID
            target_technique: Target technique name/ID
            relation_type: Type of relation (enables, blocks, etc.)
            confidence: Confidence score
            evidence: Supporting evidence
            actors: Threat actors using this chain

        Returns:
            CalibratedResponse with formatted relation
        """
        level = self.get_confidence_level(confidence)
        template = self.get_template(level)

        # Build relation statement
        qualifier = random.choice(template.qualifiers)

        relation_verbs = {
            'enables': f'{qualifier} enables',
            'blocks': f'{qualifier} blocks',
            'pivot_to': f'{qualifier} allows pivoting to',
            'exploits': f'{qualifier} exploits',
            'prerequisite': f'is {qualifier} a prerequisite for',
        }

        verb = relation_verbs.get(relation_type, f'{qualifier} relates to')
        content = f"{source_technique} {verb} {target_technique}"

        # Build evidence list
        full_evidence = evidence or []
        if actors:
            actor_list = ", ".join(actors[:5])
            full_evidence.append(f"Used by threat actors: {actor_list}")

        return self.format_response(
            content=content,
            confidence=confidence,
            evidence=full_evidence,
            include_evidence=True,
            include_caveat=True,
            include_score=True,
        )

    def generate_qa_pair(
        self,
        question: str,
        answer_content: str,
        confidence: float,
        evidence: List[str] = None,
    ) -> Tuple[str, str, Dict]:
        """
        Generate a Q&A pair with calibrated uncertainty.

        Args:
            question: The question
            answer_content: Core answer content
            confidence: Confidence in the answer
            evidence: Supporting evidence

        Returns:
            (question, formatted_answer, metadata)
        """
        response = self.format_response(
            content=answer_content,
            confidence=confidence,
            evidence=evidence,
            include_score=False,  # Don't include raw score in training data
        )

        metadata = {
            'confidence': confidence,
            'confidence_level': response.confidence_level.value,
            'has_calibrated_language': True,
            **response.metadata
        }

        return question, response.formatted_response, metadata


# Convenience functions for integration
def calibrate_response(content: str, confidence: float, evidence: List[str] = None) -> str:
    """Quick helper to calibrate a response."""
    calibrator = UncertaintyCalibrator()
    result = calibrator.format_response(content, confidence, evidence)
    return result.formatted_response


def get_uncertainty_prefix(confidence: float) -> str:
    """Get appropriate prefix for confidence level."""
    calibrator = UncertaintyCalibrator()
    level = calibrator.get_confidence_level(confidence)
    template = calibrator.get_template(level)
    return random.choice(template.prefixes)


def get_uncertainty_qualifier(confidence: float) -> str:
    """Get appropriate qualifier for confidence level."""
    calibrator = UncertaintyCalibrator()
    level = calibrator.get_confidence_level(confidence)
    template = calibrator.get_template(level)
    return random.choice(template.qualifiers)


# Example usage and testing
if __name__ == "__main__":
    calibrator = UncertaintyCalibrator(seed=42)

    print("=" * 60)
    print("CALIBRATED UNCERTAINTY EXAMPLES")
    print("=" * 60)

    # High confidence example
    print("\n--- HIGH CONFIDENCE (0.85) ---")
    result = calibrator.format_relation(
        source_technique="T1566 (Phishing)",
        target_technique="T1059 (Command Execution)",
        relation_type="enables",
        confidence=0.85,
        evidence=[
            "Observed in 15 APT campaigns",
            "Documented by MITRE ATT&CK",
            "Corroborated by 4 CTI sources"
        ],
        actors=["APT28", "APT29", "Lazarus"]
    )
    print(result.formatted_response)

    # Medium confidence example
    print("\n--- MEDIUM CONFIDENCE (0.55) ---")
    result = calibrator.format_relation(
        source_technique="T1055 (Process Injection)",
        target_technique="T1003 (Credential Dumping)",
        relation_type="enables",
        confidence=0.55,
        evidence=[
            "Documented in 3 CTI reports",
            "Single source corroboration"
        ],
        actors=["FIN7"]
    )
    print(result.formatted_response)

    # Low confidence example
    print("\n--- LOW CONFIDENCE (0.25) ---")
    result = calibrator.format_relation(
        source_technique="T1078 (Valid Accounts)",
        target_technique="T1486 (Data Encryption)",
        relation_type="enables",
        confidence=0.25,
        evidence=[
            "Inferred from single campaign"
        ]
    )
    print(result.formatted_response)

    # Speculative example
    print("\n--- SPECULATIVE (0.10) ---")
    result = calibrator.format_relation(
        source_technique="T1027 (Obfuscation)",
        target_technique="T1562 (Impair Defenses)",
        relation_type="enables",
        confidence=0.10,
        evidence=[]
    )
    print(result.formatted_response)

    print("\n" + "=" * 60)
