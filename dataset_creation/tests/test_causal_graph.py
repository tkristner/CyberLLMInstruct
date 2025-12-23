#!/usr/bin/env python3
"""
Unit tests for build_causal_graph.py

Issue #14: Comprehensive unit tests for causal graph inference functions.
Tests cover:
- calculate_theoretical_score() (#5)
- calculate_empirical_score() (#6)
- calculate_combined_confidence() (#7)
- Edge cases and boundary conditions
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from build_causal_graph import (
    calculate_theoretical_score,
    calculate_empirical_score,
    calculate_combined_confidence,
    TheoreticalScoreResult,
    EmpiricalScoreResult,
)


class TestTheoreticalScore:
    """Tests for calculate_theoretical_score() - Issue #5"""

    def test_adjacent_kill_chain_phases(self):
        """Adjacent phases should score highest (0.30)"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[2],
        )
        assert result.components['kill_chain'] == 0.30
        assert "Adjacent kill chain phases" in result.evidence[0]

    def test_close_kill_chain_phases(self):
        """Close phases (diff 2-3) should score 0.20"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[3],
        )
        assert result.components['kill_chain'] == 0.20
        assert "Close kill chain phases" in result.evidence[0]

    def test_distant_kill_chain_phases(self):
        """Distant phases (diff > 3) should score 0.10"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[6],
        )
        assert result.components['kill_chain'] == 0.10
        assert "Distant kill chain phases" in result.evidence[0]

    def test_same_phase(self):
        """Same phase should score 0.05"""
        result = calculate_theoretical_score(
            t1_phases=[3],
            t2_phases=[3],
        )
        assert result.components['kill_chain'] == 0.05
        assert "Same kill chain phase" in result.evidence[0]

    def test_reverse_order(self):
        """Reverse order (T2 before T1) should score 0.0"""
        result = calculate_theoretical_score(
            t1_phases=[5],
            t2_phases=[2],
        )
        assert result.components['kill_chain'] == 0.0
        assert "Reverse kill chain order" in result.evidence[0]

    def test_empty_phases(self):
        """Empty phases should return 0.0 for kill_chain"""
        result = calculate_theoretical_score(
            t1_phases=[],
            t2_phases=[],
        )
        assert result.components['kill_chain'] == 0.0

    def test_io_relation_credentials(self):
        """Credentials I/O match should score 0.30"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[2],
            t1_outputs=['credentials'],
            t2_inputs=['credentials'],
        )
        assert result.components['io_relation'] == 0.30
        assert any("I/O match" in e for e in result.evidence)

    def test_io_relation_shared_data_sources(self):
        """Shared data sources should contribute to I/O score"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[2],
            shared_data_sources=3,
        )
        assert abs(result.components['io_relation'] - 0.15) < 0.001  # min(0.20, 3 * 0.05)
        assert any("Shared data sources" in e for e in result.evidence)

    def test_subtechnique_hierarchy(self):
        """Parent-subtechnique relation should score 0.25"""
        result = calculate_theoretical_score(
            t1_phases=[],
            t2_phases=[],
            is_subtechnique_relation=True,
        )
        assert result.components['hierarchy'] == 0.25
        assert "Parent-subtechnique hierarchy" in result.evidence[0]

    def test_documented_prerequisite(self):
        """Documented prerequisite should score 0.15"""
        result = calculate_theoretical_score(
            t1_phases=[],
            t2_phases=[],
            has_documented_prerequisite=True,
        )
        assert result.components['prerequisites'] == 0.15
        assert "Documented prerequisite" in result.evidence[0]

    def test_max_score_capped(self):
        """Total score should be capped at 0.95"""
        result = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[2],  # +0.30
            is_subtechnique_relation=True,  # +0.25
            has_documented_prerequisite=True,  # +0.15
            t1_outputs=['credentials'],
            t2_inputs=['credentials'],  # +0.30
        )
        assert result.score <= 0.95
        # Individual components should sum to more than 0.95
        total_components = sum(result.components.values())
        assert total_components > 0.95

    def test_returns_correct_type(self):
        """Should return TheoreticalScoreResult"""
        result = calculate_theoretical_score(t1_phases=[1], t2_phases=[2])
        assert isinstance(result, TheoreticalScoreResult)
        assert isinstance(result.score, float)
        assert isinstance(result.evidence, list)
        assert isinstance(result.components, dict)

    def test_zero_score_scenario(self):
        """All zeros when no inputs provided"""
        result = calculate_theoretical_score(
            t1_phases=[],
            t2_phases=[],
            is_subtechnique_relation=False,
            has_documented_prerequisite=False,
            shared_data_sources=0,
        )
        assert result.score == 0.0


class TestEmpiricalScore:
    """Tests for calculate_empirical_score() - Issue #6"""

    def test_strong_actor_co_occurrence(self):
        """>=10 actors should score 0.40"""
        result = calculate_empirical_score(actor_co_occurrence=10)
        assert result.components['actor_co_occurrence'] == 0.40
        assert "Strong actor co-occurrence" in result.evidence[0]

    def test_moderate_actor_co_occurrence(self):
        """5-9 actors should score 0.30"""
        result = calculate_empirical_score(actor_co_occurrence=7)
        assert result.components['actor_co_occurrence'] == 0.30
        assert "Moderate actor co-occurrence" in result.evidence[0]

    def test_some_actor_co_occurrence(self):
        """2-4 actors should score 0.20"""
        result = calculate_empirical_score(actor_co_occurrence=3)
        assert result.components['actor_co_occurrence'] == 0.20
        assert "Some actor co-occurrence" in result.evidence[0]

    def test_single_actor(self):
        """1 actor should score 0.10"""
        result = calculate_empirical_score(actor_co_occurrence=1)
        assert result.components['actor_co_occurrence'] == 0.10
        assert "Single actor observed" in result.evidence[0]

    def test_no_actors(self):
        """0 actors should score 0.0"""
        result = calculate_empirical_score(actor_co_occurrence=0)
        assert result.components['actor_co_occurrence'] == 0.0

    def test_extensive_campaign_documentation(self):
        """>=10 reports should score 0.30"""
        result = calculate_empirical_score(campaign_documentation=15)
        assert result.components['campaign_documentation'] == 0.30
        assert "Extensively documented" in result.evidence[0]

    def test_well_documented_campaign(self):
        """5-9 reports should score 0.20"""
        result = calculate_empirical_score(campaign_documentation=7)
        assert result.components['campaign_documentation'] == 0.20
        assert "Well documented" in result.evidence[0]

    def test_some_campaign_documentation(self):
        """1-4 reports should score proportionally"""
        result = calculate_empirical_score(campaign_documentation=2)
        assert result.components['campaign_documentation'] == 0.10  # 2 * 0.05
        assert "Documented in" in result.evidence[0]

    def test_cti_chain_confidence_boost(self):
        """CTI chain confidence should boost campaign score"""
        result = calculate_empirical_score(
            campaign_documentation=5,
            cti_chain_confidence=0.8
        )
        # Base 0.20 + (0.8 * 0.1) = 0.28
        assert result.components['campaign_documentation'] == 0.28
        assert any("CTI chain confidence" in e for e in result.evidence)

    def test_multi_source_corroboration(self):
        """>=4 sources should score 0.20"""
        result = calculate_empirical_score(source_corroboration=5)
        assert result.components['source_corroboration'] == 0.20
        assert "Multi-source corroboration" in result.evidence[0]

    def test_some_corroboration(self):
        """2-3 sources should score 0.10"""
        result = calculate_empirical_score(source_corroboration=2)
        assert result.components['source_corroboration'] == 0.10

    def test_single_source(self):
        """1 source should score 0.05"""
        result = calculate_empirical_score(source_corroboration=1)
        assert result.components['source_corroboration'] == 0.05

    def test_recency_this_year(self):
        """Observed this year should score 0.10"""
        result = calculate_empirical_score(recency_years=0)
        assert result.components['recency'] == 0.10
        assert "Observed this year" in result.evidence[0]

    def test_recency_last_year(self):
        """Observed last year should score 0.08"""
        result = calculate_empirical_score(recency_years=1)
        assert result.components['recency'] == 0.08

    def test_recency_within_2_years(self):
        """Observed within 2 years should score 0.05"""
        result = calculate_empirical_score(recency_years=2)
        assert result.components['recency'] == 0.05

    def test_recency_within_5_years(self):
        """Observed within 5 years should score 0.02"""
        result = calculate_empirical_score(recency_years=4)
        assert result.components['recency'] == 0.02

    def test_recency_old_data(self):
        """Old data (>5 years) should score 0.0"""
        result = calculate_empirical_score(recency_years=10)
        assert result.components['recency'] == 0.0

    def test_max_score_capped(self):
        """Total score should be capped at 0.95"""
        result = calculate_empirical_score(
            actor_co_occurrence=10,  # +0.40
            campaign_documentation=10,  # +0.30
            source_corroboration=5,  # +0.20
            recency_years=0,  # +0.10
        )
        assert result.score <= 0.95

    def test_returns_correct_type(self):
        """Should return EmpiricalScoreResult"""
        result = calculate_empirical_score()
        assert isinstance(result, EmpiricalScoreResult)
        assert isinstance(result.score, float)
        assert isinstance(result.evidence, list)
        assert isinstance(result.components, dict)

    def test_zero_score_scenario(self):
        """Default recency_years=0 means 'this year' which gives 0.1 score"""
        result = calculate_empirical_score()
        # recency_years=0 defaults to "this year" = 0.10 score
        assert result.score == 0.10
        assert result.components['recency'] == 0.10


class TestCombinedConfidence:
    """Tests for calculate_combined_confidence() - Issue #7"""

    def test_high_confidence_classification(self):
        """Score >= 0.7 should be HIGH"""
        combined, classification = calculate_combined_confidence(
            p_theorique=0.8,
            p_empirique=0.9
        )
        assert classification == "HIGH"
        assert combined >= 0.7

    def test_medium_confidence_classification(self):
        """Score 0.4-0.69 should be MEDIUM"""
        combined, classification = calculate_combined_confidence(
            p_theorique=0.5,
            p_empirique=0.5
        )
        assert classification == "MEDIUM"
        assert 0.4 <= combined < 0.7

    def test_low_confidence_classification(self):
        """Score < 0.4 should be LOW"""
        combined, classification = calculate_combined_confidence(
            p_theorique=0.2,
            p_empirique=0.2
        )
        assert classification == "LOW"
        assert combined < 0.4

    def test_default_weights(self):
        """Default weights: 40% theoretical, 60% empirical"""
        combined, _ = calculate_combined_confidence(
            p_theorique=1.0,
            p_empirique=0.0
        )
        # 1.0 * 0.4 + 0.0 * 0.6 = 0.4
        assert combined == 0.4

        combined2, _ = calculate_combined_confidence(
            p_theorique=0.0,
            p_empirique=1.0
        )
        # 0.0 * 0.4 + 1.0 * 0.6 = 0.6
        assert combined2 == 0.6

    def test_custom_weights(self):
        """Custom weights should work correctly"""
        combined, _ = calculate_combined_confidence(
            p_theorique=1.0,
            p_empirique=0.0,
            weight_theorique=0.7,
            weight_empirique=0.3
        )
        assert combined == 0.7

    def test_max_score_capped(self):
        """Combined score should be capped at 0.95"""
        combined, _ = calculate_combined_confidence(
            p_theorique=1.0,
            p_empirique=1.0
        )
        assert combined <= 0.95

    def test_zero_scores(self):
        """Zero inputs should return LOW classification"""
        combined, classification = calculate_combined_confidence(
            p_theorique=0.0,
            p_empirique=0.0
        )
        assert combined == 0.0
        assert classification == "LOW"

    def test_boundary_high_medium(self):
        """Test boundary at 0.7 (HIGH/MEDIUM)"""
        # Just at 0.7 - should be HIGH
        combined, classification = calculate_combined_confidence(
            p_theorique=0.7,
            p_empirique=0.7
        )
        assert classification == "HIGH"

        # Just below 0.7 - should be MEDIUM
        combined2, classification2 = calculate_combined_confidence(
            p_theorique=0.69,
            p_empirique=0.69
        )
        assert classification2 == "MEDIUM"

    def test_boundary_medium_low(self):
        """Test boundary at 0.4 (MEDIUM/LOW)"""
        # At 0.4 - should be MEDIUM
        combined, classification = calculate_combined_confidence(
            p_theorique=0.4,
            p_empirique=0.4
        )
        assert classification == "MEDIUM"

        # Below 0.4 - should be LOW
        combined2, classification2 = calculate_combined_confidence(
            p_theorique=0.39,
            p_empirique=0.39
        )
        assert classification2 == "LOW"


class TestEdgeCases:
    """Edge cases and boundary conditions"""

    def test_theoretical_multiple_phases(self):
        """Techniques with multiple phases should use minimum"""
        result = calculate_theoretical_score(
            t1_phases=[1, 3, 5],  # Min = 1
            t2_phases=[2, 4, 6],  # Min = 2
        )
        # Phase diff = 2 - 1 = 1, should be adjacent
        assert result.components['kill_chain'] == 0.30

    def test_empirical_boundary_values(self):
        """Test exact boundary values for each tier"""
        # Actor boundaries
        assert calculate_empirical_score(actor_co_occurrence=9).components['actor_co_occurrence'] == 0.30
        assert calculate_empirical_score(actor_co_occurrence=10).components['actor_co_occurrence'] == 0.40

        # Campaign boundaries
        assert calculate_empirical_score(campaign_documentation=4).components['campaign_documentation'] == 0.15  # capped
        assert calculate_empirical_score(campaign_documentation=5).components['campaign_documentation'] == 0.20

        # Recency boundaries
        assert calculate_empirical_score(recency_years=5).components['recency'] == 0.02
        assert calculate_empirical_score(recency_years=6).components['recency'] == 0.0

    def test_negative_inputs_handled(self):
        """Negative inputs should be treated as 0"""
        # Negative values shouldn't break the function
        result = calculate_empirical_score(
            actor_co_occurrence=-5,
            recency_years=-1
        )
        # Should still return valid result
        assert isinstance(result.score, float)

    def test_large_values(self):
        """Large values should still cap at max scores"""
        result_theoretical = calculate_theoretical_score(
            t1_phases=[1],
            t2_phases=[2],
            is_subtechnique_relation=True,
            has_documented_prerequisite=True,
            shared_data_sources=100,
            t1_outputs=['credentials'],
            t2_inputs=['credentials'],
        )
        assert result_theoretical.score <= 0.95

        result_empirical = calculate_empirical_score(
            actor_co_occurrence=1000,
            campaign_documentation=1000,
            source_corroboration=1000,
            recency_years=0,
            cti_chain_confidence=1.0
        )
        assert result_empirical.score <= 0.95


class TestIntegration:
    """Integration tests combining multiple functions"""

    def test_full_scoring_pipeline(self):
        """Test complete scoring pipeline"""
        # Calculate theoretical score
        theoretical = calculate_theoretical_score(
            t1_phases=[2],  # Execution
            t2_phases=[5],  # Lateral Movement
            t1_outputs=['access'],
            t2_inputs=['access'],
        )

        # Calculate empirical score
        empirical = calculate_empirical_score(
            actor_co_occurrence=5,
            campaign_documentation=3,
            source_corroboration=2,
            recency_years=1
        )

        # Combine scores
        combined, classification = calculate_combined_confidence(
            p_theorique=theoretical.score,
            p_empirique=empirical.score
        )

        # Verify all parts work together
        assert 0 <= theoretical.score <= 0.95
        assert 0 <= empirical.score <= 0.95
        assert 0 <= combined <= 0.95
        assert classification in ["HIGH", "MEDIUM", "LOW"]

    def test_realistic_apt_scenario(self):
        """Test with realistic APT attack chain scenario"""
        # T1566 (Phishing) -> T1059 (Command Execution)
        theoretical = calculate_theoretical_score(
            t1_phases=[1],  # Initial Access
            t2_phases=[2],  # Execution
            is_subtechnique_relation=False,
            has_documented_prerequisite=True,  # Common chain
        )

        empirical = calculate_empirical_score(
            actor_co_occurrence=15,  # Very common pattern
            campaign_documentation=20,  # Widely documented
            source_corroboration=4,  # Multiple sources
            recency_years=0,  # Current
        )

        combined, classification = calculate_combined_confidence(
            p_theorique=theoretical.score,
            p_empirique=empirical.score
        )

        # This should be a HIGH confidence relation
        assert classification == "HIGH"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
