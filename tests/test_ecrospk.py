"""
Unit tests for ECROSPK scoring framework.

These tests validate the core confidence scoring logic to ensure
that threat scores are calculated correctly and consistently.
"""

import pytest
from src.scoring.ecrospk import ECROSPKScorer


class TestECROSPKScorer:
    """Test suite for the ECROSPK confidence scoring engine."""
    
    @pytest.fixture
    def scorer(self):
        """Provide a fresh scorer instance for each test."""
        return ECROSPKScorer()
    
    def test_scorer_initialization(self, scorer):
        """Test that scorer initializes correctly."""
        # Just verify the scorer object was created
        assert scorer is not None
        # Verify the score_threat method exists
        assert hasattr(scorer, 'score_threat')
    
    def test_score_threat_high_confidence(self, scorer):
        """Test scoring a high-confidence threat."""
        threat_data = {
            'cve_id': 'CVE-2024-TEST-HIGH',
            'evidence_authority': 15,
            'evidence_proof_quality': 10,
            'corroboration': 15,
            'recency_months': 1,
            'observability_availability': 10,
            'observability_clarity': 10,
            'specificity': 10,
            'proof_relevance': 10,
            'actor_sophistication': 2,
            'systemic': False,
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        result = scorer.score_threat(threat_data)
        
        # Verify result structure
        assert 'final_score' in result
        assert 'label' in result
        assert 'factors' in result
        assert 'knockdown' in result
        
        # High confidence threat should score 75+
        assert result['final_score'] >= 75
        assert result['label'] == 'High'
        assert result['investigate_now'] is False  # Not systemic
    
    def test_score_threat_medium_confidence(self, scorer):
        """Test scoring a medium-confidence threat."""
        threat_data = {
            'cve_id': 'CVE-2024-TEST-MEDIUM',
            'evidence_authority': 10,
            'evidence_proof_quality': 6,
            'corroboration': 8,
            'recency_months': 6,
            'observability_availability': 5,
            'observability_clarity': 5,
            'specificity': 5,
            'proof_relevance': 5,
            'actor_sophistication': 3,
            'systemic': False,
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        result = scorer.score_threat(threat_data)
        
        # Medium confidence should score 50-74
        assert 50 <= result['final_score'] < 75
        assert result['label'] == 'Medium'
    
    def test_score_threat_low_confidence(self, scorer):
        """Test scoring a low-confidence threat."""
        threat_data = {
            'cve_id': 'CVE-2024-TEST-LOW',
            'evidence_authority': 5,
            'evidence_proof_quality': 2,
            'corroboration': 3,
            'recency_months': 18,
            'observability_availability': 2,
            'observability_clarity': 2,
            'specificity': 2,
            'proof_relevance': 2,
            'actor_sophistication': 5,
            'systemic': False,
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        result = scorer.score_threat(threat_data)
        
        # Low confidence should score below 50
        assert result['final_score'] < 50
        assert result['label'] == 'Low'
    
    def test_systemic_flag_triggers_investigate_now(self, scorer):
        """Test that systemic threats trigger the investigate_now flag."""
        threat_data = {
            'cve_id': 'CVE-2024-TEST-SYSTEMIC',
            'evidence_authority': 15,
            'evidence_proof_quality': 10,
            'corroboration': 15,
            'recency_months': 1,
            'observability_availability': 2,  # Low observability
            'observability_clarity': 2,
            'specificity': 10,
            'proof_relevance': 10,
            'actor_sophistication': 2,
            'systemic': True,  # This is the key
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        result = scorer.score_threat(threat_data)
        
        # Systemic + high evidence + low observability = investigate now
        assert result['investigate_now'] is True
    
    def test_mitigation_reduces_score(self, scorer):
        """Test that patch deployment reduces threat score."""
        # Same threat, different patch coverage
        base_threat = {
            'cve_id': 'CVE-2024-TEST-PATCH',
            'evidence_authority': 15,
            'evidence_proof_quality': 10,
            'corroboration': 15,
            'recency_months': 1,
            'observability_availability': 10,
            'observability_clarity': 10,
            'specificity': 10,
            'proof_relevance': 10,
            'actor_sophistication': 2,
            'systemic': False,
            'counter_proof': 0,
        }
        
        # No patches deployed
        unpatched = {**base_threat, 'patch_coverage': 0.0}
        result_unpatched = scorer.score_threat(unpatched)
        
        # 50% patches deployed
        partial = {**base_threat, 'patch_coverage': 0.5}
        result_partial = scorer.score_threat(partial)
        
        # 100% patches deployed
        fully_patched = {**base_threat, 'patch_coverage': 1.0}
        result_fully_patched = scorer.score_threat(fully_patched)
        
        # Scores should decrease with patch coverage
        assert result_unpatched['final_score'] > result_partial['final_score']
        assert result_partial['final_score'] > result_fully_patched['final_score']
    
    def test_score_never_exceeds_100(self, scorer):
        """Test that scores are capped at 100."""
        # Maximum possible values for everything
        max_threat = {
            'cve_id': 'CVE-2024-TEST-MAX',
            'evidence_authority': 15,
            'evidence_proof_quality': 10,
            'corroboration': 15,
            'recency_months': 0,
            'observability_availability': 10,
            'observability_clarity': 10,
            'specificity': 10,
            'proof_relevance': 10,
            'actor_sophistication': 0,  # Easiest to exploit = highest score
            'systemic': False,
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        result = scorer.score_threat(max_threat)
        
        # Score should not exceed 100
        assert result['final_score'] <= 100
    
    def test_score_never_below_zero(self, scorer):
        """Test that scores are never negative."""
        # Minimum possible values plus maximum knockdown
        min_threat = {
            'cve_id': 'CVE-2024-TEST-MIN',
            'evidence_authority': 0,
            'evidence_proof_quality': 0,
            'corroboration': 0,
            'recency_months': 30,
            'observability_availability': 0,
            'observability_clarity': 0,
            'specificity': 0,
            'proof_relevance': 0,
            'actor_sophistication': 5,
            'systemic': False,
            'counter_proof': 5,  # Maximum counter-evidence
            'patch_coverage': 1.0  # Fully patched
        }
        
        result = scorer.score_threat(min_threat)
        
        # Score should not go below 0
        assert result['final_score'] >= 0
    
    def test_recency_decay_over_time(self, scorer):
        """Test that older CVEs score lower than newer ones."""
        base_threat = {
            'cve_id': 'CVE-2024-TEST-RECENCY',
            'evidence_authority': 15,
            'evidence_proof_quality': 10,
            'corroboration': 15,
            'observability_availability': 10,
            'observability_clarity': 10,
            'specificity': 10,
            'proof_relevance': 10,
            'actor_sophistication': 2,
            'systemic': False,
            'counter_proof': 0,
            'patch_coverage': 0.0
        }
        
        # Brand new CVE
        new_cve = {**base_threat, 'recency_months': 0}
        result_new = scorer.score_threat(new_cve)
        
        # 6 months old
        old_cve = {**base_threat, 'recency_months': 6}
        result_old = scorer.score_threat(old_cve)
        
        # Newer CVE should score higher
        assert result_new['final_score'] > result_old['final_score']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
