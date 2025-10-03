"""
Unit tests for CVE to ECROSPK mapper.

These tests validate the heuristics used to translate CVE metadata
into ECROSPK confidence factors.
"""

import pytest
from src.scoring.cve_mapper import CVEToECROSPKMapper


class TestCVEMapper:
    """Test suite for the CVE to ECROSPK mapping logic."""
    
    @pytest.fixture
    def mapper(self):
        """Provide a fresh mapper instance for each test."""
        return CVEToECROSPKMapper()
    
    def test_mapper_initialization(self, mapper):
        """Test that mapper initializes correctly."""
        assert mapper.scorer is not None
        assert len(mapper.public_safety_products) > 0
    
    def test_severity_to_proof_quality_critical(self, mapper):
        """Test that CRITICAL severity maps to maximum proof quality."""
        proof_quality = mapper._map_severity_to_proof_quality('CRITICAL', 9.8)
        assert proof_quality == 10
    
    def test_severity_to_proof_quality_high(self, mapper):
        """Test that HIGH severity maps appropriately."""
        proof_quality = mapper._map_severity_to_proof_quality('HIGH', 8.5)
        assert proof_quality == 8
    
    def test_severity_to_proof_quality_medium(self, mapper):
        """Test that MEDIUM severity maps appropriately."""
        proof_quality = mapper._map_severity_to_proof_quality('MEDIUM', 5.0)
        assert proof_quality == 6
    
    def test_severity_to_proof_quality_low(self, mapper):
        """Test that LOW severity maps appropriately."""
        proof_quality = mapper._map_severity_to_proof_quality('LOW', 2.0)
        assert proof_quality == 4
    
    def test_observability_with_public_safety_keywords(self, mapper):
        """Test that public safety keywords increase observability."""
        # CVE affecting P25 radio systems
        description = "Vulnerability in P25 radio communication system affecting emergency dispatch"
        products = ['p25 radio', 'emergency communications']
        cwe_ids = ['CWE-78']
        
        availability, clarity, reason = mapper._estimate_observability(
            description, products, cwe_ids
        )
        
        # Should have elevated observability due to PS keywords
        assert availability >= 7
        assert clarity >= 7
        assert 'public safety' in reason.lower() or 'emergency' in reason.lower()
    
    def test_observability_without_public_safety_context(self, mapper):
        """Test baseline observability without PS context."""
        description = "Generic vulnerability in web application"
        products = ['generic-app']
        cwe_ids = []
        
        availability, clarity, reason = mapper._estimate_observability(
            description, products, cwe_ids
        )
        
        # Should have lower observability
        assert availability <= 7
        assert clarity <= 7
    
    def test_specificity_with_single_cwe(self, mapper):
        """Test that single CWE ID yields high specificity."""
        cwe_ids = ['CWE-89']
        # Use a realistic description length (100+ chars to avoid penalty)
        description = ("A SQL injection vulnerability was discovered in the database query handler "
                      "that allows remote attackers to execute arbitrary SQL commands through crafted input parameters.")
        
        specificity, reason = mapper._map_cwe_to_specificity(cwe_ids, description)
        
        # Single CWE with good description should give high specificity
        assert specificity >= 9
        assert 'single' in reason.lower() or 'specific' in reason.lower()
    
    def test_specificity_with_multiple_cwes(self, mapper):
        """Test that multiple CWE IDs yield moderate specificity."""
        cwe_ids = ['CWE-89', 'CWE-79', 'CWE-20']
        # Use a realistic description length
        description = ("Multiple vulnerabilities were found in the application including SQL injection, "
                      "cross-site scripting, and improper input validation issues that affect user data handling.")
        
        specificity, reason = mapper._map_cwe_to_specificity(cwe_ids, description)
        
        # Multiple CWEs should give moderate specificity (7-8 range with good description)
        assert 7 <= specificity <= 8
        assert 'multiple' in reason.lower()
    
    def test_specificity_with_no_cwes(self, mapper):
        """Test that no CWE classification yields low specificity."""
        cwe_ids = []
        description = "Unclassified vulnerability with limited details available"
        
        specificity, reason = mapper._map_cwe_to_specificity(cwe_ids, description)
        
        # No CWE should give low specificity
        assert specificity <= 5
        assert 'no cwe' in reason.lower()
    
    def test_public_safety_relevance_high(self, mapper):
        """Test relevance assessment for highly relevant CVE."""
        products = ['p25 radio system', 'emergency dispatch', '911 system']
        description = "Critical vulnerability affecting emergency services radio communications"
        severity = 'CRITICAL'
        score = 9.8
        
        relevance, reason = mapper._assess_public_safety_relevance(
            products, description, severity, score
        )
        
        # Should have high relevance
        assert relevance >= 8
        assert 'relevant' in reason.lower()
    
    def test_public_safety_relevance_low(self, mapper):
        """Test relevance assessment for non-relevant CVE."""
        products = ['random-web-app']
        description = "Vulnerability in consumer software"
        severity = 'MEDIUM'
        score = 5.0
        
        relevance, reason = mapper._assess_public_safety_relevance(
            products, description, severity, score
        )
        
        # Should have low relevance
        assert relevance <= 5
    
    def test_actor_sophistication_critical_vuln(self, mapper):
        """Test that critical vulns require low sophistication to exploit."""
        sophistication, reason = mapper._estimate_actor_sophistication(9.8, 'CRITICAL')
        
        # Critical = easy to exploit = low sophistication needed
        assert sophistication <= 3
        assert 'critical' in reason.lower()
    
    def test_actor_sophistication_low_vuln(self, mapper):
        """Test that low severity vulns require high sophistication."""
        sophistication, reason = mapper._estimate_actor_sophistication(2.0, 'LOW')
        
        # Low severity = hard to exploit = high sophistication needed
        assert sophistication >= 4
        assert 'low' in reason.lower() or 'sophisticated' in reason.lower()
    
    def test_systemic_threat_detection(self, mapper):
        """Test detection of systemic threats."""
        # Critical + many affected products = systemic
        is_systemic, reason = mapper._is_systemic_threat(
            'CRITICAL',
            ['windows', 'linux', 'apache', 'nginx', 'openssl', 'kernel']
        )
        
        assert is_systemic is True
        assert 'systemic' in reason.lower()
    
    def test_non_systemic_threat(self, mapper):
        """Test that limited-scope threats are not marked systemic."""
        # High severity but limited products = not systemic
        is_systemic, reason = mapper._is_systemic_threat(
            'HIGH',
            ['specific-app-v1.2']
        )
        
        assert is_systemic is False
        assert 'not' in reason.lower() or 'limited' in reason.lower()
    
    def test_complete_cve_mapping(self, mapper):
        """Test complete CVE to ECROSPK mapping flow."""
        sample_cve = {
            'id': 'CVE-2024-TEST',
            'title': 'Test Vulnerability',
            'description': 'A test vulnerability in P25 radio systems',
            'severity': 'HIGH',
            'score': 8.0,
            'affected_products': ['p25 radio'],
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2024-TEST',
            'months_old': 2.0,
            'cwe_ids': ['CWE-78'],
            'source': 'NVD',
            'fetched_at': '2024-01-01'
        }
        
        result = mapper.score_cve(sample_cve)
        
        # Verify result structure
        assert 'final_score' in result
        assert 'label' in result
        assert 'reasoning' in result
        assert 'cve_metadata' in result
        
        # Verify all reasoning factors are present
        reasoning = result['reasoning']
        assert 'Evidence' in reasoning
        assert 'Corroboration' in reasoning
        assert 'Recency' in reasoning
        assert 'Observability' in reasoning
        assert 'Specificity' in reasoning
        assert 'Proof_Relevance' in reasoning
        assert 'Actor_Sophistication' in reasoning
        assert 'Knockdown' in reasoning
        assert 'Systemic' in reasoning
        
        # Verify CVE metadata is included
        metadata = result['cve_metadata']
        assert metadata['id'] == 'CVE-2024-TEST'
        assert metadata['severity'] == 'HIGH'
        assert metadata['cvss_score'] == 8.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
