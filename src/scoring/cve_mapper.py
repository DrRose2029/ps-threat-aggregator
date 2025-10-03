"""
CVE to ECROSPK Mapper

This module bridges the gap between raw CVE data from NVD and the ECROSPK
scoring framework. It translates CVE metadata into ECROSPK factor inputs
using intelligent heuristics and domain knowledge.

The mapping challenge:
- CVEs have: severity, CVSS score, affected products, age, CWE IDs
- ECROSPK needs: Evidence, Corroboration, Recency, Observability, Specificity, Proof, Actor Sophistication, Knockdown

We need to infer ECROSPK factors from CVE metadata in a way that's:
1. Defensible: We can explain why each mapping makes sense
2. Consistent: Same CVE attributes always map the same way
3. Realistic: Reflects actual threat intelligence assessment practices

This is where domain expertise matters - the quality of these mappings
determines how useful your ECROSPK scores are for real decision-making.
"""

from typing import Dict, Any, List, Optional, Tuple
from src.scoring.ecrospk import ECROSPKScorer


class CVEToECROSPKMapper:
    """
    Maps CVE vulnerability data to ECROSPK scoring factors with full reasoning.
    
    This class contains the intelligence that translates technical
    vulnerability metadata into threat confidence factors. The mappings
    are based on cybersecurity best practices and threat intelligence
    analysis workflows.
    
    Critically, this mapper doesn't just calculate scores - it explains
    WHY each score was assigned. This explainability is key for:
    1. Building trust with stakeholders
    2. Auditing and improving the scoring logic
    3. Teaching others how to assess threat confidence
    4. Defending decisions in incident reviews
    """
    
    def __init__(self):
        """
        Initialize the mapper.
        
        We could make the mapping logic configurable in the future
        (e.g., organizations might weight factors differently), but
        for now we use reasonable defaults based on industry practices.
        """
        # Initialize the ECROSPK scorer we'll use to calculate final scores
        self.scorer = ECROSPKScorer()
        
        # ========================================
        # Public Safety Product Keywords
        # ========================================
        # These help us determine Observability and Relevance factors
        # If a CVE affects these products, we assume they're relevant to
        # public safety infrastructure and we likely have visibility into them
        self.public_safety_products = [
            'motorola', 'p25', 'astro', 'tetra', 'apco',
            'dispatch', 'cad', '911', 'e911', 'psap',
            'emergency', 'first responder', 'ems', 'fire',
            'police', 'radio', 'alert', 'notification'
        ]
    
    def map_cve_to_ecrospk_input(self, cve: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Convert a CVE dictionary into ECROSPK input format with reasoning.
        
        This is the main mapping function. It takes a CVE as returned by
        the NVD ingester and produces both a dictionary of ECROSPK factors
        and a dictionary explaining why each factor was scored the way it was.
        
        Args:
            cve: Dictionary with CVE data from NVD ingester
        
        Returns:
            Tuple of (ecrospk_input_dict, reasoning_dict)
        """
        # Initialize reasoning dictionary to collect explanations
        reasoning = {}
        
        # ========================================
        # EVIDENCE (E): Source authority + proof quality
        # ========================================
        evidence_authority = 15  # Maximum - NVD is NIST
        evidence_proof_quality = self._map_severity_to_proof_quality(
            cve.get('severity', 'Unknown'),
            cve.get('score', 0.0)
        )
        
        reasoning['Evidence'] = (
            f"Authority: {evidence_authority}/15 because this CVE comes from NIST's National "
            f"Vulnerability Database, which is the gold standard for vulnerability intelligence. "
            f"Every CVE is reviewed by government analysts before publication. "
            f"Proof Quality: {evidence_proof_quality}/10 because the CVE has {cve.get('severity', 'Unknown')} "
            f"severity (CVSS {cve.get('score', 0.0)}), indicating "
            f"{'well-documented exploitability' if evidence_proof_quality >= 8 else 'moderate proof of exploitability' if evidence_proof_quality >= 6 else 'limited proof'}."
        )
        
        # ========================================
        # CORROBORATION (C): Multiple independent sources
        # ========================================
        corroboration = 10
        
        reasoning['Corroboration'] = (
            f"Score: {corroboration}/15. While NVD aggregates information from multiple sources "
            f"(researchers, vendors, bug bounties), it presents as a single authoritative source. "
            f"We score this at moderate confidence because NIST has vetted the information, "
            f"but it's not the same as multiple independent threat intelligence feeds "
            f"confirming the same threat independently."
        )
        
        # ========================================
        # RECENCY (R): How recent is this CVE?
        # ========================================
        recency_months = cve.get('months_old', 0)
        
        reasoning['Recency'] = (
            f"This CVE is {recency_months} months old. ECROSPK applies a decay curve "
            f"(starting at 10 points, losing 0.5 points per month) to reflect that older "
            f"vulnerabilities are often already patched or understood. "
            f"{'This is recent enough to warrant immediate attention.' if recency_months < 3 else 'This has aged somewhat but may still be relevant if unpatched.' if recency_months < 12 else 'This is an older vulnerability; most organizations should have addressed it by now.'}"
        )
        
        # ========================================
        # OBSERVABILITY (O): Can we see this threat?
        # ========================================
        obs_availability, obs_clarity, obs_reason = self._estimate_observability(
            cve.get('description', ''),
            cve.get('affected_products', []),
            cve.get('cwe_ids', [])
        )
        
        reasoning['Observability'] = obs_reason
        
        # ========================================
        # SPECIFICITY (S): How specific are the indicators?
        # ========================================
        specificity, spec_reason = self._map_cwe_to_specificity(
            cve.get('cwe_ids', []),
            cve.get('description', '')
        )
        
        reasoning['Specificity'] = spec_reason
        
        # ========================================
        # PROOF/RELEVANCE (P): Relevant to us? Proven to work?
        # ========================================
        proof_relevance, proof_reason = self._assess_public_safety_relevance(
            cve.get('affected_products', []),
            cve.get('description', ''),
            cve.get('severity', 'Unknown'),
            cve.get('score', 0.0)
        )
        
        reasoning['Proof_Relevance'] = proof_reason
        
        # ========================================
        # ACTOR SOPHISTICATION (AS): How sophisticated is the threat?
        # ========================================
        actor_sophistication, actor_reason = self._estimate_actor_sophistication(
            cve.get('score', 0.0),
            cve.get('severity', 'Unknown')
        )
        
        reasoning['Actor_Sophistication'] = actor_reason
        
        # ========================================
        # KNOCKDOWN (K): Factors that reduce confidence
        # ========================================
        counter_proof = 0
        patch_coverage = 0.0
        
        reasoning['Knockdown'] = (
            f"Counter-Proof: {counter_proof} because NIST-published CVEs are thoroughly vetted; "
            f"if it's in NVD, it's real (no false positives). "
            f"Mitigation: {patch_coverage * 100:.0f}% patch coverage assumed. In a production system, "
            f"this would query asset management to determine actual patch deployment. "
            f"We conservatively assume zero mitigation for maximum caution."
        )
        
        # ========================================
        # SYSTEMIC FLAG
        # ========================================
        systemic, systemic_reason = self._is_systemic_threat(
            cve.get('severity', 'Unknown'),
            cve.get('affected_products', [])
        )
        
        reasoning['Systemic'] = systemic_reason
        
        # ========================================
        # Build and return
        # ========================================
        ecrospk_input = {
            'cve_id': cve.get('id', 'unknown'),
            'cve_severity': cve.get('severity', 'Unknown'),
            'cve_score': cve.get('score', 0.0),
            'evidence_authority': evidence_authority,
            'evidence_proof_quality': evidence_proof_quality,
            'corroboration': corroboration,
            'recency_months': recency_months,
            'observability_availability': obs_availability,
            'observability_clarity': obs_clarity,
            'specificity': specificity,
            'proof_relevance': proof_relevance,
            'actor_sophistication': actor_sophistication,
            'systemic': systemic,
            'counter_proof': counter_proof,
            'patch_coverage': patch_coverage
        }
        
        return ecrospk_input, reasoning
    
    def score_cve(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map a CVE to ECROSPK factors and calculate the confidence score with full reasoning.
        
        This is a convenience method that combines mapping and scoring
        in one step with complete explainability. This is your main
        entry point for production use.
        
        Args:
            cve: CVE dictionary from NVD ingester
        
        Returns:
            Complete ECROSPK scoring result including CVE metadata and reasoning
        """
        # Map CVE to ECROSPK input format and get reasoning
        ecrospk_input, reasoning = self.map_cve_to_ecrospk_input(cve)
        
        # Score it with ECROSPK
        score_result = self.scorer.score_threat(ecrospk_input)
        
        # Combine everything for complete context
        return {
            **score_result,  # Include all ECROSPK scoring output
            'reasoning': reasoning,  # Add the explanations
            'cve_metadata': {
                'id': cve.get('id'),
                'title': cve.get('title'),
                'description': cve.get('description', '')[:300] + '...',
                'severity': cve.get('severity'),
                'cvss_score': cve.get('score'),
                'link': cve.get('link'),
                'affected_products': cve.get('affected_products', [])[:5]
            }
        }
    
    # ========================================
    # HELPER METHODS: Mapping logic with reasoning
    # ========================================
    
    def _map_severity_to_proof_quality(self, severity: str, score: float) -> int:
        """Map CVSS severity/score to Evidence proof quality (0-10)."""
        severity = severity.upper()
        
        if severity == 'CRITICAL' or score >= 9.0:
            return 10
        elif severity == 'HIGH' or score >= 7.0:
            return 8
        elif severity == 'MEDIUM' or score >= 4.0:
            return 6
        elif severity == 'LOW' or score > 0:
            return 4
        else:
            return 2
    
    def _estimate_observability(self, 
                                description: str,
                                affected_products: List[str],
                                cwe_ids: List[str]) -> Tuple[int, int, str]:
        """
        Estimate Observability with detailed reasoning.
        
        Returns:
            Tuple of (availability, clarity, reasoning_text)
        """
        availability = 5
        clarity = 5
        reasons = []
        
        # Check for public safety products
        description_lower = description.lower()
        products_text = ' '.join(affected_products).lower()
        combined_text = description_lower + ' ' + products_text
        
        ps_matches = sum(1 for keyword in self.public_safety_products 
                        if keyword in combined_text)
        
        if ps_matches > 0:
            availability += 3
            clarity += 2
            reasons.append(
                f"The CVE affects public safety infrastructure products (found {ps_matches} relevant keywords), "
                f"which we typically monitor closely in emergency services environments."
            )
        
        # Check vulnerability type observability
        network_observable_cwes = ['CWE-89', 'CWE-79', 'CWE-20', 'CWE-22', 'CWE-78']
        if any(cwe in cwe_ids for cwe in network_observable_cwes):
            availability += 2
            clarity += 3
            cwe_str = ', '.join([c for c in cwe_ids if c in network_observable_cwes])
            reasons.append(
                f"The weakness type ({cwe_str}) involves network-based attacks like SQL injection "
                f"or command injection, which leave clear traces in application logs and network traffic."
            )
        
        memory_cwes = ['CWE-119', 'CWE-416', 'CWE-125', 'CWE-787']
        if any(cwe in cwe_ids for cwe in memory_cwes):
            availability -= 2
            clarity -= 2
            reasons.append(
                f"This is a memory corruption vulnerability, which requires deep instrumentation "
                f"(like EDR or kernel-level monitoring) to detect reliably. Without that, visibility is limited."
            )
        
        # Attack vector analysis
        if 'remote' in description_lower or 'network' in description_lower:
            availability += 1
            clarity += 2
            reasons.append(
                "The attack vector is remote/network-based, making it more observable through "
                "IDS/IPS, firewall logs, and network monitoring tools."
            )
        
        if 'local' in description_lower or 'physical access' in description_lower:
            availability -= 2
            clarity -= 1
            reasons.append(
                "This requires local or physical access, which is harder to observe through "
                "typical network security monitoring."
            )
        
        # Clamp to valid range
        availability = max(0, min(10, availability))
        clarity = max(0, min(10, clarity))
        
        # Build final reasoning
        if not reasons:
            reasons.append(
                "Based on generic vulnerability characteristics without specific public safety context."
            )
        
        reasoning_text = (
            f"Availability: {availability}/10, Clarity: {clarity}/10 (Total O: {availability + clarity}/20). "
            + " ".join(reasons)
        )
        
        return (availability, clarity, reasoning_text)
    
    def _map_cwe_to_specificity(self, cwe_ids: List[str], description: str) -> Tuple[int, str]:
        """
        Map CWE IDs and description to Specificity score with reasoning.
        
        Returns:
            Tuple of (specificity_score, reasoning_text)
        """
        if not cwe_ids:
            specificity = 4
            reason = (
                f"Specificity: {specificity}/10. No CWE classification provided, which means "
                f"the vulnerability is less well-characterized. This makes it harder to write "
                f"specific detection signatures or test cases."
            )
        elif len(cwe_ids) == 1:
            specificity = 9
            reason = (
                f"Specificity: {specificity}/10. Single specific CWE classification ({cwe_ids[0]}) "
                f"means this vulnerability is well-understood and can be tested with specific, "
                f"targeted detection logic. Low false positive rate expected."
            )
        else:
            specificity = 7
            reason = (
                f"Specificity: {specificity}/10. Multiple CWE classifications ({len(cwe_ids)} types) "
                f"indicate either a complex vulnerability or one that manifests in different ways. "
                f"Still testable but requires broader detection coverage."
            )
        
        # Adjust for description detail
        desc_length = len(description)
        if desc_length > 500:
            specificity = min(10, specificity + 1)
            reason += " The detailed description provides additional context for specific detection."
        elif desc_length < 100:
            specificity = max(0, specificity - 2)
            reason += " The vague description makes it harder to develop specific indicators."
        
        return (specificity, reason)
    
    def _assess_public_safety_relevance(self,
                                       affected_products: List[str],
                                       description: str,
                                       severity: str,
                                       score: float) -> Tuple[int, str]:
        """
        Assess Proof/Relevance with reasoning.
        
        Returns:
            Tuple of (relevance_score, reasoning_text)
        """
        products_text = ' '.join(affected_products).lower()
        combined_text = (description + ' ' + products_text).lower()
        
        ps_matches = sum(1 for keyword in self.public_safety_products 
                        if keyword in combined_text)
        
        if ps_matches >= 3:
            relevance = 10
            context = "highly relevant - affects multiple public safety systems"
        elif ps_matches >= 2:
            relevance = 8
            context = "quite relevant - affects public safety infrastructure"
        elif ps_matches >= 1:
            relevance = 6
            context = "moderately relevant - some public safety connection"
        else:
            relevance = 3
            context = "generic infrastructure vulnerability, not specifically public safety focused"
        
        # Adjust for severity (proxy for proven exploitability)
        severity_upper = severity.upper()
        if severity_upper == 'CRITICAL':
            relevance = min(10, relevance + 2)
            severity_context = "Critical severity indicates this is proven highly exploitable."
        elif severity_upper == 'HIGH':
            relevance = min(10, relevance + 1)
            severity_context = "High severity indicates proven exploitability."
        elif severity_upper == 'LOW':
            relevance = max(0, relevance - 1)
            severity_context = "Low severity suggests limited or difficult exploitation."
        else:
            severity_context = ""
        
        reason = (
            f"Relevance: {relevance}/10. This vulnerability is {context}. "
            f"Found {ps_matches} matches to public safety keywords in the CVE description and affected products. "
            f"{severity_context}"
        )
        
        return (relevance, reason)
    
    def _estimate_actor_sophistication(self, score: float, severity: str) -> Tuple[int, str]:
        """
        Estimate Actor Sophistication with reasoning.
        
        Returns:
            Tuple of (sophistication_score, reasoning_text)
        """
        severity_upper = severity.upper()
        
        if severity_upper == 'CRITICAL' or score >= 9.0:
            sophistication = 2
            reason = (
                f"Actor Sophistication: {sophistication}/5. Critical vulnerabilities are typically "
                f"simple to exploit once discovered - that's why they're critical. Even relatively "
                f"unsophisticated actors (script kiddies) can leverage these with readily available exploit code."
            )
        elif severity_upper == 'HIGH' or score >= 7.0:
            sophistication = 3
            reason = (
                f"Actor Sophistication: {sophistication}/5. High severity vulnerabilities usually "
                f"require moderate skill to exploit. Competent attackers can weaponize these, "
                f"but they're not quite as trivial as Critical ones."
            )
        elif severity_upper == 'MEDIUM' or score >= 4.0:
            sophistication = 4
            reason = (
                f"Actor Sophistication: {sophistication}/5. Medium severity suggests more complex "
                f"exploitation requirements. This likely needs skilled attackers with good understanding "
                f"of the target system."
            )
        else:
            sophistication = 5
            reason = (
                f"Actor Sophistication: {sophistication}/5. Low severity vulnerabilities often require "
                f"very sophisticated actors - either the exploitation is complex, or the impact is limited "
                f"enough that only targeted, patient attackers would bother."
            )
        
        return (sophistication, reason)
    
    def _is_systemic_threat(self, severity: str, affected_products: List[str]) -> Tuple[bool, str]:
        """
        Determine if this is a systemic threat with reasoning.
        
        Returns:
            Tuple of (is_systemic, reasoning_text)
        """
        severity_upper = severity.upper()
        if severity_upper not in ['CRITICAL', 'HIGH']:
            return (False, "Not systemic: Only Critical and High severity vulnerabilities are considered systemic threats.")
        
        # Check for widespread impact
        if len(affected_products) > 5:
            return (True, f"Systemic threat: {severity} severity AND affects {len(affected_products)} different products, indicating widespread impact across the ecosystem.")
        
        # Check for common infrastructure
        products_text = ' '.join(affected_products).lower()
        widespread_indicators = ['windows', 'linux', 'cisco', 'microsoft',
                                'apache', 'nginx', 'openssl', 'kernel']
        
        matches = [ind for ind in widespread_indicators if ind in products_text]
        if matches:
            return (True, f"Systemic threat: {severity} severity AND affects widely-deployed infrastructure ({', '.join(matches)}), indicating potential for widespread exploitation.")
        
        return (False, f"{severity} severity but limited to specific products without widespread deployment indicators. Not classified as systemic.")


# ========================================
# Convenience function
# ========================================
def score_cve_with_ecrospk(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Quick function to score a CVE with ECROSPK using default mapping."""
    mapper = CVEToECROSPKMapper()
    return mapper.score_cve(cve)


if __name__ == "__main__":
    # ========================================
    # Test the mapper with sample CVE data
    # ========================================
    print("Testing CVE to ECROSPK mapper with full reasoning...")
    print("=" * 80)
    
    # Create a realistic sample CVE
    sample_cve = {
        'id': 'CVE-2024-TEST',
        'title': 'Critical RCE in Motorola P25 Radio Systems',
        'description': 'A critical remote code execution vulnerability exists in Motorola P25 radio systems that allows unauthenticated attackers to execute arbitrary code via specially crafted network packets sent to the radio management interface. This affects emergency services radio networks and could allow attackers to disrupt first responder communications.',
        'published': None,
        'severity': 'CRITICAL',
        'score': 9.8,
        'affected_products': ['motorola p25', 'motorola astro 25'],
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2024-TEST',
        'months_old': 2.5,
        'cwe_ids': ['CWE-78'],  # OS Command Injection
        'source': 'NVD',
        'fetched_at': None
    }
    
    # Score it with full reasoning
    mapper = CVEToECROSPKMapper()
    result = mapper.score_cve(sample_cve)
    
    # Display results with reasoning
    print("\n" + "=" * 80)
    print("ECROSPK SCORING RESULT")
    print("=" * 80)
    print(f"\nCVE: {result['cve_metadata']['id']}")
    print(f"Title: {result['cve_metadata']['title']}")
    print(f"CVSS: {result['cve_metadata']['severity']} ({result['cve_metadata']['cvss_score']})")
    print(f"\nFINAL ECROSPK SCORE: {result['final_score']}/100 ({result['label']})")
    print(f"Investigate Now Flag: {result['investigate_now']}")
    
    print("\n" + "-" * 80)
    print("FACTOR BREAKDOWN WITH REASONING")
    print("-" * 80)
    
    # Display each factor with its reasoning
    for factor_name, explanation in result['reasoning'].items():
        print(f"\n{factor_name}:")
        print(f"  {explanation}")
    
    print("\n" + "-" * 80)
    print("NUMERIC FACTOR VALUES")
    print("-" * 80)
    for factor, value in result['factors'].items():
        print(f"  {factor}: {value}")
    
    print("\n" + "-" * 80)
    print("KNOCKDOWN (REDUCTION FACTORS)")
    print("-" * 80)
    for key, value in result['knockdown'].items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 80)
    print("Mapper test complete!")
    print("=" * 80)
