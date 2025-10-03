"""
ECROSPK v0.3 - Threat Intelligence Confidence Scoring
Refactored for use as a Python module

This module implements the ECROSPK framework for scoring cyber threat intelligence
based on seven factors: Evidence, Clarity, Recency, Observability, Signal, Proof, and Knockdown.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ECROSPKConfig:
    """
    Configuration for ECROSPK scoring weights and thresholds.
    
    Using a dataclass here allows us to easily modify scoring parameters
    without changing the core logic. This makes the framework flexible
    for different organizations or use cases.
    """
    version: str = "0.3"
    
    # Maximum values per factor - these define the "weight" each factor has
    # in the final score. Higher max = more influence on total confidence.
    max_E: int = 25   # Evidence gets highest weight - foundation of confidence
    max_C: int = 15   # Corroboration is important but secondary to evidence
    max_R: int = 10   # Recency matters but shouldn't dominate
    max_O: int = 20   # Observability is critical - can we even see this threat?
    max_S: int = 10   # Signal specificity
    max_P: int = 10   # Proof/relevance to our environment
    max_AS: int = 5   # Actor sophistication - minor factor
    
    # Thresholds for confidence labels (out of 100)
    # These determine when we call something High/Medium/Low confidence
    high_threshold: int = 75    # 75+ = High confidence, immediate action
    medium_threshold: int = 50  # 50-74 = Medium confidence, investigate soon
                               # Below 50 = Low confidence, monitor/deprioritize
    
    # Recency decay parameters
    # Threats get less relevant over time, but we apply a floor for systemic threats
    recency_decay_per_month: float = 0.5  # Lose 0.5 points per month of age
    systemic_recency_floor: int = 3       # Nation-state threats stay relevant longer
    
    # Governance thresholds - special rules that override normal scoring
    low_observability_cutoff: int = 5           # If O ≤ 5, we can't see the threat well
    high_evidence_corroboration: int = 30       # If E+C ≥ 30, evidence is very strong


class ECROSPKScorer:
    """
    Main scoring engine for ECROSPK methodology.
    
    This class handles the actual scoring logic. It takes raw threat data,
    applies the ECROSPK factors, and returns a structured confidence score.
    """
    
    def __init__(self, config: Optional[ECROSPKConfig] = None):
        """
        Initialize the scorer with a configuration.
        
        Args:
            config: Optional custom configuration. If None, uses defaults.
        
        This allows different organizations to use different weights/thresholds
        while using the same core scoring logic.
        """
        self.config = config or ECROSPKConfig()
    
    def score_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a threat using ECROSPK factors.
        
        This is the main entry point. It takes raw threat data and returns
        a complete breakdown of the confidence score.
        
        Args:
            threat_data: Dictionary containing threat information
                Required keys:
                - evidence_authority (0-15): How credible is the source?
                - evidence_proof_quality (0-10): How solid is the proof?
                - corroboration (0-15): How many independent sources confirm this?
                - recency_months (float): How many months since last observed?
                - observability_availability (0-10): Do we have the logs/sensors to see this?
                - observability_clarity (0-10): How clear would the signals be?
                - specificity (0-10): How specific are the indicators?
                - proof_relevance (0-10): How relevant to our environment?
                - actor_sophistication (0-5): How sophisticated is the threat actor?
                
                Optional keys:
                - systemic (bool): Is this a systemic/nation-state threat?
                - counter_proof (0 to -20): Evidence that contradicts the threat
                - patch_coverage (0.0 to 1.0): What fraction is mitigated?
        
        Returns:
            Dictionary with complete score breakdown including final score,
            label (High/Medium/Low), all factor values, and whether immediate
            investigation is warranted.
        """
        
        # ========================================
        # EVIDENCE (E): Foundation of confidence
        # ========================================
        # Evidence has two components: authority of source + quality of proof
        # We clamp to valid ranges to prevent bad data from breaking scoring
        E_auth = self._clamp(threat_data.get('evidence_authority', 0), 0, 15)
        E_proof = self._clamp(threat_data.get('evidence_proof_quality', 0), 0, 10)
        
        # Sum them but cap at max_E (25) to prevent one factor from dominating
        E_total = min(E_auth + E_proof, self.config.max_E)
        
        # ========================================
        # CORROBORATION (C): Multiple sources
        # ========================================
        # How many independent sources confirm this threat?
        # More sources = higher confidence it's real
        C = self._clamp(threat_data.get('corroboration', 0), 0, self.config.max_C)
        
        # ========================================
        # RECENCY (R): Time matters
        # ========================================
        # Threats decay in relevance over time, but systemic threats
        # maintain a floor if evidence is strong
        recency_months = threat_data.get('recency_months', 0)
        systemic = threat_data.get('systemic', False)
        R = self._compute_recency(recency_months, systemic, E_total, C)
        
        # ========================================
        # OBSERVABILITY (O): Can we see it?
        # ========================================
        # Two components: Do we have the data sources (availability)?
        # And would the signals be clear (clarity)?
        O_avail = self._clamp(threat_data.get('observability_availability', 0), 0, 10)
        O_clarity = self._clamp(threat_data.get('observability_clarity', 0), 0, 10)
        O = min(O_avail + O_clarity, self.config.max_O)
        
        # ========================================
        # SIGNAL (S): Specificity of indicators
        # ========================================
        # How specific are the detection signatures?
        # High = unique indicators, low false positives
        S = self._clamp(threat_data.get('specificity', 0), 0, self.config.max_S)
        
        # ========================================
        # PROOF (P): Relevance and demonstration
        # ========================================
        # Is this threat relevant to our environment?
        # Has it been proven to work in similar contexts?
        P = self._clamp(threat_data.get('proof_relevance', 0), 0, self.config.max_P)
        
        # ========================================
        # ACTOR SOPHISTICATION (AS): Minor factor
        # ========================================
        # More sophisticated actors = slightly higher confidence they'll succeed
        AS = self._clamp(threat_data.get('actor_sophistication', 0), 0, self.config.max_AS)
        
        # ========================================
        # KNOCKDOWN (K): Factors that reduce confidence
        # ========================================
        # Two types of knockdown:
        # 1. Counter-proof: Evidence that contradicts the threat (should be negative)
        K_counter = min(0, threat_data.get('counter_proof', 0))
        
        # 2. Mitigation: If we've patched/mitigated, threat is less relevant
        #    patch_coverage of 1.0 (100% patched) = full -15 point reduction
        #    patch_coverage of 0.5 (50% patched) = -7.5 point reduction
        patch_coverage = self._clamp(threat_data.get('patch_coverage', 0), 0, 1.0)
        K_mitigation = -15 * patch_coverage
        
        # Total knockdown is sum of both negative factors
        K_total = K_counter + K_mitigation
        
        # ========================================
        # CALCULATE FINAL SCORE
        # ========================================
        # Subtotal: Sum all positive factors
        subtotal = E_total + C + R + O + S + P + AS
        
        # Apply knockdown (negative adjustment)
        final_raw = subtotal + K_total  # K_total is negative, so this subtracts
        
        # Normalize to 0-100 scale
        # We divide by the sum of all max values to get a percentage
        normalization_denominator = (self.config.max_E + self.config.max_C + 
                                     self.config.max_R + self.config.max_O + 
                                     self.config.max_S + self.config.max_P + 
                                     self.config.max_AS)  # This equals 95
        
        # Convert raw score (which could be -15 to 95) into 0-100 scale
        final_score = self._clamp((final_raw / normalization_denominator) * 100, 0, 100)
        
        # ========================================
        # DETERMINE CONFIDENCE LABEL
        # ========================================
        # Map numeric score to human-readable label
        if final_score >= self.config.high_threshold:
            label = "High"      # 75-100: Take immediate action
        elif final_score >= self.config.medium_threshold:
            label = "Medium"    # 50-74: Investigate soon
        else:
            label = "Low"       # 0-49: Monitor/deprioritize
        
        # ========================================
        # GOVERNANCE OVERRIDE
        # ========================================
        # Special rule: If evidence is very strong (E+C ≥ 30) BUT we have
        # low observability (O ≤ 5), flag for immediate investigation.
        # This catches "we know it's real but we're blind to it" scenarios.
        investigate_now = (E_total + C >= self.config.high_evidence_corroboration and 
                          O <= self.config.low_observability_cutoff)
        
        # ========================================
        # RETURN COMPLETE BREAKDOWN
        # ========================================
        # Return everything for transparency and debugging
        return {
            'version': self.config.version,
            'final_score': round(final_score, 1),
            'label': label,
            'investigate_now': investigate_now,
            'factors': {
                'E': round(E_total, 2),
                'C': round(C, 2),
                'R': round(R, 2),
                'O': round(O, 2),
                'S': round(S, 2),
                'P': round(P, 2),
                'AS': round(AS, 2)
            },
            'knockdown': {
                'K_total': round(K_total, 2),
                'K_counter': round(K_counter, 2),
                'K_mitigation': round(K_mitigation, 2)
            },
            'subtotal': round(subtotal, 2),
            'final_raw': round(final_raw, 2)
        }
    
    def _clamp(self, value: float, min_val: float, max_val: float) -> float:
        """
        Clamp value between min and max.
        
        This is a utility function to ensure values stay in valid ranges.
        For example, if someone passes evidence_authority=20 but max is 15,
        this returns 15. If they pass -5, it returns 0.
        
        Args:
            value: The value to clamp
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            Value constrained to [min_val, max_val]
        """
        return max(min_val, min(max_val, value))
    
    def _compute_recency(self, months: float, systemic: bool, 
                        E_total: float, C_total: float) -> float:
        """
        Compute recency score with decay and systemic floor.
        
        Recency starts at 10 points for brand new threats (0 months old).
        It decays by 0.5 points per month: after 12 months, raw score is 4.
        
        However, systemic threats (nation-state campaigns) maintain relevance
        longer. If evidence is strong (E≥20 AND C≥12) and it's marked systemic,
        we apply a floor of 3 points even if it's years old.
        
        Args:
            months: How many months since the threat was last observed
            systemic: Is this a systemic/nation-state threat?
            E_total: Total evidence score (to check if floor applies)
            C_total: Total corroboration score (to check if floor applies)
            
        Returns:
            Recency score (0-10)
        """
        # Start with linear decay: 10 - (0.5 * months)
        # Example: 6 months old = 10 - 3 = 7 points
        raw = max(0, 10 - self.config.recency_decay_per_month * months)
        
        # Systemic floor: If this is a nation-state threat with strong evidence,
        # don't let recency drop below 3 even if it's old.
        # Rationale: Nation-state campaigns remain relevant for years
        if systemic and (E_total >= 20 and C_total >= 12):
            raw = max(raw, self.config.systemic_recency_floor)
        
        # Clamp to valid range just in case
        return self._clamp(raw, 0, self.config.max_R)


# ========================================
# CONVENIENCE FUNCTION
# ========================================
def score_threat(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Quick score a threat with default configuration.
    
    This is a shortcut function for one-off scoring without needing
    to instantiate the ECROSPKScorer class explicitly.
    
    Args:
        threat_data: Threat information dictionary
        
    Returns:
        Complete score breakdown
    """
    scorer = ECROSPKScorer()
    return scorer.score_threat(threat_data)
