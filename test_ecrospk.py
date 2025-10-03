#!/usr/bin/env python3
"""
Quick test of ECROSPK scoring module

This test simulates scoring a threat similar to Log4Shell to verify
the scoring logic works correctly.
"""

from src.scoring.ecrospk import ECROSPKScorer

# ========================================
# TEST DATA: Log4Shell-like scenario
# ========================================
# We're simulating a well-known, well-evidenced threat (like Log4Shell was)
# but assuming it's now older (45 months) and partially patched (70%)
test_threat = {
    # EVIDENCE: Maximum credibility (CISA alert) + strong proof (working exploits)
    'evidence_authority': 15,        # Government alert = maximum authority
    'evidence_proof_quality': 10,    # Live exploits in the wild = maximum proof
    
    # CORROBORATION: Multiple independent sources confirmed
    'corroboration': 15,             # Dozens of vendors/researchers agreed
    
    # RECENCY: Old threat now (45 months = nearly 4 years)
    'recency_months': 45,            # Would normally decay to near-zero
    
    # OBSERVABILITY: Excellent visibility (we have logs and clear signatures)
    'observability_availability': 10,  # We have all necessary logs
    'observability_clarity': 10,       # Signals are very clear (JNDI patterns)
    
    # SIGNAL: Very specific indicators
    'specificity': 10,               # Unique patterns, low false positives
    
    # PROOF/RELEVANCE: Highly relevant if you use Java
    'proof_relevance': 8,            # Affects most organizations with Java apps
    
    # ACTOR SOPHISTICATION: Various actors, from script kiddies to nation-states
    'actor_sophistication': 4,       # Medium-high sophistication
    
    # SYSTEMIC: Yes - this was/is a systemic threat
    'systemic': True,                # Systemic flag applies recency floor
    
    # KNOCKDOWN: No counter-proof, but 70% patched
    'counter_proof': 0,              # No evidence this is a false alarm
    'patch_coverage': 0.7            # 70% of systems are patched
}

# ========================================
# RUN THE SCORER
# ========================================
# Create a scorer instance with default configuration
scorer = ECROSPKScorer()

# Score the test threat
result = scorer.score_threat(test_threat)

# ========================================
# DISPLAY RESULTS
# ========================================
print("ECROSPK Test Score:")
print(f"  Final Score: {result['final_score']}/100 ({result['label']})")
print(f"  Investigate Now: {result['investigate_now']}")
print(f"\n  Factor Breakdown:")
print(f"    Evidence (E):         {result['factors']['E']}/25")
print(f"    Corroboration (C):    {result['factors']['C']}/15")
print(f"    Recency (R):          {result['factors']['R']}/10")
print(f"    Observability (O):    {result['factors']['O']}/20")
print(f"    Specificity (S):      {result['factors']['S']}/10")
print(f"    Proof/Relevance (P):  {result['factors']['P']}/10")
print(f"    Actor Soph. (AS):     {result['factors']['AS']}/5")
print(f"\n  Knockdown:")
print(f"    Counter-proof:        {result['knockdown']['K_counter']}")
print(f"    Mitigation:           {result['knockdown']['K_mitigation']}")
print(f"    Total knockdown:      {result['knockdown']['K_total']}")
print(f"\n  Subtotal (before knockdown): {result['subtotal']}")
print(f"  Final Raw (after knockdown): {result['final_raw']}")

# ========================================
# INTERPRETATION
# ========================================
print("\n  Interpretation:")
print(f"  This threat scored {result['label']} confidence, meaning:")
if result['label'] == 'High':
    print("  → Take immediate action, high priority")
elif result['label'] == 'Medium':
    print("  → Investigate soon, moderate priority")
else:
    print("  → Monitor or deprioritize, low priority")

if result['investigate_now']:
    print("  ⚠️  GOVERNANCE OVERRIDE: Investigate immediately despite score!")
    print("     (Strong evidence but low observability - we might be blind to this)")
