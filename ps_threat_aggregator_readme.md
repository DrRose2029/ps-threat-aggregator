# PS-Threat-Aggregator

**Public Safety Threat Intelligence Aggregation with ECROSPK Confidence Scoring**

An automated threat intelligence platform that fetches vulnerabilities from NIST's National Vulnerability Database, filters them for public safety infrastructure relevance, and scores them using a custom confidence framework (ECROSPK) to prioritize analyst investigation efforts.

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [ECROSPK Framework](#ecrospk-framework)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Future Enhancements](#future-enhancements)

---

## Overview

Security Operations Centers (SOCs) and emergency services agencies face a critical challenge: **thousands of new CVEs are published monthly, but only a small percentage are relevant to their specific infrastructure**. Analysts waste valuable time manually triaging threats that don't apply to their environment.

PS-Threat-Aggregator solves this by:

1. **Automatically fetching** recent vulnerabilities from authoritative sources (NVD)
2. **Intelligently filtering** for public safety infrastructure (911 systems, dispatch, radio communications)
3. **Scoring threats** using ECROSPK, a custom confidence framework that quantifies how much you should trust the threat assessment
4. **Prioritizing** threats so analysts investigate high-confidence items first

**Key Innovation:** While CVSS scores tell you *how bad* a vulnerability is technically, ECROSPK tells you *how confident you should be* that this vulnerability matters to your specific organization.

---

## The Problem

### The CVE Noise Problem

- **~8,000 CVEs** published annually to NVD
- Most organizations care about **<5%** of published CVEs
- Manual triage is **slow, inconsistent, and error-prone**
- Generic threat intelligence feeds provide **high volume but low relevance**

### The Confidence Problem

Not all threat intelligence is equally trustworthy. A CVE might score 9.8 (Critical) on CVSS, but if:

- The affected product isn't deployed in your environment
- You lack monitoring tools to detect exploitation
- The vulnerability description is vague and hard to test
- Multiple sources haven't independently confirmed it

...then should you spend scarce analyst time investigating it? **Probably not.**

Traditional approaches don't quantify confidence or relevance - they just dump all threats on analysts and hope they figure it out.

---

## The Solution

PS-Threat-Aggregator implements a multi-stage pipeline:

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  NVD API Fetch  │ -->  │  Public Safety   │ -->  │  ECROSPK Score  │
│  (100s of CVEs) │      │  Filter (5-10)   │      │  & Prioritize   │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                                                              │
                                                              v
                                                    ┌──────────────────┐
                                                    │  Analyst Review  │
                                                    │  (Top 3-5 first) │
                                                    └──────────────────┘
```

### Stage 1: Intelligent Ingestion

- Queries NIST NVD API with public safety keywords
- Rate-limited requests with retry logic
- Parses CVE metadata (severity, CWE, affected products, etc.)

### Stage 2: Context-Aware Filtering

- **Keyword matching** for initial relevance (dispatch, CAD, radio, P25, TETERA, etc.)
- **Exclusion patterns** to remove false positives (e-commerce, gaming, educational software)
- **Override logic** to keep CVEs that match exclusions but have strong public safety signals

### Stage 3: ECROSPK Confidence Scoring

Maps each CVE to 8 confidence factors, calculates a 0-100 score, and labels threats as High/Medium/Low confidence for investigation prioritization.

---

## ECROSPK Framework

**ECROSPK** (Evidence-Corroboration-Recency-Observability-Specificity-Proof-Actor Sophistication-Knockdown) is a custom threat intelligence confidence scoring framework inspired by the Admiralty Code but adapted for automated CVE analysis.

### The 8 Factors

| Factor | Weight | What It Measures |
|--------|--------|------------------|
| **E** - Evidence | 25 pts | Source authority (NVD = 15) + Proof quality (CVSS severity) |
| **C** - Corroboration | 15 pts | Multiple independent sources confirming the threat |
| **R** - Recency | 10 pts | How recent the CVE is (decays 0.5 pts/month) |
| **O** - Observability | 20 pts | Can you detect this threat with your current tools? |
| **S** - Specificity | 10 pts | How specific are the indicators? (CWE classification) |
| **P** - Proof/Relevance | 10 pts | Is this relevant to your environment? Proven exploitable? |
| **AS** - Actor Sophistication | 5 pts | How sophisticated must attackers be? (Inverse of severity) |
| **K** - Knockdown | -5 pts | Reduction for mitigation (patches deployed) or false positives |

**Systemic Flag:** Critical/High severity CVEs affecting widely-deployed infrastructure get flagged for immediate investigation regardless of score.

### Score Interpretation

- **75-100 (High):** Investigate immediately. High confidence this threat matters to you.
- **50-74 (Medium):** Review when resources allow. Moderate confidence of relevance.
- **0-49 (Low):** Deprioritize unless other context elevates importance.

### Why ECROSPK Matters

Traditional scoring (CVSS, EPSS) focuses on technical severity or exploitation probability. ECROSPK focuses on **organizational confidence**:

- **Observability** recognizes that a threat you can't detect is lower priority than one you can
- **Relevance** filters out CVEs affecting products you don't use
- **Recency** acknowledges that older CVEs are often patched already
- **Specificity** values well-characterized threats over vague ones

This produces a **prioritized threat queue** aligned with analyst investigation capacity.

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection (for NVD API access)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/ps-threat-aggregator.git
cd ps-threat-aggregator

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Get NVD API key for higher rate limits
# Visit: https://nvd.nist.gov/developers/request-an-api-key
# Without key: 5 requests per 30 seconds
# With key: 50 requests per 30 seconds
```

### Quick Test

```bash
# Run the aggregator
python3 -m src.aggregator

# You should see:
# - CVE fetch from NVD
# - Filtering stats
# - ECROSPK scoring
# - Prioritized threat list
```

---

## Usage

### Basic Usage

```python
from src.aggregator import run_daily_aggregation

# Run aggregation with defaults
threats = run_daily_aggregation(
    days_back=30,           # Last 30 days of CVEs
    min_confidence=50,      # Medium+ confidence threshold
    display=True,           # Show terminal output
    export=False            # Don't export to JSON
)

# Each threat contains:
# - final_score: ECROSPK confidence score (0-100)
# - label: "High", "Medium", or "Low"
# - reasoning: Detailed explanations for each factor
# - cve_metadata: ID, severity, description, link
```

### Advanced Usage

```python
from src.aggregator import PublicSafetyThreatAggregator

# Initialize with NVD API key
aggregator = PublicSafetyThreatAggregator(nvd_api_key="your-key-here")

# Run with custom parameters
threats = aggregator.aggregate_threats(
    days_back=60,
    max_cves=200,
    min_confidence=75,      # Only High confidence threats
    debug_filtering=True    # See filtering decisions
)

# Display results
aggregator.display_threat_summary(threats, max_display=5)

# Export to JSON
aggregator.export_threats_json(threats, filename="high_priority_threats.json")
```

### Customizing for Your Environment

The system is designed to be easily configured for different operational contexts:

**1. Adjust keywords** (in `src/aggregator.py`):

```python
def _get_public_safety_keywords(self):
    return [
        # Add your specific systems
        'your-cad-system', 'your-radio-vendor',
        # Keep standards
        'p25', 'tetra', '911', ...
    ]
```

**2. Modify exclusion patterns** (in `src/aggregator.py`):

```python
exclusion_patterns = {
    'retail': ['shop', 'ecommerce', ...],
    # Add categories specific to your noise
    'social_media': ['facebook', 'twitter', ...],
}
```

**3. Adjust ECROSPK weights** (in `src/scoring/ecrospk.py`):

```python
# If your org has excellent observability tools,
# you might weight Evidence higher than Observability
```

---

## Configuration

### Environment Variables

```bash
# Optional: NVD API Key
export NVD_API_KEY="your-key-here"

# Optional: Adjust rate limiting
export NVD_RATE_LIMIT=5  # requests per 30 seconds
```

### Configuration Files

Currently uses code-based configuration. Future versions will support YAML/JSON config files for:

- Keyword lists
- Exclusion patterns
- ECROSPK factor weights
- Data source configurations

---

## Architecture

### Component Overview

```
ps-threat-aggregator/
│
├── src/
│   ├── ingest/
│   │   └── nvd_api.py          # NVD API client with rate limiting
│   │
│   ├── scoring/
│   │   ├── ecrospk.py          # ECROSPK confidence scoring engine
│   │   └── cve_mapper.py       # CVE → ECROSPK factor mapper
│   │
│   └── aggregator.py           # Main orchestration pipeline
│
├── tests/                       # Unit tests
├── data/                        # Persistent storage (future)
└── requirements.txt
```

### Data Flow

1. **NVD API Ingester** fetches recent CVEs, respecting rate limits
2. **Keyword Filter** does initial relevance screening
3. **Exclusion Filter** removes obvious false positives
4. **CVE Mapper** translates CVE metadata to ECROSPK factors using domain heuristics
5. **ECROSPK Scorer** calculates confidence scores with full reasoning
6. **Aggregator** sorts by confidence and presents prioritized threat list

### Design Principles

- **Stateless execution:** Each run is independent for easy scheduling
- **Vendor-neutral:** Focuses on standards (P25, TETRA) not proprietary systems
- **Explainable:** Every score includes detailed reasoning for each factor
- **Configurable:** Easy to adapt for different environments and priorities
- **Extensible:** Modular design supports adding new data sources or scoring factors

---

## Project Structure

```
ps-threat-aggregator/
│
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── LICENSE                      # MIT License
│
├── src/
│   ├── __init__.py
│   │
│   ├── ingest/
│   │   ├── __init__.py
│   │   └── nvd_api.py          # NVD API client
│   │
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── ecrospk.py          # Scoring framework
│   │   └── cve_mapper.py       # CVE to ECROSPK mapper
│   │
│   └── aggregator.py           # Main pipeline
│
├── tests/
│   ├── __init__.py
│   ├── test_ecrospk.py         # Scoring tests
│   ├── test_mapper.py          # Mapper tests
│   └── test_aggregator.py      # Integration tests
│
└── data/                        # Future: persistent storage
    └── threats.db              # SQLite database
```

---

## Future Enhancements

### Planned Features

- **Multiple data sources:** AlienVault OTX, Abuse.ch, VirusTotal
- **Database persistence:** SQLite for historical tracking
- **HTML report generation:** Professional threat briefings
- **Automated scheduling:** Cron job / systemd service
- **Email/Slack notifications:** Alert on high-confidence threats
- **Trending analysis:** Track vulnerability patterns over time
- **Asset inventory integration:** Cross-reference with deployed systems
- **YAML configuration:** Externalize keywords and weights

### Known Limitations

- **Single data source:** Currently only NVD (adding others is straightforward)
- **English-only:** Keyword matching assumes English CVE descriptions
- **No authentication:** Future versions could integrate with org SSO
- **Limited historical data:** Only fetches recent CVEs (no full historical scan)

---

## Contributing

Contributions are welcome! Areas of particular interest:

1. **Additional data sources:** Integrations with other threat feeds
2. **Improved filtering:** Better false positive detection
3. **Testing:** Expanded unit and integration test coverage
4. **Documentation:** Usage examples, tutorials, architecture diagrams
5. **Performance:** Optimization for large-scale deployments

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/ps-threat-aggregator.git
cd ps-threat-aggregator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python3 -m pytest tests/

# Run with debug mode
python3 -m src.aggregator --debug
```

---

## License

MIT License - see LICENSE file for details

---

## Acknowledgments

- **NIST NVD:** For providing comprehensive vulnerability data via public API
- **MITRE CWE:** For vulnerability classification system
- **Admiralty Code:** Inspiration for confidence-based threat intelligence scoring

---

## Contact

Built as part of independent security research focused on operational threat intelligence for critical infrastructure.

For questions or collaboration opportunities, reach out via GitHub Issues.

---

**Disclaimer:** This tool is for research and operational security purposes. Always validate threats through multiple sources before taking action. The author assumes no liability for decisions made based on this tool's output.