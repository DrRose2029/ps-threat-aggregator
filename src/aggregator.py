"""
PS-Threat-Aggregator: Main Orchestration Module
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import re

from src.ingest.nvd_api import NVDAPIIngester
from src.scoring.cve_mapper import CVEToECROSPKMapper


class PublicSafetyThreatAggregator:
    """Main orchestrator for the threat intelligence aggregation pipeline."""
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """Initialize the aggregator with its components."""
        self.nvd_ingester = NVDAPIIngester(api_key=nvd_api_key)
        self.mapper = CVEToECROSPKMapper()
        self.last_run_time: Optional[datetime] = None
        self.last_run_stats: Dict[str, Any] = {}
    
    def aggregate_threats(self,
                         days_back: int = 30,
                         max_cves: int = 100,
                         min_confidence: int = 50,
                         debug_filtering: bool = False) -> List[Dict[str, Any]]:
        """
        Run the complete threat aggregation pipeline.
        
        Args:
            days_back: How many days of CVEs to fetch
            max_cves: Maximum CVEs to retrieve from NVD
            min_confidence: Minimum ECROSPK score threshold
            debug_filtering: If True, print detailed filtering decisions
        """
        print("=" * 80)
        print("PUBLIC SAFETY THREAT AGGREGATOR - ECROSPK v0.3")
        print("=" * 80)
        print(f"\nStarting aggregation run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Parameters: {days_back} days back, max {max_cves} CVEs, min confidence {min_confidence}")
        
        stats = {
            'start_time': datetime.now(),
            'days_back': days_back,
            'max_cves': max_cves,
            'min_confidence': min_confidence
        }
        
        print(f"\n[Step 1/5] Fetching CVEs from NVD API...")
        
        try:
            cves = self.nvd_ingester.fetch_recent_cves(
                days_back=days_back,
                keywords=self._get_public_safety_keywords(),
                max_results=max_cves
            )
            
            stats['cves_fetched'] = len(cves)
            print(f"  ✓ Retrieved {len(cves)} CVEs matching public safety keywords")
            
        except Exception as e:
            print(f"  ✗ Failed to fetch CVEs from NVD: {e}")
            raise
        
        print(f"\n[Step 1.5/5] Applying relevance filter to remove false positives...")
        
        filtered_cves = self._filter_balanced_public_safety(cves, debug=debug_filtering)
        
        stats['cves_after_strict_filter'] = len(filtered_cves)
        print(f"  ✓ {len(filtered_cves)} CVEs remain after filtering")
        if len(cves) > len(filtered_cves):
            print(f"  (Filtered out {len(cves) - len(filtered_cves)} false positives)")
        
        print(f"\n[Step 2/5] Scoring {len(filtered_cves)} CVEs with ECROSPK framework...")
        
        scored_threats = []
        scoring_errors = 0
        
        for i, cve in enumerate(filtered_cves, 1):
            try:
                scored = self.mapper.score_cve(cve)
                scored['processed_at'] = datetime.now().isoformat()
                scored_threats.append(scored)
                
                if i % 10 == 0:
                    print(f"  Scored {i}/{len(filtered_cves)} CVEs...")
                    
            except Exception as e:
                scoring_errors += 1
                print(f"  Warning: Failed to score {cve.get('id', 'unknown')}: {e}")
                continue
        
        stats['cves_scored'] = len(scored_threats)
        stats['scoring_errors'] = scoring_errors
        print(f"  ✓ Successfully scored {len(scored_threats)} CVEs ({scoring_errors} errors)")
        
        print(f"\n[Step 3/5] Filtering for confidence ≥ {min_confidence}...")
        
        filtered_threats = [
            threat for threat in scored_threats 
            if threat['final_score'] >= min_confidence
        ]
        
        stats['threats_above_threshold'] = len(filtered_threats)
        print(f"  ✓ {len(filtered_threats)} threats meet confidence threshold")
        
        print(f"\n[Step 4/5] Prioritizing by confidence score...")
        
        prioritized_threats = sorted(
            filtered_threats,
            key=lambda x: x['final_score'],
            reverse=True
        )
        
        print(f"  ✓ Threats sorted by priority (highest confidence first)")
        
        print(f"\n[Step 5/5] Generating summary statistics...")
        
        high_count = sum(1 for t in prioritized_threats if t['label'] == 'High')
        medium_count = sum(1 for t in prioritized_threats if t['label'] == 'Medium')
        low_count = sum(1 for t in prioritized_threats if t['label'] == 'Low')
        investigate_now_count = sum(1 for t in prioritized_threats if t['investigate_now'])
        
        stats['high_confidence'] = high_count
        stats['medium_confidence'] = medium_count
        stats['low_confidence'] = low_count
        stats['investigate_now_flags'] = investigate_now_count
        stats['end_time'] = datetime.now()
        stats['duration_seconds'] = (stats['end_time'] - stats['start_time']).total_seconds()
        
        self.last_run_time = datetime.now()
        self.last_run_stats = stats
        
        print(f"\n{'=' * 80}")
        print("AGGREGATION COMPLETE")
        print(f"{'=' * 80}")
        print(f"\nProcessing Summary:")
        print(f"  Total CVEs fetched: {stats['cves_fetched']}")
        print(f"  After relevance filter: {stats['cves_after_strict_filter']}")
        print(f"  Successfully scored: {stats['cves_scored']}")
        print(f"  Above threshold ({min_confidence}): {stats['threats_above_threshold']}")
        print(f"\nThreat Breakdown:")
        print(f"  High Confidence (≥75):     {high_count} threats")
        print(f"  Medium Confidence (50-74): {medium_count} threats")
        print(f"  Low Confidence (<50):      {low_count} threats")
        
        if investigate_now_count > 0:
            print(f"\n  ⚠️  {investigate_now_count} threats flagged for immediate investigation")
            print(f"     (High evidence + Low observability = potential blind spot)")
        
        print(f"\nProcessing time: {stats['duration_seconds']:.1f} seconds")
        print(f"{'=' * 80}\n")
        
        return prioritized_threats
    
    def display_threat_summary(self, threats: List[Dict[str, Any]], max_display: int = 10):
        """Display a human-readable summary of prioritized threats."""
        if not threats:
            print("\nNo threats found above confidence threshold.")
            print("The threat landscape is quiet or your filters/thresholds may need adjustment.")
            return
        
        print("\n" + "=" * 80)
        print(f"TOP {min(max_display, len(threats))} PRIORITY THREATS")
        print("=" * 80)
        
        for i, threat in enumerate(threats[:max_display], 1):
            cve_meta = threat['cve_metadata']
            score = threat['final_score']
            label = threat['label']
            investigate_now = threat['investigate_now']
            
            print(f"\n{'─' * 80}")
            print(f"#{i} | {cve_meta['id']} | ECROSPK: {score}/100 ({label})")
            
            if investigate_now:
                print("     ⚠️  INVESTIGATE NOW FLAG SET - Potential blind spot")
            
            print(f"{'─' * 80}")
            
            print(f"Title: {cve_meta['title']}")
            print(f"CVSS: {cve_meta['severity']} ({cve_meta['cvss_score']})")
            
            if cve_meta.get('affected_products'):
                products = ', '.join(cve_meta['affected_products'][:3])
                if len(cve_meta['affected_products']) > 3:
                    products += f" (and {len(cve_meta['affected_products']) - 3} more)"
                print(f"Affects: {products}")
            
            print(f"\nKey Assessment:")
            
            reasoning = threat.get('reasoning', {})
            
            if 'Observability' in reasoning:
                obs_text = reasoning['Observability']
                obs_summary = self._extract_summary(obs_text, max_chars=150)
                print(f"  • Observability: {obs_summary}")
            
            if 'Proof_Relevance' in reasoning:
                rel_text = reasoning['Proof_Relevance']
                rel_summary = self._extract_summary(rel_text, max_chars=150)
                print(f"  • Relevance: {rel_summary}")
            
            if 'Recency' in reasoning:
                rec_text = reasoning['Recency']
                rec_summary = self._extract_summary(rec_text, max_chars=200)
                print(f"  • Recency: {rec_summary}")
            
            print(f"\nFull details: {cve_meta['link']}")
        
        if len(threats) > max_display:
            remaining = len(threats) - max_display
            print(f"\n{'=' * 80}")
            print(f"... and {remaining} more threats")
            print(f"Run with max_display={len(threats)} to see all threats")
            print(f"{'=' * 80}")
    
    def _extract_summary(self, text: str, max_chars: int = 150) -> str:
        """Extract a summary from reasoning text without breaking on decimal points."""
        sentence_pattern = r'\.(?=\s+[A-Z]|\s*$)'
        match = re.search(sentence_pattern, text)
        
        if match and match.start() < max_chars:
            return text[:match.start() + 1].strip()
        else:
            if len(text) <= max_chars:
                return text.strip()
            
            truncated = text[:max_chars]
            last_space = truncated.rfind(' ')
            if last_space > max_chars * 0.8:
                return truncated[:last_space].strip() + "..."
            else:
                return truncated.strip() + "..."
    
    def export_threats_json(self, threats: List[Dict[str, Any]], filename: str = "threats.json"):
        """Export scored threats to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(threats, f, indent=2, default=str)
            
            print(f"\n✓ Exported {len(threats)} threats to {filename}")
            print(f"  File size: {len(json.dumps(threats, default=str)) / 1024:.1f} KB")
            
        except Exception as e:
            print(f"✗ Failed to export threats: {e}")
    
    def _get_public_safety_keywords(self) -> List[str]:
        """Get the list of keywords for public safety filtering."""
        return [
            'emergency', '911', 'e911', 'ng911',
            'ambulance', 'ems', 'fire', 'police',
            'radio', 'p25', 'tetra', 'dmr', 'apco',
            'two-way radio', 'land mobile radio', 'lmr',
            'dispatch', 'cad', 'computer aided dispatch',
            'public safety', 'first responder', 'psap',
            'emergency operations', 'incident command',
            'alert', 'warning', 'notification',
            'siren', 'mass notification', 'emergency alert',
            'emergency broadcast'
        ]
    
    def _filter_balanced_public_safety(self, cves: List[Dict[str, Any]], debug: bool = False) -> List[Dict[str, Any]]:
        """
        Apply balanced filtering that removes obvious false positives.
        
        Args:
            cves: List of CVEs to filter
            debug: If True, print detailed filtering decisions
        """
        filtered = []
        
        # More comprehensive exclusion patterns
        exclusion_patterns = {
            'education': [
                'educar', 'school management', 'student information', 
                'learning management', 'classroom', 'educational',
                'i-educar', 'portabilis'
            ],
            'retail': [
                'shop', 'shopping', 'e-commerce', 'ecommerce', 'retail', 
                'storefront', 'webshop', 'web shop', 'online store',
                'wx-shop', 'wxshop', 'cart', 'checkout', 'payment gateway',
                'woocommerce', 'magento', 'shopify'
            ],
            'entertainment': [
                'game', 'gaming', 'entertainment', 'media player', 'video player'
            ],
            'publishing': [
                'blog', 'wordpress plugin', 'content management system', 'cms',
                'drupal', 'joomla'
            ],
        }
        
        # Strong public safety indicators that override exclusions
        high_confidence_indicators = [
            'p25', 'apco', 'tetra', 'psap', 'e911', 'ng911',
            '911 system', 'emergency services', 'first responder',
            'emergency dispatch', 'emergency alert system',
            'emergency operations', 'incident command',
            'public safety answering point', 'emergency broadcast'
        ]
        
        if debug:
            print("\n  DEBUG: Filtering details:")
        
        for cve in cves:
            cve_id = cve.get('id', 'unknown')
            title = cve.get('title', '').lower()
            description = cve.get('description', '').lower()
            products_text = ' '.join(cve.get('affected_products', [])).lower()
            
            full_cve_text = f"{title} {description} {products_text}"
            
            exclude = False
            exclusion_category = None
            matching_pattern = None
            
            # Check for exclusion patterns
            for category, patterns in exclusion_patterns.items():
                for pattern in patterns:
                    if pattern in full_cve_text:
                        exclude = True
                        exclusion_category = category
                        matching_pattern = pattern
                        break
                if exclude:
                    break
            
            if exclude:
                # Check for strong public safety signals that override
                has_strong_ps_signal = any(
                    indicator in full_cve_text 
                    for indicator in high_confidence_indicators
                )
                
                if has_strong_ps_signal:
                    if debug:
                        print(f"    {cve_id}: KEEP (override) - matched '{matching_pattern}' ({exclusion_category}) but has strong PS signal")
                    filtered.append(cve)
                else:
                    if debug:
                        print(f"    {cve_id}: EXCLUDE - matched '{matching_pattern}' ({exclusion_category})")
                    continue
            else:
                if debug:
                    print(f"    {cve_id}: KEEP (no exclusions matched)")
                filtered.append(cve)
        
        return filtered


def run_daily_aggregation(days_back: int = 30, 
                         min_confidence: int = 50,
                         display: bool = True,
                         export: bool = False,
                         debug_filtering: bool = False) -> List[Dict[str, Any]]:
    """Run a standard daily threat aggregation."""
    aggregator = PublicSafetyThreatAggregator()
    threats = aggregator.aggregate_threats(
        days_back=days_back,
        min_confidence=min_confidence,
        debug_filtering=debug_filtering
    )
    
    if display:
        aggregator.display_threat_summary(threats)
    
    if export:
        aggregator.export_threats_json(threats)
    
    return threats


if __name__ == "__main__":
    print("Running Public Safety Threat Aggregator...")
    print("This will fetch real CVEs from NVD and score them with ECROSPK.\n")
    
    # Run with debug mode to see filtering decisions
    threats = run_daily_aggregation(
        days_back=60,
        min_confidence=40,
        display=True,
        export=False,
        debug_filtering=True  # Enable to see what's being filtered
    )
    
    print(f"\n✓ Aggregation complete. Found {len(threats)} actionable threats.")
    print("\nTo export results, run with export=True")
    print("To see full reasoning for a threat, access the 'reasoning' field in the JSON")
