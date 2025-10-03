"""HTML Report Generator for ECROSPK Threat Intelligence"""

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path


class HTMLReportGenerator:
    """Generates HTML threat intelligence reports."""
    
    @staticmethod
    def generate_report(threats: List[Dict[str, Any]], 
                       output_path: str = "threat_report.html",
                       report_title: str = "Public Safety Threat Intelligence Report") -> str:
        """Generate an HTML report from scored threats."""
        html = HTMLReportGenerator._build_html(threats, report_title)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    @staticmethod
    def _build_html(threats: List[Dict[str, Any]], title: str) -> str:
        """Build complete HTML document."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        high_count = sum(1 for t in threats if t.get('label') == 'High')
        medium_count = sum(1 for t in threats if t.get('label') == 'Medium')
        low_count = sum(1 for t in threats if t.get('label') == 'Low')
        avg_score = sum(t.get('final_score', 0) for t in threats) / len(threats) if threats else 0
        investigate_now = sum(1 for t in threats if t.get('investigate_now'))
        
        threat_cards = '\n'.join(
            HTMLReportGenerator._build_threat_card(threat, i+1) 
            for i, threat in enumerate(threats)
        )
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px 40px; background: #f8f9fa; }}
        .stat-card {{ text-align: center; padding: 20px; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        .stat-label {{ font-size: 14px; color: #6c757d; margin-top: 5px; }}
        .threats {{ padding: 40px; }}
        .threat-card {{ border: 1px solid #dee2e6; border-radius: 8px; padding: 25px; margin-bottom: 25px; background: white; }}
        .threat-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .threat-id {{ font-size: 20px; font-weight: bold; color: #2c3e50; }}
        .score-badge {{ padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
        .score-high {{ background: #dc3545; color: white; }}
        .score-medium {{ background: #ffc107; color: #333; }}
        .score-low {{ background: #28a745; color: white; }}
        .threat-title {{ font-size: 16px; color: #495057; margin-bottom: 15px; }}
        .cve-link {{ display: inline-block; margin-top: 15px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 4px; }}
        .footer {{ padding: 30px 40px; background: #f8f9fa; text-align: center; color: #6c757d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>Generated: {timestamp} | ECROSPK v0.3</p>
        </div>
        <div class="summary">
            <div class="stat-card"><div class="stat-value">{len(threats)}</div><div class="stat-label">Total Threats</div></div>
            <div class="stat-card"><div class="stat-value">{high_count}</div><div class="stat-label">High Confidence</div></div>
            <div class="stat-card"><div class="stat-value">{medium_count}</div><div class="stat-label">Medium Confidence</div></div>
            <div class="stat-card"><div class="stat-value">{avg_score:.1f}</div><div class="stat-label">Average Score</div></div>
        </div>
        <div class="threats">{threat_cards if threats else '<p style="text-align: center;">No threats found.</p>'}</div>
        <div class="footer">
            <p>PS-Threat-Aggregator | Public Safety Threat Intelligence with ECROSPK Confidence Scoring</p>
        </div>
    </div>
</body>
</html>"""
    
    @staticmethod
    def _build_threat_card(threat: Dict[str, Any], index: int) -> str:
        """Build HTML for a single threat card."""
        metadata = threat.get('cve_metadata', {})
        score = threat.get('final_score', 0)
        label = threat.get('label', 'Unknown')
        
        badge_class = {'High': 'score-high', 'Medium': 'score-medium', 'Low': 'score-low'}.get(label, 'score-low')
        
        return f'''
        <div class="threat-card">
            <div class="threat-header">
                <span class="threat-id">#{index} {metadata.get('id', 'Unknown')}</span>
                <span class="score-badge {badge_class}">{score:.1f}/100 ({label})</span>
            </div>
            <div class="threat-title">{metadata.get('title', 'No title available')}</div>
            <p><strong>CVSS:</strong> {metadata.get('severity', 'Unknown')} ({metadata.get('cvss_score', 'N/A')})</p>
            <a href="{metadata.get('link', '#')}" target="_blank" class="cve-link">View Full CVE Details →</a>
        </div>'''
