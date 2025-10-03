"""Generate HTML report from threats stored in database."""

from src.storage.threat_db import ThreatDatabase
from src.reports.html_generator import HTMLReportGenerator
import os
import webbrowser

# Access database directly
db = ThreatDatabase()
threats = db.get_recent_threats(limit=50, min_score=40)
stats = db.get_statistics()
db.close()

print(f"Found {len(threats)} threats in database")
print(f"Database stats: {stats}")

if threats:
    output_path = HTMLReportGenerator.generate_report(
        threats,
        output_path="threat_report.html",
        report_title="Public Safety Threat Intelligence Report"
    )
    abs_path = os.path.abspath(output_path)
    print(f"\n✓ HTML report generated: {output_path}")
    print(f"  Full path: {abs_path}")
    
    # Try to open in browser automatically
    print(f"\nAttempting to open report in browser...")
    try:
        webbrowser.open('file://' + abs_path)
        print("✓ Report opened in browser")
    except Exception as e:
        print(f"⚠ Could not auto-open browser: {e}")
        print(f"  Manually open this file: {abs_path}")
else:
    print("No threats found in database matching criteria.")
