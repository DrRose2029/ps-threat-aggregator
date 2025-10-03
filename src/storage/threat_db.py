"""SQLite database for persistent threat storage."""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class ThreatDatabase:
    """Simple SQLite database for storing ECROSPK-scored threats."""
    
    def __init__(self, db_path: str = "data/threats.db"):
        """Initialize database connection."""
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._initialize_schema()
    
    def _initialize_schema(self):
        """Create tables if they don't exist."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                final_score REAL NOT NULL,
                label TEXT NOT NULL,
                investigate_now INTEGER,
                systemic INTEGER,
                factors TEXT,
                reasoning TEXT,
                affected_products TEXT,
                link TEXT,
                processed_at TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON threats(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_at ON threats(processed_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_final_score ON threats(final_score)")
        
        self.conn.commit()
    
    def store_threat(self, threat: Dict[str, Any]) -> int:
        """Store a scored threat in the database."""
        cursor = self.conn.cursor()
        metadata = threat.get('cve_metadata', {})
        
        cursor.execute("""
            INSERT INTO threats (
                cve_id, title, description, severity, cvss_score,
                final_score, label, investigate_now, systemic,
                factors, reasoning, affected_products, link, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata.get('id'),
            metadata.get('title'),
            metadata.get('description'),
            metadata.get('severity'),
            metadata.get('cvss_score'),
            threat.get('final_score'),
            threat.get('label'),
            int(threat.get('investigate_now', False)),
            int(threat.get('systemic', False)),
            json.dumps(threat.get('factors', {})),
            json.dumps(threat.get('reasoning', {})),
            json.dumps(metadata.get('affected_products', [])),
            metadata.get('link'),
            threat.get('processed_at', datetime.now().isoformat())
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def store_threats_batch(self, threats: List[Dict[str, Any]]) -> int:
        """Store multiple threats in a single transaction."""
        for threat in threats:
            self.store_threat(threat)
        return len(threats)
    
    def get_threat_by_cve_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent record for a CVE ID."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM threats 
            WHERE cve_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (cve_id,))
        
        row = cursor.fetchone()
        return self._row_to_dict(row) if row else None
    
    def get_recent_threats(self, limit: int = 100, min_score: float = 0.0) -> List[Dict[str, Any]]:
        """Get recent threats above a minimum score."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM threats 
            WHERE final_score >= ?
            ORDER BY processed_at DESC 
            LIMIT ?
        """, (min_score, limit))
        
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def get_high_confidence_threats(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get all High confidence threats from the last N days."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM threats 
            WHERE label = 'High'
            AND processed_at >= datetime('now', '-' || ? || ' days')
            ORDER BY final_score DESC
        """, (days,))
        
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get summary statistics about stored threats."""
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM threats")
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT label, COUNT(*) as count FROM threats GROUP BY label")
        label_counts = {row['label']: row['count'] for row in cursor.fetchall()}
        
        cursor.execute("SELECT AVG(final_score) as avg_score FROM threats")
        avg_score = cursor.fetchone()['avg_score'] or 0.0
        
        cursor.execute("SELECT COUNT(*) as count FROM threats WHERE investigate_now = 1")
        investigate_now_count = cursor.fetchone()['count']
        
        return {
            'total_threats': total,
            'high_confidence': label_counts.get('High', 0),
            'medium_confidence': label_counts.get('Medium', 0),
            'low_confidence': label_counts.get('Low', 0),
            'average_score': round(avg_score, 2),
            'investigate_now_flags': investigate_now_count
        }
    
    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert database row to threat dictionary with proper structure."""
        if not row:
            return None
        
        # Build the cve_metadata sub-dictionary
        cve_metadata = {
            'id': row['cve_id'],
            'title': row['title'],
            'description': row['description'],
            'severity': row['severity'],
            'cvss_score': row['cvss_score'],
            'link': row['link'],
            'affected_products': json.loads(row['affected_products']) if row['affected_products'] else []
        }
        
        # Build the main threat dictionary
        threat = {
            'final_score': row['final_score'],
            'label': row['label'],
            'investigate_now': bool(row['investigate_now']),
            'systemic': bool(row['systemic']),
            'factors': json.loads(row['factors']) if row['factors'] else {},
            'reasoning': json.loads(row['reasoning']) if row['reasoning'] else {},
            'cve_metadata': cve_metadata,
            'processed_at': row['processed_at'],
            'db_id': row['id']
        }
        
        return threat
    
    def close(self):
        """Close database connection."""
        self.conn.close()
