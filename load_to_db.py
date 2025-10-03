from src.storage.threat_db import ThreatDatabase
import json

with open('threats.json', 'r') as f:
    threats = json.load(f)

db = ThreatDatabase()
count = db.store_threats_batch(threats)
print(f"Stored {count} threats in database")
print(f"Database stats: {db.get_statistics()}")
db.close()
