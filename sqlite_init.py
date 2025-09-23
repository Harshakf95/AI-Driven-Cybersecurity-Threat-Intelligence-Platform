
import sqlite3

# Connect to SQLite database (or create it)
conn = sqlite3.connect('cybersecurity_platform.db')
cursor = conn.cursor()

# Create tables
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'analyst', 'viewer')) DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS threat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    protocol TEXT,
    threat_type TEXT,
    confidence_score REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS anomaly_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TIMESTAMP,
    feature_vector TEXT,
    anomaly_score REAL,
    detected BOOLEAN DEFAULT 0,
    model_version TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS honeypot_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_ip TEXT,
    port_accessed INTEGER,
    payload TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_signature TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    resource TEXT,
    action TEXT,
    decision TEXT CHECK(decision IN ('allow', 'deny')),
    context_json TEXT,
    evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# Create indexes
cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_logs_ip ON threat_logs(source_ip)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_score ON anomaly_events(anomaly_score)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_data(attacker_ip)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_decision ON access_requests(decision)")

# Commit and close
conn.commit()
conn.close()