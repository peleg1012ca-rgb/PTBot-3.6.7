import sqlite3
from config import DATABASE_PATH

def init_db(database_path=None):
    """Create legacy and authorization tables without deleting existing data."""
    from pathlib import Path
    Path(database_path or DATABASE_PATH).resolve().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(database_path or DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            protocol TEXT,
            service_name TEXT,
            version TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            title TEXT,
            description TEXT,
            evidence TEXT,
            source_tool TEXT,
            confidence TEXT,
            remediation TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT NOT NULL CHECK (length(trim(client_name)) > 0),
            status TEXT NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft', 'approved', 'revoked')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS included_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            target_type TEXT NOT NULL
                CHECK (target_type IN ('domain', 'wildcard', 'ip', 'cidr', 'url')),
            target_value TEXT NOT NULL CHECK (length(trim(target_value)) > 0),
            UNIQUE (engagement_id, target_type, target_value)
        );

        CREATE TABLE IF NOT EXISTS excluded_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            target_type TEXT NOT NULL
                CHECK (target_type IN ('domain', 'wildcard', 'ip', 'cidr', 'url')),
            target_value TEXT NOT NULL CHECK (length(trim(target_value)) > 0),
            UNIQUE (engagement_id, target_type, target_value)
        );

        CREATE TABLE IF NOT EXISTS policy_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            action_type TEXT NOT NULL CHECK (length(trim(action_type)) > 0),
            requests_per_minute INTEGER NOT NULL CHECK (requests_per_minute > 0),
            UNIQUE (engagement_id, action_type)
        );

        CREATE TABLE IF NOT EXISTS local_http_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            requested_url TEXT NOT NULL,
            attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            policy_decision TEXT NOT NULL CHECK (policy_decision IN ('allowed', 'denied')),
            policy_reason TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT 'pending'
                CHECK (outcome IN ('pending', 'denied', 'response', 'error')),
            http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
            detail TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_local_http_attempts_engagement
            ON local_http_attempts (engagement_id, id);

        CREATE TABLE IF NOT EXISTS action_reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            action_type TEXT NOT NULL,
            reserved_at_ms INTEGER NOT NULL,
            attempt_id INTEGER UNIQUE REFERENCES local_http_attempts(id)
        );
        CREATE INDEX IF NOT EXISTS idx_action_reservations_window
            ON action_reservations (engagement_id, action_type, reserved_at_ms);

        CREATE TABLE IF NOT EXISTS investigation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            attempt_id INTEGER UNIQUE REFERENCES local_http_attempts(id),
            action_type TEXT NOT NULL,
            target_reference TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'response', 'denied', 'error')),
            error_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_investigation_runs_engagement
            ON investigation_runs (engagement_id, id);

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL REFERENCES investigation_runs(id),
            check_type TEXT NOT NULL CHECK (length(trim(check_type)) > 0),
            severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high')),
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            review_status TEXT NOT NULL DEFAULT 'unreviewed'
                CHECK (review_status IN ('unreviewed', 'confirmed', 'dismissed'))
        );

        CREATE TABLE IF NOT EXISTS evidence_refs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id INTEGER NOT NULL REFERENCES observations(id),
            evidence_kind TEXT NOT NULL,
            reference_text TEXT NOT NULL,
            content_hash TEXT
        );
    """)

    from workbench_store import migrate
    migrate(conn)
    from xss_store import migrate as migrate_xss
    migrate_xss(conn)
    from recon_store import migrate as migrate_recon
    migrate_recon(conn)
    conn.commit()
    conn.close()

def create_scan(target):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (target, status) VALUES (?, ?)", (target, "Pending"))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_status(scan_id, status):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))
    conn.commit()
    conn.close()

def add_service(scan_id, port, protocol, service_name, version):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO services (scan_id, port, protocol, service_name, version) VALUES (?, ?, ?, ?, ?)",
        (scan_id, port, protocol, service_name, version)
    )
    conn.commit()
    conn.close()

def add_finding(scan_id, title, description, evidence, source_tool, confidence, remediation):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO findings (scan_id, title, description, evidence, source_tool, confidence, remediation) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scan_id, title, description, evidence, source_tool, confidence, remediation)
    )
    conn.commit()
    conn.close()

def get_scan_details(scan_id):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    
    cursor.execute("SELECT * FROM services WHERE scan_id = ?", (scan_id,))
    services = cursor.fetchall()
    
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = cursor.fetchall()
    
    conn.close()
    return scan, services, findings

def get_all_scans():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    scans = cursor.fetchall()
    conn.close()
    return scans
