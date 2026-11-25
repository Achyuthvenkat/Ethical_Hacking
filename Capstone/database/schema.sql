-- ====================================================================
-- Database Schema: Web Application Security Testing & Vulnerability Scanner
-- Engine: SQLite3
-- ====================================================================

-- 1. SCANS TABLE: Tracks each security scan session
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    scan_status TEXT DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0.0,
    auth_confirmed INTEGER DEFAULT 1
);

-- 2. RECON_RESULTS TABLE: Stores Module 1 outputs
CREATE TABLE IF NOT EXISTS recon_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT,
    protocol TEXT,
    http_status INTEGER,
    server_banner TEXT,
    technologies TEXT, -- JSON or comma-separated string
    ssl_valid INTEGER DEFAULT 0,
    ssl_issuer TEXT,
    ssl_expiry TEXT,
    ssl_cipher TEXT,
    security_headers_present TEXT, -- JSON string
    security_headers_missing TEXT, -- JSON string
    open_ports TEXT, -- JSON string of detected ports & services
    recon_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- 3. VULNERABILITIES TABLE: Stores Module 2 outputs
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    module_source TEXT NOT NULL, -- e.g. 'SQL Injection', 'Cross-Site Scripting (XSS)'
    vuln_name TEXT NOT NULL,
    severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    affected_url TEXT NOT NULL,
    parameter TEXT,
    evidence TEXT, -- Safe technical proof (e.g. error snippet or reflection indicator)
    impact TEXT,
    remediation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Indexes for fast query performance
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(scan_status);
CREATE INDEX IF NOT EXISTS idx_recon_scan_id ON recon_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON vulnerabilities(scan_id);
