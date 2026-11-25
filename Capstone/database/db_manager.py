import sqlite3
import os
import json
from datetime import datetime
from config import Config

def get_db_connection():
    """Returns a thread-safe connection to SQLite with row-factory enabled."""
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes database schema and ensures directories exist."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
        
    conn = get_db_connection()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()

def create_scan(target_url, auth_confirmed=1):
    """Creates a new scan record and returns its ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (target_url, scan_status, started_at, auth_confirmed)
            VALUES (?, 'RUNNING', datetime('now', 'localtime'), ?)
            """,
            (target_url, auth_confirmed)
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def update_scan_status(scan_id, status):
    """Updates the status of a scan."""
    conn = get_db_connection()
    try:
        conn.execute("UPDATE scans SET scan_status = ? WHERE id = ?", (status, scan_id))
        conn.commit()
    finally:
        conn.close()

def complete_scan(scan_id, total_findings, critical_count, high_count, medium_count, low_count, info_count, risk_score):
    """Marks a scan as completed with summarized statistics."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            UPDATE scans 
            SET scan_status = 'COMPLETED',
                completed_at = datetime('now', 'localtime'),
                total_findings = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                info_count = ?,
                risk_score = ?
            WHERE id = ?
            """,
            (total_findings, critical_count, high_count, medium_count, low_count, info_count, risk_score, scan_id)
        )
        conn.commit()
    finally:
        conn.close()

def mark_scan_failed(scan_id):
    """Marks a scan as failed."""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE scans SET scan_status = 'FAILED', completed_at = datetime('now', 'localtime') WHERE id = ?",
            (scan_id,)
        )
        conn.commit()
    finally:
        conn.close()

def save_recon_result(scan_id, recon_data):
    """Saves Module 1 reconnaissance findings."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO recon_results (
                scan_id, ip_address, protocol, http_status, server_banner,
                technologies, ssl_valid, ssl_issuer, ssl_expiry, ssl_cipher,
                security_headers_present, security_headers_missing,
                open_ports, recon_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                recon_data.get('ip_address', 'N/A'),
                recon_data.get('protocol', 'N/A'),
                recon_data.get('http_status', 0),
                recon_data.get('server_banner', 'N/A'),
                json.dumps(recon_data.get('technologies', [])),
                1 if recon_data.get('ssl_valid') else 0,
                recon_data.get('ssl_issuer', 'N/A'),
                recon_data.get('ssl_expiry', 'N/A'),
                recon_data.get('ssl_cipher', 'N/A'),
                json.dumps(recon_data.get('security_headers_present', {})),
                json.dumps(recon_data.get('security_headers_missing', [])),
                json.dumps(recon_data.get('open_ports', [])),
                recon_data.get('recon_summary', '')
            )
        )
        conn.commit()
    finally:
        conn.close()

def save_vulnerability(scan_id, module_source, vuln_name, severity, affected_url, parameter, evidence, impact, remediation):
    """Saves an identified vulnerability finding."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO vulnerabilities (
                scan_id, module_source, vuln_name, severity,
                affected_url, parameter, evidence, impact, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, module_source, vuln_name, severity.upper(), affected_url, parameter, evidence, impact, remediation)
        )
        conn.commit()
    finally:
        conn.close()

def get_all_scans():
    """Retrieves all scan records ordered by start time descending."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_scan_by_id(scan_id):
    """Retrieves metadata for a specific scan."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_recon_by_scan_id(scan_id):
    """Retrieves recon data for a specific scan."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recon_results WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        # Parse JSON fields
        data['technologies'] = json.loads(data['technologies']) if data['technologies'] else []
        data['security_headers_present'] = json.loads(data['security_headers_present']) if data['security_headers_present'] else {}
        data['security_headers_missing'] = json.loads(data['security_headers_missing']) if data['security_headers_missing'] else []
        data['open_ports'] = json.loads(data['open_ports']) if data['open_ports'] else []
        return data
    finally:
        conn.close()

def get_vulnerabilities_by_scan_id(scan_id):
    """Retrieves all vulnerability records for a specific scan."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
