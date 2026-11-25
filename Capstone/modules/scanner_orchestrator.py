import ipaddress
import socket
import threading
import time
from urllib.parse import urlparse
from config import Config
from database.db_manager import (
    create_scan,
    complete_scan,
    mark_scan_failed,
    save_recon_result,
    save_vulnerability,
    get_scan_by_id,
    get_recon_by_scan_id,
    get_vulnerabilities_by_scan_id
)
from modules.module1_recon.recon_engine import run_reconnaissance
from modules.module2_detection.vuln_engine import run_vulnerability_detection
from modules.module3_reporting.risk_engine import calculate_risk_and_findings
from modules.module3_reporting.pdf_generator import generate_pdf_report

# Global in-memory tracking for real-time progress and logs
ACTIVE_SCANS = {}

def validate_target_url(target_url):
    """
    Validates URL syntax and performs SSRF protection checks.
    """
    if not target_url or not isinstance(target_url, str):
        return False, "Target URL cannot be empty."

    target_url = target_url.strip()
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        return False, "Invalid protocol. Target URL must begin with http:// or https://"

    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: Unable to extract domain or hostname."

        # SSRF checks
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            if not Config.ALLOW_LOCAL_TESTING:
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return False, f"Access to private/loopback IP address {ip} is restricted by SSRF protection policy."
                
                for blocked in Config.BLOCKED_IP_RANGES:
                    if ip_obj in ipaddress.ip_network(blocked):
                        return False, f"Target IP belongs to restricted range: {blocked}."
        except socket.gaierror:
            return False, f"Hostname resolution failed for '{hostname}'. Please check DNS or domain spelling."

        return True, "Valid"
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

def _execute_scan_thread(scan_id, target_url):
    """
    Background worker thread executing the end-to-end scanning pipeline.
    """
    def log_msg(msg):
        timestamp = time.strftime('%H:%M:%S')
        formatted = f"[{timestamp}] {msg}"
        if scan_id in ACTIVE_SCANS:
            ACTIVE_SCANS[scan_id]['logs'].append(formatted)

    try:
        ACTIVE_SCANS[scan_id]['progress'] = 10
        log_msg("Pre-flight checks passed. Initiating security assessment.")

        # --- MODULE 1: RECONNAISSANCE ---
        ACTIVE_SCANS[scan_id]['progress'] = 25
        ACTIVE_SCANS[scan_id]['current_step'] = "Module 1: Reconnaissance & Infrastructure Profiling"
        recon_data = run_reconnaissance(target_url, log_callback=log_msg)

        ACTIVE_SCANS[scan_id]['progress'] = 40
        log_msg("Persisting reconnaissance findings to database...")
        save_recon_result(scan_id, recon_data)

        # --- MODULE 2: VULNERABILITY DETECTION ---
        ACTIVE_SCANS[scan_id]['progress'] = 55
        ACTIVE_SCANS[scan_id]['current_step'] = "Module 2: SQL Injection & XSS Vulnerability Detection"
        raw_vulns = run_vulnerability_detection(target_url, log_callback=log_msg)

        # --- MODULE 3: REPORTING & RISK CALCULATION ---
        ACTIVE_SCANS[scan_id]['progress'] = 80
        ACTIVE_SCANS[scan_id]['current_step'] = "Module 3: Risk Assessment & Report Compilation"
        log_msg("Consolidating vulnerabilities and calculating CVSS-inspired risk score...")
        
        assessment = calculate_risk_and_findings(recon_data, raw_vulns)
        consolidated_vulns = assessment['consolidated_vulns']

        # Persist all consolidated findings
        for v in consolidated_vulns:
            save_vulnerability(
                scan_id=scan_id,
                module_source=v['module_source'],
                vuln_name=v['vuln_name'],
                severity=v['severity'],
                affected_url=v['affected_url'],
                parameter=v.get('parameter', 'N/A'),
                evidence=v.get('evidence', ''),
                impact=v.get('impact', ''),
                remediation=v.get('remediation', '')
            )

        # Update Scan Status in DB
        complete_scan(
            scan_id=scan_id,
            total_findings=assessment['total_findings'],
            critical_count=assessment['critical_count'],
            high_count=assessment['high_count'],
            medium_count=assessment['medium_count'],
            low_count=assessment['low_count'],
            info_count=assessment['info_count'],
            risk_score=assessment['risk_score']
        )

        # Generate PDF Report
        ACTIVE_SCANS[scan_id]['progress'] = 95
        log_msg("Rendering ReportLab PDF Security Assessment Document...")
        scan_record = get_scan_by_id(scan_id)
        recon_record = get_recon_by_scan_id(scan_id)
        vuln_records = get_vulnerabilities_by_scan_id(scan_id)
        generate_pdf_report(scan_id, scan_record, recon_record, vuln_records)

        # Finish
        ACTIVE_SCANS[scan_id]['progress'] = 100
        ACTIVE_SCANS[scan_id]['status'] = 'COMPLETED'
        ACTIVE_SCANS[scan_id]['current_step'] = 'Scan Completed Successfully'
        log_msg(f"Security assessment completed. Overall Risk: {assessment['risk_rating']} ({assessment['risk_score']}/10.0).")

    except Exception as e:
        mark_scan_failed(scan_id)
        if scan_id in ACTIVE_SCANS:
            ACTIVE_SCANS[scan_id]['status'] = 'FAILED'
            ACTIVE_SCANS[scan_id]['current_step'] = f"Failed: {str(e)}"
            log_msg(f"FATAL ERROR during scan execution: {str(e)}")

def dispatch_scan(target_url, auth_confirmed=1):
    """
    Validates target, creates a scan database record, and launches the worker thread.
    """
    is_valid, msg = validate_target_url(target_url)
    if not is_valid:
        return {'success': False, 'message': msg}

    # Initialize Scan in DB
    scan_id = create_scan(target_url, auth_confirmed=auth_confirmed)

    # Initialize tracking memory
    ACTIVE_SCANS[scan_id] = {
        'scan_id': scan_id,
        'target_url': target_url,
        'status': 'RUNNING',
        'progress': 5,
        'current_step': 'Initializing Assessment Pipeline',
        'logs': [f"[{time.strftime('%H:%M:%S')}] Scan queued with ID #{scan_id}"]
    }

    # Launch background thread
    worker = threading.Thread(target=_execute_scan_thread, args=(scan_id, target_url), daemon=True)
    worker.start()

    return {'success': True, 'scan_id': scan_id}
