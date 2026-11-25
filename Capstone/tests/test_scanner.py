import os
import sys
import time
import threading
from urllib.parse import urlparse

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.db_manager import init_db, get_scan_by_id, get_recon_by_scan_id, get_vulnerabilities_by_scan_id
from modules.scanner_orchestrator import dispatch_scan, ACTIVE_SCANS
from test_vulnerable_app import test_app

def run_test_server():
    test_app.run(host='127.0.0.1', port=5050, debug=False, use_reloader=False)

def main():
    print("=" * 60)
    print("RUNNING END-TO-END SCANNER INTEGRATION TEST")
    print("=" * 60)
    
    init_db()

    # 1. Start the vulnerable test bench in a daemon thread
    server_thread = threading.Thread(target=run_test_server, daemon=True)
    server_thread.start()
    time.sleep(1.0) # Allow server to bind port 5050
    print("[1] Test vulnerable application online on http://127.0.0.1:5050")

    # 2. Dispatch a scan against the local test bench
    target = "http://127.0.0.1:5050"
    print(f"[2] Launching scan against target: {target}")
    result = dispatch_scan(target, auth_confirmed=1)
    
    assert result['success'] is True, f"Failed to dispatch scan: {result}"
    scan_id = result['scan_id']
    print(f"[3] Scan dispatched with ID #{scan_id}. Polling progress...")

    # 3. Poll until completed or timeout
    max_wait = 25
    elapsed = 0
    completed = False
    
    while elapsed < max_wait:
        time.sleep(1)
        elapsed += 1
        scan_mem = ACTIVE_SCANS.get(scan_id, {})
        status = scan_mem.get('status')
        progress = scan_mem.get('progress', 0)
        step = scan_mem.get('current_step', '')
        print(f"    Elapsed: {elapsed}s | Progress: {progress}% | Step: {step}")
        
        if status == 'COMPLETED':
            completed = True
            break
        elif status == 'FAILED':
            print("ERROR: Scan reported FAILED status!")
            break

    assert completed, "Scan did not complete within the timeout period!"
    print("[4] Scan completed successfully in background worker!")

    # 4. Verify database persistence
    scan_record = get_scan_by_id(scan_id)
    recon_record = get_recon_by_scan_id(scan_id)
    vulns = get_vulnerabilities_by_scan_id(scan_id)

    print("\n--- DATABASE VALIDATION ---")
    print(f"Scan ID: {scan_record['id']}")
    print(f"Target: {scan_record['target_url']}")
    print(f"Status: {scan_record['scan_status']}")
    print(f"Risk Score: {scan_record['risk_score']} / 10.0")
    print(f"Total Findings: {scan_record['total_findings']}")
    print(f"Module 1 Server Banner: {recon_record['server_banner']}")
    print(f"Module 1 Missing Headers: {len(recon_record['security_headers_missing'])}")
    print(f"Module 2 & Header Findings count: {len(vulns)}")

    assert len(vulns) > 0, "Expected vulnerability findings on vulnerable app!"
    
    for v in vulns:
        print(f"  -> [{v['severity']}] {v['vuln_name']} ({v['module_source']}) on {v['affected_url']}")

    # 5. Check PDF generation
    pdf_path = os.path.join(os.path.dirname(__file__), '..', 'reports', f"scan_report_{scan_id}.pdf")
    assert os.path.exists(pdf_path), f"PDF report was not generated at {pdf_path}"
    pdf_size = os.path.getsize(pdf_path)
    print(f"\n[5] PDF Report Verified: {pdf_path} (Size: {pdf_size} bytes)")

    print("\n" + "=" * 60)
    print("ALL INTEGRATION TESTS PASSED 100% SUCCESSFULLY!")
    print("=" * 60)

if __name__ == '__main__':
    main()
