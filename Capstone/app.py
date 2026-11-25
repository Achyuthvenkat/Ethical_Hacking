import os
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, abort
from config import Config
from database.db_manager import (
    init_db,
    get_all_scans,
    get_scan_by_id,
    get_recon_by_scan_id,
    get_vulnerabilities_by_scan_id,
    get_db_connection
)
from modules.scanner_orchestrator import dispatch_scan, ACTIVE_SCANS
from modules.module3_reporting.pdf_generator import generate_pdf_report

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database and report directory are initialized
init_db()

@app.route('/')
def index():
    """Main dashboard: scan submission and recent scans summary."""
    all_scans = get_all_scans()
    recent_scans = all_scans[:5] if all_scans else []
    return render_template('index.html', recent_scans=recent_scans)

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """API endpoint to validate target and launch a background scan."""
    data = request.get_json() or {}
    target_url = data.get('target_url')
    auth_confirmed = data.get('auth_confirmed', 0)

    if not auth_confirmed:
        return jsonify({
            'success': False,
            'message': 'Testing authorization must be confirmed before proceeding.'
        }), 400

    result = dispatch_scan(target_url, auth_confirmed=auth_confirmed)
    if not result.get('success'):
        return jsonify(result), 400

    return jsonify(result)

@app.route('/api/scan/status/<int:scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """API endpoint returning live scan progress, phase, and logs."""
    if scan_id in ACTIVE_SCANS:
        scan_mem = ACTIVE_SCANS[scan_id]
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_mem.get('status', 'RUNNING'),
            'progress': scan_mem.get('progress', 0),
            'current_step': scan_mem.get('current_step', 'Processing...'),
            'logs': scan_mem.get('logs', [])
        })

    # If not in active memory, check SQLite database
    scan_db = get_scan_by_id(scan_id)
    if scan_db:
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': scan_db['scan_status'],
            'progress': 100 if scan_db['scan_status'] == 'COMPLETED' else 0,
            'current_step': f"Status: {scan_db['scan_status']}",
            'logs': [f"Scan completed with status {scan_db['scan_status']}."]
        })

    return jsonify({'success': False, 'message': 'Scan record not found'}), 404

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """Detailed view for Module 1, Module 2, and Module 3 results."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)

    recon = get_recon_by_scan_id(scan_id)
    vulns = get_vulnerabilities_by_scan_id(scan_id)

    return render_template(
        'scan_results.html',
        scan=scan,
        recon=recon,
        vulnerabilities=vulns
    )

@app.route('/history')
def history():
    """Historical assessment log viewer."""
    scans = get_all_scans()
    return render_template('history.html', scans=scans)

@app.route('/api/scan/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Deletes a scan and its associated findings."""
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        # Also clean in-memory status if present
        if scan_id in ACTIVE_SCANS:
            del ACTIVE_SCANS[scan_id]
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@app.route('/report/<int:scan_id>/pdf')
def download_pdf(scan_id):
    """Generates and downloads the executive PDF security audit report."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)

    recon = get_recon_by_scan_id(scan_id)
    vulns = get_vulnerabilities_by_scan_id(scan_id)

    pdf_path = os.path.join(Config.REPORTS_DIR, f"scan_report_{scan_id}.pdf")
    
    # Generate fresh if not already on disk
    if not os.path.exists(pdf_path):
        generate_pdf_report(scan_id, scan, recon, vulns, output_path=pdf_path)

    return send_file(
        pdf_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"Security_Assessment_Report_Scan_{scan_id}.pdf"
    )

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" [✓] Web Application Security Testing & Vulnerability Scanner")
    print(" [✓] Capstone Server running on: http://127.0.0.1:5000")
    print("="*70 + "\n")
    app.run(host='127.0.0.1', port=5000, debug=True)
