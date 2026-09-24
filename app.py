from flask import Flask, render_template, jsonify, request
from datetime import datetime
import sqlite3
import json

from scanners.s3_scanner import scan_s3
from scanners.iam_scanner import scan_iam
from scanners.sg_scanner import scan_security_groups
from scanners.rds_scanner import scan_rds
from scanners.cloudtrail_scanner import scan_cloudtrail
from risk_engine import calculate_risk
from database import init_db, save_scan, get_scan_history

app = Flask(__name__)
init_db()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    history = get_scan_history()
    latest = history[0] if history else None
    
    if latest:
        latest['findings'] = json.loads(latest['findings'])
    
    return render_template('index.html', latest_scan=latest, history=history)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Run security scan and return results"""
    try:
        all_findings = []
        
        # Run scanners
        s3_findings = scan_s3()
        all_findings.extend(s3_findings)
        
        iam_findings = scan_iam()
        all_findings.extend(iam_findings)
        
        sg_findings = scan_security_groups()
        all_findings.extend(sg_findings)

        rds_findings = scan_rds()
        all_findings.extend(rds_findings)

        cloudtrail_findings = scan_cloudtrail()
        all_findings.extend(cloudtrail_findings)
        
        # Calculate risk
        score, grade = calculate_risk(all_findings)
        
        # Save to database
        scan_id = save_scan(all_findings, score, grade)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'score': score,
            'grade': grade,
            'findings': all_findings,
            'findings_count': len(all_findings),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan results"""
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    conn.close()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': scan['id'],
        'score': scan['score'],
        'grade': scan['grade'],
        'findings': json.loads(scan['findings']),
        'timestamp': scan['timestamp']
    })

@app.route('/api/history', methods=['GET'])
def scan_history():
    """Get scan history"""
    history = get_scan_history()
    for scan in history:
        scan['findings'] = json.loads(scan['findings'])
    
    return jsonify(history)

if __name__ == '__main__':
    app.run(debug=True, port=5000)