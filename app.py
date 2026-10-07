"""
app.py — Main Flask application for the Cloud Security Scanner.

Provides routes for:
  - Dashboard & scan execution
  - Authentication (Login/Register/Logout via Blueprint)
  - AWS Credentials connection
  - PDF report download
  - Scan history
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, g
import os
import json

from config import SECRET_KEY, DATABASE, UPLOAD_FOLDER
from database import init_db, save_scan, get_scan_history, get_scan_by_id
from auth import auth_bp, login_required
from aws_connection import set_aws_config, validate_connection, get_aws_config
from scanners.s3_scanner import scan_s3
from scanners.iam_scanner import scan_iam
from scanners.sg_scanner import scan_security_groups
from scanners.rds_scanner import scan_rds
from scanners.cloudtrail_scanner import scan_cloudtrail
from risk_engine import calculate_risk
from report_generator import generate_pdf_report

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DATABASE'] = DATABASE
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Register Authentication Blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')

# Initialize database tables on startup
init_db()


@app.route('/')
@login_required
def dashboard():
    """Main dashboard page — requires login."""
    history = get_scan_history(limit=5)
    current_aws = get_aws_config()
    return render_template('index.html', history=history, aws_config=current_aws, user=g.user)


@app.route('/connect', methods=['GET', 'POST'])
@login_required
def connect_aws():
    """Set AWS credentials or LocalStack connection."""
    if request.method == 'POST':
        mode = request.form.get('mode', 'localstack')
        aws_access_key = request.form.get('aws_access_key', 'test')
        aws_secret_key = request.form.get('aws_secret_key', 'test')
        region = request.form.get('region', 'us-east-1')
        endpoint_url = request.form.get('endpoint_url', 'http://localhost:4566')

        set_aws_config(
            mode=mode,
            aws_access_key=aws_access_key,
            aws_secret_key=aws_secret_key,
            region=region,
            endpoint_url=endpoint_url if mode == 'localstack' else None
        )

        success, message = validate_connection()
        if success:
            return redirect(url_for('dashboard'))
        else:
            return render_template('connect.html', error=message, aws_config=get_aws_config(), user=g.user)

    return render_template('connect.html', aws_config=get_aws_config(), user=g.user)


@app.route('/api/scan', methods=['POST'])
@login_required
def run_scan():
    """Triggers scan across S3, IAM, SG, RDS, and CloudTrail."""
    findings = []

    # Run all 5 scanners
    findings.extend(scan_s3())
    findings.extend(scan_iam())
    findings.extend(scan_security_groups())
    findings.extend(scan_rds())
    findings.extend(scan_cloudtrail())

    # Calculate risk score & grade
    score, grade = calculate_risk(findings)

    # Save to database
    scan_id = save_scan(score, grade, findings, user_id=g.user['id'])

    return jsonify({
        'scan_id': scan_id,
        'score': score,
        'grade': grade,
        'findings': findings
    })


@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """View details of a previous scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan not found", 440
    return render_template('scan_detail.html', scan=scan, user=g.user)


@app.route('/history')
@login_required
def scan_history():
    """View all historical scans."""
    history = get_scan_history(limit=50)
    return render_template('history.html', history=history, user=g.user)


@app.route('/report/<int:scan_id>')
@login_required
def download_report(scan_id):
    """Download PDF report for a given scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan not found", 404

    scan_data = {
        'score': scan['score'],
        'grade': scan['grade'],
        'findings': json.loads(scan['findings_json']),
        'timestamp': scan['created_at']
    }

    pdf_buffer = generate_pdf_report(scan_data)

    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'cloud_security_report_scan_{scan_id}.pdf'
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)
