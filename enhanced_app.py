"""
Enhanced Flask Web Application for QuAi Deep
Provides a comprehensive web interface for vulnerability scanning with:
- Database-backed scan management
- Real-time scan progress tracking
- Historical scan results and comparison
- Interactive filtering and reporting
- OWASP Top 10 compliance dashboard
"""

import json
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
import os

from database import ScanDatabase
from enhanced_main import QuAiDeepEnhanced

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload

# Global variables for scan management
active_scans = {}
scan_results_cache = {}

def background_scan(scan_id, repository_url, specific_path, scan_type):
    """Run scan in background thread."""
    try:
        scanner = QuAiDeepEnhanced()
        
        # Update scan status in active_scans
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'stage': 'Initializing scan...',
            'start_time': datetime.now()
        }
        
        # Run the scan
        results = scanner.run_comprehensive_scan(
            repository_url=repository_url,
            specific_path=specific_path,
            scan_type=scan_type
        )
        
        # Update completion status
        if results['status'] == 'success':
            active_scans[scan_id] = {
                'status': 'completed',
                'progress': 100,
                'stage': 'Scan completed successfully',
                'results': results,
                'end_time': datetime.now()
            }
        else:
            active_scans[scan_id] = {
                'status': 'failed',
                'progress': 0,
                'stage': f"Scan failed: {results.get('message', 'Unknown error')}",
                'error': results.get('message', 'Unknown error'),
                'end_time': datetime.now()
            }
            
    except Exception as e:
        active_scans[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'stage': f"Scan failed with exception: {str(e)}",
            'error': str(e),
            'end_time': datetime.now()
        }

@app.route('/')
def dashboard():
    """Main dashboard showing recent scans and statistics."""
    db = ScanDatabase()
    recent_scans = db.get_scans(limit=10)
    
    # Calculate dashboard statistics
    total_scans = len(recent_scans)
    completed_scans = len([s for s in recent_scans if s['status'] == 'completed'])
    
    # Get total findings across all scans
    total_findings = sum(s['total_findings'] or 0 for s in recent_scans)
    
    # Get risk distribution across recent scans
    risk_totals = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for scan in recent_scans:
        if scan['status'] == 'completed':
            try:
                stats = db.get_scan_statistics(scan['id'])
                risk_dist = stats.get('risk_distribution', {})
                for level in risk_totals:
                    risk_totals[level] += risk_dist.get(level, 0)
            except:
                continue
    
    dashboard_stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_findings': total_findings,
        'risk_distribution': risk_totals
    }
    
    return render_template('enhanced_dashboard.html', 
                         scans=recent_scans, 
                         stats=dashboard_stats,
                         active_scans=active_scans)

@app.route('/new-scan')
def new_scan_form():
    """Show form for creating a new scan."""
    return render_template('new_scan.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan."""
    repository_url = request.form.get('repository_url', '').strip()
    specific_path = request.form.get('specific_path', '').strip() or None
    scan_type = request.form.get('scan_type', 'comprehensive')
    
    if not repository_url:
        flash('Repository URL is required', 'error')
        return redirect(url_for('new_scan_form'))
    
    try:
        # Create scan record in database
        db = ScanDatabase()
        scan_id = db.create_scan(repository_url, specific_path, scan_type)
        
        # Start background scan
        thread = threading.Thread(
            target=background_scan,
            args=(scan_id, repository_url, specific_path, scan_type)
        )
        thread.daemon = True
        thread.start()
        
        flash(f'Scan started successfully (ID: {scan_id})', 'success')
        return redirect(url_for('scan_progress', scan_id=scan_id))
        
    except Exception as e:
        flash(f'Failed to start scan: {str(e)}', 'error')
        return redirect(url_for('new_scan_form'))

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """Show detailed results for a specific scan."""
    db = ScanDatabase()
    
    try:
        # Get scan info
        scans = db.get_scans(limit=1000)  # Get all scans to find this one
        scan_info = next((s for s in scans if s['id'] == scan_id), None)
        
        if not scan_info:
            flash('Scan not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Get findings and statistics
        findings = db.get_scan_findings(scan_id)
        statistics = db.get_scan_statistics(scan_id)
        
        # Process findings for display
        processed_findings = []
        for finding in findings:
            processed_findings.append({
                **finding,
                'risk_color': get_risk_color(finding.get('llm_risk_score', 'MEDIUM')),
                'severity_color': get_severity_color(finding.get('semgrep_severity', 'INFO'))
            })
        
        return render_template('scan_details.html',
                             scan_info=scan_info,
                             findings=processed_findings,
                             statistics=statistics)
        
    except Exception as e:
        flash(f'Error loading scan details: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/scan/<int:scan_id>/progress')
def scan_progress(scan_id):
    """Show scan progress page."""
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/<int:scan_id>/status')
def scan_status_api(scan_id):
    """API endpoint to get scan status."""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    else:
        # Check database for completed scan
        db = ScanDatabase()
        scans = db.get_scans(limit=1000)
        scan_info = next((s for s in scans if s['id'] == scan_id), None)
        
        if scan_info:
            if scan_info['status'] == 'completed':
                return jsonify({
                    'status': 'completed',
                    'progress': 100,
                    'stage': 'Scan completed',
                    'total_findings': scan_info['total_findings']
                })
            elif scan_info['status'] == 'running':
                return jsonify({
                    'status': 'running',
                    'progress': 50,
                    'stage': 'Processing...'
                })
        
        return jsonify({
            'status': 'not_found',
            'stage': 'Scan not found'
        }), 404

@app.route('/api/scan/<int:scan_id>/findings')
def scan_findings_api(scan_id):
    """API endpoint to get scan findings with filtering."""
    db = ScanDatabase()
    
    try:
        findings = db.get_scan_findings(scan_id)
        
        # Apply filters from query parameters
        severity_filter = request.args.get('severity')
        risk_filter = request.args.get('risk')
        owasp_filter = request.args.get('owasp')
        
        filtered_findings = findings
        
        if severity_filter and severity_filter != 'all':
            filtered_findings = [f for f in filtered_findings if f.get('semgrep_severity') == severity_filter]
        
        if risk_filter and risk_filter != 'all':
            filtered_findings = [f for f in filtered_findings if f.get('llm_risk_score') == risk_filter]
        
        if owasp_filter and owasp_filter != 'all':
            filtered_findings = [f for f in filtered_findings if owasp_filter in f.get('owasp_category', '')]
        
        return jsonify({
            'findings': filtered_findings,
            'total': len(filtered_findings)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scans')
def scan_history():
    """Show scan history with filtering and search."""
    db = ScanDatabase()
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    days_filter = int(request.args.get('days', 30))
    
    # Get scans
    all_scans = db.get_scans(limit=100)
    
    # Apply filters
    filtered_scans = all_scans
    
    if status_filter != 'all':
        filtered_scans = [s for s in filtered_scans if s['status'] == status_filter]
    
    # Filter by date
    cutoff_date = datetime.now() - timedelta(days=days_filter)
    filtered_scans = [s for s in filtered_scans 
                     if datetime.fromisoformat(s['created_at'].replace('Z', '+00:00')).replace(tzinfo=None) >= cutoff_date]
    
    return render_template('scan_history.html', scans=filtered_scans)

@app.route('/compare')
def scan_comparison():
    """Show scan comparison interface."""
    db = ScanDatabase()
    recent_scans = db.get_scans(limit=50)
    completed_scans = [s for s in recent_scans if s['status'] == 'completed']
    
    return render_template('scan_comparison.html', scans=completed_scans)

@app.route('/api/compare/<int:scan1_id>/<int:scan2_id>')
def compare_scans_api(scan1_id, scan2_id):
    """API endpoint to compare two scans."""
    db = ScanDatabase()
    
    try:
        # Get statistics for both scans
        stats1 = db.get_scan_statistics(scan1_id)
        stats2 = db.get_scan_statistics(scan2_id)
        
        # Get scan info
        scans = db.get_scans(limit=1000)
        scan1_info = next((s for s in scans if s['id'] == scan1_id), None)
        scan2_info = next((s for s in scans if s['id'] == scan2_id), None)
        
        comparison = {
            'scan1': {
                'id': scan1_id,
                'info': scan1_info,
                'statistics': stats1
            },
            'scan2': {
                'id': scan2_id,
                'info': scan2_info,
                'statistics': stats2
            },
            'differences': {
                'total_findings_diff': stats2['total_findings'] - stats1['total_findings'],
                'risk_changes': {}
            }
        }
        
        # Calculate risk level changes
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count1 = stats1['risk_distribution'].get(level, 0)
            count2 = stats2['risk_distribution'].get(level, 0)
            comparison['differences']['risk_changes'][level] = count2 - count1
        
        return jsonify(comparison)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/owasp-dashboard')
def owasp_dashboard():
    """OWASP Top 10 compliance dashboard."""
    db = ScanDatabase()
    recent_scans = db.get_scans(limit=10)
    
    # Aggregate OWASP findings across recent scans
    owasp_aggregated = {}
    
    for scan in recent_scans:
        if scan['status'] == 'completed':
            try:
                stats = db.get_scan_statistics(scan['id'])
                owasp_dist = stats.get('owasp_distribution', {})
                
                for category, count in owasp_dist.items():
                    if category not in owasp_aggregated:
                        owasp_aggregated[category] = 0
                    owasp_aggregated[category] += count
            except:
                continue
    
    return render_template('owasp_dashboard.html', owasp_data=owasp_aggregated)

def get_risk_color(risk_level):
    """Get CSS color class for risk level."""
    colors = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
        'LOW': 'success'
    }
    return colors.get(risk_level, 'secondary')

def get_severity_color(severity):
    """Get CSS color class for severity."""
    colors = {
        'ERROR': 'danger',
        'WARNING': 'warning',
        'INFO': 'info'
    }
    return colors.get(severity, 'secondary')

# Add template globals
app.jinja_env.globals.update(
    get_risk_color=get_risk_color,
    get_severity_color=get_severity_color,
    enumerate=enumerate,
    len=len
)

if __name__ == '__main__':
    # Ensure database is initialized
    db = ScanDatabase()
    
    print("QuAi Deep Enhanced Web Interface")
    print("================================")
    print("Access the dashboard at: http://localhost:5000")
    print("Features:")
    print("- Start new scans with real-time progress")
    print("- View historical scan results")
    print("- Compare scans and track improvements")
    print("- OWASP Top 10 compliance dashboard")
    print("- Filter and search findings")
    print("")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)