import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
import hashlib

class ScanDatabase:
    def __init__(self, db_path: str = "scan_results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repository_url TEXT,
                scan_path TEXT,
                scan_type TEXT DEFAULT 'full',
                status TEXT DEFAULT 'running',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                total_findings INTEGER DEFAULT 0,
                scan_hash TEXT UNIQUE
            )
        ''')
        
        # Create findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                file_path TEXT,
                line_number INTEGER,
                code_snippet TEXT,
                semgrep_rule_id TEXT,
                semgrep_message TEXT,
                semgrep_severity TEXT,
                llm_explanation TEXT,
                llm_risk_score TEXT,
                remediation_plan TEXT,
                cve_references TEXT,
                owasp_category TEXT,
                is_processed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Create CVE database table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_database (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_components TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create OWASP mappings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS owasp_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_pattern TEXT,
                owasp_category TEXT,
                description TEXT
            )
        ''')
        
        # Insert default OWASP mappings
        self._insert_default_owasp_mappings(cursor)
        
        conn.commit()
        conn.close()
    
    def _insert_default_owasp_mappings(self, cursor):
        """Insert default OWASP Top 10 mappings."""
        owasp_mappings = [
            ('sql-injection', 'A03:2021 – Injection', 'SQL Injection vulnerabilities'),
            ('xss', 'A03:2021 – Injection', 'Cross-Site Scripting vulnerabilities'),
            ('path-traversal', 'A01:2021 – Broken Access Control', 'Path traversal vulnerabilities'),
            ('insecure-crypto', 'A02:2021 – Cryptographic Failures', 'Cryptographic vulnerabilities'),
            ('hardcoded-secret', 'A07:2021 – Identification and Authentication Failures', 'Hardcoded credentials'),
            ('deserialization', 'A08:2021 – Software and Data Integrity Failures', 'Insecure deserialization'),
            ('logging', 'A09:2021 – Security Logging and Monitoring Failures', 'Insufficient logging'),
            ('ssrf', 'A10:2021 – Server-Side Request Forgery', 'Server-side request forgery')
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO owasp_mappings (rule_pattern, owasp_category, description)
            VALUES (?, ?, ?)
        ''', owasp_mappings)
    
    def create_scan(self, repository_url: str, scan_path: str = None, scan_type: str = 'full') -> int:
        """Create a new scan record and return scan ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Generate unique hash for this scan
        scan_hash = hashlib.md5(f"{repository_url}_{scan_path}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO scans (repository_url, scan_path, scan_type, scan_hash)
            VALUES (?, ?, ?, ?)
        ''', (repository_url, scan_path, scan_type, scan_hash))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id
    
    def update_scan_status(self, scan_id: int, status: str, total_findings: int = None):
        """Update scan status and completion time."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status == 'completed':
            cursor.execute('''
                UPDATE scans 
                SET status = ?, completed_at = CURRENT_TIMESTAMP, total_findings = ?
                WHERE id = ?
            ''', (status, total_findings, scan_id))
        else:
            cursor.execute('''
                UPDATE scans SET status = ? WHERE id = ?
            ''', (status, scan_id))
        
        conn.commit()
        conn.close()
    
    def add_finding(self, scan_id: int, finding_data: Dict[str, Any]) -> int:
        """Add a finding to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings (
                scan_id, file_path, line_number, code_snippet,
                semgrep_rule_id, semgrep_message, semgrep_severity,
                llm_explanation, llm_risk_score, remediation_plan,
                cve_references, owasp_category, is_processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            finding_data.get('file_path', ''),
            finding_data.get('line_number', 0),
            finding_data.get('code_snippet', ''),
            finding_data.get('semgrep_rule_id', ''),
            finding_data.get('semgrep_message', ''),
            finding_data.get('semgrep_severity', ''),
            finding_data.get('llm_explanation', ''),
            finding_data.get('llm_risk_score', ''),
            finding_data.get('remediation_plan', ''),
            json.dumps(finding_data.get('cve_references', [])),
            finding_data.get('owasp_category', ''),
            True
        ))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return finding_id
    
    def get_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scans with summary information."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
        
        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return scans
    
    def get_scan_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get all findings for a specific scan."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT f.*, s.repository_url, s.scan_path
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE f.scan_id = ?
            ORDER BY f.llm_risk_score DESC, f.semgrep_severity DESC
        ''', (scan_id,))
        
        findings = []
        for row in cursor.fetchall():
            finding = dict(row)
            # Parse CVE references back to list
            if finding['cve_references']:
                finding['cve_references'] = json.loads(finding['cve_references'])
            else:
                finding['cve_references'] = []
            findings.append(finding)
        
        conn.close()
        return findings
    
    def get_owasp_category(self, semgrep_rule_id: str) -> str:
        """Get OWASP category for a semgrep rule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT owasp_category FROM owasp_mappings
            WHERE ? LIKE '%' || rule_pattern || '%'
            LIMIT 1
        ''', (semgrep_rule_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else 'Uncategorized'
    
    def get_scan_statistics(self, scan_id: int) -> Dict[str, Any]:
        """Get statistics for a specific scan."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Risk score distribution
        cursor.execute('''
            SELECT llm_risk_score, COUNT(*) as count
            FROM findings
            WHERE scan_id = ?
            GROUP BY llm_risk_score
        ''', (scan_id,))
        
        risk_distribution = {row[0]: row[1] for row in cursor.fetchall()}
        
        # OWASP category distribution
        cursor.execute('''
            SELECT owasp_category, COUNT(*) as count
            FROM findings
            WHERE scan_id = ? AND owasp_category != 'Uncategorized'
            GROUP BY owasp_category
        ''', (scan_id,))
        
        owasp_distribution = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Total findings
        cursor.execute('''
            SELECT COUNT(*) FROM findings WHERE scan_id = ?
        ''', (scan_id,))
        
        total_findings = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_findings': total_findings,
            'risk_distribution': risk_distribution,
            'owasp_distribution': owasp_distribution
        }