import json
import os
from typing import List, Dict, Any, Optional
from database import ScanDatabase
from llm_analyzer import LLMAnalyzer
from cve_scanner import CVEScanner, DependencyScanner
import jsonlines
from datetime import datetime

class EnhancedResultsProcessor:
    def __init__(self, semgrep_results_path: str, scan_path: str = None):
        self.semgrep_results_path = semgrep_results_path
        self.scan_path = scan_path
        self.database = ScanDatabase()
        self.llm_analyzer = LLMAnalyzer()
        self.cve_scanner = CVEScanner()
        self.dependency_scanner = DependencyScanner()
        self.current_scan_id = None
        
    def process_scan_comprehensively(self, repository_url: str, scan_path: str = None) -> Dict[str, Any]:
        """Process a complete scan with incremental saving and comprehensive analysis."""
        try:
            # Create scan record in database
            scan_type = 'path' if scan_path else 'full'
            self.current_scan_id = self.database.create_scan(repository_url, scan_path, scan_type)
            
            print(f"Started comprehensive scan (ID: {self.current_scan_id})")
            
            # Phase 1: Process Semgrep findings
            semgrep_findings = self._process_semgrep_findings()
            
            # Phase 2: Scan for additional CVE patterns
            cve_findings = self._scan_for_cve_patterns()
            
            # Phase 3: Scan dependencies
            dependency_findings = self._scan_dependencies()
            
            # Combine all findings
            total_findings = len(semgrep_findings) + len(cve_findings) + len(dependency_findings)
            
            # Update scan completion
            self.database.update_scan_status(self.current_scan_id, 'completed', total_findings)
            
            return {
                'status': 'success',
                'scan_id': self.current_scan_id,
                'semgrep_findings': len(semgrep_findings),
                'cve_findings': len(cve_findings),
                'dependency_findings': len(dependency_findings),
                'total_findings': total_findings
            }
            
        except Exception as e:
            if self.current_scan_id:
                self.database.update_scan_status(self.current_scan_id, 'failed')
            print(f"Scan processing failed: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'scan_id': self.current_scan_id
            }
    
    def _process_semgrep_findings(self) -> List[Dict[str, Any]]:
        """Process Semgrep findings with incremental LLM analysis and saving."""
        if not os.path.exists(self.semgrep_results_path):
            print(f"Semgrep results file not found: {self.semgrep_results_path}")
            return []
        
        with open(self.semgrep_results_path, 'r') as f:
            raw_findings = json.load(f)
        
        findings_list = raw_findings.get('results', [])
        processed_findings = []
        
        print(f"Processing {len(findings_list)} Semgrep findings...")
        
        # Create incremental save file
        incremental_save_file = f"scan_{self.current_scan_id}_incremental.jsonl"
        
        for i, finding in enumerate(findings_list):
            try:
                print(f"Processing finding {i+1}/{len(findings_list)}")
                
                # Extract Semgrep data
                code_snippet = finding['extra']['lines']
                semgrep_message = finding['extra']['message']
                rule_id = finding['check_id']
                
                # Get OWASP category
                owasp_category = self.database.get_owasp_category(rule_id)
                
                # Analyze with LLM (with retry logic)
                llm_analysis = self._analyze_with_llm_retry(code_snippet, semgrep_message)
                
                # Prepare finding data
                finding_data = {
                    'file_path': finding['path'],
                    'line_number': finding['start']['line'],
                    'code_snippet': code_snippet,
                    'semgrep_rule_id': rule_id,
                    'semgrep_message': semgrep_message,
                    'semgrep_severity': finding['extra']['severity'],
                    'llm_explanation': llm_analysis['explanation'],
                    'llm_risk_score': llm_analysis['risk_score'],
                    'remediation_plan': llm_analysis['remediation_plan'],
                    'cve_references': [],  # Will be populated if relevant
                    'owasp_category': owasp_category
                }
                
                # Save to database immediately
                finding_id = self.database.add_finding(self.current_scan_id, finding_data)
                
                # Save to incremental file
                finding_data['finding_id'] = finding_id
                finding_data['processed_at'] = datetime.now().isoformat()
                
                with jsonlines.open(incremental_save_file, mode='a') as writer:
                    writer.write(finding_data)
                
                processed_findings.append(finding_data)
                
            except Exception as e:
                print(f"Error processing finding {i+1}: {e}")
                # Continue with next finding rather than failing completely
                continue
        
        print(f"Completed processing {len(processed_findings)} Semgrep findings")
        return processed_findings
    
    def _analyze_with_llm_retry(self, code_snippet: str, message: str, max_retries: int = 3) -> Dict[str, Any]:
        """Analyze with LLM with retry logic and fallback."""
        for attempt in range(max_retries):
            try:
                result = self.llm_analyzer.analyze_vulnerability(code_snippet, message)
                if result and result.get('explanation'):
                    return result
            except Exception as e:
                print(f"LLM analysis attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    # Return fallback analysis
                    return {
                        'explanation': f"LLM analysis failed after {max_retries} attempts. Manual review required.",
                        'risk_score': 'MEDIUM',
                        'remediation_plan': 'Please review this finding manually and apply appropriate security measures.'
                    }
        
        return {
            'explanation': 'Analysis failed',
            'risk_score': 'MEDIUM', 
            'remediation_plan': 'Manual review required'
        }
    
    def _scan_for_cve_patterns(self) -> List[Dict[str, Any]]:
        """Scan code files for additional CVE patterns not caught by Semgrep."""
        if not self.scan_path:
            print("No scan path provided for CVE pattern scanning")
            return []
        
        cve_findings = []
        print("Scanning for additional CVE patterns...")
        
        # Walk through source files
        for root, dirs, files in os.walk(self.scan_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'target', 'build', 'dist']]
            
            for file in files:
                if self._is_source_file(file):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Scan for CVE patterns
                        file_findings = self.cve_scanner.scan_code_for_cves(content, file_path)
                        
                        # Process each CVE finding
                        for cve_finding in file_findings:
                            finding_data = {
                                'file_path': cve_finding['file_path'],
                                'line_number': cve_finding['line_number'],
                                'code_snippet': cve_finding['context'],
                                'semgrep_rule_id': f"cve-pattern-{cve_finding['category']}",
                                'semgrep_message': f"Potential {cve_finding['category']} vulnerability detected",
                                'semgrep_severity': cve_finding['severity'],
                                'llm_explanation': f"Code matches pattern indicative of {cve_finding['category']}",
                                'llm_risk_score': cve_finding['severity'],
                                'remediation_plan': self._get_remediation_for_cve_category(cve_finding['category']),
                                'cve_references': cve_finding['potential_cves'],
                                'owasp_category': self.database.get_owasp_category(cve_finding['category'])
                            }
                            
                            # Save to database
                            self.database.add_finding(self.current_scan_id, finding_data)
                            cve_findings.append(finding_data)
                            
                    except Exception as e:
                        print(f"Error scanning file {file_path}: {e}")
                        continue
        
        print(f"Found {len(cve_findings)} additional CVE pattern matches")
        return cve_findings
    
    def _scan_dependencies(self) -> List[Dict[str, Any]]:
        """Scan project dependencies for known vulnerabilities."""
        if not self.scan_path:
            print("No scan path provided for dependency scanning")
            return []
        
        print("Scanning dependencies for vulnerabilities...")
        
        # Find dependency manifest files
        manifest_files = self.dependency_scanner.find_dependency_files(self.scan_path)
        
        if not manifest_files:
            print("No dependency manifest files found")
            return []
        
        print(f"Found {len(manifest_files)} dependency manifest files")
        
        # Scan dependencies
        dependency_findings = self.dependency_scanner.scan_dependencies(manifest_files)
        
        # Process and save findings
        processed_findings = []
        for dep_finding in dependency_findings:
            finding_data = {
                'file_path': dep_finding['file_path'],
                'line_number': 1,  # Manifest files don't have specific line numbers
                'code_snippet': f"Dependency: {dep_finding['dependency_name']} {dep_finding['installed_version']}",
                'semgrep_rule_id': 'dependency-vulnerability',
                'semgrep_message': dep_finding['description'],
                'semgrep_severity': dep_finding['severity'],
                'llm_explanation': f"Vulnerable dependency detected: {dep_finding['dependency_name']}",
                'llm_risk_score': dep_finding['severity'],
                'remediation_plan': dep_finding['remediation'],
                'cve_references': [dep_finding['cve_id']],
                'owasp_category': 'A06:2021 – Vulnerable and Outdated Components'
            }
            
            # Save to database
            self.database.add_finding(self.current_scan_id, finding_data)
            processed_findings.append(finding_data)
        
        print(f"Found {len(processed_findings)} vulnerable dependencies")
        return processed_findings
    
    def _is_source_file(self, filename: str) -> bool:
        """Check if a file is a source code file we should scan."""
        source_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go', 
            '.rs', '.c', '.cpp', '.cs', '.scala', '.kt', '.swift', '.m', '.h',
            '.sql', '.xml', '.yaml', '.yml', '.json', '.html', '.htm', '.jsp',
            '.asp', '.aspx', '.pl', '.sh', '.bash', '.ps1', '.bat'
        }
        
        return any(filename.lower().endswith(ext) for ext in source_extensions)
    
    def _get_remediation_for_cve_category(self, category: str) -> str:
        """Get remediation advice for CVE categories."""
        remediations = {
            'sql_injection': 'Use parameterized queries or prepared statements. Validate and sanitize user input.',
            'xss': 'Encode output data, validate input, use Content Security Policy (CSP).',
            'path_traversal': 'Validate file paths, use allowlists, avoid user-controlled file paths.',
            'command_injection': 'Avoid system calls with user input. Use safe APIs and input validation.',
            'hardcoded_credentials': 'Remove hardcoded credentials. Use environment variables or secure vaults.',
            'crypto_issues': 'Use strong cryptographic algorithms (AES, SHA-256+). Avoid deprecated methods.'
        }
        
        return remediations.get(category, 'Review the code for security issues and follow security best practices.')
    
    def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """Get comprehensive scan results from database."""
        findings = self.database.get_scan_findings(scan_id)
        statistics = self.database.get_scan_statistics(scan_id)
        
        return {
            'scan_id': scan_id,
            'findings': findings,
            'statistics': statistics
        }