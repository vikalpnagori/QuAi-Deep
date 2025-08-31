import subprocess
import json
import os
from typing import Optional, List, Dict, Any
from pathlib import Path

class EnhancedSemgrepScanner:
    def __init__(self, repo_path: str, specific_path: str = None):
        self.repo_path = repo_path
        self.specific_path = specific_path
        self.results = None
        self.scan_target = self._determine_scan_target()
        
    def _determine_scan_target(self) -> str:
        """Determine what path to scan based on configuration."""
        if self.specific_path:
            # If specific path is provided, ensure it's within the repo
            if os.path.isabs(self.specific_path):
                scan_path = self.specific_path
            else:
                scan_path = os.path.join(self.repo_path, self.specific_path)
            
            if os.path.exists(scan_path):
                return scan_path
            else:
                print(f"Specific path {scan_path} does not exist, scanning entire repo")
                return self.repo_path
        
        return self.repo_path
    
    def run_scan(self, custom_rules: List[str] = None, exclude_rules: List[str] = None) -> Optional[Dict[str, Any]]:
        """Run Semgrep scan with enhanced configuration options."""
        print(f"Starting enhanced Semgrep scan on: {self.scan_target}")
        
        # Build command with various configuration options
        command = ['semgrep']
        
        # Add configuration
        if custom_rules:
            for rule in custom_rules:
                command.extend(['--config', rule])
        else:
            command.extend(['--config', 'auto'])
        
        # Add exclusions
        if exclude_rules:
            for rule in exclude_rules:
                command.extend(['--exclude-rule', rule])
        
        # Add common exclusions
        command.extend([
            '--exclude', 'node_modules',
            '--exclude', '__pycache__',
            '--exclude', '.git',
            '--exclude', 'build',
            '--exclude', 'dist',
            '--exclude', 'target',
            '--exclude', 'vendor'
        ])
        
        # Add severity and output options
        command.extend([
            '--json',
            '--verbose',
            '--metrics=off',  # Disable telemetry
            '--disable-version-check'
        ])
        
        # Add scan target
        command.append(self.scan_target)
        
        try:
            print(f"Running command: {' '.join(command)}")
            process = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=False,  # Don't raise exception on non-zero exit
                timeout=1800  # 30 minute timeout
            )
            
            # Semgrep returns exit code 1 when findings are found, which is normal
            if process.returncode > 2:  # Only worry about exit codes > 2
                print(f"Semgrep scan failed with exit code {process.returncode}: {process.stderr}")
                return None
            
            if process.stdout:
                self.results = json.loads(process.stdout)
                print(f"Semgrep scan complete. Found {len(self.results.get('results', []))} findings.")
                return self.results
            else:
                print("Semgrep scan completed but produced no output")
                return {"results": []}
                
        except subprocess.TimeoutExpired:
            print("Semgrep scan timed out after 30 minutes")
            return None
        except json.JSONDecodeError as e:
            print(f"Failed to decode Semgrep JSON output: {e}")
            print(f"Raw output: {process.stdout[:500]}...")
            return None
        except Exception as e:
            print(f"Unexpected error during Semgrep scan: {e}")
            return None
    
    def run_focused_scan(self, file_extensions: List[str] = None, languages: List[str] = None) -> Optional[Dict[str, Any]]:
        """Run a focused scan on specific file types or languages."""
        print("Starting focused Semgrep scan...")
        
        command = ['semgrep', '--config=auto', '--json']
        
        # Add language filters
        if languages:
            for lang in languages:
                command.extend(['--lang', lang])
        
        # Add include patterns for file extensions
        if file_extensions:
            for ext in file_extensions:
                command.extend(['--include', f'*.{ext.lstrip(".")}'])
        
        # Add common exclusions
        command.extend([
            '--exclude', 'node_modules',
            '--exclude', '__pycache__',
            '--exclude', '.git',
            '--exclude', 'test',
            '--exclude', 'tests'
        ])
        
        command.append(self.scan_target)
        
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=900)
            
            if process.returncode > 2:
                print(f"Focused scan failed: {process.stderr}")
                return None
                
            if process.stdout:
                self.results = json.loads(process.stdout)
                print(f"Focused scan complete. Found {len(self.results.get('results', []))} findings.")
                return self.results
            else:
                return {"results": []}
                
        except Exception as e:
            print(f"Error in focused scan: {e}")
            return None
    
    def run_security_focused_scan(self) -> Optional[Dict[str, Any]]:
        """Run a scan focused specifically on security rules."""
        print("Starting security-focused Semgrep scan...")
        
        security_configs = [
            'p/security-audit',
            'p/owasp-top-ten',
            'p/cwe-top-25',
            'p/r2c-security-audit'
        ]
        
        command = ['semgrep', '--json', '--metrics=off']
        
        # Add security configurations
        for config in security_configs:
            command.extend(['--config', config])
        
        # Add exclusions
        command.extend([
            '--exclude', 'node_modules',
            '--exclude', '__pycache__',
            '--exclude', '.git',
            '--exclude', 'test',
            '--exclude', 'tests',
            '--exclude', 'spec'
        ])
        
        command.append(self.scan_target)
        
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800)
            
            if process.returncode > 2:
                print(f"Security scan failed: {process.stderr}")
                return None
                
            if process.stdout:
                self.results = json.loads(process.stdout)
                print(f"Security scan complete. Found {len(self.results.get('results', []))} findings.")
                return self.results
            else:
                return {"results": []}
                
        except Exception as e:
            print(f"Error in security scan: {e}")
            return None
    
    def save_results(self, output_file: str = "semgrep_results.json") -> Optional[str]:
        """Save scan results to file with enhanced metadata."""
        if self.results:
            # Add metadata to results
            enhanced_results = {
                'scan_metadata': {
                    'scan_target': self.scan_target,
                    'repo_path': self.repo_path,
                    'specific_path': self.specific_path,
                    'scan_timestamp': None,  # Will be set by calling code
                    'findings_count': len(self.results.get('results', []))
                },
                'results': self.results.get('results', []),
                'errors': self.results.get('errors', [])
            }
            
            with open(output_file, 'w') as f:
                json.dump(enhanced_results, f, indent=4)
            print(f"Enhanced scan results saved to {output_file}")
            return output_file
        
        print("No results to save")
        return None
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results."""
        if not self.results:
            return {"status": "no_results"}
        
        findings = self.results.get('results', [])
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by file
        file_counts = {}
        for finding in findings:
            file_path = finding.get('path', 'unknown')
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
        
        # Get most common issues
        rule_counts = {}
        for finding in findings:
            rule_id = finding.get('check_id', 'unknown')
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'status': 'completed',
            'total_findings': len(findings),
            'severity_distribution': severity_counts,
            'files_with_issues': len(file_counts),
            'top_files_by_issues': sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_rule_violations': top_rules
        }