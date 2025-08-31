import os
import json
import re
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path
import requests

class CVEScanner:
    def __init__(self):
        self.nvd_api_key = os.environ.get('NVD_API_KEY')  # Optional API key for higher rate limits
        self.cve_patterns = self._load_cve_patterns()
        
    def _load_cve_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that commonly indicate CVE-related vulnerabilities."""
        return {
            'sql_injection': [
                r'SELECT.*FROM.*WHERE.*\+',
                r'INSERT.*INTO.*VALUES.*\+',
                r'UPDATE.*SET.*WHERE.*\+',
                r'DELETE.*FROM.*WHERE.*\+',
                r'UNION.*SELECT',
                r'OR.*1=1',
                r'AND.*1=1'
            ],
            'xss': [
                r'<script.*?>',
                r'javascript:',
                r'onload=',
                r'onerror=',
                r'eval\(',
                r'document\.write',
                r'innerHTML.*\+',
                r'outerHTML.*\+'
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'/etc/passwd',
                r'file://',
                r'\.\.%2f',
                r'\.\.%5c'
            ],
            'command_injection': [
                r'exec\(',
                r'system\(',
                r'shell_exec\(',
                r'passthru\(',
                r'eval\(',
                r'subprocess\..*shell=True'
            ],
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']{3,}["\']',
                r'pwd\s*=\s*["\'][^"\']{3,}["\']',
                r'api_?key\s*=\s*["\'][^"\']{10,}["\']',
                r'secret\s*=\s*["\'][^"\']{10,}["\']',
                r'token\s*=\s*["\'][^"\']{20,}["\']'
            ],
            'crypto_issues': [
                r'md5\(',
                r'sha1\(',
                r'DES\(',
                r'RC4\(',
                r'random\.random\(',
                r'Math\.random\(',
                r'ssl_verify.*false',
                r'verify.*false'
            ]
        }
    
    def scan_code_for_cves(self, code_content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan code content for patterns indicating potential CVEs."""
        findings = []
        
        for category, patterns in self.cve_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = code_content[:match.start()].count('\n') + 1
                    
                    # Get context around the match
                    lines = code_content.split('\n')
                    start_line = max(0, line_num - 3)
                    end_line = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[start_line:end_line])
                    
                    findings.append({
                        'file_path': file_path,
                        'line_number': line_num,
                        'category': category,
                        'pattern_matched': pattern,
                        'matched_text': match.group(),
                        'context': context,
                        'severity': self._get_severity_for_category(category),
                        'potential_cves': self._get_related_cves(category)
                    })
        
        return findings
    
    def _get_severity_for_category(self, category: str) -> str:
        """Map vulnerability categories to severity levels."""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'hardcoded_credentials': 'HIGH',
            'crypto_issues': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_related_cves(self, category: str) -> List[str]:
        """Get example CVEs related to each category."""
        cve_examples = {
            'sql_injection': ['CVE-2023-22515', 'CVE-2023-28432', 'CVE-2023-41892'],
            'xss': ['CVE-2023-38831', 'CVE-2023-4966', 'CVE-2023-29357'],
            'path_traversal': ['CVE-2023-46604', 'CVE-2023-34362', 'CVE-2023-3519'],
            'command_injection': ['CVE-2023-22515', 'CVE-2023-46747', 'CVE-2023-22518'],
            'hardcoded_credentials': ['CVE-2023-20198', 'CVE-2023-27997', 'CVE-2023-36844'],
            'crypto_issues': ['CVE-2023-38831', 'CVE-2023-4966', 'CVE-2023-29357']
        }
        return cve_examples.get(category, [])

class DependencyScanner:
    def __init__(self):
        self.supported_manifests = {
            'requirements.txt': self._parse_pip_requirements,
            'package.json': self._parse_npm_package,
            'Pipfile': self._parse_pipfile,
            'pyproject.toml': self._parse_pyproject,
            'composer.json': self._parse_composer,
            'pom.xml': self._parse_maven,
            'build.gradle': self._parse_gradle,
            'go.mod': self._parse_go_mod,
            'Cargo.toml': self._parse_cargo
        }
    
    def find_dependency_files(self, scan_path: str) -> List[str]:
        """Find all dependency manifest files in the scan path."""
        manifest_files = []
        
        for root, dirs, files in os.walk(scan_path):
            # Skip hidden directories and common build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'target', 'build']]
            
            for file in files:
                if file in self.supported_manifests:
                    manifest_files.append(os.path.join(root, file))
        
        return manifest_files
    
    def scan_dependencies(self, manifest_files: List[str]) -> List[Dict[str, Any]]:
        """Scan dependency files for known vulnerabilities."""
        all_findings = []
        
        for manifest_file in manifest_files:
            try:
                file_type = os.path.basename(manifest_file)
                parser = self.supported_manifests.get(file_type)
                
                if parser:
                    dependencies = parser(manifest_file)
                    findings = self._check_dependencies_for_vulnerabilities(dependencies, manifest_file)
                    all_findings.extend(findings)
                    
            except Exception as e:
                print(f"Error scanning {manifest_file}: {e}")
        
        return all_findings
    
    def _parse_pip_requirements(self, file_path: str) -> List[Dict[str, str]]:
        """Parse pip requirements.txt file."""
        dependencies = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle various pip requirement formats
                        if '==' in line:
                            name, version = line.split('==', 1)
                            dependencies.append({'name': name.strip(), 'version': version.strip()})
                        elif '>=' in line:
                            name, version = line.split('>=', 1)
                            dependencies.append({'name': name.strip(), 'version': f">={version.strip()}"})
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_npm_package(self, file_path: str) -> List[Dict[str, str]]:
        """Parse npm package.json file."""
        dependencies = []
        try:
            with open(file_path, 'r') as f:
                package_data = json.load(f)
                
                for dep_type in ['dependencies', 'devDependencies']:
                    if dep_type in package_data:
                        for name, version in package_data[dep_type].items():
                            dependencies.append({'name': name, 'version': version})
                            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Pipfile (simplified parsing)."""
        # This would require toml library for proper parsing
        # For now, return empty list
        return []
    
    def _parse_pyproject(self, file_path: str) -> List[Dict[str, str]]:
        """Parse pyproject.toml (simplified parsing)."""
        # This would require toml library for proper parsing
        # For now, return empty list
        return []
    
    def _parse_composer(self, file_path: str) -> List[Dict[str, str]]:
        """Parse composer.json for PHP dependencies."""
        dependencies = []
        try:
            with open(file_path, 'r') as f:
                composer_data = json.load(f)
                
                for dep_type in ['require', 'require-dev']:
                    if dep_type in composer_data:
                        for name, version in composer_data[dep_type].items():
                            if not name.startswith('php'):  # Skip PHP version constraints
                                dependencies.append({'name': name, 'version': version})
                                
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_maven(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Maven pom.xml (simplified parsing)."""
        # This would require XML parsing
        # For now, return empty list
        return []
    
    def _parse_gradle(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Gradle build.gradle (simplified parsing)."""
        # This would require Gradle-specific parsing
        # For now, return empty list
        return []
    
    def _parse_go_mod(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Go go.mod file."""
        dependencies = []
        try:
            with open(file_path, 'r') as f:
                in_require_block = False
                for line in f:
                    line = line.strip()
                    if line == 'require (':
                        in_require_block = True
                        continue
                    elif line == ')' and in_require_block:
                        in_require_block = False
                        continue
                    elif in_require_block or line.startswith('require '):
                        # Parse require line
                        parts = line.replace('require ', '').split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            dependencies.append({'name': name, 'version': version})
                            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return dependencies
    
    def _parse_cargo(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Rust Cargo.toml (simplified parsing)."""
        # This would require toml library for proper parsing
        # For now, return empty list
        return []
    
    def _check_dependencies_for_vulnerabilities(self, dependencies: List[Dict[str, str]], manifest_file: str) -> List[Dict[str, Any]]:
        """Check dependencies against known vulnerability databases."""
        findings = []
        
        # Known vulnerable dependencies (this would typically come from a database)
        known_vulnerabilities = {
            'requests': {
                'vulnerable_versions': ['<2.31.0'],
                'cve': 'CVE-2023-32681',
                'severity': 'MEDIUM',
                'description': 'Requests vulnerable to proxy URL parsing'
            },
            'flask': {
                'vulnerable_versions': ['<2.3.2'],
                'cve': 'CVE-2023-30861',
                'severity': 'HIGH',
                'description': 'Flask vulnerable to possible disclosure of permanent session cookie'
            },
            'django': {
                'vulnerable_versions': ['<4.2.4'],
                'cve': 'CVE-2023-36053',
                'severity': 'HIGH',
                'description': 'Django vulnerable to regular expression denial of service'
            }
        }
        
        for dep in dependencies:
            dep_name = dep['name'].lower()
            if dep_name in known_vulnerabilities:
                vuln_info = known_vulnerabilities[dep_name]
                
                findings.append({
                    'file_path': manifest_file,
                    'dependency_name': dep['name'],
                    'installed_version': dep['version'],
                    'vulnerability_type': 'dependency',
                    'cve_id': vuln_info['cve'],
                    'severity': vuln_info['severity'],
                    'description': vuln_info['description'],
                    'vulnerable_versions': vuln_info['vulnerable_versions'],
                    'remediation': f"Update {dep['name']} to latest version"
                })
        
        return findings