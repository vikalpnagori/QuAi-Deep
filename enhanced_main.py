#!/usr/bin/env python3
"""
QuAi Deep - Enhanced Malicious Code Detection and Vulnerability Assessment Tool

This enhanced version provides:
- Database persistence for scan results
- Incremental result saving to prevent data loss
- CVE pattern detection and dependency scanning
- Support for scanning specific paths
- Comprehensive OWASP Top 10 mapping
- Historical scan tracking and comparison
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from ingestor import CodeIngestor
from enhanced_scanner import EnhancedSemgrepScanner
from enhanced_results_processor import EnhancedResultsProcessor
from database import ScanDatabase

class QuAiDeepEnhanced:
    def __init__(self):
        self.database = ScanDatabase()
        
    def run_comprehensive_scan(self, 
                             repository_url: str,
                             specific_path: str = None,
                             scan_type: str = 'comprehensive',
                             custom_rules: List[str] = None) -> Dict[str, Any]:
        """
        Run a comprehensive vulnerability scan with all enhancements.
        
        Args:
            repository_url: Git repository URL or local path
            specific_path: Specific path within repo to scan (optional)
            scan_type: Type of scan ('comprehensive', 'security', 'focused')
            custom_rules: Custom Semgrep rules to use (optional)
        """
        
        print(f"\n{'='*60}")
        print(f"QuAi Deep Enhanced - Comprehensive Security Scan")
        print(f"{'='*60}")
        print(f"Repository: {repository_url}")
        if specific_path:
            print(f"Specific Path: {specific_path}")
        print(f"Scan Type: {scan_type}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        try:
            # Phase 1: Repository setup
            repo_path = self._setup_repository(repository_url)
            if not repo_path:
                return self._error_result("Failed to setup repository")
            
            # Determine actual scan path
            actual_scan_path = self._determine_scan_path(repo_path, specific_path)
            
            # Phase 2: Run Semgrep scan
            semgrep_results_path = self._run_semgrep_scan(
                repo_path, specific_path, scan_type, custom_rules
            )
            
            if not semgrep_results_path:
                return self._error_result("Semgrep scan failed")
            
            # Phase 3: Comprehensive analysis and processing
            processor = EnhancedResultsProcessor(semgrep_results_path, actual_scan_path)
            
            scan_results = processor.process_scan_comprehensively(
                repository_url, specific_path
            )
            
            # Phase 4: Generate final report
            if scan_results['status'] == 'success':
                final_report = self._generate_final_report(scan_results['scan_id'])
                scan_results.update(final_report)
            
            # Cleanup
            if repository_url.startswith(('http://', 'https://', 'git@')):
                self._cleanup_temp_repo(repo_path)
            
            return scan_results
            
        except Exception as e:
            print(f"Scan failed with error: {e}")
            return self._error_result(str(e))
    
    def _setup_repository(self, repository_url: str) -> Optional[str]:
        """Setup repository for scanning (clone if remote, validate if local)."""
        if repository_url.startswith(('http://', 'https://', 'git@')):
            print("Cloning remote repository...")
            ingestor = CodeIngestor(repository_url)
            repo_path = ingestor.clone_repo()
            self.temp_ingestor = ingestor  # Keep reference for cleanup
            return repo_path
        else:
            # Local path
            if os.path.exists(repository_url):
                print(f"Using local repository: {repository_url}")
                return repository_url
            else:
                print(f"Local path does not exist: {repository_url}")
                return None
    
    def _determine_scan_path(self, repo_path: str, specific_path: str = None) -> str:
        """Determine the actual path to scan."""
        if specific_path:
            if os.path.isabs(specific_path):
                return specific_path if os.path.exists(specific_path) else repo_path
            else:
                full_path = os.path.join(repo_path, specific_path)
                return full_path if os.path.exists(full_path) else repo_path
        return repo_path
    
    def _run_semgrep_scan(self, 
                         repo_path: str, 
                         specific_path: str = None,
                         scan_type: str = 'comprehensive',
                         custom_rules: List[str] = None) -> Optional[str]:
        """Run the appropriate type of Semgrep scan."""
        
        scanner = EnhancedSemgrepScanner(repo_path, specific_path)
        
        # Choose scan method based on scan type
        if scan_type == 'security':
            scan_results = scanner.run_security_focused_scan()
        elif scan_type == 'focused':
            # You could add parameters for specific languages/extensions
            scan_results = scanner.run_focused_scan()
        else:  # comprehensive
            scan_results = scanner.run_scan(custom_rules=custom_rules)
        
        if scan_results:
            output_file = f"semgrep_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            return scanner.save_results(output_file)
        
        return None
    
    def _generate_final_report(self, scan_id: int) -> Dict[str, Any]:
        """Generate final comprehensive report."""
        print("\nGenerating comprehensive report...")
        
        # Get scan results from database
        findings = self.database.get_scan_findings(scan_id)
        statistics = self.database.get_scan_statistics(scan_id)
        
        # Generate OWASP Top 10 analysis
        owasp_analysis = self._generate_owasp_analysis(findings)
        
        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(findings, statistics)
        
        # Generate remediation priorities
        remediation_priorities = self._generate_remediation_priorities(findings)
        
        return {
            'report': {
                'scan_id': scan_id,
                'total_findings': statistics['total_findings'],
                'risk_distribution': statistics['risk_distribution'],
                'owasp_analysis': owasp_analysis,
                'risk_assessment': risk_assessment,
                'remediation_priorities': remediation_priorities,
                'report_generated_at': datetime.now().isoformat()
            }
        }
    
    def _generate_owasp_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate OWASP Top 10 compliance analysis."""
        owasp_categories = {}
        
        for finding in findings:
            category = finding.get('owasp_category', 'Uncategorized')
            if category not in owasp_categories:
                owasp_categories[category] = {
                    'count': 0,
                    'severity_breakdown': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                    'files_affected': set()
                }
            
            owasp_categories[category]['count'] += 1
            severity = finding.get('llm_risk_score', 'MEDIUM').upper()
            if severity in owasp_categories[category]['severity_breakdown']:
                owasp_categories[category]['severity_breakdown'][severity] += 1
            
            owasp_categories[category]['files_affected'].add(finding.get('file_path', ''))
        
        # Convert sets to counts
        for category in owasp_categories:
            owasp_categories[category]['files_affected'] = len(owasp_categories[category]['files_affected'])
        
        return owasp_categories
    
    def _generate_risk_assessment(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall risk assessment."""
        total_findings = statistics['total_findings']
        risk_dist = statistics['risk_distribution']
        
        # Calculate risk score (weighted)
        risk_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        total_risk_score = sum(risk_dist.get(level, 0) * weight for level, weight in risk_weights.items())
        
        # Determine overall risk level
        if risk_dist.get('CRITICAL', 0) > 0:
            overall_risk = 'CRITICAL'
        elif risk_dist.get('HIGH', 0) > 5:
            overall_risk = 'HIGH'
        elif risk_dist.get('HIGH', 0) > 0 or risk_dist.get('MEDIUM', 0) > 10:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        return {
            'overall_risk_level': overall_risk,
            'total_risk_score': total_risk_score,
            'findings_requiring_immediate_attention': risk_dist.get('CRITICAL', 0) + risk_dist.get('HIGH', 0),
            'compliance_status': 'NON_COMPLIANT' if risk_dist.get('CRITICAL', 0) > 0 else 'NEEDS_REVIEW'
        }
    
    def _generate_remediation_priorities(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation recommendations."""
        # Sort findings by risk level and impact
        risk_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                risk_order.get(x.get('llm_risk_score', 'LOW').upper(), 1),
                len(x.get('cve_references', [])),
                x.get('line_number', 0)
            ),
            reverse=True
        )
        
        # Group top issues for remediation
        top_priorities = []
        seen_files = set()
        
        for finding in sorted_findings[:20]:  # Top 20 issues
            if finding.get('file_path') not in seen_files:
                top_priorities.append({
                    'priority_rank': len(top_priorities) + 1,
                    'file_path': finding.get('file_path'),
                    'risk_score': finding.get('llm_risk_score'),
                    'issue_type': finding.get('semgrep_rule_id'),
                    'remediation': finding.get('remediation_plan'),
                    'owasp_category': finding.get('owasp_category'),
                    'cve_count': len(finding.get('cve_references', []))
                })
                seen_files.add(finding.get('file_path'))
        
        return top_priorities
    
    def _cleanup_temp_repo(self, repo_path: str):
        """Clean up temporary repository."""
        if hasattr(self, 'temp_ingestor'):
            self.temp_ingestor.cleanup()
    
    def _error_result(self, message: str) -> Dict[str, Any]:
        """Return standardized error result."""
        return {
            'status': 'error',
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
    
    def list_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List recent scans from database."""
        return self.database.get_scans(limit)
    
    def get_scan_details(self, scan_id: int) -> Dict[str, Any]:
        """Get detailed results for a specific scan."""
        findings = self.database.get_scan_findings(scan_id)
        statistics = self.database.get_scan_statistics(scan_id)
        
        return {
            'scan_id': scan_id,
            'findings': findings,
            'statistics': statistics
        }


def main():
    parser = argparse.ArgumentParser(
        description="QuAi Deep Enhanced - Comprehensive Source Code Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Scan entire repository
    python enhanced_main.py https://github.com/user/repo.git
    
    # Scan specific path in repository
    python enhanced_main.py https://github.com/user/repo.git --path src/
    
    # Run security-focused scan
    python enhanced_main.py /local/repo --scan-type security
    
    # List recent scans
    python enhanced_main.py --list-scans
    
    # Get details of specific scan
    python enhanced_main.py --scan-id 123
        """
    )
    
    parser.add_argument(
        "repository", 
        nargs='?',
        help="Repository URL (Git) or local path to scan"
    )
    
    parser.add_argument(
        "--path", 
        help="Specific path within repository to scan"
    )
    
    parser.add_argument(
        "--scan-type",
        choices=['comprehensive', 'security', 'focused'],
        default='comprehensive',
        help="Type of scan to perform"
    )
    
    parser.add_argument(
        "--custom-rules",
        nargs='*',
        help="Custom Semgrep rule configurations"
    )
    
    parser.add_argument(
        "--list-scans",
        action='store_true',
        help="List recent scans"
    )
    
    parser.add_argument(
        "--scan-id",
        type=int,
        help="Get details for specific scan ID"
    )
    
    parser.add_argument(
        "--output-format",
        choices=['json', 'summary'],
        default='summary',
        help="Output format"
    )
    
    args = parser.parse_args()
    
    scanner = QuAiDeepEnhanced()
    
    # Handle different operations
    if args.list_scans:
        scans = scanner.list_recent_scans()
        if args.output_format == 'json':
            print(json.dumps(scans, indent=2))
        else:
            print("\nRecent Scans:")
            print("-" * 60)
            for scan in scans:
                status_icon = "✓" if scan['status'] == 'completed' else "⚠" if scan['status'] == 'running' else "✗"
                print(f"{status_icon} ID: {scan['id']} | {scan['created_at']} | {scan['repository_url']} | Findings: {scan['total_findings']}")
        return
    
    if args.scan_id:
        details = scanner.get_scan_details(args.scan_id)
        if args.output_format == 'json':
            print(json.dumps(details, indent=2, default=str))
        else:
            print(f"\nScan Details for ID: {args.scan_id}")
            print("-" * 60)
            stats = details['statistics']
            print(f"Total Findings: {stats['total_findings']}")
            print(f"Risk Distribution: {stats['risk_distribution']}")
            print(f"OWASP Categories: {stats['owasp_distribution']}")
        return
    
    if not args.repository:
        parser.print_help()
        return
    
    # Run scan
    results = scanner.run_comprehensive_scan(
        repository_url=args.repository,
        specific_path=args.path,
        scan_type=args.scan_type,
        custom_rules=args.custom_rules
    )
    
    # Output results
    if args.output_format == 'json':
        print(json.dumps(results, indent=2, default=str))
    else:
        # Print summary
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        
        if results['status'] == 'success':
            report = results.get('report', {})
            print(f"Scan ID: {report.get('scan_id')}")
            print(f"Total Findings: {report.get('total_findings', 0)}")
            
            risk_dist = report.get('risk_distribution', {})
            print(f"Risk Distribution:")
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = risk_dist.get(level, 0)
                if count > 0:
                    print(f"  {level}: {count}")
            
            risk_assessment = report.get('risk_assessment', {})
            print(f"Overall Risk Level: {risk_assessment.get('overall_risk_level', 'UNKNOWN')}")
            
            print(f"\nDetailed results saved in database (Scan ID: {report.get('scan_id')})")
            print("Use --scan-id to view detailed findings")
        else:
            print(f"Scan failed: {results.get('message', 'Unknown error')}")


if __name__ == "__main__":
    main()