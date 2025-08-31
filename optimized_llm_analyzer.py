import requests
import json
import textwrap
import time
from typing import Dict, Any, Optional, List
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class OptimizedLLMAnalyzer:
    def __init__(self, 
                 api_url: str = "http://localhost:11434/api/generate", 
                 timeout: int = 60,
                 max_workers: int = 3,
                 enable_caching: bool = True):
        self.api_url = api_url
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_caching = enable_caching
        self.cache = {} if enable_caching else None
        self.rate_limit_delay = 1.0  # Minimum delay between requests
        self.last_request_time = 0
        self.request_lock = threading.Lock()
        
        # Model configuration for different types of analysis
        self.models = {
            'fast': 'qwen2.5-coder:3b',      # Fast model for basic analysis
            'balanced': 'qwen2.5-coder:7b',   # Balanced model
            'detailed': 'qwen2.5-coder:14b'  # Detailed analysis (if available)
        }
        
        # Use the fastest available model by default
        self.default_model = self.models['fast']
        
    def get_cache_key(self, code_snippet: str, message: str) -> str:
        """Generate cache key for request."""
        content = f"{code_snippet}|{message}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def compress_message(self, msg: str, max_len: int = 100) -> str:
        """Optimized message compression."""
        if not msg:
            return "No description"
        
        # Remove extra whitespace and newlines
        clean_msg = ' '.join(msg.strip().split())
        
        # Truncate if too long
        if len(clean_msg) <= max_len:
            return clean_msg
        
        # Smart truncation - try to keep meaningful parts
        if '.' in clean_msg[:max_len]:
            # Find last sentence that fits
            sentences = clean_msg.split('.')
            result = ""
            for sentence in sentences:
                if len(result + sentence + '.') <= max_len:
                    result += sentence + '.'
                else:
                    break
            return result.strip()
        
        return clean_msg[:max_len - 3] + "..."
    
    def trim_code(self, code: str, max_lines: int = 15, max_chars_per_line: int = 120) -> str:
        """Optimized code trimming."""
        if not code:
            return "No code available"
        
        lines = code.strip().splitlines()
        
        # Limit number of lines
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ['...']
        
        # Limit line length
        trimmed_lines = []
        for line in lines:
            if len(line) > max_chars_per_line:
                trimmed_lines.append(line[:max_chars_per_line - 3] + "...")
            else:
                trimmed_lines.append(line)
        
        return '\n'.join(trimmed_lines)
    
    def build_optimized_prompt(self, code_snippet: str, semgrep_message: str) -> str:
        """Build an optimized, concise prompt for faster processing."""
        compressed_msg = self.compress_message(semgrep_message)
        trimmed_code = self.trim_code(code_snippet)
        
        return textwrap.dedent(f"""
            Security Analysis Required:
            Issue: {compressed_msg}
            
            Code:
            ```
            {trimmed_code}
            ```
            
            Provide:
            1. Risk: CRITICAL/HIGH/MEDIUM/LOW
            2. Impact: Brief explanation (1-2 sentences)
            3. Fix: Specific remediation step
            
            Format:
            Risk: [LEVEL]
            Impact: [BRIEF EXPLANATION]
            Fix: [SPECIFIC ACTION]
        """).strip()
    
    def parse_optimized_response(self, llm_text: str) -> Dict[str, Any]:
        """Parse the optimized response format."""
        output = {
            "explanation": "Analysis incomplete",
            "risk_score": "MEDIUM", 
            "remediation_plan": "Manual review required"
        }
        
        if not llm_text:
            return output
        
        try:
            # Look for structured format
            lines = llm_text.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('Risk:'):
                    risk = line.replace('Risk:', '').strip().upper()
                    if risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                        output["risk_score"] = risk
                
                elif line.startswith('Impact:'):
                    impact = line.replace('Impact:', '').strip()
                    if impact:
                        output["explanation"] = impact
                
                elif line.startswith('Fix:'):
                    fix = line.replace('Fix:', '').strip()
                    if fix:
                        output["remediation_plan"] = fix
            
            # Fallback parsing for less structured responses
            if output["explanation"] == "Analysis incomplete":
                # Try to extract meaningful content
                clean_text = llm_text.replace('\n', ' ').strip()
                if len(clean_text) > 10:
                    output["explanation"] = clean_text[:200] + "..." if len(clean_text) > 200 else clean_text
            
        except Exception as e:
            print(f"Error parsing LLM response: {e}")
        
        return output
    
    def make_request_with_rate_limit(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make API request with rate limiting."""
        with self.request_lock:
            # Enforce rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - time_since_last)
            
            self.last_request_time = time.time()
        
        try:
            response = requests.post(
                self.api_url, 
                data=json.dumps(payload), 
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"API request failed with status {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            print("LLM request timed out")
            return None
        except Exception as e:
            print(f"LLM request error: {e}")
            return None
    
    def analyze_vulnerability(self, code_snippet: str, semgrep_message: str, model: str = None) -> Dict[str, Any]:
        """Analyze vulnerability with optimizations."""
        # Check cache first
        if self.enable_caching:
            cache_key = self.get_cache_key(code_snippet, semgrep_message)
            if cache_key in self.cache:
                return self.cache[cache_key]
        
        # Build optimized prompt
        prompt = self.build_optimized_prompt(code_snippet, semgrep_message)
        
        # Use specified model or default
        model_name = model or self.default_model
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Lower temperature for more consistent results
                "top_p": 0.9,
                "max_tokens": 200,   # Limit response length
                "stop": ["---", "Note:", "Additional:"]  # Stop sequences
            }
        }
        
        # Make request
        result = self.make_request_with_rate_limit(payload)
        
        if result and 'response' in result:
            parsed_result = self.parse_optimized_response(result['response'])
            
            # Cache the result
            if self.enable_caching:
                self.cache[cache_key] = parsed_result
            
            return parsed_result
        else:
            # Return fallback result
            return {
                "explanation": "LLM analysis failed - using fallback assessment",
                "risk_score": "MEDIUM",
                "remediation_plan": "Manual security review required"
            }
    
    def batch_analyze_vulnerabilities(self, findings: List[Dict[str, str]], model: str = None) -> List[Dict[str, Any]]:
        """Analyze multiple vulnerabilities in parallel."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_index = {}
            for i, finding in enumerate(findings):
                code_snippet = finding.get('code_snippet', '')
                message = finding.get('message', '')
                
                future = executor.submit(self.analyze_vulnerability, code_snippet, message, model)
                future_to_index[future] = i
            
            # Collect results in order
            results = [None] * len(findings)
            
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result()
                    results[index] = result
                except Exception as e:
                    print(f"Analysis failed for finding {index}: {e}")
                    results[index] = {
                        "explanation": f"Analysis failed: {str(e)}",
                        "risk_score": "MEDIUM", 
                        "remediation_plan": "Manual review required"
                    }
        
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.enable_caching:
            return {"caching": "disabled"}
        
        return {
            "cache_size": len(self.cache),
            "cache_enabled": True,
            "hit_rate": "Not tracked"  # Could be implemented with counters
        }
    
    def clear_cache(self):
        """Clear the analysis cache."""
        if self.cache:
            self.cache.clear()
    
    def health_check(self) -> Dict[str, Any]:
        """Check if the LLM service is available."""
        test_payload = {
            "model": self.default_model,
            "prompt": "Hello",
            "stream": False,
            "options": {"max_tokens": 10}
        }
        
        try:
            response = requests.post(
                self.api_url,
                data=json.dumps(test_payload),
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "model": self.default_model,
                    "response_time": response.elapsed.total_seconds()
                }
            else:
                return {
                    "status": "unhealthy",
                    "error": f"HTTP {response.status_code}"
                }
                
        except Exception as e:
            return {
                "status": "unreachable",
                "error": str(e)
            }
    
    def set_model(self, model_type: str):
        """Set the model to use for analysis."""
        if model_type in self.models:
            self.default_model = self.models[model_type]
        else:
            print(f"Unknown model type: {model_type}")
    
    def estimate_analysis_time(self, num_findings: int) -> Dict[str, Any]:
        """Estimate time for analyzing a batch of findings."""
        # Base time per finding (in seconds)
        base_time = 3.0  # Conservative estimate
        
        # Account for parallelism
        parallel_time = (num_findings / self.max_workers) * base_time
        
        # Add overhead
        overhead = min(10, num_findings * 0.1)
        
        total_time = parallel_time + overhead
        
        return {
            "estimated_minutes": round(total_time / 60, 1),
            "estimated_seconds": round(total_time),
            "parallelization": self.max_workers,
            "findings_count": num_findings
        }