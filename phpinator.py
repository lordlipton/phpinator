#!/usr/bin/env python3
"""
PHP Security Sink Scanner with AI Verification
Token-optimized with pattern caching and smart context extraction
For penetration testing and security research on PHP codebases
"""

import os
import re
import json
import time
import subprocess
import datetime
import sys
import hashlib
import argparse
from collections import defaultdict

# ================= CONFIGURATION =================
WAIT_MINUTES = 0  # Time between AI verification calls (0 for testing, 3+ for production)
MAX_CONTEXT_HOPS = 3  # How many times AI can request additional files
MIN_SCORE_THRESHOLD = 50  # Minimum score to trigger AI verification

# Filenames
REPORT_FILENAME = "php_security_report.md"
VULN_FILENAME = "VERIFIED_VULNERABILITIES.md"
SCAN_DB_FILE = "scan_results_temp.json"
PROGRESS_FILE = "verification_progress.json"
PATTERN_CACHE_FILE = "known_safe_patterns.json"

# Global Ignore Lists
FILES_TO_IGNORE = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                   '.html', '.txt', '.md', '.json', '.xml', '.lock', '.zip',
                   '.pdf', '.doc', '.docx', '.woff', '.ttf', '.eot', '.ico'}
DIRS_TO_IGNORE = {'.git', 'node_modules', 'vendor', 'tests', 'test', 'assets', 
                  'images', 'img', 'dist', 'build', 'docs', '.idea', '.vscode',
                  '__pycache__', 'cache', 'tmp', 'temp', 'logs'}

# Context Exclusions (reduce false positives)
CONTEXT_EXCLUSIONS = {
    "test": {"RCE_CRITICAL", "SQL_INJECTION", "EVAL_INJECTION"},
    "tests": {"RCE_CRITICAL", "SQL_INJECTION", "EVAL_INJECTION"},
    "install": {"SQL_INJECTION", "PDO_QUERY"},
    "migration": {"SQL_INJECTION", "PDO_QUERY"},
    "setup": {"SQL_INJECTION", "PDO_QUERY"},
    "cli": {"RCE_CRITICAL", "COMMAND_INJECTION"},
    "console": {"RCE_CRITICAL", "COMMAND_INJECTION"},
    "bin": {"RCE_CRITICAL"},
    "logger": {"ARBITRARY_FILE_WRITE"},
    "log": {"ARBITRARY_FILE_WRITE"},
}

# ================= COLORS =================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ================= VULNERABILITY PATTERNS =================
PATTERNS = {
    # ============ CRITICAL SEVERITY ============
    "RCE_CRITICAL": {
        "regex": r"(system|exec|passthru|shell_exec|proc_open|popen|pcntl_exec)\s*\(",
        "score": 100,
        "severity": "CRITICAL",
        "desc": "Direct Command Execution - Remote Code Execution",
        "cwe": "CWE-78"
    },
    "EVAL_INJECTION": {
        "regex": r"eval\s*\(",
        "score": 100,
        "severity": "CRITICAL",
        "desc": "eval() - Arbitrary Code Execution",
        "cwe": "CWE-95"
    },
    "ASSERT_INJECTION": {
        "regex": r"assert\s*\(",
        "score": 95,
        "severity": "CRITICAL",
        "desc": "assert() - Potential Code Execution",
        "cwe": "CWE-95"
    },
    "UNSERIALIZE_INJECTION": {
        "regex": r"unserialize\s*\(",
        "score": 95,
        "severity": "CRITICAL",
        "desc": "unserialize() - PHP Object Injection",
        "cwe": "CWE-502"
    },
    "SQL_INJECTION": {
        "regex": r"(mysqli_query|mysql_query|pg_query|mssql_query|oci_execute|sqlite_query|db_query|query)\s*\(",
        "score": 95,
        "severity": "CRITICAL",
        "desc": "Direct Database Query - SQL Injection",
        "cwe": "CWE-89"
    },
    "PDO_QUERY": {
        "regex": r"->(query|exec)\s*\(",
        "score": 90,
        "severity": "CRITICAL",
        "desc": "PDO Direct Query - Potential SQL Injection",
        "cwe": "CWE-89"
    },
    "CREATE_FUNCTION": {
        "regex": r"create_function\s*\(",
        "score": 95,
        "severity": "CRITICAL",
        "desc": "create_function() - Deprecated, Code Injection",
        "cwe": "CWE-95"
    },
    "PREG_REPLACE_EVAL": {
        "regex": r"preg_replace\s*\(\s*['\"].*['\"],.*,.*,.*['\"]e['\"]",
        "score": 95,
        "severity": "CRITICAL",
        "desc": "preg_replace /e modifier - Code Execution",
        "cwe": "CWE-95"
    },
    
    # ============ HIGH SEVERITY ============
    "FILE_INCLUSION": {
        "regex": r"(include|require|include_once|require_once)\s*\(",
        "score": 90,
        "severity": "HIGH",
        "desc": "Dynamic File Inclusion - LFI/RFI",
        "cwe": "CWE-98"
    },
    "ARBITRARY_FILE_WRITE": {
        "regex": r"(file_put_contents|fwrite|fputs|move_uploaded_file)\s*\(",
        "score": 88,
        "severity": "HIGH",
        "desc": "File Write Operation - Arbitrary File Upload/Write",
        "cwe": "CWE-434"
    },
    "FILE_DELETION": {
        "regex": r"(unlink|rmdir)\s*\(",
        "score": 85,
        "severity": "HIGH",
        "desc": "File Deletion Operation",
        "cwe": "CWE-73"
    },
    "DYNAMIC_FUNCTION_CALL": {
        "regex": r"(call_user_func|call_user_func_array|array_map|array_filter|array_reduce|array_walk|usort|uasort|uksort|preg_replace_callback)\s*\(",
        "score": 85,
        "severity": "HIGH",
        "desc": "Dynamic Function Call - Potential RCE",
        "cwe": "CWE-94"
    },
    "XML_EXTERNAL_ENTITY": {
        "regex": r"(simplexml_load_string|simplexml_load_file|DOMDocument::loadXML|xml_parse)\s*\(",
        "score": 80,
        "severity": "HIGH",
        "desc": "XML Parsing - XXE Vulnerability",
        "cwe": "CWE-611"
    },
    
    # ============ MEDIUM SEVERITY ============
    "XSS_SINK": {
        "regex": r"(echo|print|printf|vprintf|die|exit)\s+.*\$",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "Direct Output - Potential XSS",
        "cwe": "CWE-79"
    },
    "SSRF_SINK": {
        "regex": r"(file_get_contents|fopen|curl_exec|curl_init|fsockopen|pfsockopen|stream_socket_client)\s*\(",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "External Request - SSRF Potential",
        "cwe": "CWE-918"
    },
    "HEADER_INJECTION": {
        "regex": r"header\s*\(",
        "score": 70,
        "severity": "MEDIUM",
        "desc": "HTTP Header Injection / Open Redirect",
        "cwe": "CWE-601"
    },
    "XPATH_INJECTION": {
        "regex": r"->query\s*\(.*\$|xpath\s*\(",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "XPath Query - Injection Risk",
        "cwe": "CWE-643"
    },
    "LDAP_INJECTION": {
        "regex": r"ldap_search\s*\(",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "LDAP Search - Injection Risk",
        "cwe": "CWE-90"
    },
    "EXTRACT_VARIABLE_OVERRIDE": {
        "regex": r"extract\s*\(",
        "score": 70,
        "severity": "MEDIUM",
        "desc": "extract() - Variable Override",
        "cwe": "CWE-914"
    },
    "PARSE_STR_OVERRIDE": {
        "regex": r"parse_str\s*\([^,]+\)",
        "score": 68,
        "severity": "MEDIUM",
        "desc": "parse_str() without output array - Variable Override",
        "cwe": "CWE-914"
    },
    "MAIL_INJECTION": {
        "regex": r"mail\s*\(",
        "score": 65,
        "severity": "MEDIUM",
        "desc": "mail() - Email Header Injection",
        "cwe": "CWE-88"
    },
    "CSRF_MISSING_TOKEN": {
        "regex": r"\$_POST\s*\[",
        "score": 65,
        "severity": "MEDIUM",
        "desc": "POST Processing - Potential CSRF",
        "cwe": "CWE-352"
    },
    
    # ============ LOW SEVERITY ============
    "WEAK_HASH": {
        "regex": r"(md5|sha1)\s*\(",
        "score": 55,
        "severity": "LOW",
        "desc": "Weak Hash Function (MD5/SHA1)",
        "cwe": "CWE-327"
    },
    "HARDCODED_CREDENTIALS": {
        "regex": r"(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*['\"][^'\"]+['\"]",
        "score": 70,
        "severity": "MEDIUM",
        "desc": "Potential Hardcoded Credentials",
        "cwe": "CWE-798"
    },
    "INSECURE_RANDOM": {
        "regex": r"(rand|mt_rand|srand|mt_srand|lcg_value)\s*\(",
        "score": 60,
        "severity": "LOW",
        "desc": "Insecure Random Number Generation",
        "cwe": "CWE-338"
    },
    "PHPINFO_DISCLOSURE": {
        "regex": r"phpinfo\s*\(",
        "score": 50,
        "severity": "LOW",
        "desc": "phpinfo() - Information Disclosure",
        "cwe": "CWE-200"
    },
    
    # ============ INPUT SOURCES ============
    "SUPERGLOBAL_GET": {
        "regex": r"\$_GET\s*\[",
        "score": 60,
        "severity": "INFO",
        "desc": "User Input: $_GET",
        "cwe": "CWE-20"
    },
    "SUPERGLOBAL_POST": {
        "regex": r"\$_POST\s*\[",
        "score": 60,
        "severity": "INFO",
        "desc": "User Input: $_POST",
        "cwe": "CWE-20"
    },
    "SUPERGLOBAL_REQUEST": {
        "regex": r"\$_REQUEST\s*\[",
        "score": 65,
        "severity": "INFO",
        "desc": "User Input: $_REQUEST",
        "cwe": "CWE-20"
    },
}

# ================= TOKEN-EFFICIENT PATTERNS =================
KNOWN_SAFE_PATTERNS = {
    "prepared_statement": {
        "indicators": ["->prepare(", "bind_param", "bindParam", "bindValue"],
        "explanation": "Database query uses prepared statements"
    },
    "pdo_safe_methods": {
        "indicators": ["PDO::PARAM_INT", "bindParam", "execute("],
        "explanation": "PDO with parameter binding"
    },
    "input_validation": {
        "indicators": ["filter_var(", "FILTER_VALIDATE", "is_numeric(", "ctype_digit("],
        "explanation": "Input validation present"
    },
    "output_escaping": {
        "indicators": ["htmlspecialchars(", "htmlentities(", "ENT_QUOTES"],
        "explanation": "Output properly escaped"
    },
    "file_upload_validation": {
        "indicators": ["UPLOAD_ERR_OK", "mime_content_type", "pathinfo(", "in_array("],
        "explanation": "File upload with validation"
    },
    "capability_check": {
        "indicators": ["current_user_can(", "is_admin(", "check_admin_referer("],
        "explanation": "Access control present"
    },
    "framework_safe": {
        "indicators": ["Eloquent", "Query Builder", "->where(", "->find("],
        "explanation": "Framework with built-in protections"
    },
}


class PHPSinkScanner:
    def __init__(self, target_dir, filter_severity=None, filter_type=None, verbose=False, verify_with_ai=False):
        self.target_dir = os.path.abspath(target_dir)
        self.filter_severity = filter_severity.upper() if filter_severity else None
        self.filter_type = filter_type.upper() if filter_type else None
        self.verbose = verbose
        self.verify_with_ai = verify_with_ai
        self.findings = []
        self.completed_ids = set()
        self.pattern_cache = {}
        self.stats = defaultdict(int)
        
        # Paths
        self.report_path = os.path.join(self.target_dir, REPORT_FILENAME)
        self.vuln_path = os.path.join(self.target_dir, VULN_FILENAME)
        self.scan_db_path = os.path.join(self.target_dir, SCAN_DB_FILE)
        self.progress_path = os.path.join(self.target_dir, PROGRESS_FILE)
        self.cache_path = os.path.join(self.target_dir, PATTERN_CACHE_FILE)
        
        os.system('')  # Init colors
        
        if not os.path.exists(self.target_dir):
            print(f"{Colors.RED}[!] Error: Directory '{self.target_dir}' does not exist.{Colors.RESET}")
            sys.exit(1)
        
        # Load pattern cache
        self._load_pattern_cache()

    def _load_pattern_cache(self):
        """Load known safe patterns from previous scans"""
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r') as f:
                    self.pattern_cache = json.load(f)
                if self.verbose:
                    print(f"{Colors.CYAN}[i] Loaded {len(self.pattern_cache)} cached patterns{Colors.RESET}")
            except:
                pass

    def _save_pattern_cache(self):
        """Save learned patterns for future scans"""
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(self.pattern_cache, f, indent=2)
        except:
            pass

    def _check_known_pattern(self, finding, context_lines):
        """Check if this matches a known safe pattern (avoids AI call)"""
        context_str = "".join(context_lines).lower()
        
        for pattern_name, pattern_data in KNOWN_SAFE_PATTERNS.items():
            matches = sum(1 for indicator in pattern_data["indicators"] 
                         if indicator.lower() in context_str)
            if matches >= 2:  # Need at least 2 indicators
                return pattern_name, pattern_data["explanation"]
        
        # Check cache
        snippet_hash = hashlib.md5(finding['snippet'].encode()).hexdigest()
        if snippet_hash in self.pattern_cache:
            cached = self.pattern_cache[snippet_hash]
            return "cached", cached.get("reason", "Previously analyzed as safe")
        
        return None, None

    def generate_id(self, finding):
        """Generate unique ID for findings"""
        unique_str = f"{finding['file']}:{finding['line']}:{finding['type']}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    def load_progress(self):
        """Load previous verification session"""
        if os.path.exists(self.scan_db_path) and os.path.exists(self.progress_path):
            print(f"{Colors.CYAN}[?] Found previous session data.{Colors.RESET}")
            choice = input(f"    Resume from where you left off? (y/n): ").strip().lower()
            if choice == 'y':
                with open(self.scan_db_path, 'r') as f:
                    self.findings = json.load(f)
                with open(self.progress_path, 'r') as f:
                    self.completed_ids = set(json.load(f))
                print(f"{Colors.GREEN}[*] Resumed. {len(self.findings)} findings, {len(self.completed_ids)} already verified.{Colors.RESET}")
                return True
        return False

    def scan_files(self):
        """Main scanning loop"""
        if self.verify_with_ai and self.load_progress():
            return
        
        print(f"{Colors.BLUE}{Colors.BOLD}[*] PHP Security Sink Scanner{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Target: {self.target_dir}{Colors.RESET}")
        
        if self.filter_severity:
            print(f"{Colors.YELLOW}[*] Filter: Severity = {self.filter_severity}{Colors.RESET}")
        if self.filter_type:
            print(f"{Colors.YELLOW}[*] Filter: Type = {self.filter_type}{Colors.RESET}")
        if self.verify_with_ai:
            print(f"{Colors.CYAN}[*] AI Verification: ENABLED{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Token Optimization: Pattern caching + smart context extraction{Colors.RESET}")
        
        print(f"{Colors.BLUE}[*] Phase 1: Scanning...{Colors.RESET}\n")
        
        file_count = 0
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in DIRS_TO_IGNORE]
            
            for file in files:
                if not file.endswith('.php'):
                    continue
                if any(file.endswith(ext) for ext in FILES_TO_IGNORE):
                    continue
                if file in [REPORT_FILENAME, VULN_FILENAME, SCAN_DB_FILE, PROGRESS_FILE, PATTERN_CACHE_FILE]:
                    continue
                
                filepath = os.path.join(root, file)
                file_count += 1
                
                if self.verbose:
                    rel_path = os.path.relpath(filepath, self.target_dir)
                    print(f"{Colors.CYAN}[>] {rel_path}{Colors.RESET}")
                
                self._analyze_file(filepath)
        
        # Sort by score
        self.findings.sort(key=lambda x: x['score'], reverse=True)
        
        # Save scan database if AI verification enabled
        if self.verify_with_ai:
            with open(self.scan_db_path, "w") as f:
                json.dump(self.findings, f, indent=2)
            with open(self.progress_path, "w") as f:
                json.dump([], f)
        
        print(f"{Colors.GREEN}[+] Scanned {file_count} PHP files{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Found {len(self.findings)} potential security sinks{Colors.RESET}\n")
        
        if self.findings and not self.verify_with_ai:
            self._print_top_findings()

    def _analyze_file(self, filepath):
        """Analyze a single PHP file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except:
            return
        
        rel_path = os.path.relpath(filepath, self.target_dir).replace("\\", "/")
        
        # Context-based exclusions
        ignore_types = set()
        for path_key, ignored_types in CONTEXT_EXCLUSIONS.items():
            if path_key in rel_path.lower().split("/"):
                ignore_types.update(ignored_types)
        
        # Track tainted variables
        tainted_vars = set()
        
        for i, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Skip comments
            if not line_clean or line_clean.startswith(("//", "#", "/*", "*")):
                continue
            
            # Track user input
            if any(sg in line_clean for sg in ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]):
                var_match = re.search(r'\$(\w+)\s*=.*\$_(GET|POST|REQUEST|COOKIE)', line_clean)
                if var_match:
                    tainted_vars.add(f"${var_match.group(1)}")
            
            # Pattern matching
            for type_key, pattern_data in PATTERNS.items():
                # Apply filters
                if self.filter_severity and pattern_data['severity'] != self.filter_severity:
                    continue
                if self.filter_type and self.filter_type not in type_key:
                    continue
                if type_key in ignore_types:
                    continue
                
                if re.search(pattern_data['regex'], line_clean, re.IGNORECASE):
                    score = self._calculate_score(line_clean, lines, i, pattern_data, 
                                                  tainted_vars, rel_path, type_key)
                    
                    if score < 45:  # Skip low-confidence findings
                        continue
                    
                    # Get context snippet
                    start_line = max(0, i - 3)
                    end_line = min(len(lines), i + 3)
                    snippet = "".join(lines[start_line:end_line])
                    
                    finding = {
                        "file": rel_path,
                        "absolute_path": filepath,
                        "line": i,
                        "type": type_key,
                        "desc": pattern_data['desc'],
                        "severity": pattern_data['severity'],
                        "cwe": pattern_data.get('cwe', 'N/A'),
                        "score": score,
                        "snippet": snippet.strip(),
                        "matched_line": line_clean
                    }
                    
                    finding['_id'] = self.generate_id(finding)
                    self.findings.append(finding)
                    self.stats[pattern_data['severity']] += 1

    def _calculate_score(self, line, lines, line_num, pattern_data, tainted_vars, rel_path, type_key):
        """Calculate risk score with advanced heuristics"""
        score = pattern_data['score']
        
        # Get context
        context_start = max(0, line_num - 20)
        context_end = min(len(lines), line_num + 5)
        context = "".join(lines[context_start:context_end])
        
        # Increase score for tainted variables
        if any(var in line for var in tainted_vars):
            score += 15
        
        # Increase for direct superglobal usage
        if any(sg in line for sg in ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]):
            score += 20
        
        # General sanitization detection
        if any(func in line for func in ["htmlspecialchars", "htmlentities", "strip_tags", 
                                          "filter_var", "intval", "floatval", "absint"]):
            score -= 25
        
        # Type casting
        if re.search(r'\(int\)|\(string\)|\(bool\)|\(array\)', line):
            score -= 15
        
        # === Pattern-specific heuristics ===
        
        # SQL Injection
        if type_key in ["SQL_INJECTION", "PDO_QUERY"]:
            if "prepare" in line.lower() or "prepare" in context.lower():
                score -= 50
            if re.search(r'bind(Param|Value|Column)', context, re.IGNORECASE):
                score -= 40
            if any(x in line for x in ["->insert(", "->update(", "->delete("]):
                score -= 30
        
        # Command Injection / RCE
        if type_key == "RCE_CRITICAL":
            if any(x in context for x in ["escapeshellarg", "escapeshellcmd"]):
                score -= 30
            if "is_admin()" in context or "current_user_can(" in context:
                score -= 40
        
        # File Inclusion
        if type_key == "FILE_INCLUSION":
            if any(x in line for x in ["dirname(__FILE__)", "__DIR__", "ABSPATH"]):
                score -= 35
            if "sanitize_" in context or "validate_file" in context:
                score -= 30
        
        # Object Injection
        if type_key == "UNSERIALIZE_INJECTION":
            if any(x in context for x in ["get_option(", "get_post_meta(", "get_user_meta("]):
                score -= 50  # These are trusted sources
            if "json_decode" in line:  # Not unserialize
                score -= 60
        
        # XSS
        if type_key == "XSS_SINK":
            if any(x in line for x in ["esc_html", "esc_attr", "esc_url", "esc_js"]):
                score -= 40
            if "wp_kses" in line:
                score -= 35
        
        # CSRF
        if type_key == "CSRF_MISSING_TOKEN":
            if any(x in context for x in ["wp_verify_nonce", "check_admin_referer", 
                                          "check_ajax_referer", "csrf_token"]):
                score -= 40
            if "phpcs:ignore" in context and "NonceVerification" in context:
                score -= 35
        
        # File Upload
        if type_key == "ARBITRARY_FILE_WRITE":
            if any(x in context for x in ["UPLOAD_ERR_OK", "is_uploaded_file(", 
                                          "pathinfo(", "mime_content_type"]):
                score -= 30
        
        # SSRF
        if type_key == "SSRF_SINK":
            if any(x in line for x in ["127.0.0.1", "localhost", "internal-api"]):
                score += 20  # Hardcoded internal URLs increase risk
            if "filter_var" in context and "FILTER_VALIDATE_URL" in context:
                score -= 25
        
        return max(0, min(100, score))

    def _print_top_findings(self):
        """Print top findings summary"""
        print(f"{Colors.BOLD}--- TOP FINDINGS (SORTED BY SEVERITY) ---{Colors.RESET}")
        for f in self.findings[:10]:
            sev_color = {
                "CRITICAL": Colors.RED,
                "HIGH": Colors.YELLOW,
                "MEDIUM": Colors.CYAN,
                "LOW": Colors.BLUE,
                "INFO": Colors.MAGENTA
            }.get(f['severity'], Colors.RESET)
            
            print(f"{sev_color}[{f['score']}/100] {f['type']}{Colors.RESET} "
                  f"in {os.path.basename(f['file'])}:{f['line']}")
        
        if len(self.findings) > 10:
            print(f"... and {len(self.findings) - 10} more.")
        print("-" * 45 + "\n")

    # ================= AI VERIFICATION =================
    
    def run_ai_verification(self):
        """Run AI verification on findings"""
        if not self.verify_with_ai:
            return
        
        targets = [f for f in self.findings if f['score'] >= MIN_SCORE_THRESHOLD]
        targets.sort(key=lambda x: x['score'], reverse=True)
        
        # Filter already completed
        remaining = [t for t in targets if t['_id'] not in self.completed_ids]
        
        if not remaining:
            print(f"{Colors.GREEN}[*] All targets already verified.{Colors.RESET}")
            return
        
        print(f"\n{Colors.BLUE}{Colors.BOLD}[*] Phase 2: AI Verification with Claude Code{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Verifying {len(remaining)} findings (score >= {MIN_SCORE_THRESHOLD}){Colors.RESET}")
        print(f"{Colors.BLUE}[*] Rate limit: 1 verification every {WAIT_MINUTES} minutes{Colors.RESET}\n")
        
        # Initialize reports
        self._init_verification_reports()
        
        skipped_by_cache = 0
        
        for idx, finding in enumerate(remaining):
            print(f"[{idx+1}/{len(remaining)}] Verifying {finding['type']} in "
                  f"{os.path.basename(finding['file'])}:{finding['line']} (Score: {finding['score']})...")
            
            # Check known patterns first
            try:
                with open(finding['absolute_path'], 'r', errors='ignore') as f:
                    lines = f.readlines()
                context_start = max(0, finding['line'] - 25)
                context_end = min(len(lines), finding['line'] + 15)
                context_lines = lines[context_start:context_end]
            except:
                context_lines = []
            
            pattern_name, explanation = self._check_known_pattern(finding, context_lines)
            
            if pattern_name:
                print(f"   {Colors.GREEN}✓ Matched known safe pattern: {pattern_name}{Colors.RESET}")
                response = (f"VERDICT: SAFE\n\n**Pattern Matched:** {pattern_name}\n"
                           f"**Explanation:** {explanation}\n\n"
                           f"**Auto-cleared by pattern recognition (token-efficient mode)**")
                skipped_by_cache += 1
            else:
                # Run AI verification
                response = self._run_token_efficient_audit(finding)
                
                if "limit reached" in response.lower() or "rate limit" in response.lower():
                    print(f"\n{Colors.RED}[!] Rate limit detected. Stopping.{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] Progress saved. Run again later to resume.{Colors.RESET}")
                    break
                
                # Learn from verdict
                if "VERDICT: SAFE" in response:
                    snippet_hash = hashlib.md5(finding['snippet'].encode()).hexdigest()
                    self.pattern_cache[snippet_hash] = {
                        "type": finding['type'],
                        "reason": "AI determined safe",
                        "timestamp": str(datetime.datetime.now())
                    }
            
            self._process_verdict(finding, response)
            self._mark_verified(finding['_id'])
            
            # Wait between requests
            if idx < len(remaining) - 1 and not pattern_name:
                self._countdown()
        
        print(f"\n{Colors.CYAN}[i] Pattern cache saved {skipped_by_cache} AI calls{Colors.RESET}")
        self._save_pattern_cache()
        print(f"\n{Colors.GREEN}[+] AI verification complete!{Colors.RESET}")

    def _init_verification_reports(self):
        """Initialize verification report files"""
        with open(self.report_path, "a") as f:
            f.write(f"\n\n# AI VERIFICATION SESSION - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if not os.path.exists(self.vuln_path):
            with open(self.vuln_path, "w") as f:
                f.write("# VERIFIED VULNERABILITIES\n")
                f.write("This file contains only vulnerabilities confirmed by AI.\n\n")
                f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Target:** `{self.target_dir}`\n\n---\n\n")

    def _extract_function_from_file(self, filepath, target_name=None):
        """Extract function or limited context (token-efficient)"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            
            if not target_name:
                return content[:3000] + "\n...[truncated for tokens]"
            
            # Try to find function
            pattern = rf"(function\s+{re.escape(target_name)}\s*\([^)]*\)\s*\{{[^}}]*?\}})"
            match = re.search(pattern, content, re.DOTALL)
            
            if match:
                return match.group(1)[:2000]
            
            # Fallback: Return context around first mention
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if target_name in line:
                    start = max(0, i - 15)
                    end = min(len(lines), i + 20)
                    return '\n'.join(lines[start:end])
            
            return content[:2000]
        except:
            return "ERROR: Could not read file"

    def _run_token_efficient_audit(self, finding):
        """Run AI audit with token-optimized prompts"""
        
        # Ultra-compact prompt
        prompt = f"""[SECURITY AUDIT]
File: {os.path.basename(finding['file'])}:{finding['line']}
Type: {finding['type']} ({finding['desc']})
CWE: {finding['cwe']}
Severity: {finding['severity']}
Score: {finding['score']}/100

CODE:
```php
{finding['snippet'][:600]}
```

VERIFICATION RULES:
- SQL: Check for prepare(), bindParam(), or safe methods
- RCE: Check for escapeshellarg/cmd or admin capability checks
- XSS: Check for htmlspecialchars, esc_html, esc_attr
- CSRF: Check for nonce verification (wp_verify_nonce, check_admin_referer, csrf_token)
- Object Injection: get_option/get_post_meta are safe sources
- File Inclusion: Check for dirname(__FILE__), ABSPATH, or path validation
- File Upload: Check for UPLOAD_ERR_OK, mime checks, extension validation

If you need to see related code, reply with:
   READ: path/to/file.php [optional_function_name]

Otherwise, start your response with ONE of these:
   VERDICT: VULNERABLE - [brief exploitation scenario]
   VERDICT: SAFE - [why it's mitigated]
   VERDICT: MANUAL_REVIEW - [what needs human verification]

Be concise. Focus on exploitability.
"""
        
        hops = 0
        conversation = prompt
        
        while hops < MAX_CONTEXT_HOPS:
            response = self._call_claude_code(conversation)
            
            # Check for READ request
            match = re.search(r"READ:\s*(\S+)(?:\s+\[([^\]]+)\])?", response)
            if match and hops < MAX_CONTEXT_HOPS:
                requested_file = match.group(1).strip()
                requested_function = match.group(2).strip() if match.group(2) else None
                
                # Locate file
                full_path = os.path.join(self.target_dir, requested_file)
                if not os.path.exists(full_path):
                    file_dir = os.path.dirname(finding['absolute_path'])
                    full_path = os.path.join(file_dir, requested_file)
                
                print(f"   {Colors.CYAN}→ Reading: {os.path.basename(requested_file)}"
                      f"{f' [{requested_function}]' if requested_function else ''}{Colors.RESET}")
                
                # Smart extraction
                content = self._extract_function_from_file(full_path, requested_function)
                
                conversation += f"\n\nCONTEXT:\n```php\n{content}\n```\n\nNow provide your VERDICT:"
                hops += 1
                time.sleep(1)
            else:
                return response
        
        return response

    def _call_claude_code(self, prompt):
        """Call Claude Code CLI"""
        try:
            process = subprocess.Popen(
                ["claude"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=prompt, timeout=120)
            
            if stderr and ("Error" in stderr or "error" in stderr):
                return f"CLI Error: {stderr}"
            
            return stdout if stdout else "No response from Claude"
        except subprocess.TimeoutExpired:
            process.kill()
            return "ERROR: Timeout"
        except FileNotFoundError:
            return "ERROR: 'claude' command not found. Install Claude Code CLI."
        except Exception as e:
            return f"ERROR: {str(e)}"

    def _process_verdict(self, finding, response):
        """Process and save AI verdict"""
        # Append to main report
        with open(self.report_path, "a") as f:
            f.write(f"## [{finding['type']}] {finding['file']}:{finding['line']}\n")
            f.write(f"**Score:** {finding['score']}/100\n\n")
            f.write(f"### AI Analysis:\n{response}\n\n---\n\n")
        
        # Determine verdict
        verdict_color = Colors.YELLOW
        verdict_text = "MANUAL REVIEW"
        
        if "VERDICT: VULNERABLE" in response:
            verdict_color = Colors.RED
            verdict_text = "!!! VULNERABLE !!!"
            
            # Add to verified vulnerabilities
            with open(self.vuln_path, "a") as f:
                f.write(f"## {finding['type']} - {finding['desc']}\n\n")
                f.write(f"**File:** `{finding['file']}:{finding['line']}`\n")
                f.write(f"**CWE:** {finding['cwe']}\n")
                f.write(f"**Severity:** {finding['severity']}\n\n")
                f.write(f"### Code:\n```php\n{finding['snippet']}\n```\n\n")
                f.write(f"### AI Analysis:\n{response}\n\n---\n\n")
        
        elif "VERDICT: SAFE" in response:
            verdict_color = Colors.GREEN
            verdict_text = "SAFE / MITIGATED"
        
        print(f"   > Verdict: {verdict_color}{verdict_text}{Colors.RESET}")

    def _mark_verified(self, finding_id):
        """Mark finding as verified"""
        self.completed_ids.add(finding_id)
        with open(self.progress_path, "w") as f:
            json.dump(list(self.completed_ids), f)

    def _countdown(self):
        """Countdown between AI calls"""
        if WAIT_MINUTES == 0:
            return
        
        total_seconds = WAIT_MINUTES * 60
        print(f"   {Colors.CYAN}Cooling down for {WAIT_MINUTES} min(s)...{Colors.RESET}")
        for remaining in range(total_seconds, 0, -1):
            mins, secs = divmod(remaining, 60)
            sys.stdout.write(f"\r   Next verification in: {mins:02d}:{secs:02d}   ")
            sys.stdout.flush()
            time.sleep(1)
        print("\n")

    # ================= REPORTING =================
    
    def generate_reports(self):
        """Generate markdown and JSON reports"""
        if not self.findings:
            print(f"{Colors.YELLOW}[!] No findings to report{Colors.RESET}")
            return
        
        self._generate_markdown_report()
        self._generate_json_report()
        self._print_summary()

    def _generate_markdown_report(self):
        """Generate markdown report"""
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(f"# PHP Security Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Target:** `{self.target_dir}`\n\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n\n")
            
            # Stats
            f.write("## Summary\n\n| Severity | Count |\n|----------|-------|\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = self.stats.get(sev, 0)
                if count > 0:
                    f.write(f"| {sev} | {count} |\n")
            f.write("\n---\n\n")
            
            # Findings
            current_sev = None
            for finding in self.findings:
                if finding['severity'] != current_sev:
                    current_sev = finding['severity']
                    f.write(f"## {current_sev} Severity\n\n")
                
                f.write(f"### [{finding['_id'][:8]}] {finding['type']}\n\n")
                f.write(f"- **File:** `{finding['file']}:{finding['line']}`\n")
                f.write(f"- **Description:** {finding['desc']}\n")
                f.write(f"- **CWE:** {finding['cwe']}\n")
                f.write(f"- **Score:** {finding['score']}/100\n\n")
                f.write(f"```php\n{finding['snippet']}\n```\n\n---\n\n")
        
        print(f"{Colors.GREEN}[+] Report saved: {self.report_path}{Colors.RESET}")

    def _generate_json_report(self):
        """Generate JSON report"""
        json_path = os.path.join(self.target_dir, "scan_results.json")
        report = {
            "scan_date": datetime.datetime.now().isoformat(),
            "target": self.target_dir,
            "total_findings": len(self.findings),
            "statistics": dict(self.stats),
            "findings": self.findings
        }
        
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}[+] JSON saved: {json_path}{Colors.RESET}")

    def _print_summary(self):
        """Print summary"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
        
        sev_colors = {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.YELLOW,
            "MEDIUM": Colors.CYAN,
            "LOW": Colors.BLUE,
            "INFO": Colors.MAGENTA
        }
        
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.stats.get(sev, 0)
            if count > 0:
                print(f"{sev_colors[sev]}[{sev}]{Colors.RESET} {count} findings")
        
        print(f"\n{Colors.BOLD}TOP 10 FINDINGS:{Colors.RESET}\n")
        for i, f in enumerate(self.findings[:10], 1):
            sev_color = sev_colors.get(f['severity'], Colors.RESET)
            print(f"{i:2}. {sev_color}[{f['severity']}]{Colors.RESET} "
                  f"{f['type']} in {os.path.basename(f['file'])}:{f['line']} "
                  f"(Score: {f['score']})")
        
        if len(self.findings) > 10:
            print(f"\n... and {len(self.findings) - 10} more")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PHP Security Sink Scanner with AI Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 php_sink_scanner.py /path/to/php/project
  
  # Scan with AI verification
  python3 php_sink_scanner.py /path/to/php/project --verify
  
  # Filter by severity
  python3 php_sink_scanner.py /path/to/php/project --severity CRITICAL --verify
  
  # Filter by type
  python3 php_sink_scanner.py /path/to/php/project --type SQL --verify
        """
    )
    
    parser.add_argument("target", nargs="?", help="Path to PHP project")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                       help="Filter by severity")
    parser.add_argument("--type", help="Filter by type (e.g., 'SQL', 'RCE', 'XSS')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--verify", action="store_true", help="Enable AI verification with Claude Code")
    
    args = parser.parse_args()
    
    target_path = args.target
    if not target_path:
        target_path = input("Enter path to PHP project: ").strip()
    
    scanner = PHPSinkScanner(
        target_path,
        filter_severity=args.severity,
        filter_type=args.type,
        verbose=args.verbose,
        verify_with_ai=args.verify
    )
    
    scanner.scan_files()
    
    if args.verify:
        scanner.run_ai_verification()
    
    scanner.generate_reports()
    print(f"\n{Colors.GREEN}[+] Scan complete!{Colors.RESET}\n")


if __name__ == "__main__":
    main()
