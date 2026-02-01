#!/usr/bin/env python3
"""
PHP Security Sink Scanner
Identifies common vulnerability sinks in PHP codebases
Optimized for penetration testing and security research
"""

import os
import re
import json
import argparse
import hashlib
import sys
from datetime import datetime
from collections import defaultdict

# ================= CONFIGURATION =================
MIN_SCORE_THRESHOLD = 50
REPORT_FILENAME = "php_security_report.md"
JSON_REPORT = "scan_results.json"

# Global Ignore Lists
FILES_TO_IGNORE = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                   '.html', '.txt', '.md', '.json', '.xml', '.lock', '.zip',
                   '.pdf', '.doc', '.docx', '.woff', '.ttf', '.eot'}
DIRS_TO_IGNORE = {'.git', 'node_modules', 'vendor', 'tests', 'test', 'assets', 
                  'images', 'img', 'dist', 'build', 'docs', '.idea', '.vscode',
                  '__pycache__', 'cache', 'tmp', 'temp'}

# Context-based exclusions (reduce false positives)
CONTEXT_EXCLUSIONS = {
    "test": {"RCE_CRITICAL", "SQL_INJECTION", "XSS_SINK"},
    "install": {"SQL_INJECTION"},
    "migration": {"SQL_INJECTION"},
    "setup": {"SQL_INJECTION"},
    "cli": {"RCE_CRITICAL", "COMMAND_INJECTION"},
    "console": {"RCE_CRITICAL", "COMMAND_INJECTION"},
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
        "regex": r"->query\s*\(|->exec\s*\(",
        "score": 90,
        "severity": "CRITICAL",
        "desc": "PDO Direct Query - Potential SQL Injection",
        "cwe": "CWE-89"
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
        "regex": r"(file_put_contents|fwrite|fputs|fopen|move_uploaded_file)\s*\(",
        "score": 88,
        "severity": "HIGH",
        "desc": "File Write Operation - Arbitrary File Upload/Write",
        "cwe": "CWE-434"
    },
    "FILE_DELETION": {
        "regex": r"(unlink|rmdir|unlink_recursive)\s*\(",
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
    
    # ============ MEDIUM SEVERITY ============
    "XSS_SINK": {
        "regex": r"(echo|print|printf|vprintf|die|exit)\s+.*\$",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "Direct Output - Potential XSS",
        "cwe": "CWE-79"
    },
    "HEADER_INJECTION": {
        "regex": r"header\s*\(",
        "score": 70,
        "severity": "MEDIUM",
        "desc": "HTTP Header Injection / Open Redirect",
        "cwe": "CWE-601"
    },
    "SSRF_SINK": {
        "regex": r"(file_get_contents|fopen|curl_exec|curl_init|fsockopen|pfsockopen|stream_socket_client|copy)\s*\(",
        "score": 75,
        "severity": "MEDIUM",
        "desc": "External Request - SSRF Potential",
        "cwe": "CWE-918"
    },
    "XML_EXTERNAL_ENTITY": {
        "regex": r"(simplexml_load_string|simplexml_load_file|DOMDocument::loadXML|xml_parse)\s*\(",
        "score": 80,
        "severity": "HIGH",
        "desc": "XML Parsing - XXE Vulnerability",
        "cwe": "CWE-611"
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
    
    # ============ LOW-MEDIUM SEVERITY ============
    "EXTRACT_VARIABLE_OVERRIDE": {
        "regex": r"extract\s*\(",
        "score": 70,
        "severity": "MEDIUM",
        "desc": "extract() - Variable Override / Code Flow Manipulation",
        "cwe": "CWE-914"
    },
    "REGISTER_GLOBALS_SIMULATION": {
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
    "PHPINFO_DISCLOSURE": {
        "regex": r"phpinfo\s*\(",
        "score": 50,
        "severity": "LOW",
        "desc": "phpinfo() - Information Disclosure",
        "cwe": "CWE-200"
    },
    "DIRECTORY_TRAVERSAL": {
        "regex": r"(scandir|opendir|readdir|glob)\s*\(",
        "score": 65,
        "severity": "MEDIUM",
        "desc": "Directory Traversal/Listing",
        "cwe": "CWE-22"
    },
    
    # ============ INPUT SOURCES (For Tracking) ============
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
        "desc": "User Input: $_REQUEST (Cookie Poisoning Risk)",
        "cwe": "CWE-20"
    },
    "SUPERGLOBAL_COOKIE": {
        "regex": r"\$_COOKIE\s*\[",
        "score": 60,
        "severity": "INFO",
        "desc": "User Input: $_COOKIE",
        "cwe": "CWE-20"
    },
    "SUPERGLOBAL_SERVER": {
        "regex": r"\$_SERVER\s*\[",
        "score": 55,
        "severity": "INFO",
        "desc": "User Input: $_SERVER (Some indices user-controlled)",
        "cwe": "CWE-20"
    },
    
    # ============ CRYPTO/AUTH ISSUES ============
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
}


class PHPSinkScanner:
    def __init__(self, target_dir, filter_severity=None, filter_type=None, verbose=False):
        self.target_dir = os.path.abspath(target_dir)
        self.filter_severity = filter_severity.upper() if filter_severity else None
        self.filter_type = filter_type.upper() if filter_type else None
        self.verbose = verbose
        self.findings = []
        self.stats = defaultdict(int)
        
        # Paths
        self.report_path = os.path.join(self.target_dir, REPORT_FILENAME)
        self.json_path = os.path.join(self.target_dir, JSON_REPORT)
        
        os.system('')  # Init ANSI colors on Windows
        
        if not os.path.exists(self.target_dir):
            print(f"{Colors.RED}[!] Error: Directory '{self.target_dir}' does not exist.{Colors.RESET}")
            sys.exit(1)

    def generate_id(self, finding):
        """Generate unique ID for deduplication"""
        unique_str = f"{finding['file']}:{finding['line']}:{finding['type']}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:12]

    def scan_files(self):
        """Main scanning loop"""
        print(f"{Colors.BLUE}{Colors.BOLD}[*] PHP Security Sink Scanner{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Target: {self.target_dir}{Colors.RESET}")
        
        if self.filter_severity:
            print(f"{Colors.YELLOW}[*] Filter: Severity = {self.filter_severity}{Colors.RESET}")
        if self.filter_type:
            print(f"{Colors.YELLOW}[*] Filter: Type = {self.filter_type}{Colors.RESET}")
        
        print(f"{Colors.BLUE}[*] Scanning...{Colors.RESET}\n")
        
        file_count = 0
        for root, dirs, files in os.walk(self.target_dir):
            # Filter directories
            dirs[:] = [d for d in dirs if d not in DIRS_TO_IGNORE]
            
            for file in files:
                if not file.endswith('.php'):
                    continue
                if any(file.endswith(ext) for ext in FILES_TO_IGNORE):
                    continue
                    
                filepath = os.path.join(root, file)
                file_count += 1
                
                if self.verbose:
                    print(f"{Colors.CYAN}[>] {os.path.relpath(filepath, self.target_dir)}{Colors.RESET}")
                
                self._analyze_file(filepath)
        
        print(f"{Colors.GREEN}[+] Scanned {file_count} PHP files{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Found {len(self.findings)} potential security sinks{Colors.RESET}\n")

    def _analyze_file(self, filepath):
        """Analyze a single PHP file for vulnerability patterns"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[!] Error reading {filepath}: {e}{Colors.RESET}")
            return

        rel_path = os.path.relpath(filepath, self.target_dir).replace("\\", "/")
        
        # Determine context-based exclusions
        ignore_types_for_file = set()
        for path_key, ignored_types in CONTEXT_EXCLUSIONS.items():
            if path_key in rel_path.lower().split("/"):
                ignore_types_for_file.update(ignored_types)

        # Track user input variables for taint analysis
        tainted_vars = set()
        
        for i, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Skip comments and empty lines
            if not line_clean or line_clean.startswith(("//", "#", "/*", "*")):
                continue
            
            # Track tainted variables
            if any(sg in line_clean for sg in ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"]):
                var_match = re.search(r'\$(\w+)\s*=.*\$_(GET|POST|REQUEST|COOKIE|SERVER)', line_clean)
                if var_match:
                    tainted_vars.add(f"${var_match.group(1)}")
            
            # Check each pattern
            for type_key, pattern_data in PATTERNS.items():
                # Apply filters
                if self.filter_severity and pattern_data['severity'] != self.filter_severity:
                    continue
                if self.filter_type and self.filter_type not in type_key:
                    continue
                if type_key in ignore_types_for_file:
                    continue
                
                # Pattern matching
                if re.search(pattern_data['regex'], line_clean, re.IGNORECASE):
                    score = self._calculate_score(line_clean, pattern_data, tainted_vars)
                    
                    if score < MIN_SCORE_THRESHOLD:
                        continue
                    
                    # Get context snippet
                    start_line = max(0, i - 3)
                    end_line = min(len(lines), i + 2)
                    snippet = "".join(lines[start_line:end_line])
                    
                    finding = {
                        "id": "",  # Will be set after
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
                    
                    finding['id'] = self.generate_id(finding)
                    self.findings.append(finding)
                    self.stats[pattern_data['severity']] += 1

    def _calculate_score(self, line, pattern_data, tainted_vars):
        """Calculate risk score with heuristics"""
        score = pattern_data['score']
        
        # Increase score if tainted variable is used
        if any(var in line for var in tainted_vars):
            score += 15
        
        # Increase score for direct superglobal usage
        if any(sg in line for sg in ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"]):
            score += 20
        
        # Decrease score for sanitization functions
        sanitization_funcs = [
            "htmlspecialchars", "htmlentities", "strip_tags", "filter_var",
            "mysqli_real_escape_string", "addslashes", "intval", "floatval",
            "escapeshellarg", "escapeshellcmd", "preg_quote", "quotemeta",
            "urlencode", "rawurlencode", "base64_encode"
        ]
        
        if any(func in line for func in sanitization_funcs):
            score -= 25
        
        # Check for prepared statements (good practice)
        if "prepare" in line.lower() or "bind_param" in line.lower():
            score -= 30
        
        # Type casting is good
        if re.search(r'\(int\)|\(string\)|\(bool\)|\(array\)', line):
            score -= 15
        
        return max(0, min(100, score))

    def generate_reports(self):
        """Generate markdown and JSON reports"""
        if not self.findings:
            print(f"{Colors.YELLOW}[!] No findings to report{Colors.RESET}")
            return
        
        # Sort by severity and score
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda x: (severity_order.get(x['severity'], 5), -x['score']))
        
        # Generate Markdown Report
        self._generate_markdown_report()
        
        # Generate JSON Report
        self._generate_json_report()
        
        # Print summary
        self._print_summary()

    def _generate_markdown_report(self):
        """Generate detailed markdown report"""
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(f"# PHP Security Sink Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Target:** `{self.target_dir}`\n\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n\n")
            
            # Statistics
            f.write("## Summary Statistics\n\n")
            f.write("| Severity | Count |\n")
            f.write("|----------|-------|\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = self.stats.get(sev, 0)
                if count > 0:
                    f.write(f"| {sev} | {count} |\n")
            f.write("\n---\n\n")
            
            # Findings by severity
            current_severity = None
            for finding in self.findings:
                if finding['severity'] != current_severity:
                    current_severity = finding['severity']
                    f.write(f"## {current_severity} Severity Findings\n\n")
                
                f.write(f"### [{finding['id']}] {finding['type']}\n\n")
                f.write(f"- **File:** `{finding['file']}:{finding['line']}`\n")
                f.write(f"- **Description:** {finding['desc']}\n")
                f.write(f"- **CWE:** {finding['cwe']}\n")
                f.write(f"- **Risk Score:** {finding['score']}/100\n\n")
                f.write(f"**Code Context:**\n```php\n{finding['snippet']}\n```\n\n")
                f.write("---\n\n")
        
        print(f"{Colors.GREEN}[+] Markdown report saved: {self.report_path}{Colors.RESET}")

    def _generate_json_report(self):
        """Generate JSON report for tool integration"""
        report_data = {
            "scan_date": datetime.now().isoformat(),
            "target": self.target_dir,
            "total_findings": len(self.findings),
            "statistics": dict(self.stats),
            "findings": self.findings
        }
        
        with open(self.json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"{Colors.GREEN}[+] JSON report saved: {self.json_path}{Colors.RESET}")

    def _print_summary(self):
        """Print color-coded summary to console"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
        
        severity_colors = {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.YELLOW,
            "MEDIUM": Colors.CYAN,
            "LOW": Colors.BLUE,
            "INFO": Colors.MAGENTA
        }
        
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.stats.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, Colors.RESET)
                print(f"{color}[{sev}]{Colors.RESET} {count} findings")
        
        print(f"\n{Colors.BOLD}TOP 10 FINDINGS:{Colors.RESET}\n")
        for i, finding in enumerate(self.findings[:10], 1):
            sev_color = severity_colors.get(finding['severity'], Colors.RESET)
            print(f"{i:2}. {sev_color}[{finding['severity']}]{Colors.RESET} "
                  f"{finding['type']} in {os.path.basename(finding['file'])}:{finding['line']} "
                  f"(Score: {finding['score']})")
        
        if len(self.findings) > 10:
            print(f"\n... and {len(self.findings) - 10} more findings (see report)")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="PHP Security Sink Scanner - Identify common vulnerability patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python php_sink_scanner.py /path/to/php/project
  python php_sink_scanner.py /path/to/php/project --severity CRITICAL
  python php_sink_scanner.py /path/to/php/project --type SQL
  python php_sink_scanner.py /path/to/php/project --verbose
        """
    )
    
    parser.add_argument("target", nargs="?", help="Path to the PHP project directory")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Filter by severity level")
    parser.add_argument("--type", help="Filter by vulnerability type (e.g., 'SQL', 'RCE', 'XSS')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    target_path = args.target
    if not target_path:
        target_path = input("Enter the path to the PHP project: ").strip()
    
    scanner = PHPSinkScanner(
        target_path,
        filter_severity=args.severity,
        filter_type=args.type,
        verbose=args.verbose
    )
    
    scanner.scan_files()
    scanner.generate_reports()
    
    print(f"\n{Colors.GREEN}[+] Scan complete!{Colors.RESET}\n")


if __name__ == "__main__":
    main()
