# PHP Security Sink Scanner with AI Verification

A comprehensive static analysis tool with AI-powered verification for identifying security vulnerabilities in PHP codebases. Features token-optimized Claude Code integration, pattern caching, and smart context extraction for penetration testing and security research.

## Key Features

### Core Scanning
- **40+ Vulnerability Patterns**: RCE, SQL Injection, XSS, File Upload, SSRF, XXE, Object Injection, and more
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO with CWE mapping
- **Smart Scoring System**: Contextual risk scoring with taint analysis
- **False Positive Reduction**: Detects sanitization, prepared statements, and framework protections
- **Advanced Heuristics**: Pattern-specific scoring adjustments based on context

### AI Verification (NEW!)
- **Claude Code Integration**: Verify findings with AI analysis using `claude` CLI
- **Token-Efficient Prompts**: Ultra-compact prompts save 50%+ tokens
- **Pattern Caching**: Skip AI calls for known safe patterns (saves $$$)
- **Smart Context Extraction**: Only fetches relevant code (70% token savings)
- **Multi-Hop Analysis**: AI can request additional files for context (up to 3 hops)
- **Session Resume**: Interrupt and resume verification sessions
- **Automatic Learning**: Cache AI verdicts for future scans

## Installation

```bash
# Download the scanner
chmod +x php_sink_scanner.py

# For AI verification, install Claude Code CLI
# Visit: https://docs.claude.ai/
```

## Usage

### Basic Scanning (Static Analysis Only)

```bash
# Scan PHP project
python3 php_sink_scanner.py /path/to/php/project

# Filter by severity
python3 php_sink_scanner.py /path/to/project --severity CRITICAL

# Filter by vulnerability type
python3 php_sink_scanner.py /path/to/project --type SQL

# Verbose mode
python3 php_sink_scanner.py /path/to/project --verbose
```

### AI Verification (Recommended)

```bash
# Scan with AI verification
python3 php_sink_scanner.py /path/to/project --verify

# Critical findings only with AI
python3 php_sink_scanner.py /path/to/project --severity CRITICAL --verify

# SQL injection analysis
python3 php_sink_scanner.py /path/to/project --type SQL --verify --verbose
```

## How AI Verification Works

1. **Static Scan**: Scanner identifies potential vulnerabilities
2. **Pattern Check**: Compares against known safe patterns (cache)
3. **AI Analysis**: For unmatched findings, Claude Code analyzes:
   - Code context and data flow
   - Presence of security controls
   - Exploitability assessment
4. **Multi-Hop Context**: AI can request additional files if needed
5. **Verdict**: VULNERABLE | SAFE | MANUAL_REVIEW

### AI Verification Example

```
[1/15] Verifying SQL_INJECTION in users.php:145 (Score: 95)...
   → Reading: database.php [get_user_query]
   > Verdict: SAFE / MITIGATED
   Reason: Uses prepared statements with bindParam()
```

## Output Files

### Generated Reports

1. **`php_security_report.md`** - Full markdown report
   - Summary statistics
   - Findings by severity
   - Code snippets with CWE references
   - AI analysis (if --verify used)

2. **`scan_results.json`** - Machine-readable JSON
   ```json
   {
     "scan_date": "2026-01-31T...",
     "total_findings": 42,
     "statistics": {"CRITICAL": 5, "HIGH": 12, ...},
     "findings": [...]
   }
   ```

3. **`VERIFIED_VULNERABILITIES.md`** - Confirmed vulnerabilities only
   - Only created when using `--verify`
   - Contains AI-confirmed exploitable issues
   - Ready for reporting

4. **`known_safe_patterns.json`** - Pattern cache
   - Learned patterns from AI verdicts
   - Reused across scans to save tokens/$$

## Configuration

Edit constants in the script for custom behavior:

```python
# Rate limiting (minutes between AI calls)
WAIT_MINUTES = 3  # Set to 0 for testing

# AI context hops (how many files AI can request)
MAX_CONTEXT_HOPS = 3

# Minimum score for AI verification
MIN_SCORE_THRESHOLD = 50
```

## Vulnerability Patterns

### CRITICAL Severity
- **RCE_CRITICAL**: `system()`, `exec()`, `passthru()`, `shell_exec()`
- **EVAL_INJECTION**: `eval()` - arbitrary code execution
- **SQL_INJECTION**: Direct database queries
- **PDO_QUERY**: PDO without prepared statements
- **UNSERIALIZE_INJECTION**: `unserialize()` - object injection
- **CREATE_FUNCTION**: Deprecated code injection
- **PREG_REPLACE_EVAL**: `/e` modifier exploitation

### HIGH Severity
- **FILE_INCLUSION**: LFI/RFI via `include/require`
- **ARBITRARY_FILE_WRITE**: File upload/write operations
- **DYNAMIC_FUNCTION_CALL**: `call_user_func()`, `array_map()`
- **XML_EXTERNAL_ENTITY**: XXE in XML parsing
- **FILE_DELETION**: `unlink()`, `rmdir()`

### MEDIUM Severity
- **XSS_SINK**: Unescaped output
- **SSRF_SINK**: External HTTP requests
- **HEADER_INJECTION**: HTTP header manipulation
- **CSRF_MISSING_TOKEN**: POST without CSRF protection
- **XPATH_INJECTION**: Dynamic XPath queries
- **LDAP_INJECTION**: LDAP search injection
- **EXTRACT_VARIABLE_OVERRIDE**: `extract()` usage
- **MAIL_INJECTION**: Email header injection

### LOW Severity
- **WEAK_HASH**: MD5/SHA1 for passwords
- **INSECURE_RANDOM**: `rand()`, `mt_rand()`
- **PHPINFO_DISCLOSURE**: `phpinfo()` exposure

## Smart Scoring Features

The scanner adjusts risk scores based on context:

### Score Increases (+)
- Tainted variables in sinks: **+15**
- Direct `$_GET`/`$_POST` usage: **+20**
- Hardcoded internal URLs in SSRF: **+20**

### Score Decreases (-)
- Sanitization functions: **-25**
  - `htmlspecialchars()`, `filter_var()`, `intval()`
- Prepared statements: **-50**
  - `prepare()`, `bindParam()`
- Type casting: **-15**
  - `(int)`, `(string)`, `(bool)`
- Framework ORM methods: **-30**
  - `->insert()`, `->update()`, `->where()`
- Access controls: **-40**
  - `is_admin()`, `current_user_can()`

## Pattern Caching (Token Optimization)

The scanner learns from AI verdicts and caches patterns:

### Cached Pattern Types
- **prepared_statement**: Database with `prepare()` + `bindParam()`
- **pdo_safe_methods**: PDO with parameter binding
- **input_validation**: `filter_var()`, `is_numeric()`
- **output_escaping**: `htmlspecialchars()`, `esc_html()`
- **file_upload_validation**: MIME checks + extension validation
- **capability_check**: `current_user_can()`, `is_admin()`
- **framework_safe**: Laravel Eloquent, etc.

### Cache Benefits
```
Pattern cache saved 12 AI calls (~$6.00 saved)
```

## Examples

### Penetration Testing Workflow

```bash
# 1. Quick critical assessment
python3 php_sink_scanner.py /var/www/target --severity CRITICAL --verify

# 2. Full scan with AI verification
python3 php_sink_scanner.py /var/www/target --verify --verbose

# 3. Review confirmed vulnerabilities
cat /var/www/target/VERIFIED_VULNERABILITIES.md

# 4. Export for documentation
cat /var/www/target/scan_results.json | jq '.findings[] | select(.severity=="CRITICAL")'
```

### Bug Bounty Hunting

```bash
# Scan plugin/extension
python3 php_sink_scanner.py /path/to/plugin --verify

# Focus on high-payout vulns
python3 php_sink_scanner.py /path/to/plugin --type SQL --verify
python3 php_sink_scanner.py /path/to/plugin --type RCE --verify

# Check verified vulns
grep "VERDICT: VULNERABLE" /path/to/plugin/VERIFIED_VULNERABILITIES.md
```

### CI/CD Integration

```bash
#!/bin/bash
# security_check.sh

python3 php_sink_scanner.py . --severity CRITICAL --verify

CRITICAL=$(cat scan_results.json | jq '.statistics.CRITICAL // 0')

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Critical vulnerabilities found!"
    cat VERIFIED_VULNERABILITIES.md
    exit 1
fi

echo "✅ No critical vulnerabilities"
```

### Resume Interrupted Session

```bash
# Start scan with AI verification
python3 php_sink_scanner.py /path/to/project --verify

# ... rate limit hit or Ctrl+C ...

# Resume later (progress is saved)
python3 php_sink_scanner.py /path/to/project --verify
# Asks: "Resume from where you left off? (y/n):"
```

## Advanced Features

### Multi-Hop Context Gathering

AI can request additional files during analysis:

```
[SECURITY AUDIT]
Type: SQL_INJECTION
...

AI Response:
READ: includes/database.php [prepare_query]

System:
[Provides function code]

AI Response:
VERDICT: SAFE
The prepare_query() function uses PDO prepared statements with bindParam()
```

### Token-Efficient Prompts

Before (standard prompt): ~800 tokens
```
Analyze this potential SQL injection vulnerability...
[full file content]
[extensive rules]
...
```

After (optimized prompt): ~300 tokens
```
[SECURITY AUDIT]
Type: SQL_INJECTION
CODE: [snippet only]
RULES: SQL: Check prepare()/bindParam()
VERDICT: VULNERABLE|SAFE|MANUAL_REVIEW
```

**Savings**: 60%+ token reduction per verification

## Output Examples

### Console Output
```
[*] PHP Security Sink Scanner
[*] Target: /var/www/app
[*] AI Verification: ENABLED
[*] Token Optimization: Pattern caching + smart context extraction
[*] Phase 1: Scanning...

[+] Scanned 127 PHP files
[+] Found 45 potential security sinks

[*] Phase 2: AI Verification with Claude Code
[*] Verifying 23 findings (score >= 50)

[1/23] Verifying SQL_INJECTION in admin.php:145 (Score: 95)...
   ✓ Matched known safe pattern: prepared_statement
   > Verdict: SAFE / MITIGATED

[2/23] Verifying RCE_CRITICAL in upload.php:67 (Score: 100)...
   → Reading: includes/validate.php [check_permissions]
   > Verdict: VULNERABLE !!!
   
[i] Pattern cache saved 8 AI calls
```

### Verified Vulnerabilities Report
```markdown
# VERIFIED VULNERABILITIES

## RCE_CRITICAL - Direct Command Execution

**File:** `plugins/shell-exec/handler.php:67`
**CWE:** CWE-78
**Severity:** CRITICAL

### Code:
```php
$cmd = $_POST['command'];
system($cmd);
```

### AI Analysis:
VERDICT: VULNERABLE

The system() function executes user-controlled input from $_POST['command'] 
without any sanitization. No escapeshellarg() or capability checks present.

**Exploitation**: POST /handler.php with command=id to execute arbitrary OS commands.
```

## Best Practices

1. **Start with Critical**: `--severity CRITICAL --verify`
2. **Use Pattern Cache**: Rerun scans to benefit from learning
3. **Verify Before Reporting**: Always use `--verify` for bug bounties
4. **Review AI Verdicts**: Check AI reasoning in reports
5. **Combine with Manual Testing**: Confirm exploitability

## Limitations

- **Static Analysis**: Cannot detect complex runtime vulnerabilities
- **Pattern-Based**: May miss obfuscated code
- **No Data Flow**: Doesn't trace variables across functions
- **Framework Blind**: May not understand all framework protections
- **AI Rate Limits**: Respect Claude API rate limits

## Troubleshooting

### "claude command not found"
Install Claude Code CLI first

### Rate Limits
Increase `WAIT_MINUTES` to 3+ for production scans

### Too Many False Positives
1. Check if patterns are caching (run twice)
2. Use `--verify` to let AI filter false positives
3. Increase `MIN_SCORE_THRESHOLD`

### AI Verification Slow
- Reduce `MAX_CONTEXT_HOPS` to 1-2
- Use severity filters to scan less code
- Cache learns over time - subsequent scans are faster

## Cost Optimization

Pattern caching dramatically reduces AI costs:

**Without caching:**
- 50 findings × $0.50/call = $25.00

**With caching (after 2 scans):**
- 50 findings × 30% cached × $0.50 = $17.50
- **Savings: $7.50 (30%)**

## Contributing

Submit patterns in this format:
```python
"PATTERN_NAME": {
    "regex": r"your_regex",
    "score": 85,
    "severity": "HIGH",
    "desc": "Description",
    "cwe": "CWE-XXX"
}
```

## License

MIT - Use responsibly on authorized systems only.

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing any system you do not own.
