# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-022 - Path Traversal
# OWASP         : A01:2021 - Broken Access Control
# Severity      : High
# Expected rule : CWE-022/PathTraversal / UnsafeFileAccess
# Expected line : 14, 17
# ============================================================

function Get-UserReport($username) {
    # Vulnerable: no path sanitization or boundary check
    $basePath   = "C:\Reports"
    $reportPath = "$basePath\$username\report.csv"

    # Attacker: username = "..\..\Windows\System32\drivers\etc\hosts"
    $content = Get-Content $reportPath
    return $content
}

Get-UserReport $args[0]
