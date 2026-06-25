# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-798 - Hardcoded Credentials
# OWASP         : A07:2021 - Authentication Failures
# Severity      : Critical
# Expected rule : PSAvoidHardcodedCredential / SecretDetection/ApiToken
# Expected line : 12, 13, 14
# ============================================================

# Vulnerable: credentials hardcoded in plaintext
$dbUser     = "sa"
$dbPassword = "P@ssw0rd123!"
$apiToken   = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

$conn = New-Object System.Data.SqlClient.SqlConnection
$conn.ConnectionString = "Server=prod-db;User=$dbUser;Password=$dbPassword"
$conn.Open()
