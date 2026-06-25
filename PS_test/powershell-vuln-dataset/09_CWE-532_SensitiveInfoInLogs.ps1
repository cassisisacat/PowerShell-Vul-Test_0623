# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-532 - Insertion of Sensitive Information into Log File
# OWASP         : A09:2021 - Security Logging and Monitoring Failures
# Severity      : Medium
# Expected rule : CWE-532/PasswordInLog / CWE-532/SecretInOutput / CWE-532/CredentialInVerbose
# Expected line : 13, 16, 19
# ============================================================

function Connect-Service($username, $password) {
    # Vulnerable: credential written to Windows Event Log in plaintext
    Write-EventLog -LogName Application -Source "MyApp" -EventId 1001 `
        -Message "Connecting as $username with password $password"

    # Vulnerable: API token written to host output (captured by transcripts / CI logs)
    Write-Host "DEBUG: token=$env:API_TOKEN"

    # Vulnerable: password in Verbose stream (logged when -Verbose is active)
    Write-Verbose "Auth payload: user=$username pass=$password"

    # Vulnerable: connection string with embedded password written to file log
    $connStr = "Server=prod;User=$username;Password=$password"
    Add-Content -Path "C:\Logs\app.log" -Value "[$(Get-Date)] Connecting: $connStr"
}

Connect-Service $args[0] $args[1]
