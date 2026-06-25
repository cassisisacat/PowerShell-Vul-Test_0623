# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-312 - Cleartext Storage of Sensitive Information
# OWASP         : A02:2021 - Cryptographic Failures
# Severity      : High
# Expected rule : PSAvoidUsingConvertToSecureStringWithPlainText / CWE-312/PlaintextPassword
# Expected line : 13, 14
# ============================================================

# Vulnerable: password visible in plaintext in script and process list
$password   = "SuperSecret99"
$securePass = ConvertTo-SecureString $password -AsPlainText -Force

$cred = New-Object PSCredential("admin", $securePass)
Invoke-Command -ComputerName "server01" -Credential $cred -ScriptBlock {
    Get-Service
}
