# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
# OWASP         : A02:2021 - Cryptographic Failures
# Severity      : High
# Expected rule : CWE-327/WeakHashAlgorithm / CWE-327/WeakEncryptionAlgorithm
# Expected line : 12, 21
# ============================================================

# Vulnerable: MD5 for password hashing (cryptographically broken)
function Get-PasswordHash($password) {
    $md5   = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($password)
    $hash  = $md5.ComputeHash($bytes)
    return [BitConverter]::ToString($hash) -replace '-', ''
}

# Vulnerable: SHA1 for integrity check (collision-prone since 2017)
$sha1  = [System.Security.Cryptography.SHA1]::Create()

# Vulnerable: DES encryption (56-bit key, brute-forceable in hours)
$des   = [System.Security.Cryptography.DESCryptoServiceProvider]::new()

# Vulnerable: RC2 (variable key size, multiple known weaknesses)
$rc2   = [System.Security.Cryptography.RC2CryptoServiceProvider]::new()
