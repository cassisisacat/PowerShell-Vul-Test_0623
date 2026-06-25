# PowerShell SAST Vulnerability Test Dataset
# ============================================================
# Purpose : Benchmark corpus for evaluating SAST scanning tools
#           on PowerShell-specific vulnerability patterns.
#           All scripts are INTENTIONALLY VULNERABLE.
#           DO NOT execute in production or live environments.
# ============================================================


## File Index & Expected SAST Findings

| File                                  | CWE       | Category                       | Severity | Key Trigger Lines |
|---------------------------------------|-----------|--------------------------------|----------|-------------------|
| 01_CWE-078_CommandInjection.ps1       | CWE-078   | OS Command Injection           | Critical | 12, 13            |
| 02_CWE-798_HardcodedCredentials.ps1   | CWE-798   | Hardcoded Credentials          | Critical | 12, 13, 14        |
| 03_CWE-312_CleartextCredential.ps1    | CWE-312   | Cleartext Credential Storage   | High     | 13, 14            |
| 04_CWE-022_PathTraversal.ps1          | CWE-022   | Path Traversal                 | High     | 14, 17            |
| 05_CWE-327_WeakCryptography.ps1       | CWE-327   | Weak Cryptographic Algorithm   | High     | 12, 20, 23, 26    |
| 06_CWE-502_InsecureDeserialization.ps1| CWE-502   | Insecure Deserialization       | Critical | 13, 19            |
| 07_CWE-611_XXE.ps1                    | CWE-611   | XML External Entity (XXE)      | High     | 13, 15, 23        |
| 08_CWE-732_InsecurePermissions.ps1    | CWE-732   | Incorrect Permission Assignment| High     | 16, 20, 28, 32    |
| 09_CWE-532_SensitiveInfoInLogs.ps1    | CWE-532   | Sensitive Information in Logs  | Medium   | 13, 16, 19, 22    |
| 10_CWE-089_SQLInjection.ps1           | CWE-089   | SQL Injection                  | Critical | 12, 17, 23, 26    |


## Expected Findings Per File

### 01 — CWE-078 Command Injection
  Rule    : InjectionRisk.InvokeExpression
  Sev     : High / Critical
  Message : User-controlled variable concatenated into command string before Invoke-Expression.

### 02 — CWE-798 Hardcoded Credentials
  Rule    : PSAvoidHardcodedCredential
  Rule    : SecretDetection/ApiToken (GitHub PAT pattern)
  Sev     : Critical
  Message : Plaintext password/token literal detected in source code.

### 03 — CWE-312 Cleartext Credential
  Rule    : PSAvoidUsingConvertToSecureStringWithPlainText
  Sev     : Error / High
  Message : ConvertTo-SecureString used with -AsPlainText flag.

### 04 — CWE-022 Path Traversal
  Rule    : CWE-022/PathTraversal
  Rule    : UnsafeFileAccess
  Sev     : High
  Message : User input concatenated into file path without canonicalization.

### 05 — CWE-327 Weak Cryptography
  Rule    : CWE-327/WeakHashAlgorithm   (MD5, SHA1)
  Rule    : CWE-327/WeakEncryptionAlgorithm (DES, RC2)
  Sev     : High
  Message : Broken or weak algorithm instantiated. Use SHA-256+/AES-256.

### 06 — CWE-502 Insecure Deserialization
  Rule    : CWE-502/UntrustedDeserialization
  Rule    : CWE-502/RemoteDeserialization
  Sev     : Critical
  Message : Import-CliXml / ConvertFrom-Clixml called on user-controlled input.

### 07 — CWE-611 XXE
  Rule    : CWE-611/XXEViaXmlDocument
  Rule    : CWE-611/ExternalEntityEnabled
  Sev     : High
  Message : XmlDocument.LoadXml() without DtdProcessing = Prohibit or XmlResolver = null.

### 08 — CWE-732 Insecure Permissions
  Rule    : CWE-732/WorldWritablePermission
  Rule    : CWE-732/InsecureAcl
  Sev     : High
  Message : FileSystemAccessRule / RegistryAccessRule grants FullControl to "Everyone".

### 09 — CWE-532 Sensitive Info in Logs
  Rule    : CWE-532/PasswordInLog
  Rule    : CWE-532/SecretInOutput
  Rule    : CWE-532/CredentialInVerbose
  Sev     : Medium / High
  Message : Credential/token variable referenced inside Write-EventLog / Write-Host / Add-Content.

### 10 — CWE-089 SQL Injection
  Rule    : CWE-089/SQLInjection
  Rule    : CWE-089/UnsafeInvokeSqlcmd
  Sev     : Critical
  Message : User-controlled variable concatenated into SQL query string passed to Invoke-Sqlcmd.


## Scoring Your SAST Tool

For each file, record:

  TP (True Positive)  — tool correctly flags the known vulnerable line(s)
  FP (False Positive) — tool flags lines that are not actually vulnerable
  FN (False Negative) — tool misses a known vulnerable line

Then calculate:

  Detection Rate   = TP / (TP + FN)         (higher is better)
  Precision        = TP / (TP + FP)         (higher is better)
  F1 Score         = 2 * (Precision * DR) / (Precision + DR)


## Safe to Run?

These files contain NO executable payloads — they are syntactically valid
PowerShell scripts that reference dangerous API patterns but do not connect
to real databases, systems, or services without real credentials/endpoints
being supplied. Static analysis (SAST) can be run safely without execution.

For dynamic testing (DAST), use an isolated sandbox with no network egress.
