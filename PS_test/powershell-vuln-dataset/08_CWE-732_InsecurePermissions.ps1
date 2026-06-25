# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-732 - Incorrect Permission Assignment for Critical Resource
# OWASP         : A01:2021 - Broken Access Control
# Severity      : High
# Expected rule : CWE-732/WorldWritablePermission / CWE-732/InsecureAcl
# Expected line : 16, 20
# ============================================================

# Vulnerable: granting Everyone FullControl on a sensitive directory
$path = "C:\App\Secrets"
New-Item -ItemType Directory -Path $path -Force

$acl  = Get-Acl $path
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Everyone", "FullControl",
    "ContainerInherit,ObjectInherit",
    "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $path $acl

# Also vulnerable: world-writable registry key
$regPath = "HKLM:\SOFTWARE\MyApp\Config"
New-Item -Path $regPath -Force | Out-Null

$regAcl  = Get-Acl $regPath
$regRule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "Everyone", "FullControl",
    "ContainerInherit,ObjectInherit",
    "None", "Allow")
$regAcl.AddAccessRule($regRule)
Set-Acl $regPath $regAcl
