# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-502 - Deserialization of Untrusted Data
# OWASP         : A08:2021 - Software and Data Integrity Failures
# Severity      : Critical
# Expected rule : CWE-502/UntrustedDeserialization / CWE-502/RemoteDeserialization
# Expected line : 13, 19
# ============================================================

# Vulnerable: deserializing user-supplied file without validation
function Load-Config($configPath) {
    # Attacker controls $configPath and its CLIXML content
    # Gadget chains can trigger DNS lookups or arbitrary file reads
    $config = Import-CliXml -Path $configPath
    return $config
}

# Vulnerable: deserializing from a remote URL response
$userSuppliedUrl = $args[0]
$response = Invoke-WebRequest -Uri $userSuppliedUrl
$obj      = $response.Content | ConvertFrom-Clixml

Load-Config $args[1]
