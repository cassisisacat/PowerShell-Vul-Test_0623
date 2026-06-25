# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-078 - OS Command Injection
# OWASP         : A03:2021 - Injection
# Severity      : Critical
# Expected rule : InjectionRisk.InvokeExpression / CWE-078/CommandInjection
# Expected line : 13, 14
# ============================================================

function Get-FileInfo($userInput) {
    # Vulnerable: user input injected directly into command string
    $cmd = "Get-ChildItem " + $userInput
    Invoke-Expression $cmd
}

# Attacker passes: "C:\temp; Remove-Item C:\Windows -Recurse"
Get-FileInfo $args[0]
