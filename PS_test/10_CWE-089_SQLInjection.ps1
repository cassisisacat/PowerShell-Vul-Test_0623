# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-089 - SQL Injection
# OWASP         : A03:2021 - Injection
# Severity      : Critical
# Expected rule : CWE-089/SQLInjection / CWE-089/UnsafeInvokeSqlcmd
# Expected line : 12, 17
# ============================================================

function Get-UserOrders($customerId) {
    # Vulnerable: string concatenation used to build the SQL query
    $query = "SELECT * FROM Orders WHERE CustomerId = '" + $customerId + "'"

    # Attacker: customerId = "' OR '1'='1"           -> dumps all rows
    # Attacker: customerId = "'; DROP TABLE Orders;--" -> destroys table

    Invoke-Sqlcmd -ServerInstance "prod-db" `
                  -Database "Shop" `
                  -Query $query
}

function Search-Products($keyword) {
    # Vulnerable: format string injection into LIKE clause
    $query = "SELECT * FROM Products WHERE Name LIKE '%" + $keyword + "%'"

    Invoke-Sqlcmd -ServerInstance "prod-db" `
                  -Database "Shop" `
                  -Query $query
}

Get-UserOrders  $args[0]
Search-Products $args[1]
