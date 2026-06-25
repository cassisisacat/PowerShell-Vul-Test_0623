# ============================================================
# SAST TEST CASE - DO NOT USE IN PRODUCTION
# Vulnerability : CWE-611 - XML External Entity (XXE) Injection
# OWASP         : A05:2021 - Security Misconfiguration
# Severity      : High
# Expected rule : CWE-611/XXEViaXmlDocument / CWE-611/ExternalEntityEnabled
# Expected line : 13, 15
# ============================================================

# Vulnerable: XmlDocument with default settings — DTD and external entities ENABLED
function Parse-XmlData($xmlContent) {
    $doc = New-Object System.Xml.XmlDocument
    # No XmlReaderSettings configured; DTD processing is on by default
    $doc.LoadXml($xmlContent)
    return $doc.SelectSingleNode("//data").InnerText
}

# Attacker-controlled payload example:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
# <root><data>&xxe;</data></root>

# Also vulnerable: loading XML from a file path without DTD restrictions
function Load-XmlFile($filePath) {
    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($filePath)
    return $doc
}

Parse-XmlData $args[0]
Load-XmlFile  $args[1]
