"""BCheck DSL v2-beta templates for each supported vulnerability class."""

from __future__ import annotations

# Each template uses {name}, {description}, {author} for metadata substitution.
# Payloads and detection strings are hard-coded per vulnerability class.

TEMPLATES: dict[str, str] = {

    # ─────────────────────────────────────────────
    # SQL Injection
    # ─────────────────────────────────────────────
    "sqli": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "sqli", "injection", "bcheck-mcp"

# Error-based SQL injection detection
given request then
    send payload replacing each param value with "'"
    if response contains "SQL syntax" or
       response contains "mysql_fetch" or
       response contains "ORA-" or
       response contains "PostgreSQL" or
       response contains "SQLITE_ERROR" or
       response contains "Unclosed quotation mark" or
       response contains "quoted string not properly terminated" then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible SQL injection: database error triggered by single-quote payload. Manual verification required."
            remediation: "Use parameterised queries or prepared statements. Never concatenate user input into SQL strings."
        end
    end
end

# Time-based blind SQL injection (MySQL / MSSQL)
given request then
    send payload replacing each param value with "' AND SLEEP(5)-- -"
    if response time > 4500 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible time-based blind SQL injection: response delayed after SLEEP(5) payload."
            remediation: "Use parameterised queries or prepared statements."
        end
    end
end

given request then
    send payload replacing each param value with "'; WAITFOR DELAY '0:0:5'-- -"
    if response time > 4500 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible time-based blind SQL injection (MSSQL): response delayed after WAITFOR DELAY payload."
            remediation: "Use parameterised queries or prepared statements."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # Cross-Site Scripting (Reflected)
    # ─────────────────────────────────────────────
    "xss": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "xss", "injection", "bcheck-mcp"

given request then
    send payload replacing each param value with "<bcheckxss>\\">'><bcheckxss>"
    if response contains "<bcheckxss>" then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible reflected XSS: injected marker was reflected in the response unescaped."
            remediation: "HTML-encode all user-supplied output. Apply a Content Security Policy."
        end
    end
end

given request then
    send payload replacing each param value with "javascript:bcheckxss(1)"
    if response contains "javascript:bcheckxss" then
        report issue
            severity: medium
            confidence: tentative
            detail: "Possible XSS via javascript: URI scheme reflected in response."
            remediation: "Validate and sanitize URL parameters. Block javascript: scheme in href/src attributes."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # Server-Side Request Forgery
    # ─────────────────────────────────────────────
    "ssrf": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "ssrf", "bcheck-mcp"

# Cloud metadata endpoint
given request then
    send payload replacing each param value with "http://169.254.169.254/latest/meta-data/"
    if response contains "ami-id" or
       response contains "instance-id" or
       response contains "iam/security-credentials" then
        report issue
            severity: critical
            confidence: firm
            detail: "SSRF confirmed: AWS IMDSv1 metadata retrieved via user-controlled URL parameter."
            remediation: "Validate and whitelist allowed URL destinations. Use IMDSv2 with token-based access."
        end
    end
end

# Internal service detection via response time delta
given request then
    send payload replacing each param value with "http://127.0.0.1:22/"
    if response time < 500 then
        report issue
            severity: medium
            confidence: tentative
            detail: "Possible SSRF: fast response to internal loopback URL suggests server-side connection."
            remediation: "Restrict outbound connections from the application server. Validate and whitelist URL destinations."
        end
    end
end

# Collaborator-based SSRF detection
given request then
    send payload replacing each param value with {collaborator_payload}
    if dns interaction then
        report issue
            severity: high
            confidence: firm
            detail: "SSRF confirmed via Burp Collaborator: out-of-band DNS interaction triggered by user-controlled URL."
            remediation: "Validate and whitelist allowed URL destinations. Block requests to internal/cloud metadata addresses."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # Path Traversal
    # ─────────────────────────────────────────────
    "path_traversal": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "path-traversal", "lfi", "bcheck-mcp"

given request then
    send payload replacing each param value with "../../../../etc/passwd"
    if response contains "root:x:0:0" or response contains "root:*:" then
        report issue
            severity: critical
            confidence: firm
            detail: "Path traversal confirmed: /etc/passwd content returned in response."
            remediation: "Canonicalize file paths and reject any path containing '..' sequences. Use an allow-list of permitted files."
        end
    end
end

given request then
    send payload replacing each param value with "../../../../etc/shadow"
    if response contains "root:" and response contains ":" then
        report issue
            severity: critical
            confidence: firm
            detail: "Path traversal confirmed: /etc/shadow content returned — high privilege read."
            remediation: "Canonicalize file paths and reject any path containing '..' sequences."
        end
    end
end

given request then
    send payload replacing each param value with "..%2F..%2F..%2Fetc%2Fpasswd"
    if response contains "root:x:0:0" or response contains "root:*:" then
        report issue
            severity: critical
            confidence: firm
            detail: "Path traversal confirmed (URL-encoded): /etc/passwd content returned."
            remediation: "URL-decode input before validating. Reject '..' sequences after decoding."
        end
    end
end

given request then
    send payload replacing each param value with "../../../../windows/win.ini"
    if response contains "[extensions]" or response contains "; for 16-bit" then
        report issue
            severity: critical
            confidence: firm
            detail: "Path traversal confirmed: windows\\win.ini content returned."
            remediation: "Canonicalize file paths and reject any path containing '..' sequences."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # Command Injection
    # ─────────────────────────────────────────────
    "cmdi": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "cmdi", "command-injection", "rce", "bcheck-mcp"

# Output-based detection
given request then
    send payload replacing each param value with "; echo bcheckrce_$(id)"
    if response contains "bcheckrce_uid=" then
        report issue
            severity: critical
            confidence: firm
            detail: "Command injection confirmed: output of id command reflected in response."
            remediation: "Never pass user input to shell functions. Use language-native APIs instead of shell commands."
        end
    end
end

given request then
    send payload replacing each param value with "| echo bcheckrce_test"
    if response contains "bcheckrce_test" then
        report issue
            severity: critical
            confidence: firm
            detail: "Command injection confirmed: pipe-based payload output reflected in response."
            remediation: "Never pass user input to shell functions. Whitelist expected input formats."
        end
    end
end

# Time-based blind detection
given request then
    send payload replacing each param value with "; sleep 5"
    if response time > 4500 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible blind command injection: response delayed after sleep 5 payload."
            remediation: "Never pass user input to shell functions."
        end
    end
end

given request then
    send payload replacing each param value with "& ping -c 5 127.0.0.1 &"
    if response time > 4000 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible blind command injection: response delayed after ping-based payload."
            remediation: "Never pass user input to shell functions."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # XXE (XML External Entity)
    # ─────────────────────────────────────────────
    "xxe": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "xxe", "xml", "bcheck-mcp"

given request then
    if request.body contains "<?xml" or request.headers["Content-Type"] contains "xml" then
        send payload replacing request.body with "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>"
        if response contains "root:x:0:0" or response contains "root:*:" then
            report issue
                severity: critical
                confidence: firm
                detail: "XXE confirmed: /etc/passwd content returned via external entity injection."
                remediation: "Disable external entity processing in your XML parser. Use a safe parser configuration."
            end
        end
    end
end

# OOB XXE via Collaborator
given request then
    if request.body contains "<?xml" or request.headers["Content-Type"] contains "xml" then
        send payload replacing request.body with "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"http://{collaborator_payload}/xxe\\">]><foo>&xxe;</foo>"
        if dns interaction then
            report issue
                severity: high
                confidence: firm
                detail: "Out-of-band XXE confirmed via Burp Collaborator DNS interaction."
                remediation: "Disable external entity processing in your XML parser."
            end
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # IDOR / BOLA
    # ─────────────────────────────────────────────
    "idor": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "idor", "bola", "access-control", "bcheck-mcp"

# Increment numeric IDs in path segments
given path then
    if {{latest.path}} matches ".*\\/[0-9]+(\\/|$).*" then
        send payload replacing each numeric path segment matching "([0-9]+)" with increment
        if response.status_code == 200 then
            if response.body.length > 0 then
                report issue
                    severity: medium
                    confidence: tentative
                    detail: "Possible IDOR: incrementing a numeric ID in the path returned a 200 response with content. Verify whether the returned object belongs to a different user."
                    remediation: "Enforce object-level authorization checks on every resource access. Do not rely solely on object ID obscurity."
                end
            end
        end
    end
end

# Substitute common ID parameter names
given request then
    send payload replacing each param name matching "^(id|user_id|account_id|order_id|doc_id|record_id|item_id)$" with incremented numeric value
    if response.status_code == 200 then
        report issue
            severity: medium
            confidence: tentative
            detail: "Possible IDOR: changing a user-controlled ID parameter returned a 200 response. Verify ownership of the returned resource."
            remediation: "Enforce object-level authorization on every API endpoint."
        end
    end
end
""",

    # ─────────────────────────────────────────────
    # Open Redirect
    # ─────────────────────────────────────────────
    "open_redirect": """\
metadata:
    language: v2-beta
    name: "{name}"
    description: "{description}"
    author: "{author}"
    tags: "open-redirect", "bcheck-mcp"

given request then
    send payload replacing each param value with "https://bcheck-mcp-canary.example.com/redirect"
    if response.status_code is in (301, 302, 303, 307, 308) then
        if response.headers["Location"] contains "bcheck-mcp-canary.example.com" then
            report issue
                severity: medium
                confidence: firm
                detail: "Open redirect confirmed: injected external URL appears in Location header."
                remediation: "Whitelist allowed redirect destinations. Never redirect to user-supplied absolute URLs."
            end
        end
    end
end

given request then
    send payload replacing each param value with "//bcheck-mcp-canary.example.com"
    if response.status_code is in (301, 302, 303, 307, 308) then
        if response.headers["Location"] contains "bcheck-mcp-canary.example.com" then
            report issue
                severity: medium
                confidence: firm
                detail: "Open redirect confirmed via protocol-relative URL in Location header."
                remediation: "Validate redirect URLs against a strict whitelist of allowed domains."
            end
        end
    end
end
""",
}

# Keyword → vuln class mapping used when vuln_classes is empty
KEYWORD_MAP: dict[str, str] = {
    "sql": "sqli",
    "sqli": "sqli",
    "injection": "sqli",
    "xss": "xss",
    "cross-site": "xss",
    "script": "xss",
    "ssrf": "ssrf",
    "request forgery": "ssrf",
    "path traversal": "path_traversal",
    "traversal": "path_traversal",
    "lfi": "path_traversal",
    "directory traversal": "path_traversal",
    "command": "cmdi",
    "cmdi": "cmdi",
    "rce": "cmdi",
    "remote code": "cmdi",
    "xxe": "xxe",
    "xml": "xxe",
    "external entity": "xxe",
    "idor": "idor",
    "bola": "idor",
    "broken object": "idor",
    "redirect": "open_redirect",
    "open redirect": "open_redirect",
}

SUPPORTED_CLASSES = list(TEMPLATES.keys())
