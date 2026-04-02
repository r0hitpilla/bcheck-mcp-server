"""BCheck v2-beta DSL syntax reference for Claude to use when writing checks."""

BCHECK_SYNTAX_GUIDE = '''
# BCheck v2-beta DSL — Complete Syntax Reference

## File Structure

Every .bcheck file has two sections: metadata block + one or more given...then...end blocks.

```
metadata:
    language: v2-beta
    name: "Check Name Here"
    description: "What this check does"
    author: "BCheck-MCP"
    tags: "tag1", "tag2"

given <scope> then
    <conditions and actions>
end
```

## Metadata Fields (all required)
- `language: v2-beta`  — must be exactly this
- `name: "..."`         — human-readable name shown in Burp UI
- `description: "..."` — explanation of what the check tests
- `author: "..."`      — author string
- `tags: "t1", "t2"`  — optional comma-separated tags

## Scope (the `given` clause)

```
given request then          # fires on every proxied request
given response then         # fires on every proxied response
given path then             # fires on path-based checks
given insertion point then  # fires for each insertion point Burp finds
```

## Sending Payloads

### Replace query/body param values
```
send payload replacing each param value with "<payload>"
send payload replacing param value named "id" with "<payload>"
send payload replacing param value named "search" with "<payload>"
```

### Replace JSON body param values
```
send payload replacing json param value named "username" with "<payload>"
send payload replacing json param value named "url" with "<payload>"
```

### Replace cookie values
```
send payload replacing cookie value named "session" with "<payload>"
send payload replacing cookie value named "user_id" with "<payload>"
```

### Replace header values
```
send payload replacing header value named "X-Forwarded-For" with "<payload>"
send payload replacing header value named "Referer" with "<payload>"
send payload replacing header value named "Origin" with "<payload>"
```

### Replace entire request body (for XML/GraphQL/raw)
```
send payload replacing request.body with "<full-body-payload>"
```

### Replace path segments
```
send payload replacing each numeric path segment matching "([0-9]+)" with increment
```

### Multiple replacements in one payload
```
send payload replacing param value named "q" with "'-- -"
```

## Conditions

### Response body contains
```
if response contains "SQL syntax" then
if response contains "root:x:0:0" then
if not response contains "Welcome" then
```

### Response body contains multiple (OR)
```
if response contains "SQL syntax" or
   response contains "mysql_fetch" or
   response contains "ORA-" then
```

### Response body contains multiple (AND)
```
if response contains "error" and
   response contains "database" then
```

### Response status code
```
if response.status_code == 200 then
if response.status_code is in (301, 302, 303, 307, 308) then
if response.status_code != 200 then
```

### Response time (milliseconds)
```
if response time > 5000 then
if response time < 500 then
```

### Response headers
```
if response.headers["Location"] contains "evil.com" then
if response.headers["Content-Type"] contains "application/json" then
```

### Response body length
```
if response.body.length > 0 then
if response.body.length > 1000 then
```

### Request properties
```
if request.body contains "<?xml" then
if request.headers["Content-Type"] contains "xml" then
if {latest.url} matches ".*\\/api\\/.*" then
```

### Out-of-band (Burp Collaborator)
```
if dns interaction then
if http interaction then
if any interaction then
```

### Regex matching
```
if response matches "error.*line [0-9]+" then
if {latest.path} matches ".*\\/[0-9]+\\/.*" then
```

## Report Issue Block

```
report issue
    severity: info          # info | low | medium | high | critical
    confidence: tentative   # tentative | firm | certain
    detail: "Finding detail shown in Burp dashboard. Include payload and evidence."
    remediation: "How to fix this vulnerability."
end
```

## Collaborator Payloads

Use `{collaborator_payload}` as a literal placeholder — Burp substitutes the real URL:

```
send payload replacing param value named "url" with {collaborator_payload}
if dns interaction then
    report issue
        severity: high
        confidence: firm
        detail: "SSRF via OOB DNS — Collaborator received DNS lookup."
        remediation: "Whitelist allowed URL destinations."
    end
end
```

## Full Examples

### Error-based SQLi on a specific param
```
metadata:
    language: v2-beta
    name: "SQLi - id param"
    description: "Error-based SQL injection on the id parameter"
    author: "BCheck-MCP"
    tags: "sqli"

given request then
    send payload replacing param value named "id" with "'"
    if response contains "SQL syntax" or
       response contains "mysql_fetch" or
       response contains "ORA-" or
       response contains "Unclosed quotation mark" then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible SQLi: single-quote triggered database error in response."
            remediation: "Use parameterised queries."
        end
    end
end
```

### Time-based blind SQLi
```
given request then
    send payload replacing param value named "search" with "' AND SLEEP(5)-- -"
    if response time > 4500 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible time-based blind SQLi: SLEEP(5) caused response delay."
            remediation: "Use parameterised queries."
        end
    end
end
```

### SSRF via JSON body param
```
given request then
    if request.headers["Content-Type"] contains "json" then
        send payload replacing json param value named "webhook_url" with {collaborator_payload}
        if dns interaction then
            report issue
                severity: high
                confidence: firm
                detail: "SSRF: OOB DNS triggered by injecting Collaborator URL into webhook_url JSON param."
                remediation: "Validate and whitelist URL destinations."
            end
        end
    end
end
```

### Reflected XSS on query param
```
given request then
    send payload replacing param value named "q" with "<bcheckxss-probe>\\\">'><bcheckxss-probe>"
    if response contains "<bcheckxss-probe>" then
        report issue
            severity: high
            confidence: tentative
            detail: "Reflected XSS: injected marker reflected unescaped in HTML response."
            remediation: "HTML-encode all output. Apply CSP."
        end
    end
end
```

### Path traversal on file param
```
given request then
    send payload replacing param value named "file" with "../../../../etc/passwd"
    if response contains "root:x:0:0" or response contains "root:*:" then
        report issue
            severity: critical
            confidence: firm
            detail: "Path traversal: /etc/passwd read via file parameter."
            remediation: "Canonicalize paths, reject sequences containing '..'."
        end
    end
end
```

### IDOR via numeric path segment
```
given request then
    if {latest.path} matches ".*\\/[0-9]+(\\/|$).*" then
        send payload replacing param value named "user_id" with "2"
        if response.status_code == 200 then
            if response.body.length > 0 then
                report issue
                    severity: medium
                    confidence: tentative
                    detail: "Possible IDOR: changed user_id returned 200 with content. Verify ownership."
                    remediation: "Enforce object-level authorization."
                end
            end
        end
    end
end
```

### XXE on XML body
```
given request then
    if request.body contains "<?xml" then
        send payload replacing request.body with "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><foo>&xxe;</foo>"
        if response contains "root:x:0:0" then
            report issue
                severity: critical
                confidence: firm
                detail: "XXE confirmed: /etc/passwd returned via external entity injection."
                remediation: "Disable external entity processing in XML parser."
            end
        end
    end
end
```

### Command injection (blind, time-based)
```
given request then
    send payload replacing param value named "host" with "127.0.0.1; sleep 5"
    if response time > 4500 then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible blind command injection: sleep 5 caused response delay."
            remediation: "Never pass user input to shell commands."
        end
    end
end
```

### Header injection (X-Forwarded-For)
```
given request then
    send payload replacing header value named "X-Forwarded-For" with "127.0.0.1"
    if response contains "Welcome admin" or
       response contains "internal only" then
        report issue
            severity: high
            confidence: tentative
            detail: "Possible IP restriction bypass via X-Forwarded-For header spoofing."
            remediation: "Do not trust X-Forwarded-For for access control."
        end
    end
end
```

## Writing Tips for Claude

1. **Be specific**: Target named params (`replacing param value named "id"`) not all params.
2. **Match body format**: JSON bodies use `json param value named`, form bodies use `param value named`.
3. **Layer checks**: Error-based + time-based in the same file (two `given...end` blocks).
4. **Use Collaborator** for SSRF, XXE OOB, blind CMDI where direct response inspection fails.
5. **Escape quotes** in DSL strings with `\\"` inside double-quoted strings.
6. **Short canary values**: Use distinctive strings like `bchkprobe123` so detection is precise.
7. **Conditional guards**: Wrap XML/JSON-specific payloads in `if request.headers["Content-Type"] contains "..."` guards.
8. **Regex for path IDs**: Use `{latest.path} matches ".*\\/[0-9]+.*"` before IDOR attempts.
'''
