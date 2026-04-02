"""BCheck v2-beta DSL syntax reference — correct rules for Claude."""

BCHECK_SYNTAX_GUIDE = '''
# BCheck v2-beta — Correct Syntax Reference

## GOLDEN TEMPLATE

```
metadata:
  language: v2-beta
  name: "Check Name"
  description: "Description"
  author: "Author"
  tags: "tag1", "tag2"

given insertion point then
  send payload:
    replacing: "payload"
  if {condition} then
    report issue:
      severity: high
      confidence: tentative
      detail: "Detail string."
      remediation: "Remediation string."
  end if
```

## STRUCTURE RULES

1. **metadata block** — always first
2. **define block** — optional, comes after metadata
3. **given...then block** — ONE per file, NO closing keyword, ends at EOF

## CLOSING KEYWORDS

| Block | Closes with |
|---|---|
| `given...then` | **nothing** — ends at EOF |
| `if...then` | `end if` |
| `report issue:` | **nothing** — ends when `end if` is hit |

**NEVER write a bare `end` to close `given...then`.**

## INSERTION POINT SCOPES

```
given insertion point then          ← DEFAULT, covers all types
given query insertion point then
given body insertion point then
given header insertion point then
given cookie insertion point then
given any insertion point then
```

## SEND PAYLOAD SYNTAX

```
send payload:
  replacing: "your-payload"    ← replaces the insertion point value
```

```
send payload:
  appending: "your-payload"    ← appends to the insertion point value
```

**NEVER write:** `send payload replacing each parameter value with ...`

## RESPONSE REFERENCES

```
latest.response.body        ← response body (wrap in {} in expressions)
latest.response.duration    ← response time in milliseconds
```

**NEVER write:** `response.body` or `response.time` or `response time`

## CONDITIONS

```
if {to_lower(latest.response.body)} matches "pattern1|pattern2" then

if {latest.response.body} matches "root:x:0:0|root:\\*:" then

if latest.response.duration > 4500 then

if dns interaction then

if http interaction then
```

## TAGS

Comma-separated quoted strings:
```
tags: "sqli", "injection", "bcheck-mcp"
```

**NEVER:** `tags: "sqli,injection"` (single string with commas inside)

## COLLABORATOR

```
send payload:
  replacing: {collaborator_payload}
if dns interaction then
  report issue:
    severity: high
    confidence: firm
    detail: "OOB DNS interaction triggered."
    remediation: "Validate and whitelist URL destinations."
end if
```

---

## FULL EXAMPLES

### Error-based SQLi
```
metadata:
  language: v2-beta
  name: "SQLi - Error Based"
  description: "Error-based SQL injection detection"
  author: "BCheck-MCP"
  tags: "sqli", "injection"

given insertion point then
  send payload:
    replacing: "'"
  if {to_lower(latest.response.body)} matches "sql syntax|mysql_fetch|ora-[0-9]+|postgresql|sqlite_error|unclosed quotation mark|quoted string not properly terminated" then
    report issue:
      severity: high
      confidence: tentative
      detail: "SQL error triggered by single-quote payload."
      remediation: "Use parameterised queries."
  end if
```

### Time-based blind SQLi
```
metadata:
  language: v2-beta
  name: "SQLi - Time Based"
  description: "Time-based blind SQL injection"
  author: "BCheck-MCP"
  tags: "sqli", "injection"

given insertion point then
  send payload:
    replacing: "' AND SLEEP(5)-- -"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Time-based blind SQLi: SLEEP(5) caused response delay."
      remediation: "Use parameterised queries."
  end if
```

### Reflected XSS
```
metadata:
  language: v2-beta
  name: "XSS - Reflected"
  description: "Reflected XSS detection"
  author: "BCheck-MCP"
  tags: "xss", "injection"

given insertion point then
  send payload:
    replacing: "<bcheckxss>\\\">'><bcheckxss>"
  if {latest.response.body} matches "<bcheckxss>" then
    report issue:
      severity: high
      confidence: tentative
      detail: "Reflected XSS: injected marker reflected unescaped."
      remediation: "HTML-encode all output. Apply CSP."
  end if
```

### SSRF with Collaborator
```
metadata:
  language: v2-beta
  name: "SSRF - OOB"
  description: "SSRF via Burp Collaborator"
  author: "BCheck-MCP"
  tags: "ssrf"

given insertion point then
  send payload:
    replacing: {collaborator_payload}
  if dns interaction then
    report issue:
      severity: high
      confidence: firm
      detail: "SSRF: OOB DNS triggered by Collaborator payload."
      remediation: "Whitelist allowed URL destinations."
  end if
```

### Path Traversal
```
metadata:
  language: v2-beta
  name: "Path Traversal"
  description: "LFI via path traversal"
  author: "BCheck-MCP"
  tags: "path-traversal", "lfi"

given insertion point then
  send payload:
    replacing: "../../../../etc/passwd"
  if {latest.response.body} matches "root:x:0:0|root:\\*:" then
    report issue:
      severity: critical
      confidence: firm
      detail: "Path traversal: /etc/passwd returned."
      remediation: "Canonicalize paths. Reject '..' sequences."
  end if
```

### Command Injection (blind, time-based)
```
metadata:
  language: v2-beta
  name: "CMDi - Blind Time Based"
  description: "Blind command injection via sleep"
  author: "BCheck-MCP"
  tags: "cmdi", "rce"

given insertion point then
  send payload:
    replacing: "; sleep 5"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Blind command injection: sleep 5 caused delay."
      remediation: "Never pass user input to shell commands."
  end if
```

### Multiple checks in one file (multiple send/if inside one given...then)
```
metadata:
  language: v2-beta
  name: "SQLi - Full"
  description: "Error-based and time-based SQLi"
  author: "BCheck-MCP"
  tags: "sqli", "injection"

given insertion point then
  send payload:
    replacing: "'"
  if {to_lower(latest.response.body)} matches "sql syntax|mysql_fetch|ora-[0-9]+" then
    report issue:
      severity: high
      confidence: tentative
      detail: "Error-based SQLi detected."
      remediation: "Use parameterised queries."
  end if
  send payload:
    replacing: "' AND SLEEP(5)-- -"
  if latest.response.duration > 4500 then
    report issue:
      severity: high
      confidence: tentative
      detail: "Time-based blind SQLi detected."
      remediation: "Use parameterised queries."
  end if
```

## CHECKLIST BEFORE WRITING

- [ ] ONE `given...then` block only — no second given block
- [ ] `given...then` has NO closing keyword — it ends at EOF
- [ ] Every `if...then` has a matching `end if`
- [ ] `report issue:` has NO closing keyword
- [ ] `send payload:` uses colon + indented `replacing:` or `appending:`
- [ ] Response body: `latest.response.body` (not `response.body`)
- [ ] Response time: `latest.response.duration` (not `response time`)
- [ ] Tags: `"tag1", "tag2"` (not `"tag1,tag2"`)
- [ ] Use `{...}` around expressions: `{to_lower(latest.response.body)}`
'''
